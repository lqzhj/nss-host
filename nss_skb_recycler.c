/*
***************************************************************************
** Copyright (c) 2014, The Linux Foundation. All rights reserved.
** Permission to use, copy, modify, and/or distribute this software for
** any purpose with or without fee is hereby granted, provided that the
** above copyright notice and this permission notice appear in all copies.
** THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
** WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
** ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
** WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
** ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
** OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
***************************************************************************
**/

/*
 * NSS skb recycler - implements SKB allocation and free routines
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/splice.h>
#include <linux/cpu.h>
#include <trace/events/skb.h>
#include "nss_core.h"
#include "nss_skb_recycler.h"

#define NSS_SKB_RECYCLE_SIZE	2304
#define NSS_SKB_RECYCLE_MIN_SIZE	NSS_SKB_RECYCLE_SIZE
#define NSS_SKB_RECYCLE_MAX_SKBS	1024

#define NSS_SKB_RECYCLE_SPARE_MAX_SKBS 128

#define NSS_SKB_RECYCLE_MAX_SHARED_POOLS  8
#define NSS_SKB_RECYCLE_MAX_SHARED_POOLS_MASK (NSS_SKB_RECYCLE_MAX_SHARED_POOLS - 1)

struct nss_skb_global_recycle_list {
	struct sk_buff_head pool[NSS_SKB_RECYCLE_MAX_SHARED_POOLS];
				/* Global list which holds the shared skb-pools */
	uint8_t head;           /* head of the list*/
	uint8_t tail;           /* tail of the list*/
	spinlock_t lock;        /* lock for serializing access to the list */
};

#ifdef NSS_SKB_RECYCLER

static DEFINE_PER_CPU(struct sk_buff_head, cpu_recycle_list);
static DEFINE_PER_CPU(struct sk_buff_head, cpu_reserve_recycle_list);

static struct nss_skb_global_recycle_list  global_recycle_list;

struct sk_buff *nss_skb_alloc(unsigned int length)
{
	unsigned long flags;
	uint8_t head;

	if (likely(length <= NSS_SKB_RECYCLE_SIZE)) {

		struct sk_buff_head *h;
		struct sk_buff *skb = NULL;
dequeue:
		h = &get_cpu_var(cpu_recycle_list);

		local_irq_save(flags);
		skb = __skb_dequeue(h);
		local_irq_restore(flags);

		put_cpu_var(cpu_recycle_list);

		if (likely(skb)) {

#ifdef NET_SKBUFF_DATA_USES_OFFSET
			skb->mac_header = ~0U;
#endif
			return skb;
		}

		spin_lock_bh(&global_recycle_list.lock);

		/* If the Global recycle list is not empty, use buffers from there */
		head = global_recycle_list.head;
		if (head != global_recycle_list.tail) {

			/* Move the SKBs from global pool to CPU pool */
			skb_queue_splice_init(&global_recycle_list.pool[head], h);
			global_recycle_list.head =  (head + 1) & NSS_SKB_RECYCLE_MAX_SHARED_POOLS_MASK;
			spin_unlock_bh(&global_recycle_list.lock);

			goto dequeue;
		}

		spin_unlock_bh(&global_recycle_list.lock);
	}

	return dev_alloc_skb(length);
}
EXPORT_SYMBOL(nss_skb_alloc);

void nss_skb_free(struct sk_buff *skb)
{
	if (unlikely(!skb))
		return;

	/*
	 * Can we recycle this skb?  If we can then it will be much faster
	 * for us to recycle this one later than to allocate a new one
	 * from scratch.
	 */
	prefetchw((void *) skb->end);
	if (likely(skb_recycle_check(skb, NSS_SKB_RECYCLE_MIN_SIZE))) {
		unsigned long flags;
		struct sk_buff_head *h;
		struct sk_buff_head *g_head;
		uint8_t tail;

		h = &get_cpu_var(cpu_recycle_list);
		local_irq_save(flags);
		if (likely(skb_queue_len(h) < NSS_SKB_RECYCLE_MAX_SKBS)) {
			__skb_queue_head(h, skb);
			local_irq_restore(flags);
			put_cpu_var(cpu_recycle_list);
			return;
		}

		put_cpu_var(cpu_recycle_list);

		/* Enqueue to reserve pool */
		h = &get_cpu_var(cpu_reserve_recycle_list);

		if (likely(skb_queue_len(h) < NSS_SKB_RECYCLE_SPARE_MAX_SKBS)) {
			__skb_queue_head(h, skb);
			put_cpu_var(cpu_reserve_recycle_list);
			local_irq_restore(flags);
			return;
		}

		spin_lock(&global_recycle_list.lock);

		tail = (global_recycle_list.tail + 1) & NSS_SKB_RECYCLE_MAX_SHARED_POOLS_MASK;

		if (tail != global_recycle_list.head) {
			g_head = (struct sk_buff_head *) &global_recycle_list.pool[global_recycle_list.tail];

			/* Place the filled skb list into full-pool ring */
			g_head->next = h->next;
			h->next->prev = (struct sk_buff *) g_head;
			g_head->prev = h->prev;
			h->prev->next = (struct sk_buff *) g_head;

			g_head->qlen = NSS_SKB_RECYCLE_SPARE_MAX_SKBS;

			/* Reinitalize the freed skb_head */
			h->next = h->prev = (struct sk_buff *) h;
			h->qlen = 0;

			global_recycle_list.tail = tail;
		}

		spin_unlock(&global_recycle_list.lock);

		local_irq_restore(flags);
		put_cpu_var(cpu_reserve_recycle_list);
	}

	dev_kfree_skb_any(skb);

	return;
}
EXPORT_SYMBOL(nss_skb_free);

void nss_skb_recycler_init(void) {
	int cpu;
	int i;

	nss_info("Initializing skb recycler module \n");

	for_each_possible_cpu(cpu) {
		struct sk_buff_head *h = &per_cpu(cpu_recycle_list, cpu);
		skb_queue_head_init(h);
		h = &per_cpu(cpu_reserve_recycle_list, cpu);
		skb_queue_head_init(h);
	}

	spin_lock_init(&global_recycle_list.lock);

	for  (i = 0; i < NSS_SKB_RECYCLE_MAX_SHARED_POOLS; i++) {
		skb_queue_head_init(&global_recycle_list.pool[i]);
	}

	global_recycle_list.head = 0;
	global_recycle_list.tail = 0;
}

/*
 * A placeholder for now
 */
void recycler_skb_cleanup(void) {
}

#endif
