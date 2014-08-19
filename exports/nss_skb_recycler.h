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
 * Definitions for the skb recycler functions
 *
 */

#ifndef _NSS_SKBUFF_RECYCLE_H
#define _NSS_SKBUFF_RECYCLE_H

#include <linux/skbuff.h>

#if defined(NSS_SKB_RECYCLER) || defined(QCA_NSS_SKB_RECYCLER)

extern struct sk_buff *nss_skb_alloc(unsigned int length);
extern void nss_skb_free(struct sk_buff *skb);
extern void nss_skb_recycler_init(void);

#else

#define nss_skb_alloc(_len)	dev_alloc_skb(_len)
#define nss_skb_free(_skb)	dev_kfree_skb_any(_skb)
#define nss_skb_recycler_init()

#endif
#endif
