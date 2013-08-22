/* Copyright (c) 2013, Qualcomm Atheros Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */
#ifndef __NSS_CRYPTO_DATA_H
#define __NSS_CRYPTO_DATA_H

#define NSS_CRYPTO_HPT_THRESH		__USEC2NSEC(1500) /* 5 msec timer resolution */

#define nss_crypto_inc_idx(_idx)		(((_idx) + 1) % NSS_CRYPTO_MAX_QDEPTH)
#define nss_crypto_hw_offst(_idx, _sz)		(nss_crypto_inc_idx(_idx) * _sz)
#define nss_crypto_offst_to_idx(_offst, _sz)	((_offst) / (_sz))

#define nss_crypto_get_hwidx(_base, _pipe, _sz)		\
	nss_crypto_offst_to_idx(ioread32((_base) + CRYPTO_BAM_P_SW_OFSTS(_pipe)), _sz)


#if 0
enum nss_crypto_index_type {
	NSS_CRYPTO_IDX_CIPHER_KEY = 0x1,
	NSS_CRYPTO_IDX_AUTH_KEY = 0x2,
};

#endif

enum nss_crypto_buf_state {
	NSS_CRYPTO_BUF_INQ = 0x1,
	NSS_CRYPTO_BUF_DONE = 0x2
};

struct nss_crypto_swdesc {
	uint32_t idx;
	struct nss_crypto_buf *buf;
};

/**
 * @brief Per pipe data structure
 */
struct nss_crypto_data_pipe {
	uint32_t qdepth;	/**< queue depth*/
	uint32_t pidx;		/**< producer index*/
	uint32_t cidx;		/**< consumer index*/

	struct nss_crypto_desc *desc; /**< H/W descriptors */
	struct nss_crypto_swdesc sw_desc[NSS_CRYPTO_MAX_QDEPTH]; /**< S/W descriptors */
};

/**
 * @brief Per Engine datastructure
 */
struct nss_crypto_data_eng {
	uint8_t *bam_base;	/**< BAM base address for the engine */
	uint32_t used;		/**< number of times the engine is used for the pipe */
	struct nss_crypto_data_pipe pipe[NSS_CRYPTO_BAM_PP];
};

/**
 * @brief buffer waitq datastructure
 */
struct nss_crypto_wait_q {
	struct nss_crypto_buf *head;	/**< queue head */
	struct nss_crypto_buf *tail;	/**< queue tail */
	uint32_t qlen;			/**< queue len */
};

/**
 * @brief Scheduler softc structure
 */
struct nss_crypto_data {
	struct nss_crypto_wait_q hw_q;	/**< H/W queue, XXX: remove list*/
	struct nss_crypto_wait_q sw_q;	/**< S/W queue*/

	spinlock_t lock;		/**< Index access lock*/

	uint32_t num_eng;		/**< number of crypto engines available */
	uint32_t num_pkts;		/**< number of packets consumed */
	uint32_t num_comp;		/**< number of packets produced */

	struct tasklet_hrtimer hrt;	/**< high resolution timer*/

	struct nss_crypto_data_eng eng[NSS_CRYPTO_ENGINES]; /**< engines*/
};

/**
 * @brief Initialize the buffer
 *
 * @param buf
 */
static inline void
nss_crypto_waitq_buf_init(struct nss_crypto_buf *buf)
{
	buf->next = buf;
}

/**
 * @brief initialize the queue head
 *
 * @param wq[IN] queue head
 */
static inline void
nss_crypto_waitq_head_init(struct nss_crypto_wait_q *wq)
{
	wq->head = wq->tail = (struct nss_crypto_buf *)wq;
	wq->qlen = 0;
}

/**
 * @brief retrieve first element of the queue
 *
 * @param wq[IN] queue head
 *
 * @return first buffer
 */
static inline struct nss_crypto_buf *
nss_crypto_waitq_first(struct nss_crypto_wait_q *wq)
{
	return wq->head;
}

/**
 * @brief check if the queue is empty or not
 *
 * @param wq[IN] queue head
 *
 * @return true(=1) if empty
 */
static inline int
nss_crypto_waitq_empty(struct nss_crypto_wait_q *wq)
{
	return (wq->head == (struct nss_crypto_buf *)wq);
}

/**
 * @brief get queue length
 *
 * @param wq[IN] queue head
 *
 * @return length of the queue
 */
static inline uint32_t
nss_crypto_waitq_len(struct nss_crypto_wait_q *wq)
{
	return wq->qlen;
}

/**
 * @brief insert buffer at the queue tail
 *
 * @param wq[IN] queue head
 * @param buf[IN] buffer
 */
static inline void
nss_crypto_waitq_ins_tail(struct nss_crypto_wait_q *wq, struct nss_crypto_buf *buf)
{
	wq->tail->next = buf;
	wq->tail = buf;
	buf->next = (struct nss_crypto_buf *)wq;
	wq->qlen++;
}

/**
 * @brief remove the first buf from queue
 *
 * @param wq[IN] queue head
 * @param buf[OUT] first buffer
 */
static inline void
nss_crypto_waitq_rem_head(struct nss_crypto_wait_q *wq, struct nss_crypto_buf **buf)
{
	*buf = wq->head;
	wq->head = (*buf)->next;

	if (nss_crypto_waitq_empty(wq)) {
		wq->tail = wq->head;
	}
	wq->qlen--;
}


/**
 * @brief Initialize crypto data
 */
void
nss_crypto_data_init(void);

/**
 * @brief schedule buffer for crypto transform
 *
 * @param buf[IN] crypto buffer
 *
 * @return
 */
nss_crypto_status_t
nss_crypto_buf_enqueue(struct nss_crypto_buf *buf);

#endif /* __NSS_CRYPTO_DATA_H*/
