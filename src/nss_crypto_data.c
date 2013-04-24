/*
 * Copyright (C) 2013 - Qualcomm Atheros
 *
 */
#include <nss_crypto_hlos.h>
#include <nss_crypto_if.h>
#include <nss_crypto_hw.h>
#include <nss_crypto_ctrl.h>
#include <nss_crypto_data.h>
#include <nss_crypto_dbg.h>

struct nss_crypto_data gbl_crypto_data = {{0}};
extern struct nss_crypto_ctrl gbl_crypto_ctrl;

#define __CIPHER_REQ_MASK	(NSS_CRYPTO_REQ_ENCRYPT | NSS_CRYPTO_REQ_DECRYPT)

struct nss_crypto_data_eng *
nss_crypto_get_engine(uint32_t idx)
{
	struct nss_crypto_data_eng *free = NULL;
	uint32_t min_qdepth, p_qdepth = 0;
	int i;

	min_qdepth = (NSS_CRYPTO_MAX_QDEPTH - 1);

	for (i = 0; i < gbl_crypto_data.num_eng; i++) {

		p_qdepth = gbl_crypto_data.eng[i].pipe[idx].qdepth;

		if (!p_qdepth) {
			free = &gbl_crypto_data.eng[i];
			break;
		}
		if (p_qdepth < min_qdepth) {
			min_qdepth = p_qdepth;
			free = &gbl_crypto_data.eng[i];
		}
	}

	return free;
}

static nss_crypto_status_t
nss_crypto_hw_enqueue(struct nss_crypto_data_eng *eng, uint32_t idx, struct nss_crypto_buf *buf)
{
	struct nss_crypto_data_pipe *pipe;
	struct nss_crypto_bam_desc *in_data, *out_data;
	struct nss_crypto_bam_desc *res;
	struct nss_crypto_cache_cmdblk *cblk;
	void __iomem *in_addr, *out_addr;
	uint32_t pidx, auth_pos;
	uint32_t bam_len;
	uint8_t *iv_addr;

	/* Scheduler should have checked the qdepth*/
	pipe = &eng->pipe[idx];

	pipe->qdepth++;
	pidx = pipe->pidx;

	pipe->sw_desc[pidx].buf = buf;
	pipe->sw_desc[pidx].idx = buf->session_idx;

	cblk = &pipe->desc->cblk[pidx];
	in_data = &pipe->desc->in[pidx].data;
	out_data = &pipe->desc->out[pidx].data;
	res = NULL;

	switch (buf->req_type & __CIPHER_REQ_MASK) {
	case NSS_CRYPTO_REQ_ENCRYPT:
		CRYPTO_SET_ENCRYPT(cblk->encr_seg_cfg.value);
		auth_pos = CRYPTO_AUTH_SEG_CFG_POS_AFTER;
		break;

	case NSS_CRYPTO_REQ_DECRYPT:
		CRYPTO_SET_DECRYPT(cblk->encr_seg_cfg.value);
		auth_pos = CRYPTO_AUTH_SEG_CFG_POS_BEFORE;
		break;

	default:
		auth_pos = 0;
		break;
	}

	/**
	 * CFI generates the IV and the length is pretty much fixed
	 * for algorithm/Mode that need them
	 * XXX: assumes AES IV size
	 */
	iv_addr = buf->data + buf->iv_offset;

	cblk->encr_iv[0].value = cpu_to_be32(*((uint32_t *)(iv_addr)));
	cblk->encr_iv[1].value = cpu_to_be32(*((uint32_t *)(iv_addr + 4)));
	cblk->encr_iv[2].value = cpu_to_be32(*((uint32_t *)(iv_addr + 8)));
	cblk->encr_iv[3].value = cpu_to_be32(*((uint32_t *)(iv_addr + 12)));

	bam_len = buf->data_len;

	buf->data_paddr = dma_map_single(NULL, buf->data, buf->data_len, DMA_TO_DEVICE);

#if defined (CONFIG_NSS_CRYPTO_AUTH)
	res = &pipe->desc->out[pidx].results;

	if (buf->req_type & NSS_CRYPTO_REQ_AUTH) {
		cblk->auth_seg_size.value = buf->auth_len;
		cblk->auth_seg_start.value = buf->auth_skip;
		cblk->auth_seg_cfg.value |= auth_pos;

		res->data_start = buf->data_paddr + buf->hash_offset;
	}
#endif

	cblk->encr_seg_size.value = buf->cipher_len;
	cblk->encr_seg_start.value = buf->cipher_skip;
	/* Total length for crypto to consume*/
	cblk->seg_size.value = buf->data_len;


	in_data->data_start  = buf->data_paddr;
	in_data->data_len = bam_len;

	out_data->data_start = buf->data_paddr;
	out_data->data_len = bam_len;

	out_data->flags = 0;
#if defined (CONFIG_NSS_CRYPTO_IDXWAR) && defined (CONFIG_NSS_CRYPTO_AUTH)
	res->flags = 0;
#endif
	nss_crypto_dump_desc(&pipe->desc->in[pidx].cmd_lock, NSS_CRYPTO_NUM_INDESC, "consumer BAM");
	nss_crypto_dump_cblk(&cblk->config_0, NSS_CRYPTO_NUM_CMDBLK - 1, "lock");
	nss_crypto_dump_cblk(&cblk->unlock, 1, "unlock");
	nss_crypto_dump_desc(&pipe->desc->out[pidx].data, NSS_CRYPTO_NUM_OUTDESC, "producer BAM - before");

	/**
	 * __hw_offst takes care of the BAM ring wrap around condition
	 */

	in_addr  = eng->bam_base + CRYPTO_BAM_P_EVNT_REG(nss_crypto_idx_to_inpipe(idx));
	out_addr = eng->bam_base + CRYPTO_BAM_P_EVNT_REG(nss_crypto_idx_to_outpipe(idx));

	iowrite32(nss_crypto_hw_offst(pidx, NSS_CRYPTO_INDESC_SZ), in_addr);
	iowrite32(nss_crypto_hw_offst(pidx, NSS_CRYPTO_OUTDESC_SZ), out_addr);

	pidx = nss_crypto_inc_idx(pidx);

	pipe->pidx = pidx;

	return NSS_CRYPTO_STATUS_OK;
}
/*
 * NOTE: This function is tunned for single thread execution,
 * we can specify that in the OCF thread by tying it to the CPU
 * For SMP it requires a larger set of locks which during the
 * profiling showed performance degradation. Future version will
 * try to get rid of the Queue locks completely by doing some sort
 * of lock-less queueing and will have the locks for only for
 * global shared data structures
 */
nss_crypto_status_t
nss_crypto_buf_enqueue(struct nss_crypto_buf *buf)
{
	struct nss_crypto_data *data = &gbl_crypto_data;
	struct nss_crypto_data_eng *eng = NULL;
	uint32_t idx;

	idx = buf->session_idx;

	buf->state = NSS_CRYPTO_BUF_INQ;

	nss_crypto_waitq_buf_init(buf);

	spin_lock_bh(&data->lock); /* lock waitq*/
	/* local_bh_disable(); */

	data->num_pkts++;
	eng = nss_crypto_get_engine(idx);

	/*
	 * Buf will need to be queued into the SW_Q if there are older buffers lying in it
	 * or if the get_engine returned NULL
	 */
	if (!nss_crypto_waitq_empty(&data->sw_q) || (eng == NULL)) {
		nss_crypto_waitq_ins_tail(&data->sw_q, buf);

		spin_unlock_bh(&data->lock); /* unlock waitq*/
		/* local_bh_enable(); */

		goto done;
	}

	nss_crypto_waitq_ins_tail(&data->hw_q, buf);

	spin_unlock_bh(&data->lock); /* unlock waitq*/
	/* local_bh_enable(); */

	nss_crypto_hw_enqueue(eng, idx, buf);
done:
	/* this check makes sure that only guy can schedule the timer */
	if (!hrtimer_active(&data->hrt.timer)) {
		tasklet_hrtimer_start(&data->hrt, ktime_set(0, NSS_CRYPTO_HPT_THRESH), HRTIMER_MODE_REL);
	}

	return NSS_CRYPTO_STATUS_OK;
}


void
nss_crypto_buf_comp(unsigned long arg)
{
	struct nss_crypto_data *data = &gbl_crypto_data;
	struct nss_crypto_buf *buf;

	while (1) {

		if (nss_crypto_waitq_empty(&data->hw_q)) {
			break;
		}

		buf = nss_crypto_waitq_first(&data->hw_q);
		if (buf->state != NSS_CRYPTO_BUF_DONE) {
			break;
		}

		nss_crypto_waitq_rem_head(&data->hw_q, &buf);

		data->num_comp++;

		dma_unmap_single(NULL, buf->data_paddr, buf->data_len, DMA_FROM_DEVICE);

		buf->cb_fn(buf);
	}

	if (!hrtimer_active(&data->hrt.timer)) {
		tasklet_hrtimer_start(&data->hrt, ktime_set(0, NSS_CRYPTO_HPT_THRESH), HRTIMER_MODE_REL);
	}
}


nss_crypto_status_t
nss_crypto_hw_done(struct nss_crypto_data_eng *eng, uint32_t out_pipe)
{
	struct nss_crypto_data_eng *free_eng;
	struct nss_crypto_data_pipe *pipe;
	struct nss_crypto_swdesc *swdesc;
	struct nss_crypto_buf *buf;
	struct nss_crypto_desc *desc;
	struct nss_crypto_wait_q *swq, *hwq;
	uint32_t cidx, hw_pidx, idx;
	volatile struct nss_crypto_out_trans *out;
	volatile uint16_t *flags;

	idx = nss_crypto_inpipe_to_idx(NSS_CRYPTO_INPIPE(out_pipe));

	pipe = &eng->pipe[idx];
	swdesc = pipe->sw_desc;
	cidx = pipe->cidx;
	desc = eng->pipe[idx].desc;

	out = pipe->desc->out;
	swq = &gbl_crypto_data.sw_q;
	hwq = &gbl_crypto_data.hw_q;

	hw_pidx = nss_crypto_get_hwidx(eng->bam_base, out_pipe, NSS_CRYPTO_OUTDESC_SZ);

	if (hw_pidx == cidx) {
		return NSS_CRYPTO_STATUS_OK;
	}

more:
	for(;;) {

		/*
		 * H/W Index oscillation bug WAR
		 */
		if (hw_pidx == nss_crypto_inc_idx(cidx)) {
			flags = &out[cidx].results.flags;

			/* check if the descriptor got completed, otherwise break */
			if (!(*flags & CRYPTO_BAM_DESC_EOT)) {
				break;
			}
		}

		pipe->qdepth--;

		swdesc[cidx].buf->state = NSS_CRYPTO_BUF_DONE;

		swdesc[cidx].buf = NULL;

		if (!nss_crypto_waitq_empty(swq)) {
			free_eng = nss_crypto_get_engine(idx);

			nss_crypto_waitq_rem_head(swq, &buf);
			nss_crypto_waitq_ins_tail(hwq, buf);

			nss_crypto_hw_enqueue(free_eng, idx, buf);
		}

		cidx = nss_crypto_inc_idx(cidx);

		if (cidx == hw_pidx) {
			break;
		}
	}

	/* while we were processing and adding buffers to H/W from S/W queues,
	 * previously queued buffers would have completed within that time
	 * check before exiting
	 */

	hw_pidx = nss_crypto_get_hwidx(eng->bam_base, out_pipe, NSS_CRYPTO_OUTDESC_SZ);
	if (hw_pidx != cidx) {
		goto more;
	}

	eng->pipe[idx].cidx = cidx;

	return NSS_CRYPTO_STATUS_OK;
}

static enum hrtimer_restart
nss_crypto_hrtimer(struct hrtimer *timer)
{
	struct nss_crypto_data_eng *eng;
	uint32_t max_engines;
	int i;

	if (!gbl_crypto_ctrl.idx_bitmap) {
		goto done;
	}

	max_engines = gbl_crypto_data.num_eng;

	/* Pipe Pair 0 */
	for(i = 0, eng = gbl_crypto_data.eng; i < max_engines; i++, eng++) {
		nss_crypto_hw_done(eng, NSS_CRYPTO_BAM_OUTPIPE_0);
	}
	/* Pipe Pair 1 */
	for(i = 0, eng = gbl_crypto_data.eng; i < max_engines; i++, eng++) {
		nss_crypto_hw_done(eng, NSS_CRYPTO_BAM_OUTPIPE_1);
	}
	/* Pipe Pair 2 */
	for(i = 0, eng = gbl_crypto_data.eng; i < max_engines; i++, eng++) {
		nss_crypto_hw_done(eng, NSS_CRYPTO_BAM_OUTPIPE_2);
	}
	/* Pipe Pair 3 */
	for(i = 0, eng = gbl_crypto_data.eng; i < max_engines; i++, eng++) {
		nss_crypto_hw_done(eng, NSS_CRYPTO_BAM_OUTPIPE_3);
	}

	nss_crypto_buf_comp(0);
done:
	return HRTIMER_NORESTART;
}

void
nss_crypto_data_init(void)
{
	nss_crypto_info("data initialized");

	nss_crypto_waitq_head_init(&gbl_crypto_data.hw_q);
	nss_crypto_waitq_head_init(&gbl_crypto_data.sw_q);

	tasklet_hrtimer_init(&gbl_crypto_data.hrt, nss_crypto_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);

	spin_lock_init(&gbl_crypto_data.lock);
}
