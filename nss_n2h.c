/*
 **************************************************************************
 * Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

/*
 * nss_n2h.c
 *	NSS N2H node APIs
 */

#include "nss_tx_rx_common.h"

#define NSS_N2H_TIMEOUT 5*HZ

wait_queue_head_t nss_n2h_wq;

/*
 * nss_n2h_tx()
 *	Send Message to NSS to enable RPS.
 *
 * This API could be used for any additional RPS related
 * configuration in future.
 */
nss_tx_status_t nss_n2h_tx(struct nss_ctx_instance *nss_ctx, uint32_t enable_rps)
{
	struct sk_buff *nbuf;
	nss_tx_status_t status;
	struct nss_n2h_msg *nnhm;
	struct nss_n2h_rps *rps_cfg;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		return NSS_TX_FAILURE;
	}

	nnhm = (struct nss_n2h_msg *)skb_put(nbuf, sizeof(struct nss_n2h_msg));

	nnhm->cm.type = NSS_TX_METADATA_TYPE_N2H_RPS_CFG;
	nnhm->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nnhm->cm.interface = NSS_N2H_INTERFACE;
	nnhm->cm.len = nbuf->len;

	rps_cfg = &nnhm->msg.rps_cfg;

	rps_cfg->enable = enable_rps;

	nss_info("n22_n2h_rps_configure %d \n", enable_rps);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: unable to enqueue 'nss frequency change' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit, NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_n2h_stats_sync()
 *	Handle the syncing of NSS statistics.
 */
static void nss_n2h_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_n2h_stats_sync *nnss)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	spin_lock_bh(&nss_top->stats_lock);

	/*
	 * common node stats
	 */
	nss_ctx->stats_n2h[NSS_STATS_NODE_RX_PKTS] += nnss->node_stats.rx_packets;
	nss_ctx->stats_n2h[NSS_STATS_NODE_RX_BYTES] += nnss->node_stats.rx_bytes;
	nss_ctx->stats_n2h[NSS_STATS_NODE_RX_DROPPED] += nnss->node_stats.rx_dropped;
	nss_ctx->stats_n2h[NSS_STATS_NODE_TX_PKTS] += nnss->node_stats.tx_packets;
	nss_ctx->stats_n2h[NSS_STATS_NODE_TX_BYTES] += nnss->node_stats.tx_bytes;

	/*
	 * General N2H stats
	 */
	nss_ctx->stats_n2h[NSS_STATS_N2H_QUEUE_DROPPED] += nnss->queue_dropped;
	nss_ctx->stats_n2h[NSS_STATS_N2H_TOTAL_TICKS] += nnss->total_ticks;
	nss_ctx->stats_n2h[NSS_STATS_N2H_WORST_CASE_TICKS] += nnss->worst_case_ticks;
	nss_ctx->stats_n2h[NSS_STATS_N2H_ITERATIONS] += nnss->iterations;

	/*
	 * pbuf manager ocm and default pool stats
	 */
	nss_ctx->stats_n2h[NSS_STATS_N2H_PBUF_OCM_ALLOC_FAILS] += nnss->pbuf_ocm_stats.pbuf_alloc_fails;
	nss_ctx->stats_n2h[NSS_STATS_N2H_PBUF_OCM_FREE_COUNT] = nnss->pbuf_ocm_stats.pbuf_free_count;
	nss_ctx->stats_n2h[NSS_STATS_N2H_PBUF_OCM_TOTAL_COUNT] = nnss->pbuf_ocm_stats.pbuf_total_count;

	nss_ctx->stats_n2h[NSS_STATS_N2H_PBUF_DEFAULT_ALLOC_FAILS] += nnss->pbuf_default_stats.pbuf_alloc_fails;
	nss_ctx->stats_n2h[NSS_STATS_N2H_PBUF_DEFAULT_FREE_COUNT] = nnss->pbuf_default_stats.pbuf_free_count;
	nss_ctx->stats_n2h[NSS_STATS_N2H_PBUF_DEFAULT_TOTAL_COUNT] = nnss->pbuf_default_stats.pbuf_total_count;

	/*
	 * payload mgr stats
	 */
	nss_ctx->stats_n2h[NSS_STATS_N2H_PAYLOAD_ALLOC_FAILS] += nnss->payload_alloc_fails;

	/*
	 * Host <=> NSS control traffic stats
	 */
	nss_ctx->stats_n2h[NSS_STATS_N2H_H2N_CONTROL_PACKETS] += nnss->h2n_ctrl_pkts;
	nss_ctx->stats_n2h[NSS_STATS_N2H_H2N_CONTROL_BYTES] += nnss->h2n_ctrl_bytes;
	nss_ctx->stats_n2h[NSS_STATS_N2H_N2H_CONTROL_PACKETS] += nnss->n2h_ctrl_pkts;
	nss_ctx->stats_n2h[NSS_STATS_N2H_N2H_CONTROL_BYTES] += nnss->n2h_ctrl_bytes;

	/*
	 * Host <=> NSS control data traffic stats
	 */
	nss_ctx->stats_n2h[NSS_STATS_N2H_H2N_DATA_PACKETS] += nnss->h2n_data_pkts;
	nss_ctx->stats_n2h[NSS_STATS_N2H_H2N_DATA_BYTES] += nnss->h2n_data_bytes;
	nss_ctx->stats_n2h[NSS_STATS_N2H_N2H_DATA_PACKETS] += nnss->n2h_data_pkts;
	nss_ctx->stats_n2h[NSS_STATS_N2H_N2H_DATA_BYTES] += nnss->n2h_data_bytes;

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_n2h_interface_handler()
 *	Handle NSS -> HLOS messages for N2H node
 */
static void nss_n2h_interface_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_n2h_msg *nnm = (struct nss_n2h_msg *)ncm;

	BUG_ON(ncm->interface != NSS_N2H_INTERFACE);

	/*
	 * Is this a valid request/response packet?
	 */
	if (nnm->cm.type >= NSS_METADATA_TYPE_N2H_MAX) {
		nss_warning("%p: received invalid message %d for Offload stats interface", nss_ctx, nnm->cm.type);
		return;
	}

	switch (nnm->cm.type) {
	case NSS_TX_METADATA_TYPE_N2H_RPS_CFG:
		nss_ctx->n2h_rps_en = nnm->msg.rps_cfg.enable;
		nss_info("NSS N2H rps_en %d \n",nnm->msg.rps_cfg.enable);
		wake_up(&nss_n2h_wq);
		break;

	case NSS_RX_METADATA_TYPE_N2H_STATS_SYNC:
		nss_n2h_stats_sync(nss_ctx, &nnm->msg.stats_sync);
		wake_up(&nss_n2h_wq);
		break;

	default:
		if (ncm->response != NSS_CMN_RESPONSE_ACK) {
			/*
			 * Check response
			 */
			nss_info("%p: Received response %d for type %d, interface %d",
						nss_ctx, ncm->response, ncm->type, ncm->interface);
		}
	}
}

/*
 * nss_n2h_register_handler()
 */
void nss_n2h_register_handler()
{
	nss_core_register_handler(NSS_N2H_INTERFACE, nss_n2h_interface_handler, NULL);

	/*
	 * Initialize wait queue
	 */
	init_waitqueue_head(&nss_n2h_wq);
}
