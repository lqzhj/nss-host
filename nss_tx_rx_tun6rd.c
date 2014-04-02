/*
 **************************************************************************
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
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
 * nss_tx_rx_tun6rd.c
 *	NSS 6rd tunnel APIs
 */

#include "nss_tx_rx_common.h"


/*
 **********************************
 Tx APIs
 **********************************
 */

/*
 * nss_tx_metadata_tun6rd_if_create()
 *	Send the tun6rd interface create message with appropriate config information
 */
nss_tx_status_t nss_tx_tun6rd_if_create(void *ctx, struct nss_tun6rd_cfg *tun6rdcfg, uint32_t interface)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tun6rd_msg *ntm;
	struct nss_tun6rd_create *ntc;

	nss_info("%p: Tun6rd If Create, id:%d\n", nss_ctx, interface);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Tun6rd If Create' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Tun6rd If Create' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntm = (struct nss_tun6rd_msg *)skb_put(nbuf, sizeof(struct nss_tun6rd_msg));
	ntm->cm.interface = interface;
	ntm->cm.version = NSS_HLOS_MESSAGE_VERSION;
	ntm->cm.type = NSS_TX_METADATA_TYPE_TUN6RD_IF_CREATE;
	ntm->cm.len = sizeof(struct nss_tun6rd_create);

	ntc = &ntm->msg.tun6rd_create;

	ntc->prefixlen = tun6rdcfg->prefixlen;
	ntc->relay_prefix = tun6rdcfg->relay_prefix;
	ntc->relay_prefixlen = tun6rdcfg->relay_prefixlen;
	ntc->saddr = tun6rdcfg->saddr;
	ntc->daddr = tun6rdcfg->daddr;
	ntc->prefix[0] = tun6rdcfg->prefix[0];
	ntc->prefix[1] = tun6rdcfg->prefix[1];
	ntc->prefix[2] = tun6rdcfg->prefix[2];
	ntc->prefix[3] = tun6rdcfg->prefix[3];
	ntc->ttl = tun6rdcfg->ttl;
	ntc->tos = tun6rdcfg->tos;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Tun6rd If Create' rule\n", nss_ctx);
	}
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;

}

/*
 * nss_tx_metadata_tun6rd_if_destroy()
 * 	Send th tun6rd interface destroy message
 */
nss_tx_status_t nss_tx_tun6rd_if_destroy(void *ctx, struct nss_tun6rd_cfg *tun6rdcfg, uint32_t interface)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tun6rd_msg *ntm;
	struct nss_tun6rd_destroy *ntd;

	nss_info("%p: Tun6rd If Destroy, id:%d\n", nss_ctx, interface);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Tun6rd If Destroy' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Tun6rd If Destroy' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntm = (struct nss_tun6rd_msg *)skb_put(nbuf, sizeof(struct nss_tun6rd_msg));
	ntm->cm.interface = interface;
	ntm->cm.version = NSS_HLOS_MESSAGE_VERSION;
	ntm->cm.type = NSS_TX_METADATA_TYPE_TUN6RD_IF_DESTROY;
	ntm->cm.len = sizeof(struct nss_tun6rd_destroy);

	ntd = &ntm->msg.tun6rd_destroy;
	/*
	 * Need to fill in associated structure memebrs
	 */

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Tun6rd If Destroy' rule\n", nss_ctx);
	}
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 **********************************
 Rx APIs
 **********************************
 */

/*
 * nss_rx_metadata_tun6rd_stats_sync()
 *	Handle the syncing of 6rd tunnel stats.
 */
static void nss_rx_metadata_tun6rd_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_tun6rd_stats_sync *ntun6rdss, uint16_t interface)
{
	void *ctx;
	nss_tun6rd_if_event_callback_t cb;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_tun6rd_stats stats;
	uint32_t id = interface;

	if (id >= NSS_MAX_NET_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_top->if_ctx[id];
	cb = nss_top->tun6rd_if_event_callback;

	stats.rx_packets = ntun6rdss->node_stats.rx_packets;
	stats.rx_bytes = ntun6rdss->node_stats.rx_bytes;
	stats.tx_packets = ntun6rdss->node_stats.tx_packets;
	stats.tx_bytes = ntun6rdss->node_stats.tx_bytes;

	/*
	 * call 6rd tunnel callback
	 */
	if (!cb || !ctx) {
		nss_warning("%p: Event received for 6rd tunnel interface %d before registration", nss_ctx, interface);
		return;
	}

	cb(ctx, NSS_TUN6RD_EVENT_STATS, (void *)&stats, sizeof(struct nss_tun6rd_stats));
}

/*
 * nss_rx_tun6rd_interface_handler()
 *	Handle NSS -> HLOS messages for 6rd tunnel
 */
static void nss_rx_tun6rd_interface_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_tun6rd_msg *ntm = (struct nss_tun6rd_msg *)ncm;

	/*
	 * Is this a valid request/response packet?
	 */
	if (ntm->cm.type >= NSS_METADATA_TYPE_TUN6RD_MAX) {
		nss_warning("%p: received invalid message %d for Tun6RD interface", nss_ctx, ntm->cm.type);
		return;
	}

	switch (ntm->cm.type) {
	case NSS_RX_METADATA_TYPE_TUN6RD_STATS_SYNC:
		nss_rx_metadata_tun6rd_stats_sync(nss_ctx, &ntm->msg.stats_sync, ncm->interface);
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
 **********************************
 Register/Unregister/Miscellaneous APIs
 **********************************
 */

/*
 * nss_register_tun6rd_if()
 */
void *nss_register_tun6rd_if(uint32_t if_num,
				nss_tun6rd_callback_t tun6rd_callback,
				nss_tun6rd_if_event_callback_t event_callback, void *if_ctx)
{
	nss_assert((if_num >= NSS_MAX_VIRTUAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_ctx[if_num] = if_ctx;
	nss_top_main.if_rx_callback[if_num] = tun6rd_callback;
	nss_top_main.tun6rd_if_event_callback = event_callback;

	return (void *)&nss_top_main.nss[nss_top_main.tun6rd_handler_id];
}

/*
 * nss_unregister_tun6rd_if()
 */
void nss_unregister_tun6rd_if(uint32_t if_num)
{
	nss_assert((if_num >= NSS_MAX_VIRTUAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_rx_callback[if_num] = NULL;
	nss_top_main.if_ctx[if_num] = NULL;
	nss_top_main.tun6rd_if_event_callback = NULL;
}

/*
 * nss_tun6rd_register_handler()
 */
void nss_tun6rd_register_handler()
{
	nss_core_register_handler(NSS_TUNRD_IF_NUMBER, nss_rx_tun6rd_interface_handler, NULL);
}

EXPORT_SYMBOL(nss_tx_tun6rd_if_create);
EXPORT_SYMBOL(nss_tx_tun6rd_if_destroy);
EXPORT_SYMBOL(nss_register_tun6rd_if);
EXPORT_SYMBOL(nss_unregister_tun6rd_if);
