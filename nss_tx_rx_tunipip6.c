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
 * nss_tx_rx_tunipip6.c
 *	NSS DS-Lite tunnel APIs
 */

#include "nss_tx_rx_common.h"

/*
 **********************************
 Tx APIs
 **********************************
 */

/*
* nss_tx_metadata_tunipip6_if_create()
*	Send the tunipip6 interface create message with appropriate config information
*/
nss_tx_status_t nss_tx_tunipip6_if_create(void *ctx, struct nss_tunipip6_cfg *tunipip6cfg, uint32_t interface)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tunipip6_msg *ntm;
	struct nss_tunipip6_create *ntc;

	nss_info("%p: DS-Lite If Create, id:%d\n", nss_ctx, interface);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'DS-Lite If Create' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'DS-Lite If Create' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntm = (struct nss_tunipip6_msg *)skb_put(nbuf, sizeof(struct nss_tunipip6_msg));
	ntm->cm.interface = interface;
	ntm->cm.version = NSS_HLOS_MESSAGE_VERSION;
	ntm->cm.type = NSS_TX_METADATA_TYPE_TUNIPIP6_IF_CREATE;
	ntm->cm.len = sizeof(struct nss_tunipip6_create);

	ntc = &ntm->msg.tunipip6_create;

	ntc->saddr[0] = tunipip6cfg->saddr[0];
	ntc->saddr[1] = tunipip6cfg->saddr[1];
	ntc->saddr[2] = tunipip6cfg->saddr[2];
	ntc->saddr[3] = tunipip6cfg->saddr[3];
	ntc->daddr[0] = tunipip6cfg->daddr[0];
	ntc->daddr[1] = tunipip6cfg->daddr[1];
	ntc->daddr[2] = tunipip6cfg->daddr[2];
	ntc->daddr[3] = tunipip6cfg->daddr[3];
	ntc->hop_limit = tunipip6cfg->hop_limit;
	ntc->flags = tunipip6cfg->flags;
	ntc->flowlabel = tunipip6cfg->flowlabel;  /*flow Label In kernel is stored in big endian format*/

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'DS-Lite If Create' rule\n", nss_ctx);
	}
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_metadata_tun6rd_if_destroy()
 *	Send th tun6rd interface destroy message
 */
nss_tx_status_t nss_tx_tunipip6_if_destroy(void *ctx, struct nss_tunipip6_cfg *tunipip6cfg, uint32_t interface)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tunipip6_msg *ntm;
	struct nss_tunipip6_destroy *ntd;

	nss_info("%p: Ds-Lite If Destroy, id:%d\n", nss_ctx, interface);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'DS-Lite If Destroy' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'DS-Lite If Destroy' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntm = (struct nss_tunipip6_msg *)skb_put(nbuf, sizeof(struct nss_tunipip6_msg));
	ntm->cm.interface = interface;
	ntm->cm.version = NSS_HLOS_MESSAGE_VERSION;
	ntm->cm.type = NSS_TX_METADATA_TYPE_TUNIPIP6_IF_DESTROY;
	ntm->cm.len = sizeof(struct nss_tunipip6_destroy);

	ntd = &ntm->msg.tunipip6_destroy;
	/*
	 * Need to fill in associated structure memebrs
	 */

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'DS-Lite If Destroy' rule\n", nss_ctx);
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
 * nss_rx_metadata_tunipip6_stats_sync()
 *	Handle the syncing of ipip6 tunnel stats.
 */
static void nss_rx_metadata_tunipip6_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_tunipip6_stats_sync *ntunipip6ss, uint16_t interface)
{
	void *ctx;
	nss_tunipip6_if_event_callback_t cb;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_tunipip6_stats stats;
	uint32_t id = interface;

	if (id >= NSS_MAX_NET_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_top->if_ctx[id];
	cb = nss_top->tunipip6_if_event_callback;

	stats.rx_packets = ntunipip6ss->node_stats.rx_packets;
	stats.rx_bytes = ntunipip6ss->node_stats.rx_bytes;
	stats.tx_packets = ntunipip6ss->node_stats.tx_packets;
	stats.tx_bytes = ntunipip6ss->node_stats.tx_bytes;

	/*
	 * call ipip6 tunnel callback
	 */

	if (!cb || !ctx) {
		nss_warning("%p: Event received for ipip6 tunnel interface %d before registration", nss_ctx, interface);
		return;
	}

	cb(ctx, NSS_TUNIPIP6_EVENT_STATS, (void *)&stats, sizeof(struct nss_tunipip6_stats));
}

/*
 * nss_rx_tunipip6_interface_handler()
 *	Handle NSS -> HLOS messages for DS-Lite tunnel
 */
static void nss_rx_tunipip6_interface_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_tunipip6_msg *ntm = (struct nss_tunipip6_msg *)ncm;

	/*
	 * Is this a valid request/response packet?
	 */
	if (ntm->cm.type >= NSS_METADATA_TYPE_TUNIPIP6_MAX) {
		nss_warning("%p: received invalid message %d for TunIPIP6 interface", nss_ctx, ntm->cm.type);
		return;
	}

	switch (ntm->cm.type) {
	case NSS_RX_METADATA_TYPE_TUNIPIP6_STATS_SYNC:
		nss_rx_metadata_tunipip6_stats_sync(nss_ctx, &ntm->msg.stats_sync, ncm->interface);
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
 * nss_register_tunipip6_if()
 */
void *nss_register_tunipip6_if(uint32_t if_num,
				nss_tunipip6_callback_t tunipip6_callback,
				nss_tunipip6_if_event_callback_t event_callback, void *if_ctx)
{
	nss_assert((if_num >= NSS_MAX_VIRTUAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_ctx[if_num] = if_ctx;
	nss_top_main.if_rx_callback[if_num] = tunipip6_callback;
	nss_top_main.tunipip6_if_event_callback = event_callback;

	return (void *)&nss_top_main.nss[nss_top_main.tunipip6_handler_id];
}

/*
 * nss_unregister_tunipip6_if()
 */
void nss_unregister_tunipip6_if(uint32_t if_num)
{
	nss_assert((if_num >= NSS_MAX_VIRTUAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_rx_callback[if_num] = NULL;
	nss_top_main.if_ctx[if_num] = NULL;
	nss_top_main.tunipip6_if_event_callback = NULL;
}

/*
 * nss_tunipip6_register_handler()
 */
void nss_tunipip6_register_handler()
{
	nss_core_register_handler(NSS_TUNRD_IF_NUMBER, nss_rx_tunipip6_interface_handler, NULL);
}

EXPORT_SYMBOL(nss_tx_tunipip6_if_create);
EXPORT_SYMBOL(nss_tx_tunipip6_if_destroy);
EXPORT_SYMBOL(nss_register_tunipip6_if);
EXPORT_SYMBOL(nss_unregister_tunipip6_if);
