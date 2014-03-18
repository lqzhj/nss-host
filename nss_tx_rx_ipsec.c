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
 * nss_tx_rx_ipsec.c
 *	NSS IPsec APIs
 */

#include "nss_tx_rx_common.h"

/*
 **********************************
 Tx APIs
 **********************************
 */

/*
 * nss_tx_ipsec_rule
 *	Send ipsec rule to NSS.
 */
nss_tx_status_t nss_tx_ipsec_rule(void *ctx, uint32_t interface_num, uint32_t type, uint8_t *buf, uint32_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_ipsec_msg *nim;
	struct nss_ipsec_rule *nir;

	nss_info("%p: IPsec rule %d for if %d\n", nss_ctx, type, interface_num);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'IPsec' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	if (NSS_NBUF_PAYLOAD_SIZE < (len + sizeof(uint32_t) + sizeof(struct nss_ipsec_rule))) {
		return NSS_TX_FAILURE_TOO_LARGE;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'IPsec' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nim = (struct nss_ipsec_msg *)skb_put(nbuf, (sizeof(struct nss_ipsec_msg) + len));
	nim->cm.interface = interface_num;
	nim->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nim->cm.request = NSS_TX_METADATA_TYPE_IPSEC_RULE;
	nim->cm.len = sizeof(struct nss_ipsec_rule) + (len - 1);

	nim->type = NSS_TX_METADATA_TYPE_IPSEC_RULE;
	nir = &nim->msg.rule;
	nir->type = type;
	nir->len = len;
	memcpy(nir->buf, buf, len);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPsec Encap' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 **********************************
 Rx APIs
 **********************************
 */

/*
 *  nss_rx_metadata_ipsec_events_sync()
 *	Handle the IPsec events
 */
static void nss_rx_metadata_ipsec_events_sync(struct nss_ctx_instance *nss_ctx, struct nss_ipsec_events_sync *nies)
{
	void *ctx;
	nss_ipsec_event_callback_t cb;
	uint32_t id = nies->ipsec_if_num;

	if (id >= NSS_MAX_NET_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_ctx->nss_top->if_ctx[id];
	cb = nss_ctx->nss_top->ipsec_event_callback;

	/*
	 * Call IPsec callback
	 */
	if (!cb || !ctx) {
		nss_warning("%p: Event received for IPsec interface %d before registration", nss_ctx, id);
		return;
	}

	cb(ctx, nies->event_if_num, nies->buf, nies->len);
}

/*
 * nss_rx_ipsec_interface_handler()
 *	Handle NSS -> HLOS messages for IPsec
 */
static void nss_rx_ipsec_interface_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_ipsec_msg *nim = (struct nss_ipsec_msg *)ncm;

	/*
	 * Is this a valid request/response packet?
	 */
	if (nim->type >= NSS_METADATA_TYPE_IPSEC_MAX) {
		nss_warning("%p: received invalid message %d for IPsec interface", nss_ctx, nim->type);
		return;
	}

	switch (nim->type) {
	case NSS_RX_METADATA_TYPE_IPSEC_EVENTS_SYNC:
		nss_rx_metadata_ipsec_events_sync(nss_ctx, &nim->msg.sync);
		break;

	default:
		if (ncm->response != NSS_CMN_RESPONSE_ACK) {
			/*
			 * Check response
			 */
			nss_info("%p: Received response %d for request %d, interface %d",
						nss_ctx, ncm->response, ncm->request, ncm->interface);
		}
	}
}

/*
 **********************************
 Register/Unregister/Miscellaneous APIs
 **********************************
 */

/*
 * nss_register_ipsec_if()
 */
void *nss_register_ipsec_if(uint32_t if_num,
				nss_ipsec_data_callback_t ipsec_data_cb,
				void *if_ctx)
{
	nss_assert((if_num >= NSS_MAX_PHYSICAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_ctx[if_num] = if_ctx;
	nss_top_main.if_rx_callback[if_num] = ipsec_data_cb;

	return (void *)&nss_top_main.nss[nss_top_main.ipsec_handler_id];
}

/*
 * nss_register_ipsec_event_if()
 */
void nss_register_ipsec_event_if(uint32_t if_num, nss_ipsec_event_callback_t ipsec_event_cb)
{
	nss_assert((if_num >= NSS_MAX_PHYSICAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.ipsec_event_callback = ipsec_event_cb;
}

/*
 * nss_unregister_ipsec_if()
 */
void nss_unregister_ipsec_if(uint32_t if_num)
{
	nss_assert((if_num >= NSS_MAX_PHYSICAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_rx_callback[if_num] = NULL;
	nss_top_main.if_ctx[if_num] = NULL;
	nss_top_main.ipsec_event_callback = NULL;
}

/*
 * nss_ipsec_register_handler()
 */
void nss_ipsec_register_handler()
{
	nss_core_register_handler(NSS_IPSEC_ENCAP_IF_NUMBER, nss_rx_ipsec_interface_handler, NULL);
	nss_core_register_handler(NSS_IPSEC_ENCAP_IF_NUMBER, nss_rx_ipsec_interface_handler, NULL);
}


EXPORT_SYMBOL(nss_register_ipsec_if);
EXPORT_SYMBOL(nss_register_ipsec_event_if);
EXPORT_SYMBOL(nss_unregister_ipsec_if);
EXPORT_SYMBOL(nss_tx_ipsec_rule);
