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
 * nss_tx_rx_crypto.c
 *	NSS crypto APIs
 */

#include "nss_tx_rx_common.h"

/*
 **********************************
 Tx APIs
 **********************************
 */

/*
 * nss_tx_crypto_if_open()
 *	NSS crypto configure API.
 */
nss_tx_status_t nss_tx_crypto_if_open(void *ctx, uint8_t *buf, uint32_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_crypto_msg *ncm;
	struct nss_crypto_config *nco;

	nss_info("%p: Crypto If Config: buf: %p, len: %d\n", nss_ctx, buf, len);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Crypto If Config' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Crypto If Config' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ncm = (struct nss_crypto_msg *)skb_put(nbuf, sizeof(struct nss_crypto_msg) + len);
	ncm->cm.interface = NSS_CRYPTO_INTERFACE;
	ncm->cm.version = NSS_HLOS_MESSAGE_VERSION;
	ncm->cm.type = NSS_TX_METADATA_TYPE_CRYPTO_CONFIG;
	ncm->cm.len = sizeof(struct nss_crypto_config) + (len - 1);

	nco = &ncm->msg.config;
	nco->len = len;
	memcpy(nco->buf, buf, len);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Crypto If Open' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_crypto_if_buf()
 *	NSS crypto Tx API. Sends a crypto buffer to NSS.
 */
nss_tx_status_t nss_tx_crypto_if_buf(void *ctx, void *buf, uint32_t buf_paddr, uint16_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	int32_t status;

	nss_trace("%p: Crypto If Tx, buf=%p", nss_ctx, buf);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Crypto If Tx' packet dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	status = nss_core_send_crypto(nss_ctx, buf, buf_paddr, len);
	if (unlikely(status != NSS_CORE_STATUS_SUCCESS)) {
		nss_warning("%p: Unable to enqueue 'Crypto If Tx' packet", nss_ctx);
		if (status == NSS_CORE_STATUS_FAILURE_QUEUE) {
			return NSS_TX_FAILURE_QUEUE;
		}

		return NSS_TX_FAILURE;
	}

	/*
	 * Kick the NSS awake so it can process our new entry.
	 */
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CRYPTO_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 **********************************
 Rx APIs
 **********************************
 */

/*
 * nss_rx_handle_crypto_buf()
 *	Create a nss entry to accelerate the given connection
 */
void nss_rx_handle_crypto_buf(struct nss_ctx_instance *nss_ctx, uint32_t buf, uint32_t paddr, uint32_t len)
{
	void *ctx = nss_ctx->nss_top->crypto_ctx;
	nss_crypto_data_callback_t cb = nss_ctx->nss_top->crypto_data_callback;

	nss_assert(cb != 0);
	if (likely(cb) && likely(ctx)) {
		cb(ctx, (void *)buf, paddr, len);
	}
}

/*
 * nss_rx_metadata_crypto_sync()
 * 	Handle the syncing of Crypto stats.
 */
static void nss_rx_metadata_crypto_sync(struct nss_ctx_instance *nss_ctx, struct nss_crypto_sync *ncss)
{
	void *ctx;
	nss_crypto_sync_callback_t cb;

	nss_trace("%p: Callback received for interface %d", nss_ctx, ncss->interface_num);

	ctx = nss_ctx->nss_top->crypto_ctx;
	cb = nss_ctx->nss_top->crypto_sync_callback;

	/*
	 * Call Crypto sync callback
	 */
	if (!cb || !ctx) {
		nss_warning("%p: sync rcvd for crypto if %d before registration", nss_ctx, ncss->interface_num);
		return;
	}

	cb(ctx, ncss->buf, ncss->len);
}

/*
 * nss_rx_crypto_interface_handler()
 *	Handle NSS -> HLOS messages for crypto
 */
static void nss_rx_crypto_interface_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_crypto_msg *ncrm = (struct nss_crypto_msg *)ncm;

	/*
	 * Is this a valid request/response packet?
	 */
	if (ncrm->cm.type >= NSS_METADATA_TYPE_CRYPTO_MAX) {
		nss_warning("%p: received invalid message %d for crypto interface", nss_ctx, ncrm->type);
		return;
	}

	switch (ncrm->cm.type) {
	case NSS_RX_METADATA_TYPE_CRYPTO_SYNC:
		nss_rx_metadata_crypto_sync(nss_ctx, &ncrm->msg.sync);
		break;

	default:
		/*
		 * Check response
		 */
		if (ncm->response != NSS_CMN_RESPONSE_ACK) {
			nss_info("%p: Received response %d for type %d, interface %d",
							nss_ctx, ncm->response, ncm->cm.type, ncm->interface);
		}
	}
}

/*
 **********************************
 Register/Unregister/Miscellaneous APIs
 **********************************
 */

/*
 * nss_register_crypto_mgr()
 */
void *nss_register_crypto_if(nss_crypto_data_callback_t crypto_data_callback, void *ctx)
{
	nss_top_main.crypto_ctx = ctx;
	nss_top_main.crypto_data_callback = crypto_data_callback;

	return (void *)&nss_top_main.nss[nss_top_main.crypto_handler_id];
}

/*
 * nss_register_crypto_sync_if()
 */
void nss_register_crypto_sync_if(nss_crypto_sync_callback_t crypto_sync_callback, void *ctx)
{
	nss_top_main.crypto_ctx = ctx;
	nss_top_main.crypto_sync_callback = crypto_sync_callback;
}

/*
 * nss_unregister_crypto_mgr()
 */
void nss_unregister_crypto_if(void)
{
	nss_top_main.crypto_data_callback = NULL;
	nss_top_main.crypto_sync_callback = NULL;
	nss_top_main.crypto_ctx = NULL;
}

/*
 * nss_crypto_register_handler()
 */
void nss_crypto_register_handler()
{
	nss_core_register_handler(NSS_CRYPTO_INTERFACE, nss_rx_crypto_interface_handler, NULL);
}

EXPORT_SYMBOL(nss_register_crypto_if);
EXPORT_SYMBOL(nss_register_crypto_sync_if);
EXPORT_SYMBOL(nss_unregister_crypto_if);
EXPORT_SYMBOL(nss_tx_crypto_if_buf);
EXPORT_SYMBOL(nss_tx_crypto_if_open);
