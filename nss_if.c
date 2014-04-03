/*
 **************************************************************************
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
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
 * nss_if.c
 *	NSS Interface Messages
 */
#include "nss_tx_rx_common.h"
#include "nss_if.h"

/*
 * Deprecated handler for old API.
 */
extern void nss_rx_metadata_gmac_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_if_stats_sync *ngss, uint16_t interface);

/*
 * nss_if_hanlder_update_driver_stats()
 *	Update the local driver statistics
 */
#if 0
static void nss_if_hanlder_update_driver_stats(uint16_t interface, struct nss_if_stats_sync *ngss)
{
	spin_lock_bh(&nss_top->stats_lock);
	nss_top->stats_gmac[id][NSS_STATS_GMAC_TOTAL_TICKS] += ngss->gmac_total_ticks;
	if (unlikely(nss_top->stats_gmac[id][NSS_STATS_GMAC_WORST_CASE_TICKS] < ngss->gmac_worst_case_ticks)) {
		nss_top->stats_gmac[id][NSS_STATS_GMAC_WORST_CASE_TICKS] = ngss->gmac_worst_case_ticks;
	}
	nss_top->stats_gmac[id][NSS_STATS_GMAC_ITERATIONS] += ngss->gmac_iterations;
	spin_unlock_bh(&nss_top->stats_lock);
}
#endif

/*
 * nss_if_handler()
 *	Handle NSS -> HLOS messages for IPv4 bridge/route
 */
#if 0
static void nss_if_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_if_msg *nim = (struct nss_if_msg *)ncm;
	nss_if_msg_callback_t cb;

	/*
	 * Sanity check the message type
	 */
	if (ncm->type > NSS_IF_MAX_MSG_TYPES) {
		nss_warning("%p: message type out of range: %d", nss_ctx, ncm->type);
		return;
	}

	/*
	 * Update the callback and app_data for NOTIFY messages, IPv4 sends all notify messages
	 * to the same callback/app_data.
	 */
	if (nim->cm.response == NSS_CMM_RESPONSE_NOTIFY) {
		ncm->cb = (uint32_t)nss_ctx->nss_top->phys_if_event_callback[ncm->interface];
		// nim->app_data = nss_ctx->nss_top->ipv4_app_data;
	}

	/*
	 * Log failures
	 */
	nss_core_log_msg_failures(nss_ctx, ncm);

	/*
	 * Handle deprecated messages.  Eventually these messages should be removed.
	 */
	switch (nim->cm.type) {
	case NSS_IF_STATS_SYNC:
		/*
		 * Update local statistics
		 */
		// nss_if_update_driver_stats( ncm->interface, &nim->msg.stats_sync);
		break;
	}

	/*
	 * Do we have a callback?
	 */
	if (!ncm->cb) {
		return;
	}

	/*
	 * Callback
	 */
	cb = (nss_if_msg_callback_t)ncm->cb;
	cb((void *)ncm->app_data, nim);
}
#endif
/*
 * nss_if_tx()
 *	Transmit an ipv4 message to the FW.
 */
nss_tx_status_t nss_if_tx(struct nss_ctx_instance *nss_ctx, struct nss_if_msg *nim)
{
	struct nss_if_msg *nim2;
	struct nss_cmn_msg *ncm = &nim->cm;
	struct sk_buff *nbuf;
	int32_t status;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: ipv4 msg dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	/*
	 * Sanity check the message
	 */
	if (ncm->interface != NSS_IPV4_RX_INTERFACE) {
		nss_warning("%p: tx request for another interface: %d", nss_ctx, ncm->interface);
		return NSS_TX_FAILURE;
	}

	if (ncm->type > NSS_IF_MAX_MSG_TYPES) {
		nss_warning("%p: tx request type unknown: %d", nss_ctx, ncm->type);
		return NSS_TX_FAILURE;
	}

	if (ncm->len > sizeof(struct nss_if_msg)) {
		nss_warning("%p: tx request for another interface: %d", nss_ctx, ncm->interface);
		return NSS_TX_FAILURE;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: msg dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	/*
	 * Copy the message to our skb.
	 */
	nim2 = (struct nss_if_msg *)skb_put(nbuf, sizeof(struct nss_if_msg));
	nim2 = nim;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy IPv4' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 **********************************
 Register/Unregister/Miscellaneous APIs
 **********************************
 */

/*
 * nss_if_notify_register()
 *	Register for notifications
 *
 * NOTE: Do we want to pass an nss_ctx here so that we can register for ipv4 on any core?
 */
void *nss_if_notify_register(uint32_t if_num, nss_if_msg_callback_t cb, void *app_data)
{
	/*
	 * TODO: We need to have a new array in support of the new API
	 * TODO: If we use a per-context array, we would move the array into nss_ctx based.
	 * TODO: See if we can convert the internal storage of netdev so as not to use void *.
	 * TODO: Need to change the nss_top types to match the new ones and remove old code.
	 */
	// uint8_t id = nss_top_main.phys_if_handler_id[if_num];

	// nss_top_main.phys_if_event_callback[if_num] = cb;
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_if_data_register()
 *	Register for data
 *
 * NOTE: Do we want to pass an nss_ctx here so that we can register for ipv4 on any core?
 */
void *nss_if_data_register(uint32_t if_num, struct net_device *netdev, nss_if_data_callback_t cb, void *app_data)
{
	/*
	 * TODO: We need to have a new array in support of the new API
	 * TODO: If we use a per-context array, we would move the array into nss_ctx based.
	 * TODO: See if we can convert the internal storage of netdev so as not to use void *.
	 * TODO: Need to change the nss_top types to match the new ones and remove old code.
	 */
	uint8_t id = nss_top_main.phys_if_handler_id[if_num];
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[id];

	//nss_top_main.if_rx_callback[if_num] = cb;
	nss_top_main.if_ctx[if_num] = (void *)netdev;
	nss_ctx->phys_if_mtu[if_num] = NSS_ETH_NORMAL_FRAME_MTU;
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}



/*
 * nss_if_notify_unregister()
 *	Unregister to received IPv4 events.
 *
 * NOTE: Do we want to pass an nss_ctx here so that we can register for ipv4 on any core?
 */
void nss_if_notify_unregister(void)
{
	nss_top_main.ipv4_callback = NULL;
}

/*
 * nss_get_ipv4_mgr_ctx()
 *
 * TODO: This only suppports a single ipv4, do we ever want to support more?
 */
struct nss_ctx_instance *nss_if_get_mgr(void)
{
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_if_register_handler()
 *	Register our handler to receive messages for this interface
 */
void nss_if_register_handler(void)
{
}

EXPORT_SYMBOL(nss_if_tx);
EXPORT_SYMBOL(nss_if_notify_register);
EXPORT_SYMBOL(nss_if_notify_unregister);
EXPORT_SYMBOL(nss_if_get_mgr);
EXPORT_SYMBOL(nss_if_register_handler);
