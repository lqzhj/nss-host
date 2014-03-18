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
	uint32_t id = interface;

	if (id >= NSS_MAX_NET_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_top->if_ctx[id];
	cb = nss_top->tun6rd_if_event_callback;

	/*
	 * call 6rd tunnel callback
	 */
	if (!cb || !ctx) {
		nss_warning("%p: Event received for 6rd tunnel interface %d before registration", nss_ctx, ntun6rdss->interface);
		return;
	}

	cb(ctx, NSS_TUN6RD_EVENT_STATS, (void *)ntun6rdss, sizeof(struct nss_tun6rd_stats_sync));
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
	if (ntm->type >= NSS_METADATA_TYPE_TUN6RD_MAX) {
		nss_warning("%p: received invalid message %d for Tun6RD interface", nss_ctx, ntm->type);
		return;
	}

	switch (ntm->type) {
	case NSS_RX_METADATA_TYPE_TUN6RD_STATS_SYNC:
		nss_rx_metadata_tun6rd_stats_sync(nss_ctx, &ntm->msg.stats_sync, ncm->interface);
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

EXPORT_SYMBOL(nss_register_tun6rd_if);
EXPORT_SYMBOL(nss_unregister_tun6rd_if);
