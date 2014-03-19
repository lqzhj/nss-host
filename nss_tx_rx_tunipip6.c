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
	uint32_t id = interface;

	if (id >= NSS_MAX_NET_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_top->if_ctx[id];
	cb = nss_top->tunipip6_if_event_callback;

	/*
	 * call ipip6 tunnel callback
	 */

	if (!cb || !ctx) {
		nss_warning("%p: Event received for ipip6 tunnel interface %d before registration", nss_ctx, ntunipip6ss->interface);
		return;
	}

	cb(ctx, NSS_TUNIPIP6_EVENT_STATS, (void *)ntunipip6ss, sizeof(struct nss_tunipip6_stats_sync));
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

EXPORT_SYMBOL(nss_register_tunipip6_if);
EXPORT_SYMBOL(nss_unregister_tunipip6_if);
