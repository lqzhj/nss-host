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
 * nss_tx_rx_pppoe.c
 *	NSS PPPoE APIs
 */

#include "nss_tx_rx_common.h"
#include <linux/ppp_channel.h>

/*
 * nss_tx_destroy_pppoe_connection_rule)
 *	Destroy PPoE connection rule associated with the session ID and remote server MAC address.
 */
void nss_tx_destroy_pppoe_connection_rule(void *ctx, uint16_t pppoe_session_id, uint8_t *pppoe_remote_mac)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct nss_pppoe_msg npm;
	struct nss_pppoe_rule_destroy_msg *nprd;
	uint16_t *pppoe_remote_mac_uint16_t = (uint16_t *)pppoe_remote_mac;
	int32_t status;

	/*
	 * TODO Remove this function once linux kernel directly calls nss_pppoe_tx()
	 */
	nss_info("%p: Destroy all PPPoE rules of session ID: %x remote MAC: %x:%x:%x:%x:%x:%x", nss_ctx, pppoe_session_id,
			pppoe_remote_mac[0], pppoe_remote_mac[1], pppoe_remote_mac[2],
			pppoe_remote_mac[3], pppoe_remote_mac[4], pppoe_remote_mac[5]);

	nss_cmn_msg_init(&npm.cm, NSS_PPPOE_RX_INTERFACE, NSS_PPPOE_TX_CONN_RULE_DESTROY,
			sizeof(struct nss_pppoe_rule_destroy_msg), NULL, NULL);

	nprd = &npm.msg.pppoe_rule_destroy;

	nprd->pppoe_session_id = pppoe_session_id;
	nprd->pppoe_remote_mac[0] = pppoe_remote_mac_uint16_t[0];
	nprd->pppoe_remote_mac[1] = pppoe_remote_mac_uint16_t[1];
	nprd->pppoe_remote_mac[2] = pppoe_remote_mac_uint16_t[2];

	status = nss_pppoe_tx(nss_ctx, &npm);
	if (status != NSS_TX_SUCCESS) {
		nss_warning("%p: Not able to send destroy pppoe rule msg to NSS %x\n", nss_ctx, status);
	}
}

EXPORT_SYMBOL(nss_tx_destroy_pppoe_connection_rule);
