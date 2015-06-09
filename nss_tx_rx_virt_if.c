/*
 **************************************************************************
 * Copyright (c) 2013 - 2015, The Linux Foundation. All rights reserved.
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
 * nss_tx_rx_virt_if.c
 *	NSS virtual/redirect handler APIs
 */

#include "nss_tx_rx_common.h"
#include <net/arp.h>

extern int nss_ctl_redirect;

/*
 * nss_register_virt_if()
 */
void *nss_register_virt_if(void *ctx,
				nss_virt_if_rx_callback_t rx_callback,
				struct net_device *netdev)
{
	struct nss_redir_handle *handle = (struct nss_redir_handle *)ctx;

	nss_wifi_if_register(handle->whandle, rx_callback, netdev);
	nss_virt_if_register(handle->vhandle, rx_callback, netdev);

	return ctx;
}

/*
 * nss_unregister_virt_if()
 */
void nss_unregister_virt_if(void *ctx)
{
	struct nss_redir_handle *handle = (struct nss_redir_handle *)ctx;

	nss_wifi_if_unregister(handle->whandle);
	nss_virt_if_unregister(handle->vhandle);
}

/*
 * nss_tx_virt_if_recvbuf()
 *	HLOS interface has received a packet which we redirect to the NSS, if appropriate to do so.
 */
nss_tx_status_t nss_tx_virt_if_recvbuf(void *ctx, struct sk_buff *skb, uint32_t nwifi)
{
	struct nss_redir_handle *handle = (struct nss_redir_handle *)ctx;

	if (nwifi) {
		return nss_wifi_if_tx_buf(handle->whandle, skb);
	} else {
		return nss_virt_if_tx_buf(handle->vhandle, skb);
	}
}

/*
 * @brief Forward virtual interface packets
 *	This function expects packet with L3 header and eth_type_trans
 *	has been called before calling this api
 *
 * @param nss_ctx NSS context (provided during registeration)
 * @param os_buf OS buffer (e.g. skbuff)
 * @return nss_tx_status_t Tx status
 */
nss_tx_status_t nss_tx_virt_if_rxbuf(void *ctx, struct sk_buff *os_buf)
{

	return nss_tx_virt_if_recvbuf(ctx, os_buf, 0);
}

/*
 * @brief Forward Native wifi packet from virtual interface
 *	Expects packet with qca-nwifi format
 *
 * @param nss_ctx NSS context (provided during registeration)
 * @param os_buf OS buffer (e.g. skbuff)
 * @return nss_tx_status_t Tx status
 */
nss_tx_status_t nss_tx_virt_if_rx_nwifibuf(void *ctx, struct sk_buff *os_buf)
{

	return nss_tx_virt_if_recvbuf(ctx, os_buf, 1);
}

/*
 * nss_create_virt_if()
 */
void *nss_create_virt_if(struct net_device *netdev)
{
	struct nss_redir_handle *handles;

	handles = (struct nss_redir_handle *)kzalloc(sizeof(struct nss_redir_handle), GFP_KERNEL);
	if (!handles) {
		nss_warning("%s: kzalloc failed\n", __func__);
		goto error1;
	}

	handles->whandle = nss_wifi_if_create(netdev);
	if (!handles->whandle) {
		nss_warning("%s: nss_wifi_if creation failed\n", __func__);
		goto error2;
	}

	handles->vhandle = nss_virt_if_create(netdev);
	if (!handles->vhandle) {
		nss_warning("%s: nss_virt_if creation failed\n", __func__);
		goto error3;
	}

	return (void *)handles;
error3:
	nss_wifi_if_destroy(handles->whandle);
error2:
	kfree(handles);
error1:
	return NULL;
}

/*
 * nss_destroy_virt_if()
 */
nss_tx_status_t nss_destroy_virt_if(void *ctx)
{
	struct nss_redir_handle *handle = (struct nss_redir_handle *)ctx;

	nss_wifi_if_destroy(handle->whandle);
	nss_virt_if_destroy(handle->vhandle);

	return NSS_TX_SUCCESS;
}

EXPORT_SYMBOL(nss_tx_virt_if_rxbuf);
EXPORT_SYMBOL(nss_tx_virt_if_rx_nwifibuf);
EXPORT_SYMBOL(nss_create_virt_if);
EXPORT_SYMBOL(nss_destroy_virt_if);
EXPORT_SYMBOL(nss_register_virt_if);
EXPORT_SYMBOL(nss_unregister_virt_if);

