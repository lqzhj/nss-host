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
 * nss_virt_if.c
 *	NSS virtual/redirect handler APIs
 */

#include "nss_tx_rx_common.h"
#include "nss_virt_if.h"
#include <net/arp.h>

extern int nss_ctl_redirect;

/*
 * nss_virt_if_rxbuf()
 *	HLOS interface has received a packet which we redirect to the NSS, if appropriate to do so.
 */
static nss_tx_status_t nss_virt_if_rxbuf(int32_t if_num, struct sk_buff *skb, uint32_t nwifi)
{
	int32_t status;
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[nss_top_main.ipv4_handler_id];
	uint32_t bufftype;

	if (unlikely(nss_ctl_redirect == 0) || unlikely(skb->vlan_tci)) {
		return NSS_TX_FAILURE_NOT_SUPPORTED;
	}

	nss_assert(NSS_IS_IF_TYPE(VIRTUAL, if_num));
	nss_trace("%p: Virtual Rx packet, if_num:%d, skb:%p", nss_ctx, if_num, skb);

	/*
	 * Get the NSS context that will handle this packet and check that it is initialised and ready
	 */
	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: Virtual Rx packet dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	/*
	 * Sanity check the SKB to ensure that it's suitable for us
	 */
	if (unlikely(skb->len <= ETH_HLEN)) {
		nss_warning("%p: Virtual Rx packet: %p too short", nss_ctx, skb);
		return NSS_TX_FAILURE_TOO_SHORT;
	}

	if (unlikely(skb_shinfo(skb)->nr_frags != 0)) {
		/*
		 * TODO: If we have a connection matching rule for this skbuff,
		 * do we need to flush it??
		 */
		nss_warning("%p: Delivering the packet to Linux because of fragmented skb: %p\n", nss_ctx, skb);
		return NSS_TX_FAILURE_NOT_SUPPORTED;
	}

	if (nwifi) {
		bufftype = H2N_BUFFER_NATIVE_WIFI;
	} else {
		bufftype = H2N_BUFFER_PACKET;

		/*
		 * NSS expects to see buffer from Ethernet header onwards
		 * Assumption: eth_type_trans has been done by WLAN driver
		 */
		skb_push(skb, ETH_HLEN);
	}

	/*
	 * Direct the buffer to the NSS
	 */
	status = nss_core_send_buffer(nss_ctx, if_num, skb, NSS_IF_DATA_QUEUE, bufftype, H2N_BIT_FLAG_VIRTUAL_BUFFER);
	if (unlikely(status != NSS_CORE_STATUS_SUCCESS)) {
		nss_warning("%p: Virtual Rx packet unable to enqueue\n", nss_ctx);
		if (!nwifi) {
			skb_pull(skb, ETH_HLEN);
		}
		return NSS_TX_FAILURE_QUEUE;
	}

	/*
	 * Kick the NSS awake so it can process our new entry.
	 */
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].desc_ring.int_bit,
						NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_PACKET]);
	return NSS_TX_SUCCESS;
}

/*
 * @brief Forward virtual interface packets
 *	This function expects packet with L3 header and eth_type_trans
 *	has been called before calling this api
 *
 * @param nss_ctx NSS context (provided during registeration)
 * @param skb OS buffer (e.g. skbuff)
 * @return nss_tx_status_t Tx status
 */
nss_tx_status_t nss_virt_if_eth_rxbuf(int32_t if_num, struct sk_buff *skb)
{
	return nss_virt_if_rxbuf(if_num, skb, 0);
}

/*
 * @brief Forward Native wifi packet from virtual interface
 *	Expects packet with qca-nwifi format
 *
 * @param nss_ctx NSS context (provided during registeration)
 * @param skb OS buffer (e.g. skbuff)
 * @return nss_tx_status_t Tx status
 */
nss_tx_status_t nss_virt_if_nwifi_rxbuf(int32_t if_num, struct sk_buff *skb)
{
	return nss_virt_if_rxbuf(if_num, skb, 1);
}

/*
 * nss_virt_if_create()
 */
int32_t nss_virt_if_create(struct net_device *if_ctx)
{
	int32_t if_num, status;
	struct sk_buff *nbuf;
	struct nss_virtual_if_msg *nvim;
	struct nss_virtual_if_create *nvic;
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[nss_top_main.ipv4_handler_id];

	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("Interface could not be created as core not ready");
		return -1;
	}

	/*
	 * Check if net_device is Ethernet type
	 */
	if (if_ctx->type != ARPHRD_ETHER) {
		nss_warning("%p:Register virtual interface %p: type incorrect: %d ", nss_ctx, if_ctx, if_ctx->type);
		return -1;
	}

	/*
	 * Find a free virtual interface
	 */
	spin_lock_bh(&nss_top_main.lock);
	for (if_num = NSS_MAX_PHYSICAL_INTERFACES; if_num < NSS_MAX_DEVICE_INTERFACES; ++if_num) {
		if (!nss_top_main.if_ctx[if_num]) {
			/*
			 * Use this redirection interface
			 */
			nss_top_main.if_ctx[if_num] = (void *)if_ctx;
			break;
		}
	}

	spin_unlock_bh(&nss_top_main.lock);
	if (if_num == NSS_MAX_DEVICE_INTERFACES) {
		/*
		 * No available virtual contexts
		 */
		nss_warning("%p:Register virtual interface %p: no contexts available:", nss_ctx, if_ctx);
		return -1;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: Register virtual interface %p: command allocation failed", nss_ctx, if_ctx);
		return -1;
	}

	nvim = (struct nss_virtual_if_msg *)skb_put(nbuf, sizeof(struct nss_virtual_if_msg));
	nss_cmn_msg_init(&nvim->cm, if_num, NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_CREATE, sizeof(struct nss_virtual_if_create), NULL, NULL);

	nvic = &nvim->msg.create;
	nvic->flags = 0;
	memcpy(nvic->mac_addr, if_ctx->dev_addr, ETH_HLEN);
	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Register virtual interface' rule\n", nss_ctx);
		return -1;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
		NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	/*
	 * Hold a reference to the net_device
	 */
	dev_hold(if_ctx);
	nss_info("%p:Registered virtual interface %d: context %p", nss_ctx, if_num, if_ctx);

	/*
	 * The context returned is the virtual interface # which is, essentially, the index into the if_ctx
	 * array that is holding the net_device pointer
	 */
	return if_num;
}

/*
 * nss_virt_if_destroy()
 */
nss_tx_status_t nss_virt_if_destroy(int32_t if_num)
{
	int32_t status;
	struct sk_buff *skb;
	struct nss_virtual_if_msg *nvim;
	struct net_device *dev;
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[nss_top_main.ipv4_handler_id];

	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("Interface could not be destroyed as core not ready");
		return NSS_TX_FAILURE_NOT_READY;
	}

	nss_assert(NSS_IS_IF_TYPE(VIRTUAL, if_num));

	spin_lock_bh(&nss_top_main.lock);
	if (!nss_top_main.if_ctx[if_num]) {
		spin_unlock_bh(&nss_top_main.lock);
		nss_warning("%p: Unregister virtual interface %d: no context", nss_ctx, if_num);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	/*
	 * Set this context to NULL
	 */
	dev = nss_top_main.if_ctx[if_num];
	nss_top_main.if_ctx[if_num] = NULL;
	spin_unlock_bh(&nss_top_main.lock);
	nss_info("%p:Unregister virtual interface %d (%p)", nss_ctx, if_num, dev);
	dev_put(dev);

	skb = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!skb)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: Unregister virtual interface %d: command allocation failed", nss_ctx, if_num);
		return NSS_TX_FAILURE;
	}

	nvim = (struct nss_virtual_if_msg *)skb_put(skb, sizeof(struct nss_virtual_if_msg));
	nss_cmn_msg_init(&nvim->cm, if_num, NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_DESTROY, sizeof(struct nss_virtual_if_destroy), NULL, NULL);

	status = nss_core_send_buffer(nss_ctx, 0, skb, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(skb);
		nss_warning("%p: Unable to enqueue 'unregister virtual interface' rule\n", nss_ctx);
		return NSS_TX_FAILURE_QUEUE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
		NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

EXPORT_SYMBOL(nss_virt_if_create);
EXPORT_SYMBOL(nss_virt_if_destroy);
EXPORT_SYMBOL(nss_virt_if_nwifi_rxbuf);
EXPORT_SYMBOL(nss_virt_if_eth_rxbuf);

