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
 * nss_tx_rx_phys_if.c
 *	NSS Physical i/f (gmac) APIs
 */

#include "nss_tx_rx_common.h"

/*
 **********************************
 Tx APIs
 **********************************
 */

/*
 * nss_tx_phys_if_buf ()
 *	Send packet to physical interface owned by NSS
 */
nss_tx_status_t nss_tx_phys_if_buf(void *ctx, struct sk_buff *os_buf, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	int32_t status;

	nss_trace("%p: Phys If Tx packet, id:%d, data=%p", nss_ctx, if_num, os_buf->data);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Tx' packet dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	status = nss_core_send_buffer(nss_ctx, if_num, os_buf, NSS_IF_DATA_QUEUE, H2N_BUFFER_PACKET, 0);
	if (unlikely(status != NSS_CORE_STATUS_SUCCESS)) {
		nss_warning("%p: Unable to enqueue 'Phys If Tx' packet\n", nss_ctx);
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

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_PACKET]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_open()
 *	Send open command to physical interface
 */
nss_tx_status_t nss_tx_phys_if_open(void *ctx, uint32_t tx_desc_ring, uint32_t rx_desc_ring, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_if_msg *nim;
	struct nss_if_open *nio;

	nss_info("%p: Phys If Open, id:%d, TxDesc: %x, RxDesc: %x\n", nss_ctx, if_num, tx_desc_ring, rx_desc_ring);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Open' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Open' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nim = (struct nss_if_msg *)skb_put(nbuf, sizeof(struct nss_if_msg));
	nim->cm.interface = if_num;
	nim->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nim->cm.type = NSS_TX_METADATA_TYPE_INTERFACE_OPEN;
	nim->cm.len = sizeof(struct nss_if_open);

	nio = &nim->msg.open;

	nio->tx_desc_ring = tx_desc_ring;
	nio->rx_desc_ring = rx_desc_ring;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Open' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_close()
 *	Send close command to physical interface
 */
nss_tx_status_t nss_tx_phys_if_close(void *ctx, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_if_msg *nim;
	struct nss_if_close *nic;

	nss_info("%p: Phys If Close, id:%d \n", nss_ctx, if_num);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Close' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Close' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nim = (struct nss_if_msg *)skb_put(nbuf, sizeof(struct nss_if_msg));
	nim->cm.interface = if_num;
	nim->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nim->cm.type = NSS_TX_METADATA_TYPE_INTERFACE_CLOSE;
	nim->cm.len = sizeof(struct nss_if_close);

	nic = &nim->msg.close;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: Unable to enqueue 'Phys If Close' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_link_state()
 *	Send link state to physical interface
 */
nss_tx_status_t nss_tx_phys_if_link_state(void *ctx, uint32_t link_state, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_if_msg *nim;
	struct nss_if_link_state_notify *nils;

	nss_info("%p: Phys If Link State, id:%d, State: %x\n", nss_ctx, if_num, link_state);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Link State' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Link State' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nim = (struct nss_if_msg *)skb_put(nbuf, sizeof(struct nss_if_msg));
	nim->cm.interface = if_num;
	nim->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nim->cm.type = NSS_TX_METADATA_TYPE_INTERFACE_LINK_STATE_NOTIFY;
	nim->cm.len = sizeof(struct nss_if_link_state_notify);

	nils = &nim->msg.link_state_notify;
	nils->state = link_state;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Link State' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_mac_addr()
 *	Send a MAC address to physical interface
 */
nss_tx_status_t nss_tx_phys_if_mac_addr(void *ctx, uint8_t *addr, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_if_msg *nim;
	struct nss_if_mac_address_set *nmas;

	nss_info("%p: Phys If MAC Address, id:%d\n", nss_ctx, if_num);
	nss_assert(addr != 0);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If MAC Address' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If MAC Address' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nim = (struct nss_if_msg *)skb_put(nbuf, sizeof(struct nss_if_msg));
	nim->cm.interface = if_num;
	nim->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nim->cm.type = NSS_TX_METADATA_TYPE_INTERFACE_MAC_ADDR_SET;
	nim->cm.len = sizeof(struct nss_if_mac_address_set);

	nmas = &nim->msg.mac_address_set;
	memcpy(nmas->mac_addr, addr, ETH_ALEN);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Mac Address' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_change_mtu()
 *	Send a MTU change command
 */
nss_tx_status_t nss_tx_phys_if_change_mtu(void *ctx, uint32_t mtu, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status, i;
	uint16_t max_mtu;
	struct nss_if_msg *nim;
	struct nss_if_mtu_change *nimc;

	nss_info("%p: Phys If Change MTU, id:%d, mtu=%d\n", nss_ctx, if_num, mtu);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Change MTU' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nim = (struct nss_if_msg *)skb_put(nbuf, sizeof(struct nss_if_msg));
	nim->cm.interface = if_num;
	nim->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nim->cm.type = NSS_TX_METADATA_TYPE_INTERFACE_MTU_CHANGE;
	nim->cm.len = sizeof(struct nss_if_mtu_change);

	nimc = &nim->msg.mtu_change;
	nimc->min_buf_size = (uint16_t)mtu + NSS_NBUF_ETH_EXTRA;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Change MTU' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_ctx->phys_if_mtu[if_num] = (uint16_t)mtu;
	max_mtu = nss_ctx->phys_if_mtu[0];
	for (i = 1; i < NSS_MAX_PHYSICAL_INTERFACES; i++) {
		if (max_mtu < nss_ctx->phys_if_mtu[i]) {
		       max_mtu = nss_ctx->phys_if_mtu[i];
		}
	}

	if (max_mtu <= NSS_ETH_NORMAL_FRAME_MTU) {
		max_mtu = NSS_ETH_NORMAL_FRAME_MTU;
	} else if (max_mtu <= NSS_ETH_MINI_JUMBO_FRAME_MTU) {
		max_mtu = NSS_ETH_MINI_JUMBO_FRAME_MTU;
	} else if (max_mtu <= NSS_ETH_FULL_JUMBO_FRAME_MTU) {
		max_mtu = NSS_ETH_FULL_JUMBO_FRAME_MTU;
	}

	nss_ctx->max_buf_size = ((max_mtu + ETH_HLEN + SMP_CACHE_BYTES - 1) & ~(SMP_CACHE_BYTES - 1)) + NSS_NBUF_PAD_EXTRA;

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
 * nss_rx_metadata_gmac_stats_sync()
 *	Handle the syncing of GMAC stats.
 */
static void nss_rx_metadata_gmac_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_if_stats_sync *ngss, uint16_t interface)
{
	void *ctx;
	nss_phys_if_event_callback_t cb;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	uint32_t id = interface;

	if (id >= NSS_MAX_PHYSICAL_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_ctx->nss_top->if_ctx[id];
	cb = nss_ctx->nss_top->phys_if_event_callback[id];

	/*
	 * Call GMAC driver callback
	 */
	if (!cb || !ctx) {
		nss_warning("%p: Event received for GMAC interface %d before registration", nss_ctx, interface);
		return;
	}

	cb(ctx, NSS_GMAC_EVENT_STATS, (void *)ngss, sizeof(struct nss_if_stats_sync));

	spin_lock_bh(&nss_top->stats_lock);
	nss_top->stats_gmac[id][NSS_STATS_GMAC_TOTAL_TICKS] += ngss->gmac_total_ticks;
	if (unlikely(nss_top->stats_gmac[id][NSS_STATS_GMAC_WORST_CASE_TICKS] < ngss->gmac_worst_case_ticks)) {
		nss_top->stats_gmac[id][NSS_STATS_GMAC_WORST_CASE_TICKS] = ngss->gmac_worst_case_ticks;
	}

	nss_top->stats_gmac[id][NSS_STATS_GMAC_ITERATIONS] += ngss->gmac_iterations;
	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_phys_if_interface_handler()
 *	Handle NSS -> HLOS messages for physical interface/gmacs
 */
static void nss_rx_phys_if_interface_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_if_msg *nim = (struct nss_if_msg *)ncm;

	/*
	 * Is this a valid request/response packet?
	 */
	if (nim->cm.type >= NSS_METADATA_TYPE_INTERFACE_MAX) {
		nss_warning("%p: received invalid message %d for physical interface", nss_ctx, nim->type);
		return;
	}


	switch (nim->cm.type) {
	case NSS_RX_METADATA_TYPE_INTERFACE_STATS_SYNC:
		nss_rx_metadata_gmac_stats_sync(nss_ctx, &nim->msg.stats_sync, ncm->interface);
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
 * nss_register_phys_if()
 */
void *nss_register_phys_if(uint32_t if_num,
				nss_phys_if_rx_callback_t rx_callback,
				nss_phys_if_event_callback_t event_callback, struct net_device *if_ctx)
{
	uint8_t id = nss_top_main.phys_if_handler_id[if_num];
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[id];

	nss_assert(if_num <= NSS_MAX_PHYSICAL_INTERFACES);

	nss_top_main.if_ctx[if_num] = (void *)if_ctx;
	nss_top_main.if_rx_callback[if_num] = rx_callback;
	nss_top_main.phys_if_event_callback[if_num] = event_callback;

	nss_ctx->phys_if_mtu[if_num] = NSS_ETH_NORMAL_FRAME_MTU;
	return (void *)nss_ctx;
}

/*
 * nss_unregister_phys_if()
 */
void nss_unregister_phys_if(uint32_t if_num)
{
	nss_assert(if_num < NSS_MAX_PHYSICAL_INTERFACES);

	nss_top_main.if_rx_callback[if_num] = NULL;
	nss_top_main.phys_if_event_callback[if_num] = NULL;
	nss_top_main.if_ctx[if_num] = NULL;
	nss_top_main.nss[0].phys_if_mtu[if_num] = 0;
	nss_top_main.nss[1].phys_if_mtu[if_num] = 0;
}

/*
 * nss_tx_phys_if_get_napi_ctx()
 *	Get napi context
 */
nss_tx_status_t nss_tx_phys_if_get_napi_ctx(void *ctx, struct napi_struct **napi_ctx)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;

	nss_info("%p: Get interrupt context, GMAC\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	*napi_ctx = &nss_ctx->int_ctx[0].napi;

	return NSS_TX_SUCCESS;
}

/*
 * nss_phys_if_register_handler()
 */
void nss_phys_if_register_handler(uint32_t if_num)
{
	nss_core_register_handler(if_num, nss_rx_phys_if_interface_handler, NULL);
}

EXPORT_SYMBOL(nss_register_phys_if);
EXPORT_SYMBOL(nss_unregister_phys_if);
EXPORT_SYMBOL(nss_tx_phys_if_buf);
EXPORT_SYMBOL(nss_tx_phys_if_open);
EXPORT_SYMBOL(nss_tx_phys_if_close);
EXPORT_SYMBOL(nss_tx_phys_if_link_state);
EXPORT_SYMBOL(nss_tx_phys_if_change_mtu);
EXPORT_SYMBOL(nss_tx_phys_if_mac_addr);
EXPORT_SYMBOL(nss_tx_phys_if_get_napi_ctx);
