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
 * nss_tx_rx_ipv4.c
 *	NSS IPv4 APIs
 */

#include <linux/ppp_channel.h>
#include "nss_tx_rx_common.h"

/*
 **********************************
 Tx APIs
 **********************************
 */

/*
 * nss_tx_create_ipv4_rule()
 *	Create a nss entry to accelerate the given connection
 */
nss_tx_status_t nss_tx_create_ipv4_rule(void *ctx, struct nss_ipv4_create *unic)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_ipv4_msg *nim;
	struct nss_ipv4_rule_create_msg *nircm;

	nss_info("%p: Create IPv4: %pI4:%d (%pI4:%d), %pI4:%d (%pI4:%d), p: %d\n", nss_ctx,
		&unic->src_ip, unic->src_port, &unic->src_ip_xlate, unic->src_port_xlate,
		&unic->dest_ip, unic->dest_port, &unic->dest_ip_xlate, unic->dest_port_xlate, unic->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPv4' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPv4' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nim = (struct nss_ipv4_msg *)skb_put(nbuf, sizeof(struct nss_ipv4_msg));
	nim->cm.interface = NSS_IPV4_RX_INTERFACE;
	nim->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nim->cm.type = NSS_TX_METADATA_TYPE_IPV4_RULE_CREATE;
	nim->cm.len = sizeof(struct nss_ipv4_rule_create_msg);

	nircm = &nim->msg.rule_create;

	nircm->valid_flags = 0;

	/*
	 * Copy over the 5 tuple details.
	 */
	nircm->tuple.protocol = (uint8_t)unic->protocol;
	nircm->tuple.flow_ip = unic->src_ip;
	nircm->tuple.flow_ident = (uint32_t)unic->src_port;
	nircm->tuple.return_ip = unic->dest_ip;
	nircm->tuple.return_ident = (uint32_t)unic->dest_port;

	/*
	 * Copy over the connection rules and set the CONN_VALID flag
	 */
	nircm->conn_rule.flow_interface_num = unic->src_interface_num;
	nircm->conn_rule.flow_mtu = unic->from_mtu;
	nircm->conn_rule.flow_ip_xlate = unic->src_ip_xlate;
	nircm->conn_rule.flow_ident_xlate = (uint32_t)unic->src_port_xlate;
	memcpy(nircm->conn_rule.flow_mac, unic->src_mac, 6);
	nircm->conn_rule.return_interface_num = unic->dest_interface_num;
	nircm->conn_rule.return_mtu = unic->to_mtu;
	nircm->conn_rule.return_ip_xlate = unic->dest_ip_xlate;
	nircm->conn_rule.return_ident_xlate = (uint32_t)unic->dest_port_xlate;
	if (nircm->tuple.return_ip != nircm->conn_rule.return_ip_xlate || nircm->tuple.return_ident != nircm->conn_rule.return_ident_xlate) {
		memcpy(nircm->conn_rule.return_mac, unic->dest_mac_xlate, 6);
	} else {
		memcpy(nircm->conn_rule.return_mac, unic->dest_mac, 6);
	}
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_CONN_VALID;

	/*
	 * Copy over the pppoe rules and set the PPPOE_VALID flag.
	 */
	nircm->pppoe_rule.flow_pppoe_session_id = unic->flow_pppoe_session_id;
	memcpy(nircm->pppoe_rule.flow_pppoe_remote_mac, unic->flow_pppoe_remote_mac, ETH_ALEN);
	nircm->pppoe_rule.return_pppoe_session_id = unic->return_pppoe_session_id;
	memcpy(nircm->pppoe_rule.return_pppoe_remote_mac, unic->return_pppoe_remote_mac, ETH_ALEN);
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_PPPOE_VALID;

	/*
	 * Copy over the tcp rules and set the TCP_VALID flag.
	 */
	nircm->tcp_rule.flow_window_scale = unic->flow_window_scale;
	nircm->tcp_rule.flow_max_window = unic->flow_max_window;
	nircm->tcp_rule.flow_end = unic->flow_end;
	nircm->tcp_rule.flow_max_end = unic->flow_max_end;
	nircm->tcp_rule.return_window_scale = unic->return_window_scale;
	nircm->tcp_rule.return_max_window = unic->return_max_window;
	nircm->tcp_rule.return_end = unic->return_end;
	nircm->tcp_rule.return_max_end = unic->return_max_end;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_TCP_VALID;

	/*
	 * Copy over the vlan rules and set the VLAN_VALID flag
	 */
	nircm->vlan_rule.ingress_vlan_tag = unic->ingress_vlan_tag;
	nircm->vlan_rule.egress_vlan_tag = unic->egress_vlan_tag;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_VALID;

	/*
	 * Copy over the qos rules and set the QOS_VALID flag
	 */
	nircm->qos_rule.qos_tag = unic->qos_tag;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_QOS_VALID;

	nircm->rule_flags = 0;
	if (unic->flags & NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_ROUTED) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_ROUTED;
	}

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPv4' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_create_ipv4_rule1()
 *	Create a nss entry to accelerate the given connection
 */
nss_tx_status_t nss_tx_create_ipv4_rule1(void *ctx, struct nss_ipv4_create *unic)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_ipv4_msg *nim;
	struct nss_ipv4_rule_create_msg *nircm;

	nss_info("%p: Create IPv4: %pI4:%d (%pI4:%d), %pI4:%d (%pI4:%d), p: %d\n", nss_ctx,
		&unic->src_ip, unic->src_port, &unic->src_ip_xlate, unic->src_port_xlate,
		&unic->dest_ip, unic->dest_port, &unic->dest_ip_xlate, unic->dest_port_xlate, unic->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPv4' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPv4' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nim = (struct nss_ipv4_msg *)skb_put(nbuf, sizeof(struct nss_ipv4_msg));
	nim->cm.interface = NSS_IPV4_RX_INTERFACE;
	nim->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nim->cm.type = NSS_TX_METADATA_TYPE_IPV4_RULE_CREATE;
	nim->cm.len = sizeof(struct nss_ipv4_rule_create_msg);

	nircm = &nim->msg.rule_create;

	nircm->valid_flags = 0;
	nircm->rule_flags = 0;

	/*
	 * Copy over the 5 tuple details.
	 */
	nircm->tuple.protocol = (uint8_t)unic->protocol;
	nircm->tuple.flow_ip = unic->src_ip;
	nircm->tuple.flow_ident = (uint32_t)unic->src_port;
	nircm->tuple.return_ip = unic->dest_ip;
	nircm->tuple.return_ident = (uint32_t)unic->dest_port;

	/*
	 * Copy over the connection rules and set the CONN_VALID flag
	 */
	nircm->conn_rule.flow_interface_num = unic->src_interface_num;
	nircm->conn_rule.flow_mtu = unic->from_mtu;
	nircm->conn_rule.flow_ip_xlate = unic->src_ip_xlate;
	nircm->conn_rule.flow_ident_xlate = (uint32_t)unic->src_port_xlate;
	memcpy(nircm->conn_rule.flow_mac, unic->src_mac, 6);
	nircm->conn_rule.return_interface_num = unic->dest_interface_num;
	nircm->conn_rule.return_mtu = unic->to_mtu;
	nircm->conn_rule.return_ip_xlate = unic->dest_ip_xlate;
	nircm->conn_rule.return_ident_xlate = (uint32_t)unic->dest_port_xlate;
	if (nircm->tuple.return_ip != nircm->conn_rule.return_ip_xlate || nircm->tuple.return_ident != nircm->conn_rule.return_ident_xlate) {
		memcpy(nircm->conn_rule.return_mac, unic->dest_mac_xlate, 6);
	} else {
		memcpy(nircm->conn_rule.return_mac, unic->dest_mac, 6);
	}
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_CONN_VALID;

	/*
	 * Copy over the pppoe rules and set the PPPOE_VALID flag.
	 */
	nircm->pppoe_rule.flow_pppoe_session_id = unic->flow_pppoe_session_id;
	memcpy(nircm->pppoe_rule.flow_pppoe_remote_mac, unic->flow_pppoe_remote_mac, ETH_ALEN);
	nircm->pppoe_rule.return_pppoe_session_id = unic->return_pppoe_session_id;
	memcpy(nircm->pppoe_rule.return_pppoe_remote_mac, unic->return_pppoe_remote_mac, ETH_ALEN);
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_PPPOE_VALID;

	/*
	 * Copy over the tcp rules and set the TCP_VALID flag.
	 */
	nircm->tcp_rule.flow_window_scale = unic->flow_window_scale;
	nircm->tcp_rule.flow_max_window = unic->flow_max_window;
	nircm->tcp_rule.flow_end = unic->flow_end;
	nircm->tcp_rule.flow_max_end = unic->flow_max_end;
	nircm->tcp_rule.return_window_scale = unic->return_window_scale;
	nircm->tcp_rule.return_max_window = unic->return_max_window;
	nircm->tcp_rule.return_end = unic->return_end;
	nircm->tcp_rule.return_max_end = unic->return_max_end;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_TCP_VALID;

	/*
	 * Copy over the vlan rules and set the VLAN_VALID flag
	 */
	nircm->vlan_rule.ingress_vlan_tag = unic->ingress_vlan_tag;
	nircm->vlan_rule.egress_vlan_tag = unic->egress_vlan_tag;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_VALID;

	/*
	 * Copy over the qos rules and set the QOS_VALID flag
	 */
	nircm->qos_rule.qos_tag = unic->qos_tag;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_QOS_VALID;

	/*
	 * Copy over the dscp marking rules and set the DSCP_MARKING_VALID flag.
	 */
	nircm->dscp_rule.dscp_itag = unic->dscp_itag ;
	nircm->dscp_rule.dscp_imask = unic->dscp_imask;
	nircm->dscp_rule.dscp_omask = unic->dscp_omask;
	nircm->dscp_rule.dscp_oval = unic->dscp_oval;
	if (unic->flags & NSS_IPV4_CREATE_FLAG_DSCP_MARKING) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING;
		nircm->valid_flags |= NSS_IPV4_RULE_CREATE_DSCP_MARKING_VALID;
	}

	/*
	 * Copy over the vlan marking rules and set the VLAN_MARKING_VALID flag.
	 */
	nircm->vlan_rule.vlan_imask = unic->vlan_imask;
	nircm->vlan_rule.vlan_itag = unic->vlan_itag;
	nircm->vlan_rule.vlan_omask = unic->vlan_omask ;
	nircm->vlan_rule.vlan_oval = unic->vlan_oval ;
	if (unic->flags & NSS_IPV4_CREATE_FLAG_VLAN_MARKING) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_VLAN_MARKING;
		nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_MARKING_VALID;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_ROUTED) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_ROUTED;
	}

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPv4' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_destroy_ipv4_rule()
 *	Destroy the given connection in the NSS
 */
nss_tx_status_t nss_tx_destroy_ipv4_rule(void *ctx, struct nss_ipv4_destroy *unid)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_ipv4_msg *nim;
	struct nss_ipv4_rule_destroy_msg *nirdm;

	nss_info("%p: Destroy IPv4: %pI4:%d, %pI4:%d, p: %d\n", nss_ctx,
		&unid->src_ip, unid->src_port, &unid->dest_ip, unid->dest_port, unid->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy IPv4' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy IPv4' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nim = (struct nss_ipv4_msg *)skb_put(nbuf, sizeof(struct nss_ipv4_msg));
	nim->cm.interface = NSS_IPV4_RX_INTERFACE;
	nim->cm.version = NSS_HLOS_MESSAGE_VERSION;
	nim->cm.type = NSS_TX_METADATA_TYPE_IPV4_RULE_DESTROY;
	nim->cm.len = sizeof(struct nss_ipv4_rule_destroy_msg);

	nirdm = &nim->msg.rule_destroy;

	nirdm->tuple.protocol = (uint8_t)unid->protocol;
	nirdm->tuple.flow_ip = unid->src_ip;
	nirdm->tuple.flow_ident = (uint32_t)unid->src_port;
	nirdm->tuple.return_ip = unid->dest_ip;
	nirdm->tuple.return_ident = (uint32_t)unid->dest_port;

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
 Rx APIs
 **********************************
 */

/*
 * nss_rx_metadata_ipv4_rule_establish()
 *	Handle the establishment of an IPv4 rule.
 */
static void nss_rx_metadata_ipv4_rule_establish(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_rule_establish *nire)
{
	struct nss_ipv4_cb_params nicp;

	// GGG FIXME THIS SHOULD NOT BE A MEMCPY
	nicp.reason = NSS_IPV4_CB_REASON_ESTABLISH;
	memcpy(&nicp.params, nire, sizeof(struct nss_ipv4_establish));

	/*
	 * Call IPv4 manager callback function
	 */
	if (nss_ctx->nss_top->ipv4_callback) {
		nss_ctx->nss_top->ipv4_callback(&nicp);
	} else {
		nss_info("%p: IPV4 establish message received before connection manager has registered", nss_ctx);
	}
}

/*
 * nss_rx_metadata_ipv4_rule_sync()
 *	Handle the syncing of an IPv4 rule.
 */
static void nss_rx_metadata_ipv4_rule_sync(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_rule_sync *nirs)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_ipv4_cb_params nicp;
	struct net_device *pppoe_dev = NULL;

	nicp.reason = NSS_IPV4_CB_REASON_SYNC;
	nicp.params.sync.index = nirs->index;
	nicp.params.sync.flow_max_window = nirs->flow_max_window;
	nicp.params.sync.flow_end = nirs->flow_end;
	nicp.params.sync.flow_max_end = nirs->flow_max_end;
	nicp.params.sync.flow_rx_packet_count = nirs->flow_rx_packet_count;
	nicp.params.sync.flow_rx_byte_count = nirs->flow_rx_byte_count;
	nicp.params.sync.flow_tx_packet_count = nirs->flow_tx_packet_count;
	nicp.params.sync.flow_tx_byte_count = nirs->flow_tx_byte_count;
	nicp.params.sync.return_max_window = nirs->return_max_window;
	nicp.params.sync.return_end = nirs->return_end;
	nicp.params.sync.return_max_end = nirs->return_max_end;
	nicp.params.sync.return_rx_packet_count = nirs->return_rx_packet_count;
	nicp.params.sync.return_rx_byte_count = nirs->return_rx_byte_count;
	nicp.params.sync.return_tx_packet_count = nirs->return_tx_packet_count;
	nicp.params.sync.return_tx_byte_count = nirs->return_tx_byte_count;

	nicp.params.sync.qos_tag = nirs->qos_tag;

	nicp.params.sync.flags = 0;
	if (nirs->flags & NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK) {
		nicp.params.sync.flags |= NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK;
	}

	if (nirs->flags & NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW) {
		nicp.params.sync.flags |= NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW;
	}

	if (nirs->flags & NSS_IPV4_RULE_CREATE_FLAG_ROUTED) {
		nicp.params.sync.flags |= NSS_IPV4_CREATE_FLAG_ROUTED;
	}

	switch (nirs->reason) {
	case NSS_IPV4_RULE_SYNC_REASON_STATS:
		nicp.params.sync.reason = NSS_IPV4_SYNC_REASON_STATS;
		break;

	case NSS_IPV4_RULE_SYNC_REASON_FLUSH:
		nicp.params.sync.reason = NSS_IPV4_SYNC_REASON_FLUSH;
		break;

	case NSS_IPV4_RULE_SYNC_REASON_EVICT:
		nicp.params.sync.reason = NSS_IPV4_SYNC_REASON_EVICT;
		break;

	case NSS_IPV4_RULE_SYNC_REASON_DESTROY:
		nicp.params.sync.reason = NSS_IPV4_SYNC_REASON_DESTROY;
		break;

	default:
		nss_warning("Bad ipv4 sync reason: %d\n", nirs->reason);
		return;
	}

	/*
	 * Convert ms ticks from the NSS to jiffies.  We know that inc_ticks is small
	 * and we expect HZ to be small too so we can multiply without worrying about
	 * wrap-around problems.  We add a rounding constant to ensure that the different
	 * time bases don't cause truncation errors.
	 */
	nss_assert(HZ <= 100000);
	nicp.params.sync.delta_jiffies = ((nirs->inc_ticks * HZ) + (MSEC_PER_SEC / 2)) / MSEC_PER_SEC;

	/*
	 * Call IPv4 manager callback function
	 */
	if (nss_ctx->nss_top->ipv4_callback) {
		nss_ctx->nss_top->ipv4_callback(&nicp);
	} else {
		nss_info("%p: IPV4 sync message received before connection manager has registered", nss_ctx);
	}

	/*
	 * Update statistics maintained by NSS driver
	 */
	spin_lock_bh(&nss_top->stats_lock);

	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_RX_PKTS] += nirs->flow_rx_packet_count + nirs->return_rx_packet_count;
	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_RX_BYTES] += nirs->flow_rx_byte_count + nirs->return_rx_byte_count;
	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_TX_PKTS] += nirs->flow_tx_packet_count + nirs->return_tx_packet_count;
	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_TX_BYTES] += nirs->flow_tx_byte_count + nirs->return_tx_byte_count;

	/*
	 * Update the PPPoE interface stats, if there is any PPPoE session on the interfaces.
	 */
	if (nirs->flow_pppoe_session_id) {
		pppoe_dev = ppp_session_to_netdev(nirs->flow_pppoe_session_id, (uint8_t *)nirs->flow_pppoe_remote_mac);
		if (pppoe_dev) {
			ppp_update_stats(pppoe_dev, nirs->flow_rx_packet_count, nirs->flow_rx_byte_count,
					nirs->flow_tx_packet_count, nirs->flow_tx_byte_count);
			dev_put(pppoe_dev);
		}
	}

	if (nirs->return_pppoe_session_id) {
		pppoe_dev = ppp_session_to_netdev(nirs->return_pppoe_session_id, (uint8_t *)nirs->return_pppoe_remote_mac);
		if (pppoe_dev) {
			ppp_update_stats(pppoe_dev, nirs->return_rx_packet_count, nirs->return_rx_byte_count,
					nirs->return_tx_packet_count, nirs->return_tx_byte_count);
			dev_put(pppoe_dev);
		}
	}

	/*
	 * TODO: Update per dev accelerated statistics
	 */

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_ipv4_interface_handler()
 *	Handle NSS -> HLOS messages for IPv4 bridge/route
 */
static void nss_rx_ipv4_interface_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_ipv4_msg *nim = (struct nss_ipv4_msg *)ncm;

	/*
	 * Is this a valid request/response packet?
	 */
	if (nim->cm.type >= NSS_METADATA_TYPE_IPV4_MAX) {
		nss_warning("%p: received invalid message %d for IPv4 interface", nss_ctx, nim->cm.type);
		return;
	}

	switch (nim->cm.type) {
	case NSS_RX_METADATA_TYPE_IPV4_RULE_ESTABLISH:
		nss_rx_metadata_ipv4_rule_establish(nss_ctx, &nim->msg.rule_establish);
		break;

	case NSS_RX_METADATA_TYPE_IPV4_RULE_SYNC:
		nss_rx_metadata_ipv4_rule_sync(nss_ctx, &nim->msg.rule_sync);
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
 * nss_register_ipv4_mgr()
 */
void *nss_register_ipv4_mgr(nss_ipv4_callback_t event_callback)
{
	nss_top_main.ipv4_callback = event_callback;
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_unregister_ipv4_mgr()
 */
void nss_unregister_ipv4_mgr(void)
{
	nss_top_main.ipv4_callback = NULL;
}

/*
 * nss_get_ipv4_mgr_ctx()
 */
void *nss_get_ipv4_mgr_ctx(void)
{
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_ipv4_register_handler()
 */
void nss_ipv4_register_handler()
{
	nss_core_register_handler(NSS_IPV4_RX_INTERFACE, nss_rx_ipv4_interface_handler, NULL);
}

EXPORT_SYMBOL(nss_register_ipv4_mgr);
EXPORT_SYMBOL(nss_unregister_ipv4_mgr);
EXPORT_SYMBOL(nss_tx_create_ipv4_rule);
EXPORT_SYMBOL(nss_tx_create_ipv4_rule1);
EXPORT_SYMBOL(nss_tx_destroy_ipv4_rule);
EXPORT_SYMBOL(nss_get_ipv4_mgr_ctx);
