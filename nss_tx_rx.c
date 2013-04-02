/* * Copyright (c) 2013 Qualcomm Atheros, Inc. * */

/*
 * nss_tx_rx.c
 *	NSS Tx and Rx APIs
 */

#include "nss_core.h"
#include <nss_hal.h>
#include <linux/module.h>

/*
 * Global variables/extern declarations
 */
extern struct nss_top_instance nss_top_main;

#if (CONFIG_NSS_DEBUG_LEVEL > 0)
#define NSS_VERIFY_CTX_MAGIC(x) nss_verify_ctx_magic(x)
#define NSS_VERIFY_INIT_DONE(x) nss_verify_init_done(x)

/*
 * nss_verify_ctx_magic()
 */
static inline void nss_verify_ctx_magic(struct nss_ctx_instance *nss_ctx)
{
	nss_assert(nss_ctx->magic == NSS_CTX_MAGIC);
}

static inline void nss_verify_init_done(struct nss_ctx_instance *nss_ctx)
{
	nss_assert(nss_ctx->state == NSS_CORE_STATE_INITIALIZED);
}

#else
#define NSS_VERIFY_CTX_MAGIC(x)
#define NSS_VERIFY_INIT_DONE(x)
#endif

/*
 * nss_rx_metadata_ipv4_rule_establish()
 *	Handle the establishment of an IPv4 rule.
 */
static void nss_rx_metadata_ipv4_rule_establish(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_rule_establish *nire)
{
	struct nss_ipv4_statistics *nis;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	if (unlikely(nire->index >= NSS_IPV4_CONNECTION_ENTRIES)) {
		nss_warning("Bad index: %d\n", nire->index);
		return;
	}

	nis = &nss_top->nss_ipv4_statistics[nire->index];

	spin_lock_bh(&nss_top->stats_lock);
	nis->protocol = nire->protocol;
	nis->flow_interface = nire->flow_interface;
	nis->flow_mtu = nire->flow_mtu;
	nis->flow_ip = nire->flow_ip;
	nis->flow_ip_xlate = nire->flow_ip_xlate;
	nis->flow_ident = nire->flow_ident;
	nis->flow_ident_xlate = nire->flow_ident_xlate;
	nis->flow_accelerated_rx_packets = 0;
	nis->flow_accelerated_rx_bytes = 0;
	nis->flow_accelerated_tx_packets = 0;
	nis->flow_accelerated_tx_bytes = 0;
	nis->flow_pppoe_session_id = nire->flow_pppoe_session_id;
	memcpy(nis->flow_pppoe_remote_mac, nire->flow_pppoe_remote_mac, ETH_ALEN);
	nis->return_interface = nire->return_interface;
	nis->return_mtu = nire->return_mtu;
	nis->return_ip = nire->return_ip;
	nis->return_ip_xlate = nire->return_ip_xlate;
	nis->return_ident = nire->return_ident;
	nis->return_ident_xlate = nire->return_ident_xlate;
	nis->return_pppoe_session_id = nire->return_pppoe_session_id;
	memcpy(nis->return_pppoe_remote_mac, nire->return_pppoe_remote_mac, ETH_ALEN);
	nis->return_accelerated_rx_packets = 0;
	nis->return_accelerated_rx_bytes = 0;
	nis->return_accelerated_tx_packets = 0;
	nis->return_accelerated_tx_bytes = 0;
	nis->last_sync = nss_top->last_rx_jiffies;
	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_metadata_ipv4_rule_sync()
 *	Handle the syncing of an IPv4 rule.
 */
static void nss_rx_metadata_ipv4_rule_sync(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_rule_sync *nirs)
{
	/* Place holder */
}

/*
 * nss_rx_metadata_ipv6_rule_establish()
 *	Handle the establishment of an IPv6 rule.
 */
static void nss_rx_metadata_ipv6_rule_establish(struct nss_ctx_instance *nss_ctx, struct nss_ipv6_rule_establish *nire)
{
	struct nss_ipv6_statistics *nis;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	if (unlikely(nire->index >= NSS_IPV6_CONNECTION_ENTRIES)) {
		nss_warning("%p: Bad connection entry index: %d\n", nss_ctx, nire->index);
		return;
	}

	nis = &nss_top->nss_ipv6_statistics[nire->index];

	spin_lock_bh(&nss_top->stats_lock);
	nis->protocol = nire->protocol;
	nis->flow_interface = nire->flow_interface;
	nis->flow_mtu = nire->flow_mtu;
	nis->flow_ip[0] = nire->flow_ip[0];
	nis->flow_ip[1] = nire->flow_ip[1];
	nis->flow_ip[2] = nire->flow_ip[2];
	nis->flow_ip[3] = nire->flow_ip[3];
	nis->flow_ident = nire->flow_ident;
	nis->flow_pppoe_session_id = nire->flow_pppoe_session_id;
	memcpy(nis->flow_pppoe_remote_mac, nire->flow_pppoe_remote_mac, ETH_ALEN);
	nis->flow_accelerated_rx_packets = 0;
	nis->flow_accelerated_rx_bytes = 0;
	nis->flow_accelerated_tx_packets = 0;
	nis->flow_accelerated_tx_bytes = 0;
	nis->return_interface = nire->return_interface;
	nis->return_mtu = nire->return_mtu;
	nis->return_ip[0] = nire->return_ip[0];
	nis->return_ip[1] = nire->return_ip[1];
	nis->return_ip[2] = nire->return_ip[2];
	nis->return_ip[3] = nire->return_ip[3];
	nis->return_ident = nire->return_ident;
	nis->return_pppoe_session_id = nire->return_pppoe_session_id;
	memcpy(nis->return_pppoe_remote_mac, nire->return_pppoe_remote_mac, ETH_ALEN);
	nis->return_accelerated_rx_packets = 0;
	nis->return_accelerated_rx_bytes = 0;
	nis->return_accelerated_tx_packets = 0;
	nis->return_accelerated_tx_bytes = 0;
	nis->last_sync = nss_top->last_rx_jiffies;
	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_metadata_ipv6_rule_sync()
 *	Handle the syncing of an IPv6 rule.
 */
static void nss_rx_metadata_ipv6_rule_sync(struct nss_ctx_instance *nss_ctx, struct nss_ipv6_rule_sync *nirs)
{
	/* Place holder */
}

/*
 * nss_rx_metadata_gmac_stats_sync()
 *	Handle the syncing of GMAC stats.
 */
static void nss_rx_metadata_gmac_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_gmac_stats_sync *ngss)
{
	void *ctx;
	nss_phys_if_event_callback_t cb;

	if (ngss->interface >= NSS_MAX_PHYSICAL_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, ngss->interface);
		return;
	}

	ctx = nss_ctx->nss_top->phys_if_ctx[ngss->interface];

	/**
	 * We need to ensure that processor/compiler do not re-order ctx
	 * and cb reads. Note that write to ctx and cb happens in
	 * reverse order. The idea is that we do not want a case where
	 * cb is valid but ctx is NULL.
	 */
	rmb();
	cb = nss_ctx->nss_top->phys_if_event_callback[ngss->interface];

	/*
	 * Call GMAC driver callback
	 */
	if (cb) {
		cb(ctx, NSS_GMAC_EVENT_STATS, (void *)ngss, sizeof(struct nss_gmac_stats_sync));
	} else {
		nss_warning("%p: Event received for GMAC interface %d before registration", nss_ctx, ngss->interface);
	}
}

/*
 * nss_rx_metadata_interface_stats_sync()
 *	Handle the syncing of interface statistics.
 */
static void nss_rx_metadata_interface_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_interface_stats_sync *niss)
{
	/* Place holder */
}

/*
 * nss_rx_metadata_na_stats_sync()
 *	Handle the syncing of NSS statistics.
 */
static void nss_rx_metadata_nss_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_nss_stats_sync *nnss)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	spin_lock_bh(&nss_top->stats_lock);
	nss_top->ipv4_connection_create_requests += nnss->ipv4_connection_create_requests;
	nss_top->ipv4_connection_create_collisions += nnss->ipv4_connection_create_collisions;
	nss_top->ipv4_connection_create_invalid_interface += nnss->ipv4_connection_create_invalid_interface;
	nss_top->ipv4_connection_destroy_requests += nnss->ipv4_connection_destroy_requests;
	nss_top->ipv4_connection_destroy_misses += nnss->ipv4_connection_destroy_misses;
	nss_top->ipv4_connection_hash_hits += nnss->ipv4_connection_hash_hits;
	nss_top->ipv4_connection_hash_reorders += nnss->ipv4_connection_hash_reorders;
	nss_top->ipv4_connection_flushes += nnss->ipv4_connection_flushes;
	nss_top->ipv4_connection_evictions += nnss->ipv4_connection_evictions;
	nss_top->ipv6_connection_create_requests += nnss->ipv6_connection_create_requests;
	nss_top->ipv6_connection_create_collisions += nnss->ipv6_connection_create_collisions;
	nss_top->ipv6_connection_create_invalid_interface += nnss->ipv6_connection_create_invalid_interface;
	nss_top->ipv6_connection_destroy_requests += nnss->ipv6_connection_destroy_requests;
	nss_top->ipv6_connection_destroy_misses += nnss->ipv6_connection_destroy_misses;
	nss_top->ipv6_connection_hash_hits += nnss->ipv6_connection_hash_hits;
	nss_top->ipv6_connection_hash_reorders += nnss->ipv6_connection_hash_reorders;
	nss_top->ipv6_connection_flushes += nnss->ipv6_connection_flushes;
	nss_top->ipv6_connection_evictions += nnss->ipv6_connection_evictions;
	nss_top->l2switch_create_requests += nnss->l2switch_create_requests;
	nss_top->l2switch_create_collisions += nnss->l2switch_create_collisions;
	nss_top->l2switch_create_invalid_interface += nnss->l2switch_create_invalid_interface;
	nss_top->l2switch_destroy_requests += nnss->l2switch_destroy_requests;
	nss_top->l2switch_destroy_misses += nnss->l2switch_destroy_misses;
	nss_top->l2switch_hash_hits += nnss->l2switch_hash_hits;
	nss_top->l2switch_hash_reorders += nnss->l2switch_hash_reorders;
	nss_top->l2switch_flushes += nnss->l2switch_flushes;
	nss_top->l2switch_evictions += nnss->l2switch_evictions;
	nss_top->pppoe_session_create_requests += nnss->pppoe_session_create_requests;
	nss_top->pppoe_session_create_failures += nnss->pppoe_session_create_failures;
	nss_top->pppoe_session_destroy_requests += nnss->pppoe_session_destroy_requests;
	nss_top->pppoe_session_destroy_misses += nnss->pppoe_session_destroy_misses;
	nss_top->pe_queue_dropped += nnss->pe_queue_dropped;
	nss_top->pe_total_ticks += nnss->pe_total_ticks;
	if (unlikely(nss_top->pe_worst_case_ticks < nnss->pe_worst_case_ticks)) {
		nss_top->pe_worst_case_ticks = nnss->pe_worst_case_ticks;
	}
	nss_top->pe_iterations += nnss->pe_iterations;

	nss_top->except_queue_dropped += nnss->except_queue_dropped;
	nss_top->except_total_ticks += nnss->except_total_ticks;
	if (unlikely(nss_top->except_worst_case_ticks < nnss->except_worst_case_ticks)) {
		nss_top->except_worst_case_ticks = nnss->except_worst_case_ticks;
	}
	nss_top->except_iterations += nnss->except_iterations;

	nss_top->l2switch_queue_dropped += nnss->l2switch_queue_dropped;
	nss_top->l2switch_total_ticks += nnss->l2switch_total_ticks;
	if (unlikely(nss_top->l2switch_worst_case_ticks < nnss->l2switch_worst_case_ticks)) {
		nss_top->l2switch_worst_case_ticks = nnss->l2switch_worst_case_ticks;
	}
	nss_top->l2switch_iterations += nnss->l2switch_iterations;

	nss_top->pbuf_alloc_fails += nnss->pbuf_alloc_fails;
	nss_top->pbuf_payload_alloc_fails += nnss->pbuf_payload_alloc_fails;
	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_metadata_pppoe_exception_stats_sync()
 *	Handle the syncing of PPPoE exception statistics.
 */
static void nss_rx_metadata_pppoe_exception_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_pppoe_exception_stats_sync *npess)
{
	/* Place holder */
}

/*
 * nss_rx_metadata_profiler_sync()
 *	Handle the syncing of profiler information.
 */
static void nss_rx_metadata_profiler_sync(struct nss_ctx_instance *nss_ctx, struct nss_profiler_sync *profiler_sync)
{
	void *ctx;
	nss_profiler_callback_t cb;

	ctx = nss_ctx->nss_top->profiler_ctx[nss_ctx->id];

	/**
	 * We need to ensure that processor/compiler do not re-order ctx
	 * and cb reads. Note that write to ctx and cb happens in
	 * reverse order. The idea is that we do not want a case where
	 * cb is valid but ctx is NULL.
	 */
	rmb();
	cb = nss_ctx->nss_top->profiler_callback[nss_ctx->id];

	/*
	 * Call profiler callback
	 */
	if (cb) {
		cb(ctx, profiler_sync->buf, profiler_sync->len);
	} else {
		nss_warning("%p: Event received for profiler interface before registration", nss_ctx);
	}
}

/*
 * nss_rx_handle_status_pkt()
 *	Handle the metadata/status packet.
 */
void nss_rx_handle_status_pkt(struct nss_ctx_instance *nss_ctx, struct sk_buff *nbuf)
{
	struct nss_rx_metadata_object *nrmo;

	nrmo = (struct nss_rx_metadata_object *)nbuf->data;
	switch (nrmo->type) {
	case NSS_RX_METADATA_TYPE_IPV4_RULE_ESTABLISH:
		nss_rx_metadata_ipv4_rule_establish(nss_ctx, &nrmo->sub.ipv4_rule_establish);
		break;

	case NSS_RX_METADATA_TYPE_IPV4_RULE_SYNC:
		nss_rx_metadata_ipv4_rule_sync(nss_ctx, &nrmo->sub.ipv4_rule_sync);
		break;

	case NSS_RX_METADATA_TYPE_IPV6_RULE_ESTABLISH:
		nss_rx_metadata_ipv6_rule_establish(nss_ctx, &nrmo->sub.ipv6_rule_establish);
		break;

	case NSS_RX_METADATA_TYPE_IPV6_RULE_SYNC:
		nss_rx_metadata_ipv6_rule_sync(nss_ctx, &nrmo->sub.ipv6_rule_sync);
		break;

	case NSS_RX_METADATA_TYPE_GMAC_STATS_SYNC:
		nss_rx_metadata_gmac_stats_sync(nss_ctx, &nrmo->sub.gmac_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_INTERFACE_STATS_SYNC:
		nss_rx_metadata_interface_stats_sync(nss_ctx, &nrmo->sub.interface_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_NSS_STATS_SYNC:
		nss_rx_metadata_nss_stats_sync(nss_ctx, &nrmo->sub.nss_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_PPPOE_STATS_SYNC:
		nss_rx_metadata_pppoe_exception_stats_sync(nss_ctx, &nrmo->sub.pppoe_exception_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_PROFILER_SYNC:
		nss_rx_metadata_profiler_sync(nss_ctx, &nrmo->sub.profiler_sync);
		break;

	default:
		/*
		 * WARN: Unknown metadata type
		 */
		nss_warning("%p: Unknown NRMO %d received from NSS, nbuf->data=%p", nss_ctx, nrmo->type, nbuf->data);
	}
}

/*
 * nss_rx_handle_crypto_buf()
 *	Create a nss entry to accelerate the given connection
 */
void nss_rx_handle_crypto_buf(struct nss_ctx_instance *nss_ctx, uint32_t buf, uint32_t paddr, uint32_t len)
{
	void *ctx;
	nss_crypto_callback_t cb;

	ctx = nss_ctx->nss_top->crypto_ctx;

	/**
	 * We need to ensure that processor/compiler do not re-order ctx
	 * and cb reads. Note that write to ctx and cb happens in
	 * reverse order. The idea is that we do not want a case where
	 * cb is valid but ctx is NULL.
	 */
	rmb();
	cb = nss_ctx->nss_top->crypto_callback;

	/*
	 * We do not know what to do with this buffer if crypto driver has not
	 * registered with us
	 */
	nss_assert(nss_ctx->nss_top->crypto_callback != NULL);

	if (likely(cb)) {
		cb(ctx, (void *)buf, paddr, len);
	}
}

/*
 * nss_tx_create_ipv4_rule()
 *	Create a nss entry to accelerate the given connection
 */
nss_tx_status_t nss_tx_create_ipv4_rule(void *ctx, struct nss_ipv4_create *unic)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipv4_rule_create *nirc;

	nss_info("%p: Create IPv4: %pI4:%d (%pI4:%d), %pI4:%d (%pI4:%d), p: %d\n", nss_ctx,
		&unic->src_ip, unic->src_port, &unic->src_ip_xlate, unic->src_port_xlate,
		&unic->dest_ip, unic->dest_port, &unic->dest_ip_xlate, unic->dest_port_xlate, unic->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPv4' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPv4' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV4_RULE_CREATE;

	nirc = &ntmo->sub.ipv4_rule_create;
	nirc->protocol = (uint8_t)unic->protocol;

	nirc->flow_pppoe_session_id = unic->flow_pppoe_session_id;
	memcpy(nirc->flow_pppoe_remote_mac, unic->flow_pppoe_remote_mac, ETH_ALEN);
	nirc->flow_interface_num = unic->src_interface_num;
	nirc->flow_ip = unic->src_ip;
	nirc->flow_ip_xlate = unic->src_ip_xlate;
	nirc->flow_ident = (uint32_t)unic->src_port;
	nirc->flow_ident_xlate = (uint32_t)unic->src_port_xlate;
	nirc->flow_window_scale = unic->flow_window_scale;
	nirc->flow_max_window = unic->flow_max_window;
	nirc->flow_end = unic->flow_end;
	nirc->flow_max_end = unic->flow_max_end;
	nirc->flow_mtu = unic->from_mtu;
	memcpy(nirc->flow_mac, unic->src_mac, 6);

	nirc->return_pppoe_session_id = unic->return_pppoe_session_id;
	memcpy(nirc->return_pppoe_remote_mac, unic->return_pppoe_remote_mac, ETH_ALEN);
	nirc->return_interface_num = unic->dest_interface_num;
	nirc->return_ip = unic->dest_ip;
	nirc->return_ip_xlate = unic->dest_ip_xlate;
	nirc->return_ident = (uint32_t)unic->dest_port;
	nirc->return_ident_xlate = (uint32_t)unic->dest_port_xlate;
	nirc->return_window_scale = unic->return_window_scale;
	nirc->return_max_window = unic->return_max_window;
	nirc->return_end = unic->return_end;
	nirc->return_max_end = unic->return_max_end;
	nirc->return_mtu = unic->to_mtu;
	if (nirc->return_ip != nirc->return_ip_xlate || nirc->return_ident != nirc->return_ident_xlate) {
		memcpy(nirc->return_mac, unic->dest_mac_xlate, 6);
	} else {
		memcpy(nirc->return_mac, unic->dest_mac, 6);
	}

	nirc->flags = 0;
	if (unic->flags & NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK;
	}

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPv4' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

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
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipv4_rule_destroy *nird;

	nss_info("%p: Destroy IPv4: %pI4:%d, %pI4:%d, p: %d\n", nss_ctx,
		&unid->src_ip, unid->src_port, &unid->dest_ip, unid->dest_port, unid->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy IPv4' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy IPv4' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV4_RULE_DESTROY;

	nird = &ntmo->sub.ipv4_rule_destroy;
	nird->protocol = (uint8_t)unid->protocol;
	nird->flow_ip = unid->src_ip;
	nird->flow_ident = (uint32_t)unid->src_port;
	nird->return_ip = unid->dest_ip;
	nird->return_ident = (uint32_t)unid->dest_port;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy IPv4' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_create_ipv6_rule()
 *	Create a NSS entry to accelerate the given connection
 */
nss_tx_status_t nss_tx_create_ipv6_rule(void *ctx, struct nss_ipv6_create *unic)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipv6_rule_create *nirc;

	nss_info("%p: Create IPv6: %pI6:%d, %pI6:%d, p: %d\n", nss_ctx,
		unic->src_ip, unic->src_port, unic->dest_ip, unic->dest_port, unic->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPv6' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf =  __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPv6' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV6_RULE_CREATE;

	nirc = &ntmo->sub.ipv6_rule_create;
	nirc->protocol = (uint8_t)unic->protocol;

	nirc->flow_pppoe_session_id = unic->flow_pppoe_session_id;
	memcpy(nirc->flow_pppoe_remote_mac, unic->flow_pppoe_remote_mac, ETH_ALEN);
	nirc->flow_interface_num = unic->src_interface_num;
	nirc->flow_ip[0] = unic->src_ip[0];
	nirc->flow_ip[1] = unic->src_ip[1];
	nirc->flow_ip[2] = unic->src_ip[2];
	nirc->flow_ip[3] = unic->src_ip[3];
	nirc->flow_ident = (uint32_t)unic->src_port;
	nirc->flow_window_scale = unic->flow_window_scale;
	nirc->flow_max_window = unic->flow_max_window;
	nirc->flow_end = unic->flow_end;
	nirc->flow_max_end = unic->flow_max_end;
	nirc->flow_mtu = unic->from_mtu;
	memcpy(nirc->flow_mac, unic->src_mac, 6);

	nirc->return_pppoe_session_id = unic->return_pppoe_session_id;
	memcpy(nirc->return_pppoe_remote_mac, unic->return_pppoe_remote_mac, ETH_ALEN);
	nirc->return_interface_num = unic->dest_interface_num;
	nirc->return_ip[0] = unic->dest_ip[0];
	nirc->return_ip[1] = unic->dest_ip[1];
	nirc->return_ip[2] = unic->dest_ip[2];
	nirc->return_ip[3] = unic->dest_ip[3];
	nirc->return_ident = (uint32_t)unic->dest_port;
	nirc->return_window_scale = unic->return_window_scale;
	nirc->return_max_window = unic->return_max_window;
	nirc->return_end = unic->return_end;
	nirc->return_max_end = unic->return_max_end;
	nirc->return_mtu = unic->to_mtu;
	memcpy(nirc->return_mac, unic->dest_mac, 6);

	nirc->flags = 0;
	if (unic->flags & NSS_IPV6_CREATE_FLAG_NO_SEQ_CHECK) {
		nirc->flags |= NSS_IPV6_RULE_CREATE_FLAG_NO_SEQ_CHECK;
	}

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPv6' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_destroy_ipv6_rule()
 *	Destroy the given connection in the NSS
 */
nss_tx_status_t nss_tx_destroy_ipv6_rule(void *ctx, struct nss_ipv6_destroy *unid)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipv6_rule_destroy *nird;

	nss_info("%p: Destroy IPv6: %pI6:%d, %pI6:%d, p: %d\n", nss_ctx,
		unid->src_ip, unid->src_port, unid->dest_ip, unid->dest_port, unid->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy IPv6' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf =  __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy IPv6' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV6_RULE_DESTROY;

	nird = &ntmo->sub.ipv6_rule_destroy;
	nird->protocol = (uint8_t)unid->protocol;
	nird->flow_ip[0] = unid->src_ip[0];
	nird->flow_ip[1] = unid->src_ip[1];
	nird->flow_ip[2] = unid->src_ip[2];
	nird->flow_ip[3] = unid->src_ip[3];
	nird->flow_ident = (uint32_t)unid->src_port;
	nird->return_ip[0] = unid->dest_ip[0];
	nird->return_ip[1] = unid->dest_ip[1];
	nird->return_ip[2] = unid->dest_ip[2];
	nird->return_ip[3] = unid->dest_ip[3];
	nird->return_ident = (uint32_t)unid->dest_port;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy IPv6' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_create_l2switch_rule()
 *	Create a NSS entry to accelerate the given connection
 */
nss_tx_status_t nss_tx_create_l2switch_rule(void *ctx, struct nss_l2switch_create *unlc)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_l2switch_rule_create *nlrc;

	nss_info("%p: Create L2switch rule, addr=%p\n", nss_ctx, unlc->addr);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create L2switch' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create L2switch' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_L2SWITCH_RULE_CREATE;

	nlrc = &ntmo->sub.l2switch_rule_create;
	nlrc->addr[0] = unlc->addr[0];
	nlrc->addr[1] = unlc->addr[1];
	nlrc->addr[2] = unlc->addr[2];
	nlrc->interface_num = unlc->interface_num;
	nlrc->state = unlc->state;
	nlrc->priority =  unlc->priority;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create L2switch' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_destroy_l2switch_rule()
 *	Destroy the given connection in the NSS
 */
nss_tx_status_t nss_tx_destroy_l2switch_rule(void *ctx, struct nss_l2switch_destroy *unld)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_l2switch_rule_destroy *nlrd;

	nss_info("%p: L2switch destroy rule, addr=%p\n", nss_ctx, unld->addr);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy L2switch' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy L2switch' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_L2SWITCH_RULE_DESTROY;

	nlrd = &ntmo->sub.l2switch_rule_destroy;
	nlrd->mac_addr[0] = unld->addr[0];
	nlrd->mac_addr[1] = unld->addr[1];
	nlrd->mac_addr[2] = unld->addr[2];
	nlrd->interface_num = unld->interface_num;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy L2switch'\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_destroy_all_l2switch_rules
 *	Destroy all L2 switch rules in NSS.
 */
nss_tx_status_t nss_tx_destroy_all_l2switch_rules(void *ctx)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;

	nss_info("%p: L2switch destroy all rules", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy all L2switch' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy all L2switch' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_DESTROY_ALL_L2SWITCH_RULES;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy all L2switch' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_create_ipsec_tx_rule
 *	Create ipsec_tx rule in NSS.
 */
nss_tx_status_t nss_tx_create_ipsec_tx_rule(void *ctx, struct nss_ipsec_tx_create *nitc)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipsec_tx_rule_create *nitrc;

	nss_info("%p: Create IPsec Tx rule\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPsec Tx' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPsec Tx' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPSEC_TX_RULE_CREATE;

	nitrc = &ntmo->sub.ipsec_tx_rule_create;
	nitrc->spi = nitc->spi;
	nitrc->replay = nitc->replay;
	nitrc->src_addr = nitc->src_addr;
	nitrc->dest_addr = nitc->dest_addr;
	nitrc->ses_idx = nitc->ses_idx;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPsec Tx' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_destroy_ipsec_tx_rule
 *	Destroy ipsec_tx rule in NSS.
 */
nss_tx_status_t nss_tx_destroy_ipsec_tx_rule(void *ctx, struct nss_ipsec_tx_destroy *nitd)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipsec_tx_rule_destroy *nitrd;

	nss_info("%p: Destroy IPsec Tx rule\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy IPsec Tx' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy IPsec Tx' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPSEC_TX_RULE_DESTROY;

	nitrd = &ntmo->sub.ipsec_tx_rule_destroy;
	nitrd->ses_idx = nitd->ses_idx;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy IPsec Tx' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_create_ipsec_rx_rule
 *	Create ipsec_rx rule in NSS.
 */
nss_tx_status_t nss_tx_create_ipsec_rx_rule(void *ctx, struct nss_ipsec_rx_create *nirc)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipsec_rx_rule_create *nirrc;

	nss_info("%p: Create IPsec Rx rule\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPsec Rx' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPsec Rx' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPSEC_RX_RULE_CREATE;

	nirrc = &ntmo->sub.ipsec_rx_rule_create;
	nirrc->spi = nirc->spi;
	nirrc->replay = nirc->replay;
	nirrc->src_addr = nirc->src_addr;
	nirrc->dest_addr = nirc->dest_addr;
	nirrc->ses_idx = nirc->ses_idx;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPsec Rx' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_destroy_ipsec_rx_rule
 *	Destroy ipsec_rx rule in NSS
 */
nss_tx_status_t nss_tx_destroy_ipsec_rx_rule(void *ctx, struct nss_ipsec_rx_destroy *nird)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipsec_rx_rule_destroy *nirrd;

	nss_info("%p: Destroy IPsec Rx rule\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy IPsec Rx' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy IPsec Rx' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPSEC_RX_RULE_DESTROY;

	nirrd = &ntmo->sub.ipsec_rx_rule_destroy;
	nirrd->ses_idx = nird->ses_idx;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy IPsec Rx' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

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
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_open *nio;

	nss_info("%p: Phys If Open, id:%d, TxDesc: %x, RxDesc: %x\n", nss_ctx, if_num, tx_desc_ring, rx_desc_ring);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Open' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Open' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_INTERFACE_OPEN;

	nio = &ntmo->sub.if_open;
	nio->interface_num = if_num;
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
	return NSS_TX_SUCCESS;
}

/*
 * nss_phys_if_close()
 *	Send close command to physical interface
 */
nss_tx_status_t nss_tx_phys_if_close(void *ctx, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_close *nic;

	nss_info("%p: Phys If Close, id:%d \n", nss_ctx, if_num);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Close' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Close' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_INTERFACE_CLOSE;

	nic = &ntmo->sub.if_close;
	nic->interface_num = if_num;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: Unable to enqueue 'Phys If Close' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
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
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_link_state_notify *nils;

	nss_info("%p: Phys If Link State, id:%d, State: %x\n", nss_ctx, if_num, link_state);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Link State' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Link State' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_INTERFACE_LINK_STATE_NOTIFY;

	nils = &ntmo->sub.if_link_state_notify;
	nils->interface_num = if_num;
	nils->state = link_state;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Link State' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
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
	struct nss_tx_metadata_object *ntmo;
	struct nss_mac_address_set *nmas;

	nss_info("%p: Phys If MAC Address, id:%d\n", nss_ctx, if_num);
	nss_assert(addr != NULL);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If MAC Address' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If MAC Address' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_MAC_ADDR_SET;

	nmas = &ntmo->sub.mac_address_set;
	nmas->interface_num = if_num;
	memcpy(nmas->mac_addr, addr, ETH_ALEN);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Mac Address' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
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
	int32_t status;
	struct nss_tx_metadata_object *ntmo;

	nss_info("%p: Phys If Change MTU, id:%d, mtu=%d\n", nss_ctx, if_num, mtu);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Change MTU' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_DESTROY_ALL_L3_RULES;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Change MTU' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_crypto_if_open()
 *	NSS crypto open API. Opens a crypto session.
 */
nss_tx_status_t nss_tx_crypto_if_open(void *ctx, uint8_t *buf, uint32_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_crypto_open *nco;

	nss_info("%p: Crypto If Open: buf: %p, len: %d\n", nss_ctx, buf, len);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Crypto If Open' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Crypto If Open' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_CRYPTO_OPEN;

	nco = &ntmo->sub.crypto_open;
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
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_crypto_if_close()
 *	NSS crypto if close API. Closes a crypto session.
 */
nss_tx_status_t nss_tx_crypto_if_close(void *ctx, uint32_t eng)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_crypto_close *ncc;

	nss_info("%p: Crypto If Close:%d\n", nss_ctx, eng);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Crypto If Close' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Crypto If Close' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_CRYPTO_CLOSE;

	ncc = &ntmo->sub.crypto_close;
	ncc->eng = eng;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Crypto If Close' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
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
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_profiler_if_buf()
 *	NSS profiler Tx API
 */
nss_tx_status_t nss_tx_profiler_if_buf(void *ctx, uint8_t *buf, uint32_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_profiler_tx *npt;

	nss_trace("%p: Profiler If Tx, buf=%p", nss_ctx, buf);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Profiler If Tx' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Profiler If Tx' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_PROFILER_TX;

	npt = &ntmo->sub.profiler_tx;
	npt->len = len;
	memcpy(npt->buf, buf, len);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Profiler If Tx' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_get_interface_number()
 *	Return the interface number of the NSS net_device.
 *
 * Returns -1 on failure or the interface number of dev is an NSS net_device.
 */
int32_t nss_get_interface_number(void *ctx, void *dev)
{
	int i;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: Interface number could not be found as core not ready", nss_ctx);
		return -1;
	}

	nss_assert(dev != NULL);
	for (i = 0; i < NSS_MAX_NET_INTERFACES; i++) {
		if (dev == ((struct nss_ctx_instance *)nss_ctx)->nss_top->phys_if_ctx[i]) {
			return i;
		}
	}

	/*
	 * TODO: Take care of virtual interfaces
	 */

	nss_warning("%p: Interface number could not be found as interface has not registered yet", nss_ctx);
	return -1;
}

/*
 * nss_get_state()
 *	return the NSS initialization state
 */
nss_state_t nss_get_state(void *ctx)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	nss_state_t state = NSS_STATE_UNINITIALIZED;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	spin_lock_bh(&nss_top_main.lock);
	if (nss_ctx->state == NSS_CORE_STATE_INITIALIZED) {
		state = NSS_STATE_INITIALIZED;
	}
	spin_unlock_bh(&nss_top_main.lock);

	return state;
}

/*
 * nss_register_ipv4_mgr()
 */
void *nss_register_ipv4_mgr(nss_ipv4_sync_callback_t event_callback)
{
	nss_top_main.ipv4_sync = event_callback;
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_unregister_ipv4_mgr()
 */
void nss_unregister_ipv4_mgr(void)
{
	nss_top_main.ipv4_sync = NULL;
}

/*
 * nss_register_ipv6_mgr()
 *	Called to register an IPv6 connection manager with this driver
 */
void *nss_register_ipv6_mgr(nss_ipv6_sync_callback_t event_callback)
{
	nss_top_main.ipv6_sync = event_callback;
	return (void *)&nss_top_main.nss[nss_top_main.ipv6_handler_id];
}

/*
 * nss_unregister_ipv6_mgr()
 *	Called to unregister an IPv6 connection manager
 */
void nss_unregister_ipv6_mgr(void)
{
	nss_top_main.ipv6_sync = NULL;
}

/*
 * nss_register_l2switch_mgr()
 */
void *nss_register_l2switch_mgr(nss_l2switch_sync_callback_t event_callback)
{
	nss_top_main.l2switch_sync = event_callback;
	return (void *)&nss_top_main.nss[nss_top_main.l2switch_handler_id];
}

/*
 * nss_unregister_l2switch_mgr()
 */
void nss_unregister_l2switch_mgr(void)
{
	nss_top_main.l2switch_sync = NULL;
}

/*
 * nss_register_connection_expire_all()
 */
void nss_register_connection_expire_all(nss_connection_expire_all_callback_t event_callback)
{
	nss_top_main.conn_expire = event_callback;
}

/*
 * nss_unregister_connection_expire_all()
 */
void nss_unregister_connection_expire_all(void)
{
	nss_top_main.conn_expire = NULL;
}

/*
 * nss_register_queue_decongestion()
 *	Register for queue decongestion event
 */
nss_cb_register_status_t nss_register_queue_decongestion(void *ctx, nss_queue_decongestion_callback_t event_callback, void *app_ctx)
{
	uint32_t i;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	spin_lock_bh(&nss_ctx->decongest_cb_lock);

	/*
	 * Find vacant location in callback table
	 */
	for (i = 0; i< NSS_MAX_CLIENTS; i++) {
		if (nss_ctx->queue_decongestion_callback[i] == NULL) {
			nss_ctx->queue_decongestion_callback[i] = event_callback;
			nss_ctx->queue_decongestion_ctx[i] = app_ctx;
			spin_unlock_bh(&nss_ctx->decongest_cb_lock);
			return NSS_CB_REGISTER_SUCCESS;
		}
	}

	spin_unlock_bh(&nss_ctx->decongest_cb_lock);
	return NSS_CB_REGISTER_FAILED;
}

/*
 * nss_unregister_queue_decongestion()
 *	Unregister for queue decongestion event
 */
nss_cb_unregister_status_t nss_unregister_queue_decongestion(void *ctx, nss_queue_decongestion_callback_t event_callback)
{
	uint32_t i;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	spin_lock_bh(&nss_ctx->decongest_cb_lock);

	/*
	 * Find actual location in callback table
	 */
	for (i = 0; i< NSS_MAX_CLIENTS; i++) {
		if (nss_ctx->queue_decongestion_callback[i] == event_callback) {
			nss_ctx->queue_decongestion_callback[i] = NULL;
			nss_ctx->queue_decongestion_ctx[i] = NULL;
			spin_unlock_bh(&nss_ctx->decongest_cb_lock);
			return NSS_CB_UNREGISTER_SUCCESS;
		}
	}

	spin_unlock_bh(&nss_ctx->decongest_cb_lock);
	return NSS_CB_UNREGISTER_FAILED;
}

/*
 * nss_register_crypto_mgr()
 */
void *nss_register_crypto_if(nss_crypto_callback_t crypto_callback, void *ctx)
{
	nss_top_main.crypto_ctx = ctx;

	/**
	 * We need to ensure that processor/compiler do not re-order ctx
	 * and cb writes
	 */
	wmb();
	nss_top_main.crypto_callback = crypto_callback;

	return (void *)&nss_top_main.nss[nss_top_main.crypto_handler_id];
}

/*
 * nss_unregister_crypto_mgr()
 */
void nss_unregister_crypto_if(void)
{
	nss_top_main.crypto_callback = NULL;

	/**
	 * We need to ensure that processor/compiler do not re-order ctx
	 * and cb writes
	 */
	wmb();
	nss_top_main.crypto_ctx = NULL;
}

/*
 * nss_register_phys_if()
 */
void *nss_register_phys_if(uint32_t if_num,
				nss_phys_if_rx_callback_t rx_callback,
				nss_phys_if_event_callback_t event_callback, void *if_ctx)
{
	uint8_t id = nss_top_main.phys_if_handler_id[if_num];

	nss_assert(if_num <= NSS_MAX_PHYSICAL_INTERFACES);

	nss_top_main.phys_if_ctx[if_num] = if_ctx;

	/**
	 * We need to ensure that processor/compiler do not re-order ctx
	 * and cb writes
	 */
	wmb();
	nss_top_main.phys_if_rx_callback[if_num] = rx_callback;
	nss_top_main.phys_if_event_callback[if_num] = event_callback;

	return (void *)&nss_top_main.nss[id];
}

/*
 * nss_unregister_phys_if()
 */
void nss_unregister_phys_if(uint32_t if_num)
{
	nss_assert(if_num <= NSS_MAX_PHYSICAL_INTERFACES);

	nss_top_main.phys_if_rx_callback[if_num] = NULL;
	nss_top_main.phys_if_event_callback[if_num] = NULL;

	/**
	 * We need to ensure that processor/compiler do not re-order ctx
	 * and cb writes
	 */
	wmb();
	nss_top_main.phys_if_ctx[if_num] = NULL;
}

/*
 * nss_register_ipsec_if()
 */
void *nss_register_ipsec_if(nss_ipsec_callback_t crypto_callback, void *ctx)
{
	return (void *)&nss_top_main.nss[nss_top_main.ipsec_handler_id];
}

/*
 * nss_unregister_ipsec_if()
 */
void nss_unregister_ipsec_if(void)
{
	/*
	 * Place holder for now
	 */
}

/*
 * nss_register_profiler_if()
 */
void *nss_register_profiler_if(nss_profiler_callback_t profiler_callback, nss_core_id_t core_id, void *ctx)
{
	nss_assert(core_id < NSS_CORE_MAX);

	nss_top_main.profiler_ctx[core_id] = ctx;

	/**
	 * We need to ensure that processor/compiler do not re-order ctx
	 * and cb writes
	 */
	wmb();
	nss_top_main.profiler_callback[core_id] = profiler_callback;

	return (void *)&nss_top_main.nss[core_id];
}

/*
 * nss_unregister_profiler_if()
 */
void nss_unregister_profiler_if(nss_core_id_t core_id)
{
	nss_assert(core_id < NSS_CORE_MAX);

	nss_top_main.profiler_callback[core_id] = NULL;

	/**
	 * We need to ensure that processor/compiler do not re-order ctx
	 * and cb writes
	 */
	wmb();
	nss_top_main.profiler_ctx[core_id] = NULL;
}

EXPORT_SYMBOL(nss_get_interface_number);
EXPORT_SYMBOL(nss_get_state);

EXPORT_SYMBOL(nss_register_connection_expire_all);
EXPORT_SYMBOL(nss_unregister_connection_expire_all);

EXPORT_SYMBOL(nss_register_queue_decongestion);
EXPORT_SYMBOL(nss_unregister_queue_decongestion);

EXPORT_SYMBOL(nss_register_ipv4_mgr);
EXPORT_SYMBOL(nss_unregister_ipv4_mgr);
EXPORT_SYMBOL(nss_tx_create_ipv4_rule);
EXPORT_SYMBOL(nss_tx_destroy_ipv4_rule);

EXPORT_SYMBOL(nss_register_ipv6_mgr);
EXPORT_SYMBOL(nss_unregister_ipv6_mgr);
EXPORT_SYMBOL(nss_tx_create_ipv6_rule);
EXPORT_SYMBOL(nss_tx_destroy_ipv6_rule);

EXPORT_SYMBOL(nss_register_l2switch_mgr);
EXPORT_SYMBOL(nss_unregister_l2switch_mgr);
EXPORT_SYMBOL(nss_tx_create_l2switch_rule);
EXPORT_SYMBOL(nss_tx_destroy_l2switch_rule);
EXPORT_SYMBOL(nss_tx_destroy_all_l2switch_rules);

EXPORT_SYMBOL(nss_register_crypto_if);
EXPORT_SYMBOL(nss_unregister_crypto_if);
EXPORT_SYMBOL(nss_tx_crypto_if_buf);
EXPORT_SYMBOL(nss_tx_crypto_if_open);
EXPORT_SYMBOL(nss_tx_crypto_if_close);

EXPORT_SYMBOL(nss_register_phys_if);
EXPORT_SYMBOL(nss_unregister_phys_if);
EXPORT_SYMBOL(nss_tx_phys_if_buf);
EXPORT_SYMBOL(nss_tx_phys_if_open);
EXPORT_SYMBOL(nss_tx_phys_if_close);
EXPORT_SYMBOL(nss_tx_phys_if_link_state);
EXPORT_SYMBOL(nss_tx_phys_if_change_mtu);
EXPORT_SYMBOL(nss_tx_phys_if_mac_addr);

EXPORT_SYMBOL(nss_register_ipsec_if);
EXPORT_SYMBOL(nss_unregister_ipsec_if);
EXPORT_SYMBOL(nss_tx_create_ipsec_tx_rule);
EXPORT_SYMBOL(nss_tx_destroy_ipsec_tx_rule);
EXPORT_SYMBOL(nss_tx_create_ipsec_rx_rule);
EXPORT_SYMBOL(nss_tx_destroy_ipsec_rx_rule);

EXPORT_SYMBOL(nss_register_profiler_if);
EXPORT_SYMBOL(nss_unregister_profiler_if);
EXPORT_SYMBOL(nss_tx_profiler_if_buf);
