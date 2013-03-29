/* * Copyright (c) 2013 Qualcomm Atheros, Inc. * */

/**
 * nss_tx_rx.c
 *	NSS Tx and Rx APIs
 */

#include "nss_core.h"
#include <nss_hal.h>
#include <linux/module.h>

/**
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

	if (unlikely(nire->index >= IPV4_CONNECTION_ENTRIES)) {
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

	if (unlikely(nire->index >= IPV6_CONNECTION_ENTRIES)) {
		nss_warning("Bad index: %d\n", nire->index);
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
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	if (ngss->interface >= NSS_MAX_PHYSICAL_INTERFACES) {
		nss_info("%p: Callback received for invalid interface %d", nss_ctx, ngss->interface);
		return;
	}

	spin_lock_bh(&nss_top->phys_if_lock[ngss->interface]);
	if (nss_top->phys_if_event_callback[ngss->interface]) {
		nss_top->phys_if_event_callback[ngss->interface](nss_top->phys_if_ctx[ngss->interface],
				NSS_GMAC_EVENT_STATS, (void *)ngss, sizeof(struct nss_gmac_stats_sync));
	} else {
		nss_warning("%p: Event received for GMAC interface %d before registration", nss_ctx, ngss->interface);
	}
	spin_unlock_bh(&nss_top->phys_if_lock[ngss->interface]);
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
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	spin_lock_bh(&nss_top->profiler_lock[nss_ctx->id]);
	if (nss_top->profiler_callback[nss_ctx->id]) {
		nss_top->profiler_callback[nss_ctx->id](nss_top->profiler_ctx[nss_ctx->id], profiler_sync->buf, profiler_sync->len);
	} else {
		nss_warning("%p: Event received for profiler interface before registration", nss_ctx);
	}
	spin_unlock_bh(&nss_top->profiler_lock[nss_ctx->id]);
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
		 * WARN:
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
	if (likely(nss_ctx->nss_top->crypto_callback)) {
		nss_ctx->nss_top->crypto_callback(nss_ctx->nss_top->crypto_ctx, (void *)buf, paddr, len);
	} else {
		nss_assert(0);
	}
}

/*
 * nss_create_ipv4_rule()
 *	Create a nss entry to accelerate the given connection
 */
nss_tx_status_t nss_create_ipv4_rule(void *ctx, struct nss_ipv4_create *unic)
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
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'IPv4 rule create' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_destroy_ipv4_rule()
 *	Destroy the given connection in the NSS
 */
nss_tx_status_t nss_destroy_ipv4_rule(void *ctx, struct nss_ipv4_destroy *unid)
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
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf =  __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'IPv4 rule destroy' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_create_ipv6_rule()
 *	Create a NSS entry to accelerate the given connection
 */
nss_tx_status_t nss_create_ipv6_rule(void *ctx, struct nss_ipv6_create *unic)
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
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf =  __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'IPv6 rule create' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_destroy_ipv6_rule()
 *	Destroy the given connection in the NSS
 */
nss_tx_status_t nss_destroy_ipv6_rule(void *ctx, struct nss_ipv6_destroy *unid)
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
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf =  __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'IPv6 rule destroy' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_create_l2switch_rule()
 *	Create a NSS entry to accelerate the given connection
 */
nss_tx_status_t nss_create_l2switch_rule(void *ctx, struct nss_l2switch_create *unlc)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_l2switch_rule_create *nlrc;

	nss_info("%p: L2switch create rule, addr=%p\n", nss_ctx, unlc->addr);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'L2switch create rule' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_destroy_l2switch_rule()
 *	Destroy the given connection in the NSS
 */
nss_tx_status_t nss_destroy_l2switch_rule(void *ctx, struct nss_l2switch_destroy *unld)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_l2switch_rule_destroy *nlrd;

	nss_info("%p: L2switch destroy rule, addr=%p\n", nss_ctx, unld->addr);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'L2switch destroy rule' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_destroy_all_l2switch_rules
 *	Destroy all L2 switch rules in NSS.
 */
nss_tx_status_t nss_destroy_all_l2switch_rules(void *ctx)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;

	nss_info("%p: L2switch destroy all rules", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_DESTROY_ALL_L2SWITCH_RULES;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: Unable to enqueue 'L2switch destroy all rules' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_create_ipsec_tx_rule
 *	Create ipsec tx rule in NSS.
 */
nss_tx_status_t nss_create_ipsec_tx_rule(void *ctx, struct nss_ipsec_tx_create *nitc)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipsec_tx_rule_create *nitrc;

	nss_info("%p: IPsec Tx Rule Create\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_warning("%p: Unable to enqueue 'IPsec tx create rule' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_destroy_ipsec_tx_rule
 *	Destroy ipsec tx rule in NSS.
 */
nss_tx_status_t nss_destroy_ipsec_tx_rule(void *ctx, struct nss_ipsec_tx_destroy *nitd)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipsec_tx_rule_destroy *nitrd;

	nss_info("%p: IPsec Tx Rule Destroy\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPSEC_TX_RULE_DESTROY;

	nitrd = &ntmo->sub.ipsec_tx_rule_destroy;
	nitrd->ses_idx = nitd->ses_idx;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'IPsec tx destroy rule' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_create_ipsec_rx_rule
 *	Create ipsec rx rule in NSS.
 */
nss_tx_status_t nss_create_ipsec_rx_rule(void *ctx, struct nss_ipsec_rx_create *nirc)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipsec_rx_rule_create *nirrc;

	nss_info("%p: IPsec Rx Rule Create\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_warning("%p: Unable to enqueue 'IPsec rx create rule' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_destroy_ipsec_rx_rule
 *	Destroy ipsec rx rule in NSS
 */
nss_tx_status_t nss_destroy_ipsec_rx_rule(void *ctx, struct nss_ipsec_rx_destroy *nird)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipsec_rx_rule_destroy *nirrd;

	nss_info("%p: IPsec Rx Rule Destroy\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPSEC_RX_RULE_DESTROY;

	nirrd = &ntmo->sub.ipsec_rx_rule_destroy;
	nirrd->ses_idx = nird->ses_idx;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'IPsec Rx destroy rule' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_phys_if_tx()
 *	Send packet to physical interface owned by NSS
 */
nss_tx_status_t nss_phys_if_tx(void *ctx, struct sk_buff *os_buf, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	int32_t status;

	nss_trace("%p: Received Tx network packet from physical interface driver, data=%p", nss_ctx, os_buf->data);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	status = nss_core_send_buffer(nss_ctx, if_num, os_buf, NSS_IF_DATA_QUEUE, H2N_BUFFER_PACKET, 0);
	if (unlikely(status != NSS_CORE_STATUS_SUCCESS)) {
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
 * nss_phys_if_open()
 *	Open a physical interface
 */
nss_tx_status_t nss_phys_if_open(void *ctx, uint32_t tx_desc_ring, uint32_t rx_desc_ring, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_open *nio;

	nss_info("%p: Open if:%d TxDesc: %x, RxDesc: %x\n", nss_ctx, if_num, tx_desc_ring, rx_desc_ring);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'if open' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_phys_if_close()
 *	Open a physical interface
 */
nss_tx_status_t nss_phys_if_close(void *ctx, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_close *nic;

	nss_info("%p: Close if:%d \n", nss_ctx, if_num);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_INTERFACE_CLOSE;

	nic = &ntmo->sub.if_close;
	nic->interface_num = if_num;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: Unable to enqueue 'if close' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_phys_if_link_state()
 *	Open a physical interface
 */
nss_tx_status_t nss_phys_if_link_state(void *ctx, uint32_t link_state, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_link_state_notify *nils;

	nss_info("%p: Link State if:%d State: %x\n", nss_ctx, if_num, link_state);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'if link state' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_phys_if_mac_addr()
 *	Send a MAC address
 */
nss_tx_status_t nss_phys_if_mac_addr(void *ctx, uint8_t *addr, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_mac_address_set *nmas;

	nss_info("%p: MAC address if:%d\n", nss_ctx, if_num);
	nss_assert(addr != NULL);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'mac address' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_phys_if_mac_addr()
 *	Send a MAC address
 */
nss_tx_status_t nss_phys_if_change_mtu(void *ctx, uint32_t mtu, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;

	nss_info("%p: Change MTU if:%d, mtu=%d\n", nss_ctx, if_num, mtu);

	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_DESTROY_ALL_L3_RULES;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: Unable to enqueue 'mac address' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_crypto_if_open()
 *	NSS crypto open API
 */
nss_tx_status_t nss_crypto_if_open(void *ctx, uint8_t *buf, uint32_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_crypto_open *nco;

	nss_info("%p: Crypto open: buf: %p, len: %d\n", nss_ctx, buf, len);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'crypto if open' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_crypto_if_close()
 *	NSS crypto if close API
 */
nss_tx_status_t nss_crypto_if_close(void *ctx, uint32_t eng)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_crypto_close *ncc;

	nss_info("%p: Crypto close:%d\n", nss_ctx, eng);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
        if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_CRYPTO_CLOSE;

	ncc = &ntmo->sub.crypto_close;
	ncc->eng = eng;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: Unable to enqueue 'crypto if close' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_crypto_if_tx()
 *	NSS crypto Tx API
 */
nss_tx_status_t nss_crypto_if_tx(void *ctx, void *buf, uint32_t buf_paddr, uint16_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	int32_t status;

	nss_trace("%p: Received crypto packet from crypto driver, buf=%p", nss_ctx, buf);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	status = nss_core_send_crypto(nss_ctx, buf, buf_paddr, len);
	if (unlikely(status != NSS_CORE_STATUS_SUCCESS)) {
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
 * nss_profiler_if_tx()
 *	NSS profiler Tx API
 */
nss_tx_status_t nss_profiler_if_tx(void *ctx, uint8_t *buf, uint16_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_profiler_tx *npt;

	nss_trace("%p: Received profiler command packet, buf=%p", nss_ctx, buf);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
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
		nss_info("%p: Unable to enqueue 'profiler tx' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	return NSS_TX_SUCCESS;
}

/*
 * nss_interface_number_get()
 *	Return the interface number of the NSS net_device.
 *
 * Returns -1 on failure or the interface number of dev is an NSS net_device.
 */
int32_t nss_interface_number_get(void *ctx, void *dev)
{
	int i;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nss_assert(dev != NULL);
	for (i = 0; i < NSS_MAX_NET_INTERFACES; i++) {
		spin_lock_bh(&(nss_ctx->nss_top->phys_if_lock[i]));
		if (dev == ((struct nss_ctx_instance *)nss_ctx)->nss_top->phys_if_ctx[i]) {
			spin_unlock_bh(&(nss_ctx->nss_top->phys_if_lock[i]));
			return i;
		}
		spin_unlock_bh(&(nss_ctx->nss_top->phys_if_lock[i]));
	}

	/*
	 * TODO: Take care of virtual interfaces
	 */

	return -1;
}

/*
 * nss_state_get()
 *	return the NSS initialization state
 */
nss_state_t nss_state_get(void *ctx)
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
	spin_lock_bh(&nss_top_main.cm_lock);
	nss_top_main.ipv4_sync = event_callback;
	spin_unlock_bh(&nss_top_main.cm_lock);
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_unregister_ipv4_mgr()
 */
void nss_unregister_ipv4_mgr(void)
{
	spin_lock_bh(&nss_top_main.cm_lock);
	nss_top_main.ipv4_sync = NULL;
	spin_unlock_bh(&nss_top_main.cm_lock);
}

/*
 * nss_register_ipv6_mgr()
 *	Called to register an IPv6 connection manager with this driver
 */
void *nss_register_ipv6_mgr(nss_ipv6_sync_callback_t event_callback)
{
	spin_lock_bh(&nss_top_main.cm_lock);
	nss_top_main.ipv6_sync = event_callback;
	spin_unlock_bh(&nss_top_main.cm_lock);
	return (void *)&nss_top_main.nss[nss_top_main.ipv6_handler_id];
}

/*
 * nss_unregister_ipv6_mgr()
 *	Called to unregister an IPv6 connection manager
 */
void nss_unregister_ipv6_mgr(void)
{
	spin_lock_bh(&nss_top_main.cm_lock);
	nss_top_main.ipv6_sync = NULL;
	spin_unlock_bh(&nss_top_main.cm_lock);
}

/*
 * nss_register_l2switch_mgr()
 */
void *nss_register_l2switch_mgr(nss_l2switch_sync_callback_t event_callback)
{
	spin_lock_bh(&nss_top_main.cm_lock);
	nss_top_main.l2switch_sync = event_callback;
	spin_unlock_bh(&nss_top_main.cm_lock);
	return (void *)&nss_top_main.nss[nss_top_main.l2switch_handler_id];
}

/*
 * nss_unregister_l2switch_mgr()
 */
void nss_unregister_l2switch_mgr(void)
{
	spin_lock_bh(&nss_top_main.cm_lock);
	nss_top_main.l2switch_sync = NULL;
	spin_unlock_bh(&nss_top_main.cm_lock);
}

/*
 * nss_connection_expire_all_register()
 */
void nss_connection_expire_all_register(nss_connection_expire_all_callback_t event_callback)
{
	spin_lock_bh(&nss_top_main.cm_lock);
	nss_top_main.conn_expire = event_callback;
	spin_unlock_bh(&nss_top_main.cm_lock);
}

/*
 * nss_connection_expire_all_unregister()
 */
void nss_connection_expire_all_unregister(void)
{
	spin_lock_bh(&nss_top_main.cm_lock);
	nss_top_main.conn_expire = NULL;
	spin_unlock_bh(&nss_top_main.cm_lock);
}

/*
 * nss_register_crypto_mgr()
 */
void *nss_register_crypto_if(nss_crypto_callback_t crypto_callback, void *ctx)
{
	spin_lock_bh(&nss_top_main.crypto_lock);
	nss_top_main.crypto_callback = crypto_callback;
	nss_top_main.crypto_ctx = ctx;
	spin_unlock_bh(&nss_top_main.crypto_lock);
	return (void *)&nss_top_main.nss[nss_top_main.crypto_handler_id];
}

/*
 * nss_unregister_crypto_mgr()
 */
void nss_unregister_crypto_if(void)
{
	spin_lock_bh(&nss_top_main.crypto_lock);
	nss_top_main.crypto_callback = NULL;
	nss_top_main.crypto_ctx = NULL;
	spin_unlock_bh(&nss_top_main.crypto_lock);
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

	spin_lock_bh(&nss_top_main.phys_if_lock[if_num]);
	nss_top_main.phys_if_rx_callback[if_num] = rx_callback;
	nss_top_main.phys_if_event_callback[if_num] = event_callback;
	nss_top_main.phys_if_ctx[if_num] = if_ctx;
	spin_unlock_bh(&nss_top_main.phys_if_lock[if_num]);
	return (void *)&nss_top_main.nss[id];
}

/*
 * nss_unregister_phys_if()
 */
void nss_unregister_phys_if(uint32_t if_num)
{
	nss_assert(if_num <= NSS_MAX_PHYSICAL_INTERFACES);

	spin_lock_bh(&nss_top_main.phys_if_lock[if_num]);
	nss_top_main.phys_if_rx_callback[if_num] = NULL;
	nss_top_main.phys_if_event_callback[if_num] = NULL;
	nss_top_main.phys_if_ctx[if_num] = NULL;
	spin_unlock_bh(&nss_top_main.phys_if_lock[if_num]);
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

void *nss_register_profiler_if(nss_profiler_callback_t profiler_callback, nss_core_id_t core_id, void *ctx)
{
	nss_assert(core_id < NSS_CORE_MAX);

	spin_lock_bh(&nss_top_main.profiler_lock[core_id]);
	nss_top_main.profiler_callback[core_id] = profiler_callback;
	nss_top_main.profiler_ctx[core_id] = ctx;
	spin_unlock_bh(&nss_top_main.profiler_lock[core_id]);
	return (void *)&nss_top_main.nss[core_id];
}

void nss_unregister_profiler_if(nss_core_id_t core_id)
{
	nss_assert(core_id < NSS_CORE_MAX);

	spin_lock_bh(&nss_top_main.profiler_lock[core_id]);
	nss_top_main.profiler_callback[core_id] = NULL;
	nss_top_main.profiler_ctx[core_id] = NULL;
	spin_unlock_bh(&nss_top_main.profiler_lock[core_id]);
}

nss_tx_status_t nss_profiler_send(void *ctx, uint8_t *buf, uint32_t len);

EXPORT_SYMBOL(nss_interface_number_get);
EXPORT_SYMBOL(nss_state_get);
EXPORT_SYMBOL(nss_connection_expire_all_register);
EXPORT_SYMBOL(nss_connection_expire_all_unregister);

EXPORT_SYMBOL(nss_register_ipv4_mgr);
EXPORT_SYMBOL(nss_unregister_ipv4_mgr);
EXPORT_SYMBOL(nss_create_ipv4_rule);
EXPORT_SYMBOL(nss_destroy_ipv4_rule);

EXPORT_SYMBOL(nss_register_ipv6_mgr);
EXPORT_SYMBOL(nss_unregister_ipv6_mgr);
EXPORT_SYMBOL(nss_create_ipv6_rule);
EXPORT_SYMBOL(nss_destroy_ipv6_rule);

EXPORT_SYMBOL(nss_register_l2switch_mgr);
EXPORT_SYMBOL(nss_unregister_l2switch_mgr);
EXPORT_SYMBOL(nss_create_l2switch_rule);
EXPORT_SYMBOL(nss_destroy_l2switch_rule);
EXPORT_SYMBOL(nss_destroy_all_l2switch_rules);

EXPORT_SYMBOL(nss_register_crypto_if);
EXPORT_SYMBOL(nss_unregister_crypto_if);
EXPORT_SYMBOL(nss_crypto_if_tx);
EXPORT_SYMBOL(nss_crypto_if_open);
EXPORT_SYMBOL(nss_crypto_if_close);

EXPORT_SYMBOL(nss_register_phys_if);
EXPORT_SYMBOL(nss_unregister_phys_if);
EXPORT_SYMBOL(nss_phys_if_tx);
EXPORT_SYMBOL(nss_phys_if_open);
EXPORT_SYMBOL(nss_phys_if_close);
EXPORT_SYMBOL(nss_phys_if_link_state);

EXPORT_SYMBOL(nss_register_ipsec_if);
EXPORT_SYMBOL(nss_unregister_ipsec_if);
EXPORT_SYMBOL(nss_create_ipsec_tx_rule);
EXPORT_SYMBOL(nss_destroy_ipsec_tx_rule);
EXPORT_SYMBOL(nss_create_ipsec_rx_rule);
EXPORT_SYMBOL(nss_destroy_ipsec_rx_rule);

EXPORT_SYMBOL(nss_register_profiler_if);
EXPORT_SYMBOL(nss_unregister_profiler_if);
EXPORT_SYMBOL(nss_profiler_if_tx);
