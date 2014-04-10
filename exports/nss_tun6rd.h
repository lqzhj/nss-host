/*
 *  **************************************************************************
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * *************************************************************************
 */

 /*
  * nss_tun6rd.h
  * 	NSS TO HLOS interface definitions.
  */

#ifndef __NSS_TUN6RD_H
#define __NSS_TUN6RD_H

/*
 * 6RD (IPv6 in IPv4) tunnel messages
 */

/**
 * Request/Response types
 */
enum nss_tun6rd_metadata_types {
	NSS_TUN6RD_TX_IF_CREATE,
	NSS_TUN6RD_TX_IF_DESTROY,
	NSS_TUN6RD_RX_STATS_SYNC,
	NSS_TUN6RD_MAX,
};

/**
 * 6rd configuration command structure
 */
struct nss_tun6rd_create_msg {
	uint32_t prefix[4];	/* 6rd prefix */
	uint32_t relay_prefix;	/* Relay prefix */
	uint16_t prefixlen;	/* 6rd prefix len */
	uint16_t relay_prefixlen;/* Relay prefix length*/
	uint32_t saddr;		/* Tunnel source address */
	uint32_t daddr;		/* Tunnel destination addresss */
	uint8_t  tos;		/* Tunnel tos field */
	uint8_t  ttl;		/* Tunnel ttl field */
	uint16_t reserved;	/* Reserved field */
};

/**
 * 6rd tunnel interface down command structure
 */
struct nss_tun6rd_destroy_msg {
	uint32_t prefix[4];	/* Place holder */
};

/**
 * The NSS tun6rd statistics sync structure.
 */
struct nss_tun6rd_stats_sync_msg {
	struct nss_cmn_node_stats node_stats;
};

/**
 * Message structure to send/receive 6rd commands
 */
struct nss_tun6rd_msg {
	struct nss_cmn_msg cm;		/* Message Header */
	union {
		struct nss_tun6rd_create_msg tun6rd_create;		/* Message: Create 6rd tunnel */
		struct nss_tun6rd_destroy_msg tun6rd_destroy;	/* Message: Destroy 6rd tunnel */
		struct nss_tun6rd_stats_sync_msg stats_sync;	/* Message: interface stats sync */
	} msg;
};

/**
 * Callback to receive tun6rd messages
 */
typedef void (*nss_tun6rd_msg_callback_t)(void *app_data, struct nss_tun6rd_msg *msg);

/**
 *  API to send tun6rd messages
 **/
extern nss_tx_status_t nss_tun6rd_tx(struct nss_ctx_instance *nss_ctx, struct nss_tun6rd_msg *msg);

/**
 * Callback to receive 6rd callback
 */
typedef void (*nss_tun6rd_callback_t)(void *app_data, void *os_buf);

/**
 * @brief Register to send/receive 6rd tunnel messages to NSS
 *
 * @param tun6rd_callback Callback
 * @param ctx 6rd tunnel context
 *
 * @return void* NSS context
 */
extern struct nss_ctx_instance *nss_register_tun6rd_if(uint32_t if_num, nss_tun6rd_callback_t tun6rd_callback,
							nss_tun6rd_msg_callback_t msg_callback, struct net_device *netdev);

/**
 * @brief Unregister 6rd tunnel interface with NSS
 */
extern void nss_unregister_tun6rd_if(uint32_t if_num);

#endif /* __NSS_TUN6RD_H */
