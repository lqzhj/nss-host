/*
 **************************************************************************
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
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
 * nss_phys_if
 *	Physical interface message structure
 */

#ifndef __NSS_PHYS_IF_H
#define __NSS_PHYS_IF_H

/*
 * Physical IF
 */

/**
 * @brief Request/Response types
 */
enum nss_phys_if_msg_types {
	NSS_PHYS_IF_OPEN = NSS_IF_OPEN,
	NSS_PHYS_IF_CLOSE = NSS_IF_CLOSE,
	NSS_PHYS_IF_LINK_STATE_NOTIFY = NSS_IF_LINK_STATE_NOTIFY,
	NSS_PHYS_IF_MTU_CHANGE = NSS_IF_MTU_CHANGE,
	NSS_PHYS_IF_MAC_ADDR_SET = NSS_IF_MAC_ADDR_SET,
	NSS_PHYS_IF_RESERVED = NSS_IF_RESERVED,
	NSS_PHYS_IF_STATS_SYNC = NSS_IF_STATS_SYNC,
	NSS_PHYS_IF_ISHAPER_ASSIGN = NSS_IF_ISHAPER_ASSIGN,
	NSS_PHYS_IF_BSHAPER_ASSIGN = NSS_IF_BSHAPER_ASSIGN,
	NSS_PHYS_IF_ISHAPER_UNASSIGN = NSS_IF_ISHAPER_UNASSIGN,
	NSS_PHYS_IF_BSHAPER_UNASSIGN = NSS_IF_BSHAPER_UNASSIGN,
	NSS_PHYS_IF_ISHAPER_CONFIG = NSS_IF_ISHAPER_CONFIG,
	NSS_PHYS_IF_BSHAPER_CONFIG = NSS_IF_BSHAPER_CONFIG,
	NSS_PHYS_IF_MAX_MSG_TYPES
};

/**
 * Message structure to send/receive virtual interface commands
 */
struct nss_phys_if_msg {
	struct nss_cmn_msg cm;	/**> Message Header */
	union {
		union nss_if_msgs if_msg;	/**> Interfaces messages */
	} msg;
};


/**
 * Callback to receive physical interface messages
 */
typedef void (*nss_phys_if_msg_callback_t)(void *app_data, struct nss_phys_if_msg *msg);

/**
 * TODO: Adjust to pass app_data as unknown to the list layer and netdev/sk as known.
 */
typedef void (*nss_phys_if_rx_callback_t)(void *app_data, void *os_buf);

/**
 * @brief Get NAPI context
 *
 * @param nss_ctx NSS context
 * @param napi_ctx Pointer to address to return NAPI context
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_phys_if_get_napi_ctx(struct nss_ctx_instance *nss_ctx, struct napi_struct **napi_ctx);

/**
 * @brief Register to send/receive GMAC packets/messages
 *
 * @param if_num GMAC i/f number
 * @param rx_callback Receive callback for packets
 * @param event_callback Receive callback for events
 * @param if_ctx Interface context provided in callback
 *		(must be OS network device context pointer e.g.
 *		struct net_device * in Linux)
 *
 * @return void* NSS context
 */
extern struct nss_ctx_instance *nss_phys_if_register(uint32_t if_num,
					nss_phys_if_rx_callback_t rx_callback,
					nss_phys_if_msg_callback_t msg_callback,
					struct net_device *if_ctx);

/**
 * @brief Send GMAC packet
 *
 * @param nss_ctx NSS context
 * @param os_buf OS buffer (e.g. skbuff)
 * @param if_num GMAC i/f number
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_phys_if_tx_buf(struct nss_ctx_instance *nss_ctx, struct sk_buff *os_buf, uint32_t if_num);

/**
 * @brief Assign dynamic interface number to a virtual interface
 *
 * @param if_ctx Interface context
 *
 * @return int32_t Interface number
 */
extern int32_t nss_phys_if_assign_if_num(struct net_device *if_ctx);

/**
 * @brief Send message to virtual interface
 *
 * @param nvim Virtual interface message
 *
 * @return command Tx status
 */
nss_tx_status_t nss_phys_if_tx_msg(struct nss_ctx_instance *nss_ctx, struct nss_phys_if_msg *nvim);

/**
 * @brief Forward Native wifi packet from virtual interface
 *	-Expects packet with qca-nwifi format
 * @param if_num Interface number (provided during
 *	 registeration)
 * @param skb HLOS data buffer (sk_buff in Linux)
 * @return command Tx status
 */
extern nss_tx_status_t nss_phys_if_tx_nwifi_rxbuf(int32_t if_num, struct sk_buff *skb);

/**
 * @brief Forward virtual interface packets
 *
 * @param if_num Interface number (provided during
 *	 registeration)
 * @param skb HLOS data buffer (sk_buff in Linux)
 *
 * @return command Tx status
 */
extern nss_tx_status_t nss_phys_if_tx_eth_rxbuf(int32_t if_num, struct sk_buff *skb);

#endif /* __NSS_PHYS_IF_H */
