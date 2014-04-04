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
 * nss_virt_if
 *	Virtual interface message Structure and APIs
 */

#ifndef __NSS_VIRT_IF_H
#define __NSS_VIRT_IF_H

/*
 * Virtual IF/Redirect
 */

/**
 * @brief Request/Response types
 */
enum nss_virt_if_metadata_types {
	NSS_VIRT_IF_TX_CREATE_MSG,
	NSS_VIRT_IF_TX_DESTROY_MSG,
	NSS_VIRT_IF_MAX_MSG_TYPES,
};

/**
 * The NSS virtual interface creation structure.
 */
struct nss_virt_if_create {
	uint32_t flags;			/**> Interface flags */
	uint8_t mac_addr[ETH_ALEN];	/**> MAC address */
};

/**
 * The NSS virtual interface destruction structure.
 */
struct nss_virt_if_destroy {
	int32_t reserved;		/**> place holder */
};

/**
 * Message structure to send/receive virtual interface commands
 */
struct nss_virt_if_msg {
	struct nss_cmn_msg cm;				/**> Message Header */
	union {
		struct nss_virt_if_create create;	/**> Message: create virt if rule */
		struct nss_virt_if_destroy destroy;	/**> Message: destroy virt if rule */
	} msg;
};

/**
 * @brief Assign dynamic interface number to a virtual interface
 *
 * @param if_ctx Interface context
 *
 * @return int32_t Interface number
 */
extern int32_t nss_virt_if_assign_if_num(struct net_device *if_ctx);

/**
 * @brief Send message to virtual interface
 *
 * @param nvim Virtual interface message
 *
 * @return command Tx status
 */
extern nss_tx_status_t nss_virt_if_tx_msg(struct nss_virt_if_msg *nvim);

/**
 * @brief Forward Native wifi packet from virtual interface
 *    -Expects packet with qca-nwifi format
 * @param if_num Interface number (provided during
 *      	 registeration)
 * @param skb HLOS data buffer (sk_buff in Linux)
 * @return command Tx status
 */
extern nss_tx_status_t nss_virt_if_tx_nwifi_rxbuf(int32_t if_num, struct sk_buff *skb);

/**
 * @brief Forward virtual interface packets
 *
 * @param if_num Interface number (provided during
 *      	 registeration)
 * @param skb HLOS data buffer (sk_buff in Linux)
 *
 * @return command Tx status
 */
extern nss_tx_status_t nss_virt_if_tx_eth_rxbuf(int32_t if_num, struct sk_buff *skb);

#endif /* __NSS_VIRT_IF_H */
