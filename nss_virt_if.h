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
enum nss_virtual_if_metadata_types {
	NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_CREATE,
	NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_DESTROY,
	NSS_METADATA_TYPE_VIRTUAL_INTERFACE_MAX,
};

/**
 * The NSS virtual interface creation structure.
 */
struct nss_virtual_if_create {
	uint32_t flags;			/**> Interface flags */
	uint8_t mac_addr[ETH_ALEN];	/**> MAC address */
};

/**
 * The NSS virtual interface destruction structure.
 */
struct nss_virtual_if_destroy {
	int32_t reserved;		/**> place holder */
};

/**
 * Message structure to send/receive virtual interface commands
 */
struct nss_virtual_if_msg {
	struct nss_cmn_msg cm;				/**> Message Header */
	union {
		struct nss_virtual_if_create create;	/**> Message: create virt if rule */
		struct nss_virtual_if_destroy destroy;	/**> Message: destroy virt if rule */
	} msg;
};

/**
 * @brief Create virtual interface (VAPs)
 *
 * @param if_ctx Interface context
 *		(struct net_device * in Linux)
 *
 * @return int32_t Interface number
 */
extern int32_t nss_virt_if_create(struct net_device *if_ctx);

/**
 * @brief Destroy virtual interface (VAPs)
 *
 * @param if_num Interface number (provided during registration)
 *
 * @return None
 */
extern nss_tx_status_t nss_virt_if_destroy(int32_t if_num);

/**
 * @brief Forward Native wifi packet from virtual interface
 *    -Expects packet with qca-nwifi format
 * @param if_num Interface number (provided during
 *      	 registeration)
 * @param skb HLOS data buffer (sk_buff in Linux)
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_virt_if_nwifi_rxbuf(int32_t if_num, struct sk_buff *skb);

/**
 * @brief Forward virtual interface packets
 *
 * @param if_num Interface number (provided during
 *      	 registeration)
 * @param skb HLOS data buffer (sk_buff in Linux)
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_virt_if_eth_rxbuf(int32_t if_num, struct sk_buff *skb);

#endif /* __NSS_VIRT_IF_H */
