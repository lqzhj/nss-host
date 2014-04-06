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
 * NSS Interface Messages
 */

#ifndef __NSS_IF_H
#define __NSS_IF_H

/*
 * Message numbers
 */
enum nss_if_message_types {
	NSS_IF_OPEN,
	NSS_IF_CLOSE,
	NSS_IF_LINK_STATE_NOTIFY,
	NSS_IF_MTU_CHANGE,
	NSS_IF_MAC_ADDR_SET,
	NSS_IF_STATS,
	NSS_IF_ISHAPER_ASSIGN,
	NSS_IF_BSHAPER_ASSIGN,
	NSS_IF_ISHAPER_UNASSIGN,
	NSS_IF_BSHAPER_UNASSIGN,
	NSS_IF_ISHAPER_CONFIG,
	NSS_IF_BSHAPER_CONFIG,
	NSS_IF_MAX_MSG_TYPES = 9999,
};

enum nss_if_error_types {
	NSS_IF_ERROR_NO_ISHAPERS,
	NSS_IF_ERROR_NO_BSHAPERS,
	NSS_IF_ERROR_NO_ISHAPER,
	NSS_IF_ERROR_NO_BSHAPER,
	NSS_IF_ERROR_ISHAPER_OLD,
	NSS_IF_ERROR_B_SHAPER_OLD,
	NSS_IF_ERROR_I_SHAPER_CONFIG_FAILED,
	NSS_IF_ERROR_B_SHAPER_CONFIG_FAILED,
	NSS_IF_ERROR_TYPE_UNKNOWN,
	NSS_IF_ERROR_TYPE_EOPEN,
};

/*
 * Interface open command
 */
struct nss_if_open {
	uint32_t tx_desc_ring;		/* Tx descriptor ring address */
	uint32_t rx_desc_ring;		/* Rx descriptor ring address */
};

/*
 * Interface close command
 */
struct nss_if_close {
	uint32_t reserved;		/* Place holder */
};

/*
 * Link state notification to NSS
 */
struct nss_if_link_state_notify {
	uint32_t state;			/* Link State (UP/DOWN), speed/duplex settings */
};

/*
 * Interface mtu change
 */
struct nss_if_mtu_change {
	uint16_t min_buf_size;		/* Changed min buf size value */
};

/*
 * Interface statistics.
 */
struct nss_if_stats {
	uint32_t rx_packets;		/* Number of packets received */
	uint32_t rx_bytes;		/* Number of bytes received */
	uint32_t rx_dropped;		/* Number of RX dropped packets */
	uint32_t tx_packets;		/* Number of packets transmitted */
	uint32_t tx_bytes;		/* Number of bytes transmitted */
};

/*
 * The NSS MAC address structure.
 */
struct nss_if_mac_address_set {
	uint8_t mac_addr[ETH_ALEN];	/* MAC address */
};


/*
 * Message structure to send/receive phys i/f commands
 */
union nss_if_msgs {
	struct nss_if_link_state_notify link_state_notify;	/* Message: notify link status */
	struct nss_if_open open;	/* Message: open interface */
	struct nss_if_close close;	/* Message: close interface */
	struct nss_if_mtu_change mtu_change;	/* Message: MTU change notification */
	struct nss_if_mac_address_set mac_address_set;	/* Message: set MAC address for i/f */
	struct nss_if_stats stats;	/* Message: statistics sync */
};

#endif /*  __NSS_IF_H */
