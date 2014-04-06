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
	NSS_IF_STATS_SYNC,
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
 * The NSS MAC address structure.
 */
struct nss_if_mac_address_set {
	uint8_t mac_addr[ETH_ALEN];	/* MAC address */
};

/*
 * The NSS per-GMAC statistics sync structure.
 */
struct nss_if_stats_sync {
	uint32_t rx_bytes;		/* Number of RX bytes */
	uint32_t rx_packets;		/* Number of RX packets */
	uint32_t rx_errors;		/* Number of RX errors */
	uint32_t rx_receive_errors;	/* Number of RX receive errors */
	uint32_t rx_overflow_errors;	/* Number of RX overflow errors */
	uint32_t rx_descriptor_errors;	/* Number of RX descriptor errors */
	uint32_t rx_watchdog_timeout_errors;
					/* Number of RX watchdog timeout errors */
	uint32_t rx_crc_errors;		/* Number of RX CRC errors */
	uint32_t rx_late_collision_errors;
					/* Number of RX late collision errors */
	uint32_t rx_dribble_bit_errors;	/* Number of RX dribble bit errors */
	uint32_t rx_length_errors;	/* Number of RX length errors */
	uint32_t rx_ip_header_errors;	/* Number of RX IP header errors */
	uint32_t rx_ip_payload_errors;	/* Number of RX IP payload errors */
	uint32_t rx_no_buffer_errors;	/* Number of RX no-buffer errors */
	uint32_t rx_transport_csum_bypassed;
					/* Number of RX packets where the transport checksum was bypassed */
	uint32_t tx_bytes;		/* Number of TX bytes */
	uint32_t tx_packets;		/* Number of TX packets */
	uint32_t tx_collisions;		/* Number of TX collisions */
	uint32_t tx_errors;		/* Number of TX errors */
	uint32_t tx_jabber_timeout_errors;
					/* Number of TX jabber timeout errors */
	uint32_t tx_frame_flushed_errors;
					/* Number of TX frame flushed errors */
	uint32_t tx_loss_of_carrier_errors;
					/* Number of TX loss of carrier errors */
	uint32_t tx_no_carrier_errors;	/* Number of TX no carrier errors */
	uint32_t tx_late_collision_errors;
					/* Number of TX late collision errors */
	uint32_t tx_excessive_collision_errors;
					/* Number of TX excessive collision errors */
	uint32_t tx_excessive_deferral_errors;
					/* Number of TX excessive deferral errors */
	uint32_t tx_underflow_errors;	/* Number of TX underflow errors */
	uint32_t tx_ip_header_errors;	/* Number of TX IP header errors */
	uint32_t tx_ip_payload_errors;	/* Number of TX IP payload errors */
	uint32_t tx_dropped;		/* Number of TX dropped packets */
	uint32_t hw_errs[10];		/* GMAC DMA error counters */
	uint32_t rx_missed;		/* Number of RX packets missed by the DMA */
	uint32_t fifo_overflows;	/* Number of RX FIFO overflows signalled by the DMA */
	uint32_t rx_scatter_errors;	/* Number of scattered frames received by the DMA */
	uint32_t gmac_total_ticks;	/* Total clock ticks spend inside the GMAC */
	uint32_t gmac_worst_case_ticks;	/* Worst case iteration of the GMAC in ticks */
	uint32_t gmac_iterations;	/* Number of iterations around the GMAC */
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
	struct nss_if_stats_sync stats_sync;	/* Message: statistics sync */
};

#endif /*  __NSS_IF_H */
