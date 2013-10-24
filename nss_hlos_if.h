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
 * nss_hlos_if.h
 *	NSS to HLOS interface definitions.
 */

#ifndef __NSS_HLOS_IF_H
#define __NSS_HLOS_IF_H

/*
 * LRO modes
 */
enum nss_lro_modes {
	NSS_LRO_MODE_DISABLED, /* Indicates that LRO is not enabled on either direction of this connection */
	NSS_LRO_MODE_ORIG, /* Indicates that LRO is enabled on original direction of this connection */
	NSS_LRO_MODE_REPLY /* Indicates that LRO is enabled on reply direction of this connection */
};

/*
 * NA IPv4 rule creation flags.
 */
#define NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK 0x01
					/* Do not perform sequence number checks */
#define NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW 0x02
					/* This is a pure bridge forwarding flow */

/*
 * The NSS IPv4 rule creation structure.
 */
struct nss_ipv4_rule_create {
	uint8_t protocol;			/* Protocol number */
	int32_t flow_interface_num;		/* Flow interface number */
	uint32_t flow_ip;			/* Flow IP address */
	uint32_t flow_ip_xlate;			/* Translated flow IP address */
	uint32_t flow_ident;			/* Flow ident (e.g. port) */
	uint32_t flow_ident_xlate;		/* Translated flow ident (e.g. port) */
	uint16_t flow_mac[3];			/* Flow MAC address */
	uint8_t flow_window_scale;		/* Flow direction's window scaling factor */
	uint32_t flow_max_window;		/* Flow direction's largest seen window */
	uint32_t flow_end;			/* Flow direction's largest seen sequence + segment length */
	uint32_t flow_max_end;			/* Flow direction's largest seen ack + max(1, win) */
	uint32_t flow_mtu;			/* Flow interface`s MTU */
	uint16_t flow_pppoe_session_id;		/* PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];	/* PPPoE Server MAC address */
	uint16_t ingress_vlan_tag;		/* Ingress VLAN tag expected for this flow */
	int32_t return_interface_num;		/* Return interface number */
	uint32_t return_ip;			/* Return IP address */
	uint32_t return_ip_xlate;		/* Translated return IP address */
	uint32_t return_ident;			/* Return ident (e.g. port) */
	uint32_t return_ident_xlate;		/* Translated return ident (e.g. port) */
	uint16_t return_mac[3];			/* Return MAC address */
	uint8_t return_window_scale;		/* Return direction's window scaling factor */
	uint32_t return_max_window;		/* Return direction's largest seen window */
	uint32_t return_end;			/* Return direction's largest seen sequence + segment length */
	uint32_t return_max_end;		/* Return direction's largest seen ack + max(1, win) */
	uint32_t return_mtu;			/* Return interface`s MTU */
	uint16_t return_pppoe_session_id;	/* PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];	/* PPPoE Server MAC address */
	uint16_t egress_vlan_tag;		/* Egress VLAN tag expected for this flow */
	uint8_t flags;				/* Bit flags associated with the rule */
	enum nss_lro_modes lro_mode;	/* LRO mode for this connection */
};

/*
 * The NA IPv4 rule destruction structure.
 */
struct nss_ipv4_rule_destroy {
	uint8_t protocol;		/* Protocol number */
	uint32_t flow_ip;		/* Flow IP address */
	uint32_t flow_ident;		/* Flow ident (e.g. port) */
	uint32_t return_ip;		/* Return IP address */
	uint32_t return_ident;		/* Return ident (e.g. port) */
};

/*
 * NSS IPv6 rule creation flags.
 */
#define NSS_IPV6_RULE_CREATE_FLAG_NO_SEQ_CHECK 0x01
					/* Do not perform sequence number checks */
#define NSS_IPV6_RULE_CREATE_FLAG_BRIDGE_FLOW 0x02
					/* This is a pure bridge forwarding flow */

/*
 * The NSS IPv6 rule creation structure.
 */
struct nss_ipv6_rule_create {
	uint8_t protocol;			/* Protocol number */
	int32_t flow_interface_num;		/* Flow interface number */
	uint32_t flow_ip[4];			/* Flow IP address */
	uint32_t flow_ident;			/* Flow ident (e.g. port) */
	uint16_t flow_mac[3];			/* Flow MAC address */
	uint8_t flow_window_scale;		/* Flow direction's window scaling factor */
	uint32_t flow_max_window;		/* Flow direction's largest seen window */
	uint32_t flow_end;			/* Flow direction's largest seen sequence + segment length */
	uint32_t flow_max_end;			/* Flow direction's largest seen ack + max(1, win) */
	uint32_t flow_mtu;			/* Flow interface`s MTU */
	uint16_t flow_pppoe_session_id;		/* PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];	/* PPPoE Server MAC address */
	uint16_t ingress_vlan_tag;		/* Ingress VLAN tag expected for this flow */
	int32_t return_interface_num;		/* Return interface number */
	uint32_t return_ip[4];			/* Return IP address */
	uint32_t return_ident;			/* Return ident (e.g. port) */
	uint16_t return_mac[3];			/* Return MAC address */
	uint8_t return_window_scale;		/* Return direction's window scaling factor */
	uint32_t return_max_window;		/* Return direction's largest seen window */
	uint32_t return_end;			/* Return direction's largest seen sequence + segment length */
	uint32_t return_max_end;		/* Return direction's largest seen ack + max(1, win) */
	uint32_t return_mtu;			/* Return interface`s MTU */
	uint16_t return_pppoe_session_id;	/* PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];	/* PPPoE Server MAC address */
	uint16_t egress_vlan_tag;		/* Egress VLAN tag expected for this flow */
	uint8_t flags;				/* Bit flags associated with the rule */
};

/*
 * The NSS IPv6 rule destruction structure.
 */
struct nss_ipv6_rule_destroy {
	uint8_t protocol;		/* Protocol number */
	uint32_t flow_ip[4];		/* Flow IP address */
	uint32_t flow_ident;		/* Flow ident (e.g. port) */
	uint32_t return_ip[4];		/* Return IP address */
	uint32_t return_ident;		/* Return ident (e.g. port) */
};

/*
 * L2 switch entry creation structure.
 */
struct nss_l2switch_rule_create {
	int32_t interface_num;		/* Interface number */
	uint16_t addr[3];		/* Destination MAC address */
	uint8_t state;			/* State of interfece */
	uint8_t priority;		/* Priority of interface */
};

/*
 * L2 switch entry destruction structure.
 */
struct nss_l2switch_rule_destroy {
	int32_t interface_num;		/* Interface number */
	uint16_t mac_addr[3];		/* Destination MAC address */
};

/*
 * The NSS MAC address structure.
 */
struct nss_mac_address_set {
	int32_t interface_num;		/* physical interface number */
	uint8_t mac_addr[ETH_ALEN];	/* MAC address */
};

/*
 * The NSS virtual interface creation structure.
 */
struct nss_virtual_interface_create {
	int32_t interface_num;		/* Virtual interface number */
	uint32_t flags;			/* Interface flags */
	uint8_t mac_addr[ETH_ALEN];	/* MAC address */
};

/*
 * The NSS virtual interface destruction structure.
 */
struct nss_virtual_interface_destroy {
	int32_t interface_num;		/* Virtual interface number */
};

/*
 * The NSS PPPoE rule destruction structure.
 */
struct nss_pppoe_rule_destroy {
	uint16_t pppoe_session_id;	/* PPPoE session ID */
	uint16_t pppoe_remote_mac[3];	/* PPPoE server MAC address */
};

/*
 * Link state notification to NSS
 */
struct nss_if_link_state_notify {
	uint32_t state;			/* Link State (UP/DOWN), speed/duplex settings */
	uint32_t interface_num;		/* Interface for which link state will be sent */
};

/*
 * Interface open command
 */
struct nss_if_open {
	uint32_t tx_desc_ring;		/* Tx descriptor ring address */
	uint32_t rx_desc_ring;		/* Rx descriptor ring address */
	uint32_t interface_num;		/* Interface to open */
};

/*
 * Interface close command
 */
struct nss_if_close {
	uint32_t interface_num;		/* Interface to close */
};

/*
 * Crypto open command
 */
struct nss_crypto_open {
	uint32_t len;			/* Valid information length */
	uint8_t buf[1];			/* Buffer */
};

/*
 * Crypto open command
 */
struct nss_crypto_close {
	uint32_t eng;			/* Engine number */
};

/*
 * The MSS (Maximum Segment Size) structure.
 */
struct nss_mss_set {
	uint16_t mss;			/* MSS value */
	int32_t interface_num;		/* Interface for which MSS will be set */
};

/*
 * NSS Tx Map
 */
struct nss_c2c_tx_map {
	uint32_t c2c_start;		/* Peer core C2C Rx queue start address */
	uint32_t c2c_int_addr;		/* Peer core C2C interrupt register address */
};

/*
 * IPsec Tx rule create
 */
struct nss_ipsec_rule {
	uint32_t interface_num;		/* Interface number */
	uint32_t type;			/* Rule type */
	uint32_t len;			/* Valid information length */
	uint8_t buf[1];			/* Buffer */
};

/*
 * Profiler Tx command
 */
struct nss_profiler_tx {
	uint32_t len;		/* Valid information length */
	uint8_t buf[1];		/* Buffer */
};

/*
 * Interface params command
 */
struct nss_generic_if_params {
	uint32_t interface_num;		/* Interface number */
	uint32_t len;			/* Valid information length */
	uint8_t buf[1];			/* Buffer */
};

/*
 * The NSS freq start or stop strcture
 */
struct nss_freq_change {
	uint32_t frequency;
	uint32_t start_or_end;
};

/*
 * Types of TX metadata.
 */
enum nss_tx_metadata_types {
	NSS_TX_METADATA_TYPE_IPV4_RULE_CREATE,
	NSS_TX_METADATA_TYPE_IPV4_RULE_DESTROY,
	NSS_TX_METADATA_TYPE_IPV6_RULE_CREATE,
	NSS_TX_METADATA_TYPE_IPV6_RULE_DESTROY,
	NSS_TX_METADATA_TYPE_L2SWITCH_RULE_CREATE,
	NSS_TX_METADATA_TYPE_L2SWITCH_RULE_DESTROY,
	NSS_TX_METADATA_TYPE_MAC_ADDR_SET,
	NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_CREATE,
	NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_DESTROY,
	NSS_TX_METADATA_TYPE_DESTROY_ALL_L3_RULES,
	NSS_TX_METADATA_TYPE_DESTROY_ALL_L2SWITCH_RULES,
	NSS_TX_METADATA_TYPE_DESTROY_PPPOE_CONNECTION_RULE,
	NSS_TX_METADATA_TYPE_INTERFACE_OPEN,
	NSS_TX_METADATA_TYPE_INTERFACE_CLOSE,
	NSS_TX_METADATA_TYPE_INTERFACE_LINK_STATE_NOTIFY,
	NSS_TX_METADATA_TYPE_CRYPTO_OPEN,
	NSS_TX_METADATA_TYPE_CRYPTO_CLOSE,
	NSS_TX_METADATA_TYPE_MSS_SET,
	NSS_TX_METADATA_TYPE_C2C_TX_MAP,
	NSS_TX_METADATA_TYPE_IPSEC_RULE,
	NSS_TX_METADATA_TYPE_PROFILER_TX,
	NSS_TX_METADATA_TYPE_GENERIC_IF_PARAMS,
	NSS_TX_METADATA_TYPE_NSS_FREQ_CHANGE,
};

/*
 * Structure that describes all TX metadata objects.
 */
struct nss_tx_metadata_object {
	enum nss_tx_metadata_types type;	/* Object type */
	union {				/* Sub-message type */
		struct nss_ipv4_rule_create ipv4_rule_create;
		struct nss_ipv4_rule_destroy ipv4_rule_destroy;
		struct nss_ipv6_rule_create ipv6_rule_create;
		struct nss_ipv6_rule_destroy ipv6_rule_destroy;
		struct nss_l2switch_rule_create l2switch_rule_create;
		struct nss_l2switch_rule_destroy l2switch_rule_destroy;
		struct nss_mac_address_set mac_address_set;
		struct nss_virtual_interface_create virtual_interface_create;
		struct nss_virtual_interface_destroy virtual_interface_destroy;
		struct nss_pppoe_rule_destroy pppoe_rule_destroy;
		struct nss_if_open if_open;
		struct nss_if_close if_close;
		struct nss_if_link_state_notify if_link_state_notify;
		struct nss_crypto_open crypto_open;
		struct nss_crypto_close crypto_close;
		struct nss_mss_set mss_set;
		struct nss_c2c_tx_map c2c_tx_map;
		struct nss_ipsec_rule ipsec_rule;
		struct nss_profiler_tx profiler_tx;
		struct nss_generic_if_params generic_if_params;
		struct nss_freq_change freq_change;
	} sub;
};

/*
 * The NSS freq ack structure
 */
struct nss_freq_ack {
	uint32_t freq_current;
	int32_t ack_status;
};

struct nss_port_info {
	uint8_t num_phys_ports;
};

/*
 * The NSS IPv4 rule establish structure.
 */
struct nss_ipv4_rule_establish {
	uint32_t index;				/* Slot ID for cache stats to host OS */
	uint8_t protocol;			/* Protocol number */
	uint8_t reserved[3];			/* Reserved to align fields */
	int32_t flow_interface;			/* Flow interface number */
	uint32_t flow_mtu;			/* MTU for flow interface */
	uint32_t flow_ip;			/* Flow IP address */
	uint32_t flow_ip_xlate;			/* Translated flow IP address */
	uint32_t flow_ident;			/* Flow ident (e.g. port) */
	uint32_t flow_ident_xlate;		/* Translated flow ident (e.g. port) */
	uint16_t flow_pppoe_session_id;		/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];	/* Flow direction`s PPPoE Server MAC address */
	int32_t return_interface;		/* Return interface number */
	uint32_t return_mtu;			/* MTU for return interface */
	uint32_t return_ip;			/* Return IP address */
	uint32_t return_ip_xlate;		/* Translated return IP address */
	uint32_t return_ident;			/* Return ident (e.g. port) */
	uint32_t return_ident_xlate;		/* Translated return ident (e.g. port) */
	uint16_t return_pppoe_session_id;	/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];	/* Return direction's PPPoE Server MAC address */
};

/*
 * IPv4 rule sync reasons.
 */
#define NSS_IPV4_RULE_SYNC_REASON_STATS 0
					/* Sync is to synchronize stats */
#define NSS_IPV4_RULE_SYNC_REASON_FLUSH 1
					/* Sync is to flush a cache entry */
#define NSS_IPV4_RULE_SYNC_REASON_EVICT 2
					/* Sync is to evict a cache entry */
#define NSS_IPV4_RULE_SYNC_REASON_DESTROY 3
					/* Sync is to destroy a cache entry (requested by host OS) */
#define NSS_IPV4_RULE_SYNC_REASON_PPPOE_DESTROY 4
					/* Sync is to destroy a cache entry which belongs to a particular PPPoE session */

/*
 * The NSS IPv4 rule sync structure.
 */
struct nss_ipv4_rule_sync {
	uint32_t index;			/* Slot ID for cache stats to host OS */
	uint32_t flow_max_window;	/* Flow direction's largest seen window */
	uint32_t flow_end;		/* Flow direction's largest seen sequence + segment length */
	uint32_t flow_max_end;		/* Flow direction's largest seen ack + max(1, win) */
	uint32_t flow_rx_packet_count;	/* Flow interface's RX packet count */
	uint32_t flow_rx_byte_count;	/* Flow interface's RX byte count */
	uint32_t flow_tx_packet_count;	/* Flow interface's TX packet count */
	uint32_t flow_tx_byte_count;	/* Flow interface's TX byte count */
	uint16_t flow_pppoe_session_id; /* Flow interface`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];
					/* Flow interface's PPPoE remote server MAC address if there is any */
	uint32_t return_max_window;	/* Return direction's largest seen window */
	uint32_t return_end;		/* Return direction's largest seen sequence + segment length */
	uint32_t return_max_end;	/* Return direction's largest seen ack + max(1, win) */
	uint32_t return_rx_packet_count;
					/* Return interface's RX packet count */
	uint32_t return_rx_byte_count;	/* Return interface's RX byte count */
	uint32_t return_tx_packet_count;
					/* Return interface's TX packet count */
	uint32_t return_tx_byte_count;	/* Return interface's TX byte count */
	uint16_t return_pppoe_session_id;
					/* Return interface`s PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];
					/* Return interface's PPPoE remote server MAC address if there is any */
	uint32_t inc_ticks;		/* Number of ticks since the last sync */
	uint32_t reason;		/* Reason for the sync */
};

/*
 * The NSS IPv6 rule establish structure.
 */
struct nss_ipv6_rule_establish {
	uint32_t index;				/* Slot ID for cache stats to host OS */
	uint8_t protocol;			/* Protocol number */
	uint8_t reserved[3];			/* Reserved to align fields */
	int32_t flow_interface;			/* Flow interface number */
	uint32_t flow_mtu;			/* MTU for flow interface */
	uint32_t flow_ip[4];			/* Flow IP address */
	uint32_t flow_ident;			/* Flow ident (e.g. port) */
	uint16_t flow_pppoe_session_id;		/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];	/* Flow direction`s PPPoE Server MAC address */
	int32_t return_interface;		/* Return interface number */
	uint32_t return_mtu;			/* MTU for return interface */
	uint32_t return_ip[4];			/* Return IP address */
	uint32_t return_ident;			/* Return ident (e.g. port) */
	uint16_t return_pppoe_session_id;	/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];	/* Return direction's PPPoE Server MAC address */
};

/*
 * IPv6 rule sync reasons.
 */
#define NSS_IPV6_RULE_SYNC_REASON_STATS 0
					/* Sync is to synchronize stats */
#define NSS_IPV6_RULE_SYNC_REASON_FLUSH 1
					/* Sync is to flush a cache entry */
#define NSS_IPV6_RULE_SYNC_REASON_EVICT 2
					/* Sync is to evict a cache entry */
#define NSS_IPV6_RULE_SYNC_REASON_DESTROY 3
					/* Sync is to destroy a cache entry (requested by host OS) */
#define NSS_IPV6_RULE_SYNC_REASON_PPPOE_DESTROY 4
					/* Sync is to destroy a cache entry which belongs to a particular PPPoE session */

/*
 * The NSS IPv6 rule sync structure.
 */
struct nss_ipv6_rule_sync {
	uint32_t index;			/* Slot ID for cache stats to host OS */
	uint32_t flow_max_window;	/* Flow direction's largest seen window */
	uint32_t flow_end;		/* Flow direction's largest seen sequence + segment length */
	uint32_t flow_max_end;		/* Flow direction's largest seen ack + max(1, win) */
	uint32_t flow_rx_packet_count;	/* Flow interface's RX packet count */
	uint32_t flow_rx_byte_count;	/* Flow interface's RX byte count */
	uint32_t flow_tx_packet_count;	/* Flow interface's TX packet count */
	uint32_t flow_tx_byte_count;	/* Flow interface's TX byte count */
	uint16_t flow_pppoe_session_id; /* Flow interface`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];
					/* Flow interface's PPPoE remote server MAC address if there is any */
	uint32_t return_max_window;	/* Return direction's largest seen window */
	uint32_t return_end;		/* Return direction's largest seen sequence + segment length */
	uint32_t return_max_end;	/* Return direction's largest seen ack + max(1, win) */
	uint32_t return_rx_packet_count;
					/* Return interface's RX packet count */
	uint32_t return_rx_byte_count;	/* Return interface's RX byte count */
	uint32_t return_tx_packet_count;
					/* Return interface's TX packet count */
	uint32_t return_tx_byte_count;	/* Return interface's TX byte count */
	uint16_t return_pppoe_session_id;
					/* Return interface`s PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];
					/* Return interface's PPPoE remote server MAC address if there is any */
	uint32_t inc_ticks;		/* Number of ticks since the last sync */
	uint32_t reason;		/* Reason for the sync */
};

/*
 * The NSS L2 switch rule establish structure.
 */
struct nss_l2switch_rule_establish {
	uint32_t index;			/* Slot ID for cache stats to host OS */
	int32_t interface_num;          /* Interface number */
	uint16_t mac_addr[3];		/* MAC Adress */
};

/*
 * Rule sync reasons.
 */
#define NSS_L2SWITCH_RULE_SYNC_REASON_STATS 0
					/*  Sync is to synchronize stats */
#define NSS_L2SWITCH_RULE_SYNC_REASON_FLUSH 1
					/*  Sync is to flush a cache entry */
#define NSS_L2SWITCH_RULE_SYNC_REASON_EVICT 2
					/*  Sync is to evict a cache entry */
#define NSS_L2SWITCH_RULE_SYNC_REASON_DESTROY 3
					/*  Sync is to destroy a cache entry (requested by host OS) */

/*
 * The NSS L2 switch rule sync structure.
 */
struct nss_l2switch_rule_sync {
	uint32_t index;			/* Slot ID for cache stats to host OS */
	uint32_t rx_packet_count;	/* Number of packets RX'd */
	uint32_t rx_byte_count;		/* Number of bytes RX'd */
	uint32_t inc_ticks;		/* Number of ticks since the last sync */
	uint32_t reason;		/* Reason for the sync */
};

/*
 * The NSS per-GMAC statistics sync structure.
 */
struct nss_gmac_stats_sync {
	int32_t interface;		/* Interface number */
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
	uint32_t gmac_total_ticks;	/* Total clock ticks spend inside the GMAC */
	uint32_t gmac_worst_case_ticks;	/* Worst case iteration of the GMAC in ticks */
	uint32_t gmac_iterations;	/* Number of iterations around the GMAC */
};

/*
 * Exception events from PE
 */
enum exception_events_unknown {
	NSS_EXCEPTION_EVENT_UNKNOWN_L2_PROTOCOL,
	NSS_EXCEPTION_EVENT_UNKNOWN_MAX
};

/*
 * Exception events from PE
 */
enum exception_events_ipv4 {
	NSS_EXCEPTION_EVENT_IPV4_ICMP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_UNHANDLED_TYPE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_IPV4_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_IPV4_UDP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_IPV4_TCP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_IPV4_UNKNOWN_PROTOCOL,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_FLUSH_TO_HOST,
	NSS_EXCEPTION_EVENT_IPV4_TCP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_TCP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_TCP_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_TCP_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_TCP_SMALL_TTL,
	NSS_EXCEPTION_EVENT_IPV4_TCP_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_TCP_FLAGS,
	NSS_EXCEPTION_EVENT_IPV4_TCP_SEQ_EXCEEDS_RIGHT_EDGE,
	NSS_EXCEPTION_EVENT_IPV4_TCP_SMALL_DATA_OFFS,
	NSS_EXCEPTION_EVENT_IPV4_TCP_BAD_SACK,
	NSS_EXCEPTION_EVENT_IPV4_TCP_BIG_DATA_OFFS,
	NSS_EXCEPTION_EVENT_IPV4_TCP_SEQ_BEFORE_LEFT_EDGE,
	NSS_EXCEPTION_EVENT_IPV4_TCP_ACK_EXCEEDS_RIGHT_EDGE,
	NSS_EXCEPTION_EVENT_IPV4_TCP_ACK_BEFORE_LEFT_EDGE,
	NSS_EXCEPTION_EVENT_IPV4_UDP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_UDP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_UDP_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_UDP_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_UDP_SMALL_TTL,
	NSS_EXCEPTION_EVENT_IPV4_UDP_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_WRONG_TARGET_MAC,
	NSS_EXCEPTION_EVENT_IPV4_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_BAD_TOTAL_LENGTH,
	NSS_EXCEPTION_EVENT_IPV4_BAD_CHECKSUM,
	NSS_EXCEPTION_EVENT_IPV4_NON_INITIAL_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_DATAGRAM_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_OPTIONS_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_UNKNOWN_PROTOCOL,
	NSS_EXCEPTION_EVENT_IPV4_MAX
};

/*
 * Exception events from PE
 */
enum exception_events_ipv6 {
	NSS_EXCEPTION_EVENT_IPV6_ICMP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV6_ICMP_UNHANDLED_TYPE,
	NSS_EXCEPTION_EVENT_IPV6_ICMP_IPV6_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV6_ICMP_IPV6_UDP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV6_ICMP_IPV6_TCP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV6_ICMP_IPV6_UNKNOWN_PROTOCOL,
	NSS_EXCEPTION_EVENT_IPV6_ICMP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV6_ICMP_FLUSH_TO_HOST,
	NSS_EXCEPTION_EVENT_IPV6_TCP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV6_TCP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV6_TCP_SMALL_HOP_LIMIT,
	NSS_EXCEPTION_EVENT_IPV6_TCP_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV6_TCP_FLAGS,
	NSS_EXCEPTION_EVENT_IPV6_TCP_SEQ_EXCEEDS_RIGHT_EDGE,
	NSS_EXCEPTION_EVENT_IPV6_TCP_SMALL_DATA_OFFS,
	NSS_EXCEPTION_EVENT_IPV6_TCP_BAD_SACK,
	NSS_EXCEPTION_EVENT_IPV6_TCP_BIG_DATA_OFFS,
	NSS_EXCEPTION_EVENT_IPV6_TCP_SEQ_BEFORE_LEFT_EDGE,
	NSS_EXCEPTION_EVENT_IPV6_TCP_ACK_EXCEEDS_RIGHT_EDGE,
	NSS_EXCEPTION_EVENT_IPV6_TCP_ACK_BEFORE_LEFT_EDGE,
	NSS_EXCEPTION_EVENT_IPV6_UDP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV6_UDP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV6_UDP_SMALL_HOP_LIMIT,
	NSS_EXCEPTION_EVENT_IPV6_UDP_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV6_WRONG_TARGET_MAC,
	NSS_EXCEPTION_EVENT_IPV6_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV6_UNKNOWN_PROTOCOL,
	NSS_EXCEPTION_EVENT_IPV6_MAX
};

/*
 * Exception events from PE
 */
enum exception_events_pppoe {
	NSS_EXCEPTION_EVENT_PPPOE_WRONG_VERSION_OR_TYPE,
	NSS_EXCEPTION_EVENT_PPPOE_WRONG_CODE,
	NSS_EXCEPTION_EVENT_PPPOE_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_PPPOE_UNSUPPORTED_PPP_PROTOCOL,
	NSS_EXCEPTION_EVENT_PPPOE_MAX
};

/*
 * The NSS per-interface statistics sync structure.
 */
struct nss_interface_stats_sync {
	int32_t interface;		/* Interface number */
	uint32_t rx_packets;		/* Number of packets received */
	uint32_t rx_bytes;		/* Number of bytes received */
	uint32_t tx_packets;		/* Number of packets transmitted */
	uint32_t tx_bytes;		/* Number of bytes transmitted */
	uint32_t rx_errors;		/* Number of receive errors */
	uint32_t tx_errors;		/* Number of transmit errors */
	uint32_t tx_dropped;		/* Number of TX dropped packets */
	uint32_t collisions;		/* Number of TX and RX collisions */
	uint32_t host_rx_packets;	/* Number of RX packets received by host OS */
	uint32_t host_rx_bytes;		/* Number of RX bytes received by host OS */
	uint32_t host_tx_packets;	/* Number of TX packets sent by host OS */
	uint32_t host_tx_bytes;		/* Number of TX bytes sent by host OS */
	uint32_t rx_length_errors;	/* Number of RX length errors */
	uint32_t rx_overflow_errors;	/* Number of RX overflow errors */
	uint32_t rx_crc_errors;		/* Number of RX CRC errors */
	uint32_t exception_events_unknown[NSS_EXCEPTION_EVENT_UNKNOWN_MAX];
					/* Number of unknown protocol exception events */
	uint32_t exception_events_ipv4[NSS_EXCEPTION_EVENT_IPV4_MAX];
					/* Number of IPv4 exception events */
	uint32_t exception_events_ipv6[NSS_EXCEPTION_EVENT_IPV6_MAX];
					/* Number of IPv6 exception events */
};

/*
 * The NSS NSS statistics sync structure.
 */
struct nss_nss_stats_sync {
	uint32_t ipv4_connection_create_requests;
					/* Number of IPv4 connection create requests */
	uint32_t ipv4_connection_create_collisions;
					/* Number of IPv4 connection create requests that collided with existing entries */
	uint32_t ipv4_connection_create_invalid_interface;
					/* Number of IPv4 connection create requests that had invalid interface */
	uint32_t ipv4_connection_destroy_requests;
					/* Number of IPv4 connection destroy requests */
	uint32_t ipv4_connection_destroy_misses;
					/* Number of IPv4 connection destroy requests that missed the cache */
	uint32_t ipv4_connection_hash_hits;
					/* Number of IPv4 connection hash hits */
	uint32_t ipv4_connection_hash_reorders;
					/* Number of IPv4 connection hash reorders */
	uint32_t ipv4_connection_flushes;
					/* Number of IPv4 connection flushes */
	uint32_t ipv4_connection_evictions;
					/* Number of IPv4 connection evictions */
	uint32_t ipv6_connection_create_requests;
					/* Number of IPv6 connection create requests */
	uint32_t ipv6_connection_create_collisions;
					/* Number of IPv6 connection create requests that collided with existing entries */
	uint32_t ipv6_connection_create_invalid_interface;
					/* Number of IPv6 connection create requests that had invalid interface */
	uint32_t ipv6_connection_destroy_requests;
					/* Number of IPv6 connection destroy requests */
	uint32_t ipv6_connection_destroy_misses;
					/* Number of IPv6 connection destroy requests that missed the cache */
	uint32_t ipv6_connection_hash_hits;
					/* Number of IPv6 connection hash hits */
	uint32_t ipv6_connection_hash_reorders;
					/* Number of IPv6 connection hash reorders */
	uint32_t ipv6_connection_flushes;
					/* Number of IPv6 connection flushes */
	uint32_t ipv6_connection_evictions;
					/* Number of IPv6 connection evictions */
	uint32_t l2switch_create_requests;
					/* Number of l2 switch entry create requests */
	uint32_t l2switch_create_collisions;
					/* Number of l2 switch entry create requests that collided with existing entries */
	uint32_t l2switch_create_invalid_interface;
					/* Number of l2 switch entry create requests that had invalid interface */
	uint32_t l2switch_destroy_requests;
					/* Number of l2 switch entry destroy requests */
	uint32_t l2switch_destroy_misses;
					/* Number of l2 switch entry destroy requests that missed the cache */
	uint32_t l2switch_hash_hits;	/* Number of l2 switch entry hash hits */
	uint32_t l2switch_hash_reorders;/* Number of l2 switch entry hash reorders */
	uint32_t l2switch_flushes;	/* Number of l2 switch entry flushes */
	uint32_t l2switch_evictions;	/* Number of l2 switch entry evictions */
	uint32_t pppoe_session_create_requests;
					/* Number of PPPoE session create requests */
	uint32_t pppoe_session_create_failures;
					/* Number of PPPoE session create failures */
	uint32_t pppoe_session_destroy_requests;
					/* Number of PPPoE session destroy requests */
	uint32_t pppoe_session_destroy_misses;
					/* Number of PPPoE session destroy requests that missed the cache */
	uint32_t pe_queue_dropped;	/* Number of packets dropped because the PE queue is too full */
	uint32_t pe_total_ticks;	/* Total clock ticks spend inside the PE */
	uint32_t pe_worst_case_ticks;	/* Worst case iteration of the PE in ticks */
	uint32_t pe_iterations;		/* Number of iterations around the PE */
	uint32_t except_queue_dropped;	/* Number of packets dropped because the exception queue is too full */
	uint32_t except_total_ticks;	/* Total clock ticks spend inside the PE */
	uint32_t except_worst_case_ticks;
					/* Worst case iteration of the exception path in ticks */
	uint32_t except_iterations;	/* Number of iterations around the PE */
	uint32_t l2switch_queue_dropped;/* Number of packets dropped because the L2 switch queue is too full */
	uint32_t l2switch_total_ticks;	/* Total clock ticks spend inside the L2 switch */
	uint32_t l2switch_worst_case_ticks;
					/* Worst case iteration of the L2 switch in ticks */
	uint32_t l2switch_iterations;	/* Number of iterations around the L2 switch */
	uint32_t pbuf_alloc_fails;	/* Number of pbuf allocations that have failed */
	uint32_t pbuf_payload_alloc_fails;
					/* Number of pbuf allocations that have failed because there were no free payloads */
};

/*
 * The NSS PPPoE exception statistics sync structure.
 */
struct nss_pppoe_exception_stats_sync {
	uint16_t pppoe_session_id;	/* PPPoE session ID on which stats are based */
	uint8_t pppoe_remote_mac[ETH_ALEN];
					/* PPPoE server MAC address */
	uint32_t exception_events_pppoe[NSS_EXCEPTION_EVENT_PPPOE_MAX];
					/* PPPoE exception events */
	uint32_t index;			/* Per interface array index */
	uint32_t interface_num;		/* Interface number on which this session is created */
};

/*
 * The NSS PPPoE rule create success structure.
 */
struct nss_pppoe_rule_create_success {
	uint16_t pppoe_session_id;	/* PPPoE session ID on which stats are based */
	uint8_t pppoe_remote_mac[ETH_ALEN];
					/* PPPoE server MAC address */
};

/*
 * Profiler sync
 */
struct nss_profiler_sync {
	uint32_t len;		/* Valid information length */
	uint8_t buf[1];		/* Buffer */
};

/*
 * NSS core stats
 */
struct nss_core_stats {
	uint32_t inst_cnt_total;
};

/*
 * Types of RX metadata.
 */
enum nss_rx_metadata_types {
	NSS_RX_METADATA_TYPE_IPV4_RULE_ESTABLISH,
	NSS_RX_METADATA_TYPE_IPV4_RULE_SYNC,
	NSS_RX_METADATA_TYPE_IPV6_RULE_ESTABLISH,
	NSS_RX_METADATA_TYPE_IPV6_RULE_SYNC,
	NSS_RX_METADATA_TYPE_L2SWITCH_RULE_ESTABLISH,
	NSS_RX_METADATA_TYPE_L2SWITCH_RULE_SYNC,
	NSS_RX_METADATA_TYPE_GMAC_STATS_SYNC,
	NSS_RX_METADATA_TYPE_INTERFACE_STATS_SYNC,
	NSS_RX_METADATA_TYPE_NSS_STATS_SYNC,
	NSS_RX_METADATA_TYPE_PPPOE_STATS_SYNC,
	NSS_RX_METADATA_TYPE_PPPOE_RULE_CREATE_SUCCESS,
	NSS_RX_METADATA_TYPE_PROFILER_SYNC,
	NSS_RX_METADATA_TYPE_FREQ_ACK,
	NSS_RX_METADATA_TYPE_CORE_STATS,
};

/*
 * Structure that describes all RX metadata objects.
 */
struct nss_rx_metadata_object {
	enum nss_rx_metadata_types type;	/* Object type */
	union {				/* Sub-message type */
		struct nss_ipv4_rule_establish ipv4_rule_establish;
		struct nss_ipv4_rule_sync ipv4_rule_sync;
		struct nss_ipv6_rule_establish ipv6_rule_establish;
		struct nss_ipv6_rule_sync ipv6_rule_sync;
		struct nss_l2switch_rule_establish l2switch_rule_establish;
		struct nss_l2switch_rule_sync l2switch_rule_sync;
		struct nss_gmac_stats_sync gmac_stats_sync;
		struct nss_interface_stats_sync interface_stats_sync;
		struct nss_nss_stats_sync nss_stats_sync;
		struct nss_pppoe_exception_stats_sync pppoe_exception_stats_sync;
		struct nss_pppoe_rule_create_success pppoe_rule_create_success;
		struct nss_profiler_sync profiler_sync;
		struct nss_freq_ack freq_ack;
		struct nss_core_stats core_stats;
	} sub;
};


/*
 * H2N Buffer Types
 */
#define H2N_BUFFER_EMPTY	0
#define H2N_BUFFER_PACKET	2
#define H2N_BUFFER_CTRL		4
#define H2N_BUFFER_CRYPTO_REQ	7
#define H2N_BUFFER_MAX		16

/*
 * H2N Bit Flag Definitions
 */
#define H2N_BIT_FLAG_GEN_IPV4_IP_CHECKSUM	0x0001
#define H2N_BIT_FLAG_GEN_IP_TRANSPORT_CHECKSUM	0x0002
#define H2N_BIT_FLAG_FIRST_SEGMENT		0x0004
#define H2N_BIT_FLAG_LAST_SEGMENT		0x0008
#define H2N_BIT_FLAG_DISCARD			0x0080
#define H2N_BIT_FLAG_SEGMENTATION_ENABLE	0x0100
#define H2N_BIT_FLAG_SEGMENT_TSO		0x0200
#define H2N_BIT_FLAG_SEGMENT_UFO		0x0400
#define H2N_BIT_FLAG_SEGMENT_TSO6		0x0800
#define H2N_BIT_FLAG_VIRTUAL_BUFFER		0x2000
#define H2N_BIT_BUFFER_REUSE			0x8000

/*
 * HLOS to NSS descriptor structure.
 */
struct h2n_descriptor {
	uint32_t opaque;
			/* 32-bit value provided by the HLOS to associate with the buffer. The cookie has no meaning to the NSS */
	uint32_t buffer;
			/* Physical buffer address. This is the address of the start of the usable buffer being provided by the HLOS */
	uint16_t buffer_len;	/* Length of the buffer (in bytes) */
	uint16_t metadata_off;	/* Reserved for future use */
	uint16_t payload_len;	/* Length of the active payload of the buffer (in bytes) */
	uint16_t mss;		/* MSS to be used with TSO/UFO */
	uint16_t payload_offs;	/* Offset from the start of the buffer to the start of the payload (in bytes) */
	uint16_t interface_num;	/* Interface number to which the buffer is to be sent (where appropriate) */
	uint8_t buffer_type;	/* Type of buffer */
	uint8_t reserved3;	/* Reserved for future use */
	uint16_t bit_flags;	/* Bit flags associated with the buffer */
	uint8_t qos_class;	/* QoS class of the buffer (where appropriate) */
	uint8_t qos_priority;	/* QoS priority of the buffer (where appropriate) */
	uint16_t qos_flow_id;	/* QoS flow ID of the buffer (where appropriate) */
	uint32_t reserved4;	/* Reserved for future use */
};

/*
 * N2H Buffer Types
 */
#define N2H_BUFFER_EMPTY		1
#define N2H_BUFFER_PACKET		3
#define N2H_BUFFER_COMMAND_RESP		5
#define N2H_BUFFER_STATUS		6
#define N2H_BUFFER_CRYPTO_RESP		8
#define N2H_BUFFER_PACKET_VIRTUAL	10
#define N2H_BUFFER_MAX			16

/*
 * Command Response Types
 */
#define N2H_COMMAND_RESP_OK			0
#define N2H_COMMAND_RESP_BUFFER_TOO_SMALL	1
#define N2H_COMMAND_RESP_BUFFER_NOT_WRITEABLE	2
#define N2H_COMMAND_RESP_UNSUPPORTED_COMMAND	3
#define N2H_COMMAND_RESP_INVALID_PARAMETERS	4
#define N2H_COMMAND_RESP_INACTIVE_SUBSYSTEM	5

/*
 * N2H Bit Flag Definitions
 */
#define N2H_BIT_FLAG_IPV4_IP_CHECKSUM_VALID		0x0001
#define N2H_BIT_FLAG_IP_TRANSPORT_CHECKSUM_VALID	0x0002
#define N2H_BIT_FLAG_FIRST_SEGMENT			0x0004
#define N2H_BIT_FLAG_LAST_SEGMENT			0x0008
#define N2H_BIT_FLAG_VIRTUAL_BUFFER			0x2000

/*
 * NSS to HLOS descriptor structure
 */
struct n2h_descriptor {
	uint32_t opaque;
			/* 32-bit value provided by the HLOS to associate with the buffer. The cookie has no meaning to the NSS */
	uint32_t buffer;
			/* Physical buffer address. This is the address of the start of the usable buffer being provided by the HLOS */
	uint16_t buffer_len;	/* Length of the buffer (in bytes) */
	uint16_t reserved1;	/* Reserved for future use */
	uint16_t payload_len;	/* Length of the active payload of the buffer (in bytes) */
	uint16_t reserved2;	/* Reserved for future use */
	uint16_t payload_offs;	/* Offset from the start of the buffer to the start of the payload (in bytes) */
	uint16_t interface_num;	/* Interface number to which the buffer is to be sent (where appropriate) */
	uint8_t buffer_type;	/* Type of buffer */
	uint8_t response_type;	/* Response type if the buffer is a command response */
	uint16_t bit_flags;	/* Bit flags associated with the buffer */
	uint32_t timestamp_lo;	/* Low 32 bits of any timestamp associated with the buffer */
	uint32_t timestamp_hi;	/* High 32 bits of any timestamp associated with the buffer */
};

/*
 * Device Memory Map Definitions
 */
#define DEV_MAGIC		0x4e52522e
#define DEV_INTERFACE_VERSION	1
#define DEV_DESCRIPTORS		256 /* Do we need it here? */

/**
 * H2N descriptor ring
 */
struct h2n_desc_if_instance {
	struct h2n_descriptor *desc;
	uint16_t size;			/* Size in entries of the H2N0 descriptor ring */
	uint16_t int_bit;		/* H2N0 descriptor ring interrupt */
};

/**
 * N2H descriptor ring
 */
struct n2h_desc_if_instance {
	struct n2h_descriptor *desc;
	uint16_t size;			/* Size in entries of the H2N0 descriptor ring */
	uint16_t int_bit;		/* H2N0 descriptor ring interrupt */
};

/**
 * NSS virtual interface map
 */
struct nss_if_mem_map {
	struct h2n_desc_if_instance h2n_desc_if[16];	/* Base address of H2N0 descriptor ring */
	struct n2h_desc_if_instance n2h_desc_if[15];	/* Base address of N2H0 descriptor ring */
	uint32_t magic;				/* Magic value used to identify NSS implementations (must be 0x4e52522e) */
	uint16_t if_version;			/* Interface version number (must be 1 for this version) */
	uint8_t h2n_rings;			/* Number of descriptor rings in the H2N direction */
	uint8_t n2h_rings;			/* Number of descriptor rings in the N2H direction */
	uint32_t h2n_nss_index[16];
			/* Index number for the next descriptor that will be read by the NSS in the H2N0 descriptor ring (NSS owned) */
	uint32_t n2h_nss_index[15];
			/* Index number for the next descriptor that will be written by the NSS in the N2H0 descriptor ring (NSS owned) */
	uint8_t num_phys_ports;
	uint8_t reserved1[3];	/* Reserved for future use */
	uint32_t h2n_hlos_index[16];
			/* Index number for the next descriptor that will be written by the HLOS in the H2N0 descriptor ring (HLOS owned) */
	uint32_t n2h_hlos_index[15];
			/* Index number for the next descriptor that will be read by the HLOS in the N2H0 descriptor ring (HLOS owned) */
	uint32_t c2c_start;	/* Reserved for future use */
};
#endif /* __NSS_HLOS_IF_H */
