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

/**
 * na_api_if.h
 *	NSS driver APIs and Declarations.
 */

/**
 * @addtogroup nss_drv
 * @{
 */

/**
  * @file
  * This file declares all the public interfaces for NSS driver.
  *
  */

#ifndef __NSS_API_IF_H
#define __NSS_API_IF_H

#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

/*
 * Interface numbers are reserved in the
 * following sequence of interface types:
 * 	Physical
 * 	Virtual
 *	Tunnel
 *	Special
 *
 * Interfaces starting from 'Special' do
 * not have statistics associated with them.
 */

/*
 * Maximum Number of interfaces
 */
#define NSS_MAX_PHYSICAL_INTERFACES 4
#define NSS_MAX_VIRTUAL_INTERFACES 16
#define NSS_MAX_TUNNEL_INTERFACES 12
#define NSS_MAX_SPECIAL_INTERFACES 24

/**
 * Start of individual interface groups
 */
#define NSS_PHYSICAL_IF_START 0
#define NSS_VIRTUAL_IF_START (NSS_PHYSICAL_IF_START + NSS_MAX_PHYSICAL_INTERFACES)
#define NSS_TUNNEL_IF_START (NSS_VIRTUAL_IF_START + NSS_MAX_VIRTUAL_INTERFACES)
#define NSS_SPECIAL_IF_START (NSS_TUNNEL_IF_START + NSS_MAX_TUNNEL_INTERFACES)

/**
 * Special interface numbers
 */
#define NSS_LAG0_INTERFACE_NUM (NSS_SPECIAL_IF_START + 10) /* Special IF number for LAG0 */
#define NSS_LAG1_INTERFACE_NUM (NSS_SPECIAL_IF_START + 11) /* Special IF number for LAG1 */
#define NSS_C2C_TX_INTERFACE (NSS_SPECIAL_IF_START + 12) /* Virtual Interface Number for IPSec Tunnel */

/**
 * Tunnel interface numbers
 */
#define NSS_IPSEC_ENCAP_IF_NUMBER (NSS_TUNNEL_IF_START + 0)
#define NSS_IPSEC_DECAP_IF_NUMBER (NSS_TUNNEL_IF_START + 1)
#define NSS_TUNRD_IF_NUMBER (NSS_TUNNEL_IF_START + 2)
#define NSS_TUNIPIP6_IF_NUMBER (NSS_TUNNEL_IF_START + 3)

/**
 * This macro converts format for IPv6 address (from Linux to NSS)
 */
#define IN6_ADDR_TO_IPV6_ADDR(ipv6, in6) \
	{ \
		((uint32_t *)ipv6)[0] = in6.in6_u.u6_addr32[0]; \
		((uint32_t *)ipv6)[1] = in6.in6_u.u6_addr32[1]; \
		((uint32_t *)ipv6)[2] = in6.in6_u.u6_addr32[2]; \
		((uint32_t *)ipv6)[3] = in6.in6_u.u6_addr32[3]; \
	}

/**
 * This macro converts format for IPv6 address (from NSS to Linux)
 */
#define IPV6_ADDR_TO_IN6_ADDR(in6, ipv6) \
	{ \
		in6.in6_u.u6_addr32[0] = ((uint32_t *)ipv6)[0]; \
		in6.in6_u.u6_addr32[1] = ((uint32_t *)ipv6)[1]; \
		in6.in6_u.u6_addr32[2] = ((uint32_t *)ipv6)[2]; \
		in6.in6_u.u6_addr32[3] = ((uint32_t *)ipv6)[3]; \
	}

/**
 * This macro can be used to print IPv6 address (16 * 8 bits)
 */
#define IPV6_ADDR_OCTAL_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"

/**
 * This macro can be used to print IPv6 address (16 * 8 bits)
 */
#define IPV6_ADDR_TO_OCTAL(ipv6) ((uint16_t *)ipv6)[0], ((uint16_t *)ipv6)[1], ((uint16_t *)ipv6)[2], ((uint16_t *)ipv6)[3], ((uint16_t *)ipv6)[4], ((uint16_t *)ipv6)[5], ((uint16_t *)ipv6)[6], ((uint16_t *)ipv6)[7]

#define NSS_ETH_NORMAL_FRAME_MTU 1500
#define NSS_ETH_MINI_JUMBO_FRAME_MTU 1978
#define NSS_ETH_FULL_JUMBO_FRAME_MTU 9600
/*
 * Link aggregation enslave/release events
 */
enum nss_lag_event {
	NSS_LAG_RELEASE,
	NSS_LAG_ENSLAVE,
};

/*
 * Link aggregation commands
 */
enum nss_lag_cmd {
	NSS_LAG_STATE_CHANGE = 0,
};

/*
 * Structure used to send Link Aggregation enslave/release commands.
 */
struct nss_lag_state_change {
	uint32_t cmd;
	uint32_t lag_id;		/* LAG id */
	uint32_t if_num;		/* Interface number */
	uint32_t event;			/* NSS_LAG_{RELEASE/ENSLAVE} */
};

/*
 * @brief NSS PM Clients
 * NSS clients that can request for Bus/Clock performance levels
 **/
typedef enum nss_pm_client {
	NSS_PM_CLIENT_GMAC,
	NSS_PM_CLIENT_CRYPTO,
	NSS_PM_CLIENT_NETAP,
	NSS_PM_MAX_CLIENTS,
} nss_pm_client_t;

/**
 * @brief NSS Performance Levels
 * This is passed as parameter to NSS PM perf level requests
 */
typedef enum nss_pm_perf_level {
	NSS_PM_PERF_LEVEL_SUSPEND = 0,
	NSS_PM_PERF_LEVEL_IDLE,
	NSS_PM_PERF_LEVEL_NOMINAL,
	NSS_PM_PERF_LEVEL_TURBO,
	NSS_PM_PERF_MAX_LEVELS,
} nss_pm_perf_level_t;

/**
 * IPv4 rule sync reasons.
 */
#define NSS_IPV4_SYNC_REASON_STATS 0
					/**< Sync is to synchronize stats */

#define NSS_IPV4_SYNC_REASON_FLUSH 1
					/**< Sync is to flush a cache entry */

#define NSS_IPV4_SYNC_REASON_EVICT 2
					/**< Sync is to evict a cache entry */

#define NSS_IPV4_SYNC_REASON_DESTROY 3
					/**< Sync is to destroy a cache entry (requested by host OS) */

#define NSS_IPV4_SYNC_REASON_PPPOE_DESTROY 4
					/**< Sync is to destroy a cache entry which belongs to a particular PPPoE session */
/**
 * Structure to be used while sending an IPv4 flow/connection destroy rule.
 *
 * Caution: All fields must be passed in host endian order
 */
struct nss_ipv4_create {
	int32_t src_interface_num;	/**< Source i/f number (virtual/physical) */
	int32_t dest_interface_num;	/**< Destination i/f number (virtual/physical) */
	int32_t protocol;		/**< L4 Protocol (e.g. TCP/UDP) */
	uint32_t flags;			/**< Flags (if any) associated with this rule */
	uint32_t from_mtu;		/**< MTU of incoming interface */
	uint32_t to_mtu;		/**< MTU of outgoing interface */
	uint32_t src_ip;		/**< Source IP address */
	int32_t src_port;		/**< Source L4 port (e.g. TCP/UDP port) */
	uint32_t src_ip_xlate;		/**< Translated Source IP address (used with SNAT) */
	int32_t src_port_xlate;		/**< Translated Source L4 port (used with SNAT) */
	uint32_t dest_ip;		/**< Destination IP address */
	int32_t dest_port;		/**< Destination L4 port (e.g. TCP/UDP port) */
	uint32_t dest_ip_xlate;		/**< Translated Destination IP address (used with DNAT) */
	int32_t dest_port_xlate;	/**< Translated Destination L4 port (used with DNAT) */
	uint8_t src_mac[ETH_ALEN];	/**< Source MAC address */
	uint8_t dest_mac[ETH_ALEN];	/**< Destination MAC address */
	uint8_t src_mac_xlate[ETH_ALEN];	/**< Translated Source MAC address (post routing) */
	uint8_t dest_mac_xlate[ETH_ALEN];	/**< Translated Destination MAC address (post routing) */
	uint8_t flow_window_scale;	/**< Window scaling factor (TCP) */
	uint32_t flow_max_window;	/**< Maximum window size (TCP) */
	uint32_t flow_end;		/**< Flow end */
	uint32_t flow_max_end;		/**< Flow maximum end */
	uint16_t flow_pppoe_session_id;			/**< PPPoE session associated with flow */
	uint8_t flow_pppoe_remote_mac[ETH_ALEN];	/**< Remote PPPoE peer MAC address */
	uint16_t ingress_vlan_tag;	/**< Ingress VLAN tag expected for this flow */
	uint8_t return_window_scale;	/**< Window scaling factor of return direction (TCP) */
	uint32_t return_max_window;	/**< Maximum window size of return direction */
	uint32_t return_end;		/**< Flow end for return direction */
	uint32_t return_max_end;	/**< Flow maximum end for return direction */
	uint16_t return_pppoe_session_id;		/**< PPPoE session ID for return direction */
	uint8_t return_pppoe_remote_mac[ETH_ALEN];	/**< Remote PPPoE peer MAC sddress for return */
	uint16_t egress_vlan_tag;	/**< Egress VLAN tag expected for this flow */
	uint8_t spo_needed;		/**< Is SPO required */
	uint32_t param_a0;		/**< Custom extra parameter 0 */
	uint32_t param_a1;		/**< Custom extra parameter 1 */
	uint32_t param_a2;		/**< Custom extra parameter 2 */
	uint32_t param_a3;		/**< Custom extra parameter 3 */
	uint32_t param_a4;		/**< Custom extra parameter 4 */
};

/**
 * IPv4 connection flags (to be used with flags field of nss_ipv4_create structure)
 */

/** Indicates that we should not check sequence numbers */
#define NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK 0x01

/** Indicates that this is a pure bridge flow (no routing involved) */
#define NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW 0x02

/**
 * Structure to be used while sending an IPv4 flow/connection destroy rule.
 */
struct nss_ipv4_destroy {
	int32_t protocol;		/**< L4 protocol ID */
	uint32_t src_ip;		/**< Source IP address */
	int32_t src_port;		/**< Source L4 port (e.g. TCP/UDP port) */
	uint32_t dest_ip;		/**< Destination IP address */
	int32_t dest_port;		/**< Destination L4 port (e.g. TCP/UDP port) */
};

/**
 * IPv6 rule sync reasons.
 */
#define NSS_IPV6_SYNC_REASON_STATS 0
					/**< Sync is to synchronize stats */

#define NSS_IPV6_SYNC_REASON_FLUSH 1
					/**< Sync is to flush a cache entry */

#define NSS_IPV6_SYNC_REASON_EVICT 2
					/**< Sync is to evict a cache entry */

#define NSS_IPV6_SYNC_REASON_DESTROY 3
					/**< Sync is to destroy a cache entry (requested by host OS) */

#define NSS_IPV6_SYNC_REASON_PPPOE_DESTROY 4
					/**< Sync is to destroy a cache entry which belongs to a particular PPPoE session */

/**
 * Structure to be used while sending an IPv6 flow/connection destroy rule.
 *
 * Caution: All fields must be passed in host endian order
 */
struct nss_ipv6_create {
	int32_t src_interface_num;	/**< Source i/f number (virtual/physical) */
	int32_t dest_interface_num;	/**< Destination i/f number (virtual/physical) */
	int32_t protocol;		/**< L4 Protocol (e.g. TCP/UDP) */
	uint32_t flags;			/**< Flags (if any) associated with this rule */
	uint32_t from_mtu;		/**< MTU of incoming interface */
	uint32_t to_mtu;		/**< MTU of outgoing interface */
	uint32_t src_ip[4];		/**< Source IP address */
	int32_t src_port;		/**< Source L4 port (e.g. TCP/UDP port) */
	uint32_t dest_ip[4];		/**< Destination IP address */
	int32_t dest_port;		/**< Destination L4 port (e.g. TCP/UDP port) */
	uint8_t src_mac[ETH_ALEN];	/**< Source MAC address */
	uint8_t dest_mac[ETH_ALEN];	/**< Destination MAC address */
	uint8_t flow_window_scale;	/**< Window scaling factor (TCP) */
	uint32_t flow_max_window;	/**< Maximum window size (TCP) */
	uint32_t flow_end;		/**< Flow end */
	uint32_t flow_max_end;		/**< Flow max end */
	uint16_t flow_pppoe_session_id;			/**< PPPoE session associated with flow */
	uint8_t flow_pppoe_remote_mac[ETH_ALEN];	/**< Remote PPPoE peer MAC address */
	uint16_t ingress_vlan_tag;	/**< Ingress VLAN tag expected for this flow */
	uint8_t return_window_scale;	/**< Window scaling factor (TCP) for return */
	uint32_t return_max_window;	/**< Maximum window size (TCP) for return */
	uint32_t return_end;		/**< End for return */
	uint32_t return_max_end;	/**< Maximum end for return */
	uint16_t return_pppoe_session_id;		/**< PPPoE session associated with return */
	uint8_t return_pppoe_remote_mac[ETH_ALEN];	/**< Remote PPPoE peer MAC address for return */
	uint16_t egress_vlan_tag;	/**< Egress VLAN tag expected for this flow */
};

/**
 * IPv6 connection flags (to be used with flags filed of nss_ipv6_create structure.
 */
#define NSS_IPV6_CREATE_FLAG_NO_SEQ_CHECK 0x1
					/**< Indicates that we should not check sequence numbers */
#define NSS_IPV6_CREATE_FLAG_BRIDGE_FLOW 0x02
					/**< Indicates that this is a pure bridge flow (no routing involved) */

/**
 * Structure to be used while sending an IPv6 flow/connection destroy rule.
 */
struct nss_ipv6_destroy {
	int32_t protocol;		/**< L4 Protocol (e.g. TCP/UDP) */
	uint32_t src_ip[4];		/**< Source IP address */
	int32_t src_port;		/**< Source L4 port (e.g. TCP/UDP port) */
	uint32_t dest_ip[4];		/**< Destination IP address */
	int32_t dest_port;		/**< Destination L4 port (e.g. TCP/UDP port) */
};

/**
 * Structure to define packet stats (bytes / packets seen over a connection) and also keep alive.
 *
 * NOTE: The addresses here are NON-NAT addresses, i.e. the true endpoint addressing.
 * 'src' is the creator of the connection.
 */
struct nss_ipv4_sync {
	uint32_t index;			/**< Slot ID for cache stats to host OS */
					/*TODO: use an opaque information as host and NSS
					  may be using a different mechanism to store rules */
	uint32_t flow_max_window;	/**< Maximum window size (TCP) */
	uint32_t flow_end;		/**< Flow end */
	uint32_t flow_max_end;		/**< Flow max end */
	uint32_t flow_rx_packet_count;	/**< Rx Packet count for the flow */
	uint32_t flow_rx_byte_count;	/**< Rx Byte count for the flow */
	uint32_t flow_tx_packet_count;	/**< Tx Packet count for the flow */
	uint32_t flow_tx_byte_count;	/**< Tx Byte count for the flow */
	uint32_t return_max_window;	/**< Maximum window size (TCP) for return */
	uint32_t return_end;		/**< End for return */
	uint32_t return_max_end;	/**< Max end for return */
	uint32_t return_rx_packet_count;	/**< Rx Packet count for return */
	uint32_t return_rx_byte_count;	/**< Rx Byte count for return */
	uint32_t return_tx_packet_count;	/**< Tx Packet count for return */
	uint32_t return_tx_byte_count;	/**< Tx Byte count for return */
	unsigned long int delta_jiffies;
					/**< Time in Linux jiffies to be added to the current timeout to keep the connection alive */
	uint8_t reason;			/**< Reason of synchronization */
	uint32_t param_a0;		/**< Custom extra parameter 0 */
	uint32_t param_a1;		/**< Custom extra parameter 1 */
	uint32_t param_a2;		/**< Custom extra parameter 2 */
	uint32_t param_a3;		/**< Custom extra parameter 3 */
	uint32_t param_a4;		/**< Custom extra parameter 4 */
};

/**
 * struct nss_ipv4_establish
 *	Define connection established message parameters for
 *	IPv4
 */
struct nss_ipv4_establish {
	uint32_t index;			/**< Slot ID for cache stats to host OS */
					/*TODO: use an opaque information as host and NSS
					  may be using a different mechanism to store rules */
	uint8_t protocol;		/**< Protocol number */
	uint8_t reserved[3];		/**< Reserved to align bytes */
	int32_t flow_interface;		/**< Flow interface number */
	uint32_t flow_mtu;		/**< MTU for flow interface */
	uint32_t flow_ip;		/**< Flow IP address */
	uint32_t flow_ip_xlate;		/**< Translated flow IP address */
	uint32_t flow_ident;		/**< Flow ident (e.g. port) */
	uint32_t flow_ident_xlate;	/**< Translated flow ident (e.g. port) */
	uint16_t flow_mac[3];		/**< Flow direction source MAC address */
	uint16_t flow_pppoe_session_id;	/**< Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];
					/**< Flow direction`s PPPoE Server MAC address */
	uint16_t ingress_vlan_tag;	/**< Ingress VLAN tag */
	int32_t return_interface;	/**< Return interface number */
	uint32_t return_mtu;		/**< MTU for return interface */
	uint32_t return_ip;		/**< Return IP address */
	uint32_t return_ip_xlate;	/**< Translated return IP address */
	uint32_t return_ident;		/**< Return ident (e.g. port) */
	uint32_t return_ident_xlate;	/**< Translated return ident (e.g. port) */
	uint16_t return_mac[3];		/**< Return direction source MAC address */
	uint16_t return_pppoe_session_id;
					/**< Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];
					/**< Return direction's PPPoE Server MAC address */
	uint16_t egress_vlan_tag;	/**< Egress VLAN tag */
};

/**
 * enum nss_ipv4_cb_reason
 *	Provides reason for IPv4 callback
 */
enum nss_ipv4_cb_reason {
	NSS_IPV4_CB_REASON_ESTABLISH = 0,
					/**< Reason is rule establish */
	NSS_IPV4_CB_REASON_SYNC,	/**< Reason is rule sync */
};

/**
 * struct nss_ipv4_cb_params
 *	Define message parameters for IPv4 callback
 */
struct nss_ipv4_cb_params {
	enum nss_ipv4_cb_reason reason;	/**< callback reason */
	union {
		struct nss_ipv4_sync sync;
					/**< sync parameters */
		struct nss_ipv4_establish establish;
					/**< establish parameters */
	} params;
};

/**
 * struct nss_ipv6_sync
 *	Update packet stats (bytes / packets seen over a connection) and also keep alive.
 *
 * NOTE: The addresses here are NON-NAT addresses, i.e. the true endpoint addressing.
 * 'src' is the creator of the connection.
 */
struct nss_ipv6_sync {
	uint32_t index;			/**< Slot ID for cache stats to host OS */
	uint32_t flow_max_window;	/**< Maximum window size (TCP) */
	uint32_t flow_end;		/**< Flow end */
	uint32_t flow_max_end;		/**< Flow max end */
	uint32_t flow_rx_packet_count;	/**< Rx Packet count for the flow */
	uint32_t flow_rx_byte_count;	/**< Rx Byte count for the flow */
	uint32_t flow_tx_packet_count;	/**< Tx Packet count for the flow */
	uint32_t flow_tx_byte_count;	/**< Tx Byte count for the flow */
	uint32_t return_max_window;	/**< Maximum window size (TCP) for return */
	uint32_t return_end;		/**< End for return */
	uint32_t return_max_end;	/**< Max end for return */
	uint32_t return_rx_packet_count;	/**< Rx Packet count for return */
	uint32_t return_rx_byte_count;	/**< Rx Byte count for return */
	uint32_t return_tx_packet_count;	/**< Tx Packet count for return */
	uint32_t return_tx_byte_count;	/**< Tx Byte count for return */
	unsigned long int delta_jiffies;
					/**< Time in Linux jiffies to be added to the current timeout to keep the connection alive */
	uint8_t final_sync;		/**< Non-zero when the NA has ceased to accelerate the given connection */
	uint8_t evicted;		/**< Non-zero if connection evicted */
};

/**
 * struct nss_ipv6_establish
 *	Define connection established message parameters for
 *	IPv6
 */
struct nss_ipv6_establish {
	uint32_t index;			/**< Slot ID for cache stats to host OS */
	uint8_t protocol;		/**< Protocol number */
	int32_t flow_interface;		/**< Flow interface number */
	uint32_t flow_mtu;		/**< MTU for flow interface */
	uint32_t flow_ip[4];		/**< Flow IP address */
	uint32_t flow_ident;		/**< Flow ident (e.g. port) */
	uint16_t flow_mac[3];		/**< Flow direction source MAC address */
	uint16_t flow_pppoe_session_id;	/**< Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];
					/**< Flow direction`s PPPoE Server MAC address */
	uint16_t ingress_vlan_tag;	/**< Ingress VLAN tag */
	int32_t return_interface;	/**< Return interface number */
	uint32_t return_mtu;		/**< MTU for return interface */
	uint32_t return_ip[4];		/**< Return IP address */
	uint32_t return_ident;		/**< Return ident (e.g. port) */
	uint16_t return_mac[3];		/**< Return direction source MAC address */
	uint16_t return_pppoe_session_id;
					/**< Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];
					/**< Return direction's PPPoE Server MAC address */
	uint16_t egress_vlan_tag;	/**< Egress VLAN tag */
};

/**
 * enum nss_ipv6_cb_reason
 *	Provides reason for IPv6 callback
 */
enum nss_ipv6_cb_reason {
	NSS_IPV6_CB_REASON_ESTABLISH = 0,
					/**< Reason is rule establish */
	NSS_IPV6_CB_REASON_SYNC,	/**< Reason is rule sync */
};

/**
 * struct nss_ipv6_cb_params
 *	Define message parameters for IPv6 callback
 */
struct nss_ipv6_cb_params {
	enum nss_ipv6_cb_reason reason;	/**< reason */
	union {
		struct nss_ipv6_sync sync;
					/**< sync parameters */
		struct nss_ipv6_establish establish;
					/**< establish parameters */
	} params;
};

/*
 * struct nss_gmac_sync
 * The NA per-GMAC statistics sync structure.
 */
struct nss_gmac_sync {
	int32_t interface;		/**< Interface number */
	uint32_t rx_bytes;		/**< Number of RX bytes */
	uint32_t rx_packets;		/**< Number of RX packets */
	uint32_t rx_errors;		/**< Number of RX errors */
	uint32_t rx_receive_errors;	/**< Number of RX receive errors */
	uint32_t rx_overflow_errors;	/**< Number of RX overflow errors */
	uint32_t rx_descriptor_errors;	/**< Number of RX descriptor errors */
	uint32_t rx_watchdog_timeout_errors;
					/**< Number of RX watchdog timeout errors */
	uint32_t rx_crc_errors;		/**< Number of RX CRC errors */
	uint32_t rx_late_collision_errors;
					/**< Number of RX late collision errors */
	uint32_t rx_dribble_bit_errors;	/**< Number of RX dribble bit errors */
	uint32_t rx_length_errors;	/**< Number of RX length errors */
	uint32_t rx_ip_header_errors;	/**< Number of RX IP header errors */
	uint32_t rx_ip_payload_errors;	/**< Number of RX IP payload errors */
	uint32_t rx_no_buffer_errors;	/**< Number of RX no-buffer errors */
	uint32_t rx_transport_csum_bypassed;
					/**< Number of RX packets where the transport checksum was bypassed */
	uint32_t tx_bytes;		/**< Number of TX bytes */
	uint32_t tx_packets;		/**< Number of TX packets */
	uint32_t tx_collisions;		/**< Number of TX collisions */
	uint32_t tx_errors;		/**< Number of TX errors */
	uint32_t tx_jabber_timeout_errors;
					/**< Number of TX jabber timeout errors */
	uint32_t tx_frame_flushed_errors;
					/**< Number of TX frame flushed errors */
	uint32_t tx_loss_of_carrier_errors;
					/**< Number of TX loss of carrier errors */
	uint32_t tx_no_carrier_errors;	/**< Number of TX no carrier errors */
	uint32_t tx_late_collision_errors;
					/**< Number of TX late collision errors */
	uint32_t tx_excessive_collision_errors;
					/**< Number of TX excessive collision errors */
	uint32_t tx_excessive_deferral_errors;
					/**< Number of TX excessive deferral errors */
	uint32_t tx_underflow_errors;	/**< Number of TX underflow errors */
	uint32_t tx_ip_header_errors;	/**< Number of TX IP header errors */
	uint32_t tx_ip_payload_errors;	/**< Number of TX IP payload errors */
	uint32_t tx_dropped;		/**< Number of TX dropped packets */
	uint32_t hw_errs[10];		/**< GMAC DMA error counters */
	uint32_t rx_missed;		/**< Number of RX packets missed by the DMA */
	uint32_t fifo_overflows;	/**< Number of RX FIFO overflows signalled by the DMA */
	uint32_t rx_scatter_errors;     /**< Number of scattered frames received by the DMA */
	uint32_t gmac_total_ticks;	/**< Total clock ticks spend inside the GMAC */
	uint32_t gmac_worst_case_ticks;	/**< Worst case iteration of the GMAC in ticks */
	uint32_t gmac_iterations;	/**< Number of iterations around the GMAC */
};

/**
 * Tx command status
 */
typedef enum {
	NSS_TX_SUCCESS = 0,	/**< Success */
	NSS_TX_FAILURE,		/**< Command failure other than descriptor not available */
	NSS_TX_FAILURE_QUEUE,	/**< Command failure due to descriptor not available */
	NSS_TX_FAILURE_NOT_READY,	/**< Command failure due to NSS state uninitialized */
	NSS_TX_FAILURE_TOO_LARGE,	/**< Command is too large to fit in one message */
	NSS_TX_FAILURE_TOO_SHORT,	/**< Command/Packet is shorter than expected size */
	NSS_TX_FAILURE_NOT_SUPPORTED,	/**< Command/Packet not accepted for forwarding */
	NSS_TX_FAILURE_BAD_PARAM,	/**< Command failure due to bad parameters */
} nss_tx_status_t;

/**
 * NSS state status
 */
typedef enum {
	NSS_STATE_UNINITIALIZED = 0,	/**< NSS state is initailized */
	NSS_STATE_INITIALIZED		/**< NSS state is uninitialized */
} nss_state_t;

/**
 * NSS core id
 */
typedef enum {
	NSS_CORE_0 = 0,
	NSS_CORE_1,
	NSS_CORE_MAX
} nss_core_id_t;

/**
 * Callback register status
 */
typedef enum {
	NSS_CB_REGISTER_SUCCESS = 0,	/**< Callback register successful */
	NSS_CB_REGISTER_FAILED,		/**< Callback register failed */
} nss_cb_register_status_t;

/**
 * Callback unregister status
 */
typedef enum {
	NSS_CB_UNREGISTER_SUCCESS = 0,	/**< Callback unregister successful */
	NSS_CB_UNREGISTER_FAILED,		/**< Callback unregister failed */
} nss_cb_unregister_status_t;

/**
 * PM Client interface status
 */
typedef enum {
	NSS_PM_API_SUCCESS = 0,
	NSS_PM_API_FAILED,
} nss_pm_interface_status_t;

/**
 * NSS GMAC event type
 */
typedef enum {
	NSS_GMAC_EVENT_STATS,
	NSS_GMAC_EVENT_OTHER,
	NSS_GMAC_EVENT_MAX
} nss_gmac_event_t;

/**
 * NSS 6rd tunnel event type
 */
typedef enum {
	NSS_TUN6RD_EVENT_STATS,
	NSS_TUN6RD_EVENT_MAX
} nss_tun6rd_event_t;

/**
 * NSS ipip6 tunnel event type
 */
typedef enum {
	NSS_TUNIPIP6_EVENT_STATS,
	NSS_TUNIPIP6_EVENT_MAX
} nss_tunipip6_event_t;

/**
 * General utilities
 */

/**
 * @brief Obtain interface number
 *
 * @param nss_ctx NSS context
 * @param dev OS network device pointer
 *
 * @return int32_t Interface number
 */
extern int32_t nss_get_interface_number(void *nss_ctx, void *dev);

/**
 * @brief Obtain interface device pointer
 *
 * @param nss_ctx NSS context
 * @param uint32_t Interface number
 *
 * @return void* Interface device pointer
 */
extern void *nss_get_interface_dev(void *nss_ctx, uint32_t if_num);

/**
 * @brief Obtain the NSS state
 *
 * @param nss_ctx NSS context
 *
 * @return nss_state_t NSS state
 */
extern nss_state_t nss_get_state(void *nss_ctx);

/**
 * Callback function for all connection expired notification
 */
typedef void (*nss_connection_expire_all_callback_t)(void);

/**
 * @brief Register for all connection expire notification
 *
 * @param event_callback Event callback
 */
extern void nss_register_connection_expire_all(nss_connection_expire_all_callback_t event_callback);

/**
 * @brief Unregister for all connection expire notification
 */
extern void nss_unregister_connection_expire_all(void);

/**
 * Callback for queue decongestion message
 */
typedef void (*nss_queue_decongestion_callback_t)(void *app_ctx);

/**
 * @brief Register for queue decongestion event
 *
 * @param nss_ctx NSS context
 * @param event_callback Event callback
 * @param ctx Callee context to be returned in callback
 *
 * @note Callback function will be called with spinlock taken
 */
extern nss_cb_register_status_t nss_register_queue_decongestion(void *nss_ctx, nss_queue_decongestion_callback_t event_callback, void *app_ctx);

/**
 * @brief Unregister for queue decongestion event
 *
 * @param event_callback
 */
extern nss_cb_unregister_status_t nss_unregister_queue_decongestion(void *nss_ctx, nss_queue_decongestion_callback_t event_callback);

/**
 * Methods provided by NSS device driver for use by connection tracking logic for IPv4.
 */

/**
 * Callback for IPv4 connection sync messages
 */
typedef void (*nss_ipv4_callback_t)(struct nss_ipv4_cb_params *nicb);

/**
 * @brief Register for sending/receiving IPv4 messages
 *
 * @param event_callback Event callback
 *
 * @return void* NSS context to be provided with every message
 */
extern void *nss_register_ipv4_mgr(nss_ipv4_callback_t event_callback);

/**
 * @brief API to get NSS context for IPv4 Connection manager
 *
 */
extern void *nss_get_ipv4_mgr_ctx(void);

/**
 * @brief Get handle to sending/receiving Frequency messages
 *
 * @return void* NSS context to be provided with every message
 */
extern void *nss_get_frequency_mgr(void);

/**
 * @brief Unregister for sending/receiving IPv4 messages
 */
extern void nss_unregister_ipv4_mgr(void);

/**
 * @brief Send IPv4 connection setup rule
 *
 * @param nss_ctx NSS context
 * @param unic Rule parameters
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_create_ipv4_rule(void *nss_ctx, struct nss_ipv4_create *unic);

/**
 * @brief Send IPv4 connection destroy rule
 *
 * @param nss_ctx NSS context
 * @param unid Rule parameters
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_destroy_ipv4_rule(void *nss_ctx, struct nss_ipv4_destroy *unid);

/**
 * Methods provided by NSS device driver for use by connection tracking logic for IPv6.
 */

/**
 * Callback for IPv6 sync messages
 */
typedef void (*nss_ipv6_callback_t)(struct nss_ipv6_cb_params *nicb);

/**
 * @brief Register for sending/receiving IPv6 messages
 *
 * @param event_callback Callback
 *
 * @return void* NSS context to be provided with every message
 */
extern void *nss_register_ipv6_mgr(nss_ipv6_callback_t event_callback);

/**
 * @brief Unregister for sending/receiving IPv4 messages
 */
extern void nss_unregister_ipv6_mgr(void);

/**
 * @brief Send IPv6 connection setup rule
 *
 * @param nss_ctx NSS context
 * @param unic Rule parameters
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_create_ipv6_rule(void *nss_ctx, struct nss_ipv6_create *unic);

/**
 * @brief Send IPv6 connection destroy rule
 *
 * @param nss_ctx NSS context
 * @param unid Rule parameters
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_destroy_ipv6_rule(void *nss_ctx, struct nss_ipv6_destroy *unid);

/**
 * Methods provided by NSS device driver for use by crypto driver
 */

/**
 * Callback to receive crypto buffers
 */
typedef void (*nss_crypto_callback_t)(void *ctx, void *buf, uint32_t buf_paddr, uint16_t len);

/**
 * @brief Register for sending/receiving crypto buffers
 *
 * @param crypto_callback Callback
 * @param ctx Crypto context
 *
 * @return void* NSS context to be provided with every message
 */
extern void *nss_register_crypto_if(nss_crypto_callback_t crypto_callback, void *ctx);

/**
 * @brief Unregister for sending/receiving crypto buffers
 */
extern void nss_unregister_crypto_if(void);

/**
 * @brief Open crypto interface
 *
 * @param ctx NSS context
 * @param buf Buffer to send to NSS
 * @param len Length of buffer
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_crypto_if_open(void *ctx, uint8_t *buf, uint32_t len);

/**
 * @brief Close crypto interface
 *
 * @param ctx NSS context
 * @param eng Engine number
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_crypto_if_close(void *ctx, uint32_t eng);

/**
 * @brief Send crypto buffer to NSS
 *
 * @param nss_ctx NSS context
 * @param buf Crypto buffer
 * @param buf_paddr Physical address of buffer
 * @param len Length of buffer
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_crypto_if_buf(void *nss_ctx, void *buf, uint32_t buf_paddr, uint16_t len);

/**
 * Methods provided by NSS device driver for use by GMAC driver
 */

/**
 * Callback to receive GMAC events
 */
typedef void (*nss_phys_if_event_callback_t)(void *if_ctx, nss_gmac_event_t ev_type, void *buf, uint32_t len);

/**
 * Callback to receive GMAC packets
 */
typedef void (*nss_phys_if_rx_callback_t)(void *if_ctx, void *os_buf);

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
extern void *nss_register_phys_if(uint32_t if_num, nss_phys_if_rx_callback_t rx_callback,
					nss_phys_if_event_callback_t event_callback, struct net_device *if_ctx);

/**
 * @brief Unregister GMAC handlers with NSS driver
 *
 * @param if_num GMAC Interface number
 */
extern void nss_unregister_phys_if(uint32_t if_num);

/**
 * @brief Send GMAC packet
 *
 * @param nss_ctx NSS context
 * @param os_buf OS buffer (e.g. skbuff)
 * @param if_num GMAC i/f number
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_phys_if_buf(void *nss_ctx, struct sk_buff *os_buf, uint32_t if_num);

/**
 * @brief Open GMAC interface on NSS
 *
 * @param nss_ctx NSS context
 * @param tx_desc_ring Tx descriptor ring address
 * @param rx_desc_ring Rx descriptor ring address
 * @param if_num GMAC i/f number
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_phys_if_open(void *nss_ctx, uint32_t tx_desc_ring, uint32_t rx_desc_ring, uint32_t if_num);

/**
 * @brief Close GMAC interface on NSS
 *
 * @param nss_ctx NSS context
 * @param if_num GMAC i/f number
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_phys_if_close(void *nss_ctx, uint32_t if_num);

/**
 * @brief Send link state message to NSS
 *
 * @param nss_ctx NSS context
 * @param link_state Link state
 * @param if_num GMAC i/f number
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_phys_if_link_state(void *nss_ctx, uint32_t link_state, uint32_t if_num);

/**
 * @brief Send MAC address to NSS
 *
 * @param nss_ctx NSS context
 * @param addr MAC address pointer
 * @param if_num GMAC i/f number
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_phys_if_mac_addr(void *nss_ctx, uint8_t *addr, uint32_t if_num);

/**
 * @brief Send MTU change notification to NSS
 *
 * @param nss_ctx NSS context
 * @param mtu MTU
 * @param if_num GMAC i/f number
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_phys_if_change_mtu(void *nss_ctx, uint32_t mtu, uint32_t if_num);

/**
 * @brief Get NAPI context
 *
 * @param nss_ctx NSS context
 * @param napi_ctx Pointer to address to return NAPI context
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_phys_if_get_napi_ctx(void *nss_ctx, struct napi_struct **napi_ctx);

/**
 * Methods provided by NSS driver for use by virtual interfaces (VAPs)
 */

/**
 * @brief Create virtual interface (VAPs)
 *
 * @param if_ctx Interface context
 *		(struct net_device * in Linux)
 *
 * @return void* context
 */
extern void *nss_create_virt_if(struct net_device *if_ctx);

/**
 * @brief Destroy virtual interface (VAPs)
 *
 * @param ctx Context provided by NSS driver during registration
 *
 * @return None
 */
extern nss_tx_status_t nss_destroy_virt_if(void *ctx);

/**
 * @brief Forward Native wifi packet from virtual interface
 *    -Expects packet with qca-nwifi format
 * @param nss_ctx NSS context (provided during registeration)
 * @param os_buf OS buffer (e.g. skbuff)
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_virt_if_rx_nwifibuf(void *nss_ctx, struct sk_buff *os_buf);

/**
 * @brief Forward virtual interface packets
 *
 * @param nss_ctx NSS context (provided during registeration)
 * @param os_buf OS buffer (e.g. skbuff)
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_virt_if_rxbuf(void *nss_ctx, struct sk_buff *os_buf);

/**
 * Methods provided by NSS driver for use by IPsec stack
 */

/**
 * Callback to receive IPsec events
 */
typedef void (*nss_ipsec_event_callback_t)(void *if_ctx, uint32_t if_num, void *buf, uint32_t len);

/**
 * Callback to receive ipsec data message
 */
typedef void (*nss_ipsec_data_callback_t)(void *ctx, void *os_buf);

/**
 * @brief Register to send/receive IPsec data to NSS
 *
 * @param ipsec interface number if_num
 * @param ipsec_data callback ipsec_data_cb
 * @param ctx IPsec context
 *
 * @return void* NSS context
 */
extern void *nss_register_ipsec_if(uint32_t if_num, nss_ipsec_data_callback_t ipsec_data_cb, void *ctx);

/**
 * @brief Register to send/receive IPsec events to NSS
 *
 * @param ipsec interface number if_num
 * @param ipsec_data callback ipsec_data_cb
 *
 */
extern void nss_register_ipsec_event_if(uint32_t if_num, nss_ipsec_event_callback_t ipsec_event_cb);

/**
 * @brief Unregister IPsec interface with NSS
 */
extern void nss_unregister_ipsec_if(uint32_t if_num);

/**
 * @brief Send rule creation message for IPsec Tx node
 *
 * @param nss_ctx NSS context
 * @param interface_num interface number for Ipsec tunnel
 * @param type IPsec rule type
 * @param buf Rule buffer that needs to be sent to NSS
 * @param len Length of valid data in buffer
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_tx_ipsec_rule(void *nss_ctx, uint32_t interface_num, uint32_t type, uint8_t *buf, uint32_t len);

/**
 * Methods provided by NSS driver for use by NSS Profiler
 */

/**
 * Callback to receive profiler messages
 *
 * @note Memory pointed by buf is owned by caller (i.e. NSS driver)
 *	NSS driver does not interpret "buf". It is up to profiler to make sense of it.
 */
typedef void (*nss_profiler_callback_t)(void *ctx, uint8_t *buf, uint16_t len);

/**
 * @brief Register to send/receive profiler messages
 *
 * @param profiler_callback Profiler callback
 * @param core_id NSS core id
 * @param ctx Profiler context
 *
 * @return void* NSS context
 *
 * @note Caller must provide valid core_id that is being profiled. This function must be called once for each core.
 *	Context (ctx) will be provided back to caller in the registered callback function
 */
extern void *nss_register_profiler_if(nss_profiler_callback_t profiler_callback, nss_core_id_t core_id, void *ctx);

/**
 * @brief Unregister profiler interface
 *
 * @param core_id NSS core id
 *
 */
extern void nss_unregister_profiler_if(nss_core_id_t core_id);

/**
 * @brief Send profiler command to NSS
 *
 * @param nss_ctx NSS context
 * @param buf Buffer to send to NSS
 * @param len Length of buffer
 *
 * @return nss_tx_status_t Tx status
 *
 * @note Valid context must be provided (for the right core).
 *	This context was returned during registration.
 */
extern nss_tx_status_t nss_tx_profiler_if_buf(void *nss_ctx, uint8_t *buf, uint32_t len);

/**
 * @brief Send generic interface based command to NSS
 *
 * @param nss_ctx NSS context
 * @param if_num NSS interface to deliver this message
 * @param buf Buffer to send to NSS
 * @param len Length of buffer
 *
 * @return nss_tx_status_t Tx status
 *
 * @note Valid context must be provided (for the right core).
 *	This context was returned during registration.
 */
extern nss_tx_status_t nss_tx_generic_if_buf(void *nss_ctx, uint32_t if_num, uint8_t *buf, uint32_t len);

/**
 * Methods provided by NSS driver for use by 6rd tunnel
 */

/**
 * Callback to receive tun6rd events
 */
typedef void (*nss_tun6rd_if_event_callback_t)(void *if_ctx, nss_tun6rd_event_t ev_type, void *buf, uint32_t len);

/**
 * Callback to receive 6rd callback
 */
typedef void (*nss_tun6rd_callback_t)(void *ctx, void *os_buf);

/**
 * Callback to receive tunipip6 events
 */
typedef void (*nss_tunipip6_if_event_callback_t)(void *if_ctx, nss_tunipip6_event_t ev_type, void *buf, uint32_t len);

/**
 * Callback to receive ipip6 callback
 */
typedef void (*nss_tunipip6_callback_t)(void *ctx, void *os_buf);

/**
 * @brief Register to send/receive 6rd tunnel messages to NSS
 *
 * @param tun6rd_callback Callback
 * @param ctx 6rd tunnel context
 *
 * @return void* NSS context
 */
extern void *nss_register_tun6rd_if(uint32_t if_num, nss_tun6rd_callback_t tun6rd_callback, nss_tun6rd_if_event_callback_t event_callback, void *ctx);

/**
 * @brief Unregister 6rd tunnel interface with NSS
 */
extern void nss_unregister_tun6rd_if(uint32_t if_num);

/**
 * @brief Register to send/receive ipip6 tunnel messages to NSS
 *
 * @param tunipip6_callback Callback
 * @param ctx ipip6 tunnel context
 *
 * @return void* NSS context
 */
extern void *nss_register_tunipip6_if(uint32_t if_num, nss_tunipip6_callback_t tunipip6_callback, nss_tunipip6_if_event_callback_t event_callback, void *ctx);

/**
 * @brief Unregister ipip6 tunnel interface with NSS
 */
extern void nss_unregister_tunipip6_if(uint32_t if_num);

/*
 * @brief NSS Frequency Change
 * @ param ctx NSS context
 * @ param eng Frequency Value in Hz
 * @ param stats_enable Enable NSS to send scaling statistics
 * @ param start_or_end Start or End of Freq Change
 *
 * @return nss_tx_status_t Tx Status
 */
nss_tx_status_t nss_freq_change(void *ctx, uint32_t eng, uint32_t stats_enable, uint32_t start_or_end);

/**
 * @brief Register PM Driver Client
 *
 * @param client_id Identifies the Client driver registering with PM driver
 *
 * @return
 */
extern void *nss_pm_client_register(nss_pm_client_t client_id);

/**
 * @brief Unregister PM Driver Client
 *
 * @param client_id Identifies the Client driver registering with PM driver
 *
 * @return
 */
int nss_pm_client_unregister(nss_pm_client_t client_id);

/**
 * @brief Update Bus Bandwidth level for a client
 *
 * @param handle - Client Handle
 * @param lvl - Perf Level
 */
extern nss_pm_interface_status_t nss_pm_set_perf_level(void *handle, nss_pm_perf_level_t lvl);

/**@}*/
#endif /** __NSS_API_IF_H */
