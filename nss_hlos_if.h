/*
 **************************************************************************
 * Copyright (c) 2013, Qualcomm Atheros, Inc.
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
 * Common response structure
 */
enum nss_cmn_response {
	NSS_CMN_RESPONSE_ACK = 0,		/* Message Acknowledge */
	NSS_CMN_RESPONSE_EVERSION = 1,	/* Message Version Error */
	NSS_CMN_RESPONSE_EINTERFACE = 2,	/* Message Interface Error */
	NSS_CMN_RESPONSE_ELENGTH = 3,	/* Message Length Error */
	NSS_CMN_RESPONSE_EMSG = 4,		/* Message Error */
	NSS_CMM_RESPONSE_NOTIFY = 5		/* Message Independant of Request */
};

/*
 * Common message structure
 */
struct nss_cmn_msg {
	uint16_t version;		/* Version id for main message format */
	uint16_t interface;		/* Primary Key for all messages */
	enum nss_cmn_response response;	/* Primary response */
	uint32_t type;		/* Decetralized request #, to be used to match response # */
	uint32_t error;		/* Decentralized specific error message, response == EMSG */
	uint32_t len;		/* What is the length of the message excluding this header */
};

/*
 * IPv4 bridge/route rule messages
 */

enum nss_ipv4_metadata_types {
	NSS_TX_METADATA_TYPE_IPV4_RULE_CREATE,
	NSS_TX_METADATA_TYPE_IPV4_RULE_DESTROY,
	NSS_RX_METADATA_TYPE_IPV4_RULE_ESTABLISH,
	NSS_RX_METADATA_TYPE_IPV4_RULE_SYNC,
	NSS_METADATA_TYPE_IPV4_MAX,
};

/*
 * NA IPv4 rule creation flags.
 */
#define NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK 0x01
					/* Do not perform sequence number checks */
#define NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW 0x02
					/* This is a pure bridge forwarding flow */
#define NSS_IPV4_RULE_CREATE_FLAG_ROUTED 0x04
					/* Rule is for a routed connection. */
#define NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING 0x08
					/* Rule is for a DSCP marking . */
#define NSS_IPV4_RULE_CREATE_FLAG_VLAN_MARKING 0x10
					/* Rule is for a VLAN marking . */

/*
 * IPv4 rule creation validity flags.
 */
#define NSS_IPV4_RULE_CREATE_CONN_VALID 0x01	/* Protocol fields are valid */
#define NSS_IPV4_RULE_CREATE_TCP_VALID 0x02	/* Protocol fields are valid */
#define NSS_IPV4_RULE_CREATE_PPPOE_VALID 0x04	/* PPPoE fields are valid */
#define NSS_IPV4_RULE_CREATE_QOS_VALID 0x08	/* QoS fields are valid */
#define NSS_IPV4_RULE_CREATE_VLAN_VALID 0x10	/* VLAN fields are valid */
#define NSS_IPV4_RULE_CREATE_DSCP_MARKING_VALID 0x20	/* DSCP fields are valid */
#define NSS_IPV4_RULE_CREATE_VLAN_MARKING_VALID 0x40	/* VLAN fields are valid */

/*
 * Common 5 tuple structure
 */
struct nss_ipv4_5tuple {
	uint32_t flow_ip;		/* Flow IP address */
	uint32_t flow_ident;		/* Flow ident (e.g. port) */
	uint32_t return_ip;		/* Return IP address */
	uint32_t return_ident;		/* Return ident (e.g. port) */
	uint8_t protocol;		/* Protocol number */
};

/*
 * Connection create structure
 */
struct nss_ipv4_connection_rule {
	uint8_t flags;
	uint16_t flow_mac[3];		/* Flow MAC address */
	int32_t flow_interface_num;	/* Flow interface number */
	uint32_t flow_ip_xlate;		/* Translated flow IP address */
	uint32_t flow_ident_xlate;	/* Translated flow ident (e.g. port) */
	uint16_t return_mac[3];		/* Return MAC address */
	int32_t return_interface_num;	/* Return interface number */
	uint32_t return_ip_xlate;	/* Translated return IP address */
	uint32_t return_ident_xlate;	/* Translated return ident (e.g. port) */
};

/*
 * PPPoE connection rules structure
 */
struct nss_ipv4_pppoe_rule {
	uint16_t flow_pppoe_session_id;	/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];
					/* Flow direction`s PPPoE Server MAC address */
	uint16_t return_pppoe_session_id;
					/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];
					/* Return direction's PPPoE Server MAC address */
};

/*
 * DSCP connection rule structure
 */
struct nss_ipv4_dscp_rule {
	uint8_t dscp_itag;		/* Input tag for DSCP marking */
	uint8_t dscp_imask;		/* Input mask for DSCP marking */
	uint8_t dscp_omask;		/* Output mask for DSCP marking */
	uint8_t dscp_oval;		/* Output value of DSCP marking */
};

/*
 * VLAN connection rule structure
 */
struct nss_ipv4_vlan_rule {
	uint16_t ingress_vlan_tag;	/* VLAN Tag for the ingress packets */
	uint16_t egress_vlan_tag;	/* VLAN Tag for egress packets */
	uint16_t vlan_itag;		/* Input tag for VLAN marking */
	uint16_t vlan_imask;		/* Input mask for VLAN marking */
	uint16_t vlan_omask;		/* Output mask for VLAN marking */
	uint16_t vlan_oval;		/* Output value of VLAN marking */
};

/*
 * TCP connection rulr structure
 */
struct nss_ipv4_protocol_tcp_rule {
	uint8_t flow_window_scale;	/* Flow direction's window scaling factor */
	uint32_t flow_max_window;	/* Flow direction's largest seen window */
	uint32_t flow_end;		/* Flow direction's largest seen sequence + segment length */
	uint32_t flow_max_end;		/* Flow direction's largest seen ack + max(1, win) */
	uint32_t flow_mtu;		/* Flow interface`s MTU */
	uint8_t return_window_scale;	/* Return direction's window scaling factor */
	uint32_t return_max_window;	/* Return direction's largest seen window */
	uint32_t return_end;		/* Return direction's largest seen sequence + segment length */
	uint32_t return_max_end;	/* Return direction's largest seen ack + max(1, win) */
	uint32_t return_mtu;		/* Return interface`s MTU */
};

/*
 * QoS connection rule structure
 */
struct nss_ipv4_qos_rule {
	uint32_t qos_tag;			/* QoS tag associated with this rule */
};

/*
 * Error types for create rule (CR) msg
 */
enum {
	NSS_IPV4_CR_INVALID_PNODE_ERROR = 1,
	NSS_IPV4_CR_MISSING_CONNECTION_RULE_ERROR,
	NSS_IPV4_CR_BUFFER_ALLOC_FAIL_ERROR,
	NSS_IPV4_CR_PPPOE_SESSION_CREATION_ERROR,
};

/*
 * The IPv4 rule create sub-message structure.
 */
struct nss_ipv4_rule_create_msg {
	struct nss_ipv4_5tuple tuple;			/* Holds values of the 5 tuple */

	struct nss_ipv4_connection_rule conn_rule;	/* Basic connection specific data */
	struct nss_ipv4_protocol_tcp_rule tcp_rule;	/* TCP related accleration parameters */
	struct nss_ipv4_pppoe_rule pppoe_rule;		/* PPPoE related accleration parameters */
	struct nss_ipv4_qos_rule qos_rule;		/* QoS related accleration parameters */
	struct nss_ipv4_dscp_rule dscp_rule;		/* DSCP related accleration parameters */
	struct nss_ipv4_vlan_rule vlan_rule;		/* VLAN related accleration parameters */

	uint32_t opaque[2];			/* NSS driver opaques */
	uint16_t valid_flags;			/* Bit flags associated with the validity of parameters */
	uint8_t rule_flags;			/* Bit flags associated with the rule */
};

/*
 * Error types for destroy rule (DR) msg
 */
enum {
	NSS_IPV4_DR_NO_CONNECTION_ENTRY_ERROR = 1,
};

/*
 * The IPv4 rule destroy sub-message structure.
 */
struct nss_ipv4_rule_destroy_msg {
	struct nss_ipv4_5tuple tuple;	/* Holds values of the 5 tuple */
	uint32_t opaque[2];			/* NSS driver opaques */
};

/*
 * Message types for ipv4
 */
typedef enum {
	NSS_IPV4_CREATE_RULE_MSG,		/* Message type - create rule */
	NSS_IPV4_DESTROY_RULE_MSG,		/* Message type - destroy rule */
} nss_ipv4_msg_types_t;

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
	uint16_t flow_mac[3];			/* Flow direction source MAC address */
	uint16_t flow_pppoe_session_id;		/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];	/* Flow direction`s PPPoE Server MAC address */
	uint16_t ingress_vlan_tag;		/* Ingress VLAN tag */
	int32_t return_interface;		/* Return interface number */
	uint32_t return_mtu;			/* MTU for return interface */
	uint32_t return_ip;			/* Return IP address */
	uint32_t return_ip_xlate;		/* Translated return IP address */
	uint32_t return_ident;			/* Return ident (e.g. port) */
	uint32_t return_ident_xlate;		/* Translated return ident (e.g. port) */
	uint16_t return_mac[3];			/* Return direction source MAC address */
	uint16_t return_pppoe_session_id;	/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];	/* Return direction's PPPoE Server MAC address */
	uint16_t egress_vlan_tag;		/* Egress VLAN tag */
	uint8_t flags;				/* Bit flags associated with the rule */
	uint32_t qos_tag;			/* Qos Tag */
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

	uint8_t flags;			/* Bit flags associated with the rule */
	uint32_t qos_tag;		/* Qos Tag */
};

/*
 * Message structure to send/receive IPv4 bridge/route commands
 */
struct nss_ipv4_msg {
	struct nss_cmn_msg cm;		/* Message Header */
	union {
		struct nss_ipv4_rule_create_msg rule_create;	/* Message: rule create */
		struct nss_ipv4_rule_destroy_msg rule_destroy;	/* Message: rule destroy */
		struct nss_ipv4_rule_establish rule_establish;	/* Message: rule establish confirmation */
		struct nss_ipv4_rule_sync rule_sync;	/* Message: stats sync */
	} msg;
};

/*
 * IPv6 bridge/route rule messages
 */

 enum nss_ipv6_metadata_types {
	NSS_TX_METADATA_TYPE_IPV6_RULE_CREATE,
	NSS_TX_METADATA_TYPE_IPV6_RULE_DESTROY,
	NSS_RX_METADATA_TYPE_IPV6_RULE_ESTABLISH,
	NSS_RX_METADATA_TYPE_IPV6_RULE_SYNC,
	NSS_METADATA_TYPE_IPV6_MAX,
};

/*
 * NSS IPv6 rule creation flags.
 */
#define NSS_IPV6_RULE_CREATE_FLAG_NO_SEQ_CHECK 0x01
					/* Do not perform sequence number checks */
#define NSS_IPV6_RULE_CREATE_FLAG_BRIDGE_FLOW 0x02
					/* This is a pure bridge forwarding flow */
#define NSS_IPV6_RULE_CREATE_FLAG_ROUTED 0x04
					/* Rule is for a routed connection. */
#define NSS_IPV6_RULE_CREATE_FLAG_DSCP_MARKING 0x08
					/* Rule is for a DSCP marking . */
#define NSS_IPV6_RULE_CREATE_FLAG_VLAN_MARKING 0x10
					/* Rule is for a VLAN marking . */

/*
 * IPv6 rule creation validity flags.
 */
#define NSS_IPV6_RULE_CREATE_CONN_VALID 0x01	/* Protocol fields are valid */
#define NSS_IPV6_RULE_CREATE_TCP_VALID 0x02	/* Protocol fields are valid */
#define NSS_IPV6_RULE_CREATE_PPPOE_VALID 0x04	/* PPPoE fields are valid */
#define NSS_IPV6_RULE_CREATE_QOS_VALID 0x08	/* QoS fields are valid */
#define NSS_IPV6_RULE_CREATE_VLAN_VALID 0x10	/* VLAN fields are valid */
#define NSS_IPV6_RULE_CREATE_DSCP_MARKING_VALID 0x20	/* DSCP fields are valid */
#define NSS_IPV6_RULE_CREATE_VLAN_MARKING_VALID 0x40	/* VLAN fields are valid */

/*
 * Common 5 tuple structure
 */
struct nss_ipv6_5tuple {
	uint32_t flow_ip[4];		/* Flow IP address */
	uint32_t flow_ident;		/* Flow ident (e.g. port) */
	uint32_t return_ip[4];		/* Return IP address */
	uint32_t return_ident;		/* Return ident (e.g. port) */
	uint8_t protocol;		/* Protocol number */
};

/*
 * Connection create structure
 */
struct nss_ipv6_connection_rule {
	uint16_t flow_mac[3];		/* Flow MAC address */
	int32_t flow_interface_num;	/* Flow interface number */
	uint16_t return_mac[3];		/* Return MAC address */
	int32_t return_interface_num;	/* Return interface number */
};

/*
 * PPPoE connection rules structure
 */
struct nss_ipv6_pppoe_rule {
	uint16_t flow_pppoe_session_id;	/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];
					/* Flow direction`s PPPoE Server MAC address */
	uint16_t return_pppoe_session_id;
					/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];
					/* Return direction's PPPoE Server MAC address */
};

/*
 * DSCP connection rule structure
 */
struct nss_ipv6_dscp_rule {
	uint8_t dscp_itag;		/* Input tag for DSCP marking */
	uint8_t dscp_imask;		/* Input mask for DSCP marking */
	uint8_t dscp_omask;		/* Output mask for DSCP marking */
	uint8_t dscp_oval;		/* Output value of DSCP marking */
};

/*
 * VLAN connection rule structure
 */
struct nss_ipv6_vlan_rule {
	uint16_t ingress_vlan_tag;	/* VLAN Tag for the ingress packets */
	uint16_t egress_vlan_tag;	/* VLAN Tag for egress packets */
	uint16_t vlan_itag;		/* Input tag for VLAN marking */
	uint16_t vlan_imask;		/* Input mask for VLAN marking */
	uint16_t vlan_omask;		/* Output mask for VLAN marking */
	uint16_t vlan_oval;		/* Output value of VLAN marking */
};

/*
 * TCP connection rulr structure
 */
struct nss_ipv6_protocol_tcp_rule {
	uint8_t flow_window_scale;	/* Flow direction's window scaling factor */
	uint32_t flow_max_window;	/* Flow direction's largest seen window */
	uint32_t flow_end;		/* Flow direction's largest seen sequence + segment length */
	uint32_t flow_max_end;		/* Flow direction's largest seen ack + max(1, win) */
	uint32_t flow_mtu;		/* Flow interface`s MTU */
	uint8_t return_window_scale;	/* Return direction's window scaling factor */
	uint32_t return_max_window;	/* Return direction's largest seen window */
	uint32_t return_end;		/* Return direction's largest seen sequence + segment length */
	uint32_t return_max_end;	/* Return direction's largest seen ack + max(1, win) */
	uint32_t return_mtu;		/* Return interface`s MTU */
};

/*
 * QoS connection rule structure
 */
struct nss_ipv6_qos_rule {
	uint32_t qos_tag;			/* QoS tag associated with this rule */
};

/*
 * Error types for create rule (CR) msg
 */
enum {
	NSS_IPV6_CR_INVALID_PNODE_ERROR = 1,
	NSS_IPV6_CR_MISSING_CONNECTION_RULE_ERROR,
	NSS_IPV6_CR_BUFFER_ALLOC_FAIL_ERROR,
	NSS_IPV6_CR_PPPOE_SESSION_CREATION_ERROR,
};

/*
 * The IPv6 rule create sub-message structure.
 */
struct nss_ipv6_rule_create_msg {
	struct nss_ipv6_5tuple tuple;			/* Holds values of the 5 tuple */

	struct nss_ipv6_connection_rule conn_rule;	/* Basic connection specific data */
	struct nss_ipv6_protocol_tcp_rule tcp_rule;	/* Protocol related accleration parameters */
	struct nss_ipv6_pppoe_rule pppoe_rule;		/* PPPoE related accleration parameters */
	struct nss_ipv6_qos_rule qos_rule;		/* QoS related accleration parameters */
	struct nss_ipv6_dscp_rule dscp_rule;		/* DSCP related accleration parameters */
	struct nss_ipv6_vlan_rule vlan_rule;		/* VLAN related accleration parameters */

	uint32_t opaque[2];			/* NSS driver opaques */
	uint16_t valid_flags;			/* Bit flags associated with the validity of parameters */
	uint8_t rule_flags;			/* Bit flags associated with the rule */
};

/*
 * Error types for destroy rule (DR) msg
 */
enum {
	NSS_IPV6_DR_NO_CONNECTION_ENTRY_ERROR = 1,
};

/*
 * The IPv6 rule destroy sub-message structure.
 */
struct nss_ipv6_rule_destroy_msg {
	struct nss_ipv6_5tuple tuple;	/* Holds values of the 5 tuple */
	uint32_t opaque[2];		/* NSS driver opaques */
};

/*
 * Message types for ipv6
 */
typedef enum {
	NSS_IPV6_CREATE_RULE_MSG,		/* Message type - Rule create */
	NSS_IPV6_DESTROY_RULE_MSG,		/* Message type - Rule destroy */
} nss_ipv6_msg_types_t;

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
	uint16_t flow_mac[3];			/* Flow direction source MAC address */
	uint16_t flow_pppoe_session_id;		/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];	/* Flow direction`s PPPoE Server MAC address */
	uint16_t ingress_vlan_tag;		/* Ingress VLAN tag */
	int32_t return_interface;		/* Return interface number */
	uint32_t return_mtu;			/* MTU for return interface */
	uint32_t return_ip[4];			/* Return IP address */
	uint32_t return_ident;			/* Return ident (e.g. port) */
	uint16_t return_mac[3];			/* Return direction source MAC address */
	uint16_t return_pppoe_session_id;	/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];	/* Return direction's PPPoE Server MAC address */
	uint16_t egress_vlan_tag;		/* Egress VLAN tag */
	uint8_t flags;				/* Bit flags associated with the rule */
	uint32_t qos_tag;			/* Qos Tag */
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

	uint8_t flags;			/* Bit flags associated with the rule */
	uint32_t qos_tag;		/* Qos Tag */
};

/*
 * Message structure to send/receive IPv6 bridge/route commands
 */
struct nss_ipv6_msg {
	struct nss_cmn_msg cm;		/* Message Header */
	union {
		struct nss_ipv6_rule_create_msg rule_create;	/* Message: rule create */
		struct nss_ipv6_rule_destroy_msg rule_destroy;	/* Message: rule destroy */
		struct nss_ipv6_rule_establish rule_establish;	/* Message: rule establish confirmation */
		struct nss_ipv6_rule_sync rule_sync;	/* Message: stats sync */
	} msg;
};

/*
 * Virtual IF/Redirect
 */

/*
 * Request/Response types
 */
enum nss_virtual_if_metadata_types {
	NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_CREATE,
	NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_DESTROY,
	NSS_METADATA_TYPE_VIRTUAL_INTERFACE_MAX,
};

/*
 * The NSS virtual interface creation structure.
 */
struct nss_virtual_if_create {
	uint32_t flags;			/* Interface flags */
	uint8_t mac_addr[ETH_ALEN];	/* MAC address */
};

/*
 * The NSS virtual interface destruction structure.
 */
struct nss_virtual_if_destroy {
	int32_t reserved;		/* place holder */
};

/*
 * Message structure to send/receive virtual interface commands
 */
struct nss_virtual_if_msg {
	struct nss_cmn_msg cm;				/* Message Header */
	union {
		struct nss_virtual_if_create create;	/* Message: create virt if rule */
		struct nss_virtual_if_destroy destroy;	/* Message: destroy virt if rule */
	} msg;
};

/*
 * PPPoE
 */

/*
 * Request/Response types
 */
enum nss_pppoe_metadata_types {
	NSS_TX_METADATA_TYPE_PPPOE_DESTROY_SESSION,
	NSS_RX_METADATA_TYPE_PPPOE_RULE_STATUS,
	NSS_RX_METADATA_TYPE_PPPOE_STATS_SYNC,
	NSS_METADATA_TYPE_PPPOE_MAX
};

/*
 * Exception events from bridge/route handler
 */
enum exception_events_pppoe {
	NSS_EXCEPTION_EVENT_PPPOE_WRONG_VERSION_OR_TYPE,
	NSS_EXCEPTION_EVENT_PPPOE_WRONG_CODE,
	NSS_EXCEPTION_EVENT_PPPOE_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_PPPOE_UNSUPPORTED_PPP_PROTOCOL,
	NSS_EXCEPTION_EVENT_PPPOE_MAX,
};


/*
 * The NSS PPPoE rule destruction structure.
 */
struct nss_pppoe_destroy {
	uint16_t pppoe_session_id;	/* PPPoE session ID */
	uint16_t pppoe_remote_mac[3];	/* PPPoE server MAC address */
};

/*
 * The NSS PPPoE rule create success structure.
 */
struct nss_pppoe_rule_status {
	uint16_t pppoe_session_id;	/* PPPoE session ID on which stats are based */
	uint8_t pppoe_remote_mac[ETH_ALEN];
					/* PPPoE server MAC address */
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
 * Message structure to send/receive PPPoE session commands
 */
struct nss_pppoe_msg {
	struct nss_cmn_msg cm;		/* Message Header */
	union {
		struct nss_pppoe_destroy destroy;	/* Message: destroy pppoe rule */
		struct nss_pppoe_rule_status rule_status;	/* Message: rule status response */
		struct nss_pppoe_exception_stats_sync stats_sync;	/* Message: statistics sync */
	} msg;
};

/*
 * Physical interface rule structures
 */

/*
 * Request/Response types
 */
enum nss_if_metadata_types {
	NSS_TX_METADATA_TYPE_INTERFACE_OPEN,
	NSS_TX_METADATA_TYPE_INTERFACE_CLOSE,
	NSS_TX_METADATA_TYPE_INTERFACE_LINK_STATE_NOTIFY,
	NSS_TX_METADATA_TYPE_INTERFACE_MTU_CHANGE,
	NSS_TX_METADATA_TYPE_INTERFACE_MAC_ADDR_SET,
	NSS_TX_METADATA_TYPE_INTERFACE_MSS_SET,
	NSS_RX_METADATA_TYPE_INTERFACE_STATS_SYNC,
	NSS_METADATA_TYPE_INTERFACE_MAX,
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
 * The MSS (Maximum Segment Size) structure.
 */
struct nss_if_mss_set {
	uint16_t mss;			/* MSS value */
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
struct nss_if_msg {
	struct nss_cmn_msg cm;			/* Message Header */
	union {
		struct nss_if_link_state_notify link_state_notify;	/* Message: notify link status */
		struct nss_if_open open;	/* Message: open interface */
		struct nss_if_close close;	/* Message: close interface */
		struct nss_if_mtu_change mtu_change;	/* Message: MTU change notification */
		struct nss_if_mss_set mss_set;	/* Message: set MSS */
		struct nss_if_mac_address_set mac_address_set;	/* Message: set MAC address for i/f */
		struct nss_if_stats_sync stats_sync;	/* Message: statistics sync */
	} msg;
};

/*
 * C2C message structures
 */

/*
 * Request/Response types
 */
enum nss_c2c_metadata_types {
	NSS_TX_METADATA_TYPE_C2C_TX_MAP,
	NSS_METADATA_TYPE_C2C_MAX,
};

/*
 * NSS Tx Map
 */
struct nss_c2c_tx_map {
	uint32_t c2c_start;		/* Peer core C2C Rx queue start address */
	uint32_t c2c_int_addr;		/* Peer core C2C interrupt register address */
};

/*
 * Message structure to send/receive phys i/f commands
 */
struct nss_c2c_msg {
	struct nss_cmn_msg cm;              /* Message Header */
	union {
		struct nss_c2c_tx_map tx_map;
	} msg;
};

/*
 * General statistics messages
 */

/*
 * Request/Response types
 */
enum nss_offload_stats_metadata_types {
	NSS_RX_METADATA_TYPE_PER_INTERFACE_STATS_SYNC,
	NSS_RX_METADATA_TYPE_NSS_OFFLOAD_STATS_SYNC,
	NSS_METADATA_TYPE_OFFLOAD_STATS_MAX
};

/*
 * Exception events from bridge/route handler
 */
enum exception_events_unknown {
	NSS_EXCEPTION_EVENT_UNKNOWN_L2_PROTOCOL,
	NSS_EXCEPTION_EVENT_UNKNOWN_MAX
};

/*
 * Exception events from bridge/route handler
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
	NSS_EXCEPTION_EVENT_IPV4_ESP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ESP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_ESP_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_ESP_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_ESP_SMALL_TTL,
	NSS_EXCEPTION_EVENT_IPV4_ESP_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_IVID_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV4_6RD_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_6RD_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_6RD_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_6RD_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_DSCP_MARKING_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV4_VLAN_MARKING_MISMATCH,
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
	NSS_EXCEPTION_EVENT_IPV6_IVID_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV6_DSCP_MARKING_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV6_VLAN_MARKING_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV6_MAX
};

/*
 * The NSS per-interface statistics sync structure.
 */
struct nss_per_if_stats_sync {
	uint32_t interface;		/* Interface number */
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
struct nss_offload_stats_sync {
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
 * Message structure to send/receive phys i/f commands
 */
struct nss_offload_msg {
	struct nss_cmn_msg cm;			/* Message Header */
	union {
		struct nss_per_if_stats_sync per_if_stats_sync;		/* Message: interface stats sync */
		struct nss_offload_stats_sync offload_stats_sync;	/* Message: offload stats sync */
	} msg;
};

/*
 * 6RD (IPv6 in IPv4) tunnel messages
 */

/*
 * Request/Response types
 */
enum nss_tun6rd_metadata_types {
	NSS_RX_METADATA_TYPE_TUN6RD_STATS_SYNC,
	NSS_METADATA_TYPE_TUN6RD_MAX,
};

/*
 *  The NSS tun6rd statistics sync structure.
 */
struct nss_tun6rd_stats_sync {
	uint32_t rx_packets;		/* Number of packets received */
	uint32_t rx_bytes;		/* Number of bytes received */
	uint32_t tx_packets;		/* Number of packets transmitted */
	uint32_t tx_bytes;		/* Number of bytes transmitted */
};

/*
 * Message structure to send/receive 6rd commands
 */
struct nss_tun6rd_msg {
	struct nss_cmn_msg cm;			/* Message Header */
	union {
		struct nss_tun6rd_stats_sync stats_sync;		/* Message: interface stats sync */
	} msg;
};

/*
 * DS-Lite (IPv4 in IPv6) tunnel messages
 */

/*
 * Request/Response types
 */
enum nss_tunipip6_metadata_types {
	NSS_RX_METADATA_TYPE_TUNIPIP6_STATS_SYNC,
	NSS_METADATA_TYPE_TUNIPIP6_MAX,
};

/*
 * The NSS tunipip6 statistics sync structure.
 */
struct nss_tunipip6_stats_sync {
	uint32_t rx_packets;		/* Number of packets received */
	uint32_t rx_bytes;		/* Number of bytes received */
	uint32_t tx_packets;		/* Number of packets transmitted */
	uint32_t tx_bytes;		/* Number of bytes transmitted */
};

/*
 * Message structure to send/receive DS-Lite commands
 */
struct nss_tunipip6_msg {
	struct nss_cmn_msg cm;			/* Message Header */
	union {
		struct nss_tunipip6_stats_sync stats_sync;	/* Message: NSS stats sync */
	} msg;
};

/*
 * Crypto messages
 */

/*
 * Request/Response types
 */
enum nss_crypto_metadata_types {
	NSS_TX_METADATA_TYPE_CRYPTO_CONFIG,
	NSS_TX_METADATA_TYPE_CRYPTO_CLOSE,
	NSS_RX_METADATA_TYPE_CRYPTO_SYNC,
	NSS_METADATA_TYPE_CRYPTO_MAX,
};

/*
 * Crypto config command
 */
struct nss_crypto_config {
	uint32_t len;			/* Valid information length */
	uint8_t buf[1];			/* Buffer */
};

/*
 * Crypto stats sync structure
 */
struct nss_crypto_sync {
	uint32_t interface_num;
	uint32_t len;
	uint8_t buf[1];
};

/*
 * Message structure to send/receive crypto commands
 */
struct nss_crypto_msg {
	struct nss_cmn_msg cm;			/* Message Header */
	union {
		struct nss_crypto_config config;	/* Message: configure crypto rule */
		struct nss_crypto_sync sync;	/* Message: Crypto stats sync */
	} msg;
};

/*
 * IPsec messages
 */

/*
 * Request/Response types
 */
enum nss_ipsec_metadata_types {
	NSS_TX_METADATA_TYPE_IPSEC_RULE,
	NSS_RX_METADATA_TYPE_IPSEC_EVENTS_SYNC,
	NSS_METADATA_TYPE_IPSEC_MAX,
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
 * NSS IPsec event sync structure
 */
struct nss_ipsec_events_sync {
	uint32_t ipsec_if_num;
	uint32_t event_if_num;
	uint32_t len;
	uint8_t buf[1];
};

/*
 * Message structure to send/receive ipsec messages
 */
struct nss_ipsec_msg {
	struct nss_cmn_msg cm;			/* Message Header */
	union {
		struct nss_ipsec_rule rule;	/* Message: IPsec rule */
		struct nss_ipsec_events_sync sync;	/* Message: IPsec events sync */
	} msg;
};

/*
 * Generic interface messages
 */
enum nss_generic_metadata_types {
	NSS_TX_METADATA_TYPE_GENERIC_IF_PARAMS,
	NSS_METADATA_TYPE_GENERIC_IF_MAX
};

/*
 * Interface params command
 */
struct nss_generic_if_params {
	uint8_t buf[1];		/* Buffer */
};

/*
 * Message structure to send/receive ipsec messages
 */
struct nss_generic_msg {
	struct nss_cmn_msg cm;			/* Message Header */
	union {
		struct nss_generic_if_params rule;	/* Message: generic rule */
	} msg;
};

/*
 * NSS Profiler messages
 */

/*
 * Profiler Tx command
 */
struct nss_profiler_tx {
	uint32_t len;		/* Valid information length */
	uint8_t buf[1];		/* Buffer */
};

/*
 * Profiler sync
 */
struct nss_profiler_sync {
	uint32_t len;		/* Valid information length */
	uint8_t buf[1];		/* Buffer */
};

/*
 * NSS frequency scaling messages
 */
enum nss_freq_stats_metadata_types {
	COREFREQ_METADATA_TYPE_ERROR = 0,
	COREFREQ_METADATA_TYPE_RX_FREQ_CHANGE = 1,
	COREFREQ_METADATA_TYPE_TX_FREQ_ACK = 2,
	COREFREQ_METADATA_TYPE_TX_CORE_STATS = 3,
};

/*
 * The NSS freq start or stop strcture
 */
struct nss_freq_change {
	/* Request */
	uint32_t frequency;
	uint32_t start_or_end;
	uint32_t stats_enable;

	/* Response */
	uint32_t freq_current;
	int32_t ack;
};

/*
 * NSS core stats
 */
struct nss_core_stats {
	uint32_t inst_cnt_total;
};

/*
 * Message structure to send/receive NSS Freq commands
 */
struct nss_corefreq_msg {
	struct nss_cmn_msg cm;			/* Message Header */
	union {
		struct nss_freq_change nfc;	/* Message: freq stats */
		struct nss_core_stats ncs;	/* Message: NSS stats sync */
	} msg;
};

/*
 * struct nss_tx_shaper_config_assign_shaper
 */
struct nss_tx_shaper_config_assign_shaper {
	uint32_t shaper_num;		/* Number of the shaper to assign an existing one, or 0 if any new one will do.*/
};

/*
 * struct nss_tx_shaper_config_unassign_shaper
 */
struct nss_tx_shaper_config_unassign_shaper {
	uint32_t shaper_num;		/* Number of the shaper to unassign. */
};

/*
 * enum nss_tx_shaper_node_types
 *	Types of shaper node we export to the HLOS
 */
enum nss_tx_shaper_node_types {
	NSS_TX_SHAPER_NODE_TYPE_CODEL = 1,		/* Matched SHAPER_NODE_TYPE_CODEL */
	NSS_TX_SHAPER_NODE_TYPE_PRIO = 3,		/* Matches SHAPER_NODE_TYPE_PRIO */
	NSS_TX_SHAPER_NODE_TYPE_FIFO = 4,		/* Matches SHAPER_NODE_TYPE_FIFO */
	NSS_TX_SHAPER_NODE_TYPE_TBL = 5,		/* Matched SHAPER_NODE_TYPE_FIFO */
};
typedef enum nss_tx_shaper_node_types nss_tx_shaper_node_type_t;

/*
 * struct nss_tx_shaper_config_alloc_shaper_node
 */
struct nss_tx_shaper_config_alloc_shaper_node {
	nss_tx_shaper_node_type_t node_type;
					/* Type of shaper node */
	uint32_t qos_tag;		/* The qos tag to give the new node */
};

/*
 * struct nss_tx_shaper_config_free_shaper_node
 */
struct nss_tx_shaper_config_free_shaper_node {
	uint32_t qos_tag;		/* The qos tag of the node to free */
};

/*
 * struct nss_tx_shaper_config_set_root_node
 */
struct nss_tx_shaper_config_set_root_node {
	uint32_t qos_tag;		/* The qos tag of the node that becomes root */
};

/*
 * struct nss_tx_shaper_config_set_default_node
 */
struct nss_tx_shaper_config_set_default_node {
	uint32_t qos_tag;		/* The qos tag of the node that becomes default */
};

/*
 * struct nss_tx_shaper_shaper_node_basic_stats_get
 *	Obtain basic stats for a shaper node
 */
struct nss_tx_shaper_shaper_node_basic_stats_get {
	uint32_t qos_tag;		/* The qos tag of the node from which to obtain basic stats */
};

/*
 * struct nss_tx_shaper_config_prio_attach
 */
struct nss_tx_shaper_config_prio_attach {
	uint32_t child_qos_tag;		/* Qos tag of shaper node to add as child */
	uint32_t priority;		/* Priority of the child */
};

/*
 * struct nss_tx_shaper_config_prio_detach
 */
struct nss_tx_shaper_config_prio_detach {
	uint32_t priority;		/* Priority of the child to detach */
};

/*
 * struct nss_tx_shaper_config_codel_alg_param
 */
struct nss_tx_shaper_config_codel_alg_param {
	uint16_t interval;		/* Buffer time to smoothen state transition */
	uint16_t target;		/* Acceptable delay associated with a queue */
	uint16_t mtu;			/* MTU for the associated interface */
};

/*
 * struct nss_tx_shaper_configure_codel_param
 */
struct nss_tx_shaper_config_codel_param {
	int32_t qlen_max;					/* Max no. of packets that can be enqueued */
	struct nss_tx_shaper_config_codel_alg_param cap;	/* Config structure for codel algorithm */
};

/*
 * struct nss_tx_shaper_config_limiter_alg_param
 */
struct nss_tx_shaper_config_limiter_alg_param {
	uint32_t rate;		/* Allowed Traffic rate measured in bytes per second */
	uint32_t burst;		/* Max bytes that can be sent before the next token update */
	uint32_t max_size;	/* The maximum size of packets (in bytes) supported */
	bool short_circuit;	/* When set, limiter will stop limiting the sending rate */
};

/*
 * struct nss_tx_shaper_configure_tbl_attach
 */
struct nss_tx_shaper_config_tbl_attach {
	uint32_t child_qos_tag;						/* Qos tag of shaper node to add as child */
};

/*
 * struct nss_tx_shaper_configure_tbl_param
 */
struct nss_tx_shaper_config_tbl_param {
	uint32_t qlen_bytes;						/* Max size of queue in bytes */
	struct nss_tx_shaper_config_limiter_alg_param lap_cir;	/* Config committed information rate */
	struct nss_tx_shaper_config_limiter_alg_param lap_pir;	/* Config committed information rate */
};

/*
 * struct nss_tx_shaper_config_bf_attach
 */
struct nss_tx_shaper_config_bf_attach {
	uint32_t child_qos_tag;		/* Qos tag of the shaper node to add as child */
};

/*
 * struct nss_tx_shaper_config_bf_detach
 */
struct nss_tx_shaper_config_bf_detach {
	uint32_t child_qos_tag;		/* Qos tag of the shaper node to add as child */
};

/*
 * struct nss_tx_shaper_config_bf_group_attach
 */
struct nss_tx_shaper_config_bf_group_attach {
	uint32_t child_qos_tag;		/* Qos tag of shaper node to add as child */
};

/*
 * struct nss_tx_shaper_config_bf_group_param
 */
struct nss_tx_shaper_config_bf_group_param {
	uint32_t qlen_bytes;					/* Maximum size of queue in bytes */
	uint32_t quantum;					/* Smallest increment value for the DRRs */
	struct nss_tx_shaper_config_limiter_alg_param lap;	/* Config structure for codel algorithm */
};

/*
 * enum nss_shaper_config_fifo_drop_modes
 *	Different drop modes for fifo
 */
enum nss_tx_shaper_config_fifo_drop_modes {
	NSS_TX_SHAPER_FIFO_DROP_MODE_HEAD = 0,
	NSS_TX_SHAPER_FIFO_DROP_MODE_TAIL,
	NSS_TX_SHAPER_FIFO_DROP_MODES,			/* Must be last */
};
typedef enum nss_tx_shaper_config_fifo_drop_modes nss_tx_shaper_config_fifo_drop_mode_t;

/*
 * struct pnode_h2c_shaper_config_fifo_param
 */
struct nss_tx_shaper_config_fifo_param {
	uint32_t limit;						/* Queue limit in packets */
	nss_tx_shaper_config_fifo_drop_mode_t drop_mode;	/* FIFO drop mode when queue is full */
};

/*
 * struct nss_tx_shaper_node_config
 *	Configurartion messages for shaper nodes, which one depends on the type of configuration message
 *
 * This structure contains all of the different node configuration messages that can be sent, though not to all shaper node types.
 */
struct nss_tx_shaper_node_config {
	uint32_t qos_tag;		/* Identifier of the shaper node to which the config is targetted */
	union {
		struct nss_tx_shaper_config_prio_attach prio_attach;
		struct nss_tx_shaper_config_prio_detach prio_detach;
		struct nss_tx_shaper_config_codel_param codel_param;
		struct nss_tx_shaper_config_tbl_attach tbl_attach;
		struct nss_tx_shaper_config_tbl_param tbl_param;
		struct nss_tx_shaper_config_bf_attach bf_attach;
		struct nss_tx_shaper_config_bf_detach bf_detach;
		struct nss_tx_shaper_config_bf_group_attach bf_group_attach;
		struct nss_tx_shaper_config_bf_group_param bf_group_param;
		struct nss_tx_shaper_config_fifo_param fifo_param;
	} snc;
};

/*
 * enum nss_tx_shaper_config_types
 *	Types of shaper configuration messages
 */
enum nss_tx_shaper_config_types {
	NSS_TX_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER,	/* Assign a shaper to an interface (B or I) */
	NSS_TX_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE,	/* Allocate a type of shaper node and give it a qos tag */
	NSS_TX_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE,	/* Free a shaper node */
	NSS_TX_SHAPER_CONFIG_TYPE_PRIO_ATTACH,		/* Configure prio to attach a node with a given priority */
	NSS_TX_SHAPER_CONFIG_TYPE_PRIO_DETACH,		/* Configure prio to detach a node at a given priority */
	NSS_TX_SHAPER_CONFIG_TYPE_SET_DEFAULT,		/* Configure shaper to have a default node */
	NSS_TX_SHAPER_CONFIG_TYPE_SET_ROOT,		/* Configure shaper to have a root node */
	NSS_TX_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER,	/* Unassign a shaper from an interface (B or I) */
	NSS_TX_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM,	/* Configure codel parameters */
	NSS_TX_SHAPER_CONFIG_TYPE_TBL_ATTACH,		/* Configure tbl to attach a node as child */
	NSS_TX_SHAPER_CONFIG_TYPE_TBL_DETACH,		/* Configure tbl to detach its child */
	NSS_TX_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM,	/* Configure tbl to tune its parameters */
	NSS_TX_SHAPER_CONFIG_TYPE_BF_ATTACH,		/* Configure bf to attach a node to its round robin list */
	NSS_TX_SHAPER_CONFIG_TYPE_BF_DETACH,		/* Configure bf to detach a node with a particular QoS tag */
	NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_ATTACH,	/* Configure bf group to attach a node as child */
	NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_DETACH,	/* Configure bf group to detach its child */
	NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_CHANGE_PARAM,
							/* Configure bf group to tune its parameters */
	NSS_TX_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM,	/* Configure fifo */
	NSS_TX_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET,
							/* Get shaper node basic stats */
};
typedef enum nss_tx_shaper_config_types nss_tx_shaper_config_type_t;

/*
 * struct nss_tx_shaper_configure
 *	Shaper configuration messages
 */
struct nss_tx_shaper_configure {
	uint32_t opaque1;		/* DO NOT TOUCH, HLOS USE ONLY */
	uint32_t reserved1;		/* DO NOT TOUCH */
	uint32_t opaque2;		/* DO NOT TOUCH, HLOS USE ONLY */
	uint32_t reserved2;		/* DO NOT TOUCH */
	uint32_t opaque3;		/* DO NOT TOUCH, HLOS USE ONLY */
	uint32_t reserved3;		/* DO NOT TOUCH */
	uint32_t reserved4;		/* DO NOT TOUCH */
	uint32_t reserved5;		/* DO NOT TOUCH */
	uint32_t interface_num;		/* Interface (pnode) number for which the shaper config message is targetted */
	bool i_shaper;			/* true when I shaper, false when B shaper */
	nss_tx_shaper_config_type_t type;
					/* Type of configuration message mt */
	union {
		struct nss_tx_shaper_config_assign_shaper assign_shaper;
		struct nss_tx_shaper_config_assign_shaper unassign_shaper;
		struct nss_tx_shaper_config_alloc_shaper_node alloc_shaper_node;
		struct nss_tx_shaper_config_free_shaper_node free_shaper_node;
		struct nss_tx_shaper_config_set_default_node set_default_node;
		struct nss_tx_shaper_config_set_root_node set_root_node;
		struct nss_tx_shaper_node_config shaper_node_config;
		struct nss_tx_shaper_shaper_node_basic_stats_get shaper_node_basic_stats_get;
	} mt;
};

/*
 * Types of TX metadata.
 */
enum nss_tx_metadata_types {
	NSS_TX_METADATA_TYPE_PROFILER_TX,
	NSS_TX_METADATA_TYPE_NSS_FREQ_CHANGE,
	NSS_TX_METADATA_TYPE_SHAPER_CONFIGURE,
};

/*
 * Structure that describes all TX metadata objects.
 */
struct nss_tx_metadata_object {
	enum nss_tx_metadata_types type;	/* Object type */
	union {				/* Sub-message type */
		struct nss_profiler_tx profiler_tx;
		struct nss_freq_change freq_change;
		struct nss_tx_shaper_configure shaper_configure;
	} sub;
};

/*
 * Structure that describes all TX metadata objects.
 */
struct nss_tx_metadata_object1 {
	enum nss_tx_metadata_types type;	/* Object type */
	union {				/* Sub-message type */
		struct nss_profiler_tx profiler_tx;
		struct nss_freq_change freq_change;
		struct nss_tx_shaper_configure shaper_configure;
	} sub;
};

/*
 * enum nss_rx_shaper_response_types
 *	Types of shaper configuration response messages
 */
enum nss_rx_shaper_response_types {
	/*
	 * Failure messages are < 0
	 */
	NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPERS = -65536,		/* No shaper available for a shaper assign command to succeed */
	NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPER,				/* No shaper to which to issue a shaper or node configuration message */
	NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODE,			/* No shaper node to which to issue a configuration message */
	NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODES,			/* No available shaper nodes available of the type requested */
	NSS_RX_SHAPER_RESPONSE_TYPE_OLD,				/* Request is old / environment changed by the time the request was processed */
	NSS_RX_SHAPER_RESPONSE_TYPE_UNRECOGNISED,			/* Request is not recognised by the recipient */
	NSS_RX_SHAPER_RESPONSE_TYPE_FIFO_QUEUE_LIMIT_INVALID,		/* Fifo queue Limit is bad */
	NSS_RX_SHAPER_RESPONSE_TYPE_FIFO_DROP_MODE_INVALID,		/* Fifo Drop mode is bad */
	NSS_RX_SHAPER_RESPONSE_TYPE_BAD_DEFAULT_CHOICE,			/* Node selected has no queue to enqueue to */
	NSS_RX_SHAPER_RESPONSE_TYPE_DUPLICATE_QOS_TAG,			/* Duplicate QoS tag as another node */
        NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CIR_RATE_AND_BURST_REQUIRED,	/* CIR rate and burst are mandatory */
	NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CIR_BURST_LESS_THAN_MTU,	/* CIR burst size is smaller than MTU */
	NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_LESS_THAN_MTU,	/* PIR burst size is smaller than MTU */
	NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_REQUIRED,		/* PIR burst size must be provided if peakrate
									 * limiting is required.
									 */
	NSS_RX_SHAPER_RESPONSE_TYPE_CODEL_ALL_PARAMS_REQUIRED,		/* Codel requires non-zero value for target,
									 * interval and limit.
									 */
	/*
	 * Success messages are >= 0
	 */
	NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_ASSIGN_SUCCESS = 0,		/* Successfully assigned a shaper */
	NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_NODE_ALLOC_SUCCESS,		/* Alloc shaper node request successful */
	NSS_RX_SHAPER_RESPONSE_TYPE_PRIO_ATTACH_SUCCESS,		/* Prio attach success */
	NSS_RX_SHAPER_RESPONSE_TYPE_PRIO_DETACH_SUCCESS,		/* Prio detach success */
	NSS_RX_SHAPER_RESPONSE_TYPE_CODEL_CHANGE_PARAM_SUCCESS,		/* Codel parameter configuration success */
	NSS_RX_SHAPER_RESPONSE_TYPE_TBL_ATTACH_SUCCESS,			/* Tbl attach success */
	NSS_RX_SHAPER_RESPONSE_TYPE_TBL_DETACH_SUCCESS,			/* Tbl detach success */
	NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CHANGE_PARAM_SUCCESS,		/* Tbl parameter configuration success */
	NSS_RX_SHAPER_RESPONSE_TYPE_BF_ATTACH_SUCCESS,			/* Bigfoot attach success */
	NSS_RX_SHAPER_RESPONSE_TYPE_BF_DETACH_SUCCESS,			/* Bigfoot detach success */
	NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_ATTACH_SUCCESS,		/* Bigfoot group attach success */
	NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_DETACH_SUCCESS,		/* Bigfoot group detach success */
	NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_CHANGE_PARAM_SUCCESS,	/* Bigfoot group parameter configuration success */
	NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_SET_ROOT_SUCCESS,		/* Setting of root successful */
	NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_SET_DEFAULT_SUCCESS,		/* Setting of default successful */
	NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_NODE_FREE_SUCCESS,		/* Free shaper node request successful */
	NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_UNASSIGN_SUCCESS,		/* Successfully unassigned a shaper */
	NSS_RX_SHAPER_RESPONSE_TYPE_FIFO_CHANGE_PARAM_SUCCESS,		/* Fifo limit set success */
	NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_NODE_BASIC_STATS_GET_SUCCESS,
									/* Success response for a shaper node basic stats get request */
};
typedef enum nss_rx_shaper_response_types nss_rx_shaper_response_type_t;

/*
 * struct nss_rx_shaper_response_shaper_assign_success
 *	Shaper successfully assigned
 */
struct nss_rx_shaper_response_shaper_assign_success {
	uint32_t shaper_num;		/* Number of the shaper assigned */
};

/*
 * struct nss_rx_shaper_node_basic_statistics_delta
 *	Stastics that are sent as deltas
 */
struct nss_rx_shaper_node_basic_statistics_delta {
	uint32_t enqueued_bytes;			/* Bytes enqueued successfully */
	uint32_t enqueued_packets;			/* Packets enqueued successfully */
	uint32_t enqueued_bytes_dropped;		/* Bytes dropped during an enqueue operation due to node limits */
	uint32_t enqueued_packets_dropped;		/* Packets dropped during an enqueue operation due to node limits */
	uint32_t dequeued_bytes;			/* Bytes dequeued successfully from a shaper node */
	uint32_t dequeued_packets;			/* Packets dequeued successfully from a shaper node */
	uint32_t dequeued_bytes_dropped;		/* Bytes dropped by this node during dequeue (some nodes drop packets during dequeue rather than enqueue) */
	uint32_t dequeued_packets_dropped;		/* Packets dropped by this node during dequeue (some nodes drop packets during dequeue rather than enqueue) */
	uint32_t queue_overrun;				/* Number of times any queue limit has been overrun / perhaps leading to a drop of packet(s) */
};

/*
 * struct nss_rx_shaper_response_shaper_node_basic_stats_get_success
 *	Response to a request for basic stats of a shaper node
 */
struct nss_rx_shaper_response_shaper_node_basic_stats_get_success {
	uint32_t qlen_bytes;				/* Total size of all packets in queue */
	uint32_t qlen_packets;				/* Number of packets waiting in queue */
	uint32_t packet_latency_peak_msec_dequeued;	/* Maximum milliseconds a packet was in this shaper node before being dequeued */
	uint32_t packet_latency_minimum_msec_dequeued;	/* Minimum milliseconds a packet was in this shaper node before being dequeued */
	uint32_t packet_latency_peak_msec_dropped;	/* Maximum milliseconds a packet was in this shaper node before being dropped */
	uint32_t packet_latency_minimum_msec_dropped;	/* Minimum milliseconds a packet was in this shaper node before being dropped */
	struct nss_rx_shaper_node_basic_statistics_delta delta;
							/* Statistics that are sent as deltas */
};

/*
 * union nss_rx_shaper_responses
 *	Types of response message
 */
union nss_rx_shaper_responses {
	struct nss_rx_shaper_response_shaper_assign_success shaper_assign_success;
	struct nss_rx_shaper_response_shaper_node_basic_stats_get_success shaper_node_basic_stats_get_success;
};

/*
 * struct nss_rx_shaper_response
 *	Shaper configuration response messages
 */
struct nss_rx_shaper_response {
	struct nss_tx_shaper_configure request;
					/* Original request to which this response relates */
	nss_rx_shaper_response_type_t type;
					/* The response type (rt) being issued to the request */
	union nss_rx_shaper_responses rt;
};

/*
 * Types of RX metadata.
 */
enum nss_rx_metadata_types {
	NSS_RX_METADATA_TYPE_PROFILER_SYNC,
	NSS_RX_METADATA_TYPE_SHAPER_RESPONSE,
};

/*
 * Structure that describes all RX metadata objects.
 */
struct nss_rx_metadata_object {
	enum nss_rx_metadata_types type;	/* Object type */
	union {				/* Sub-message type */
		struct nss_profiler_sync profiler_sync;
		struct nss_rx_shaper_response shaper_response;
	} sub;
};

/*
 * H2N Buffer Types
 */
#define H2N_BUFFER_EMPTY			0
#define H2N_BUFFER_PACKET			2
#define H2N_BUFFER_CTRL				4
#define H2N_BUFFER_CRYPTO_REQ			7
#define H2N_BUFFER_NATIVE_WIFI	    8
#define H2N_BUFFER_SHAPER_BOUNCE_INTERFACE	9
#define H2N_BUFFER_SHAPER_BOUNCE_BRIDGE	10
#define H2N_BUFFER_MAX				16

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
	uint16_t buffer_len;
				/* Length of the buffer (in bytes) */
	uint16_t metadata_off;
				/* Reserved for future use */
	uint16_t payload_len;
				/* Length of the active payload of the buffer (in bytes) */
	uint16_t mss;	/* MSS to be used with TSO/UFO */
	uint16_t payload_offs;
				/* Offset from the start of the buffer to the start of the payload (in bytes) */
	uint16_t interface_num;
				/* Interface number to which the buffer is to be sent (where appropriate) */
	uint8_t buffer_type;
				/* Type of buffer */
	uint8_t reserved3;
				/* Reserved for future use */
	uint16_t bit_flags;
				/* Bit flags associated with the buffer */
	uint32_t qos_tag;
				/* QoS tag information of the buffer (where appropriate) */
	uint32_t reserved4;	/* Reserved for future use */
};

/*
 * N2H Buffer Types
 */
#define N2H_BUFFER_EMPTY			1
#define N2H_BUFFER_PACKET			3
#define N2H_BUFFER_COMMAND_RESP			5
#define N2H_BUFFER_STATUS			6
#define N2H_BUFFER_CRYPTO_RESP			8
#define N2H_BUFFER_PACKET_VIRTUAL		10
#define N2H_BUFFER_SHAPER_BOUNCED_INTERFACE	11
#define N2H_BUFFER_SHAPER_BOUNCED_BRIDGE	12
#define N2H_BUFFER_MAX				16

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
	uint16_t buffer_len;
				/* Length of the buffer (in bytes) */
	uint16_t reserved1;
				/* Reserved for future use */
	uint16_t payload_len;
				/* Length of the active payload of the buffer (in bytes) */
	uint16_t reserved2;
				/* Reserved for future use */
	uint16_t payload_offs;
				/* Offset from the start of the buffer to the start of the payload (in bytes) */
	uint16_t interface_num;
				/* Interface number to which the buffer is to be sent (where appropriate) */
	uint8_t buffer_type;
				/* Type of buffer */
	uint8_t response_type;
				/* Response type if the buffer is a command response */
	uint16_t bit_flags;
				/* Bit flags associated with the buffer */
	uint32_t timestamp_lo;
				/* Low 32 bits of any timestamp associated with the buffer */
	uint32_t timestamp_hi;
				/* High 32 bits of any timestamp associated with the buffer */
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
	volatile uint32_t n2h_nss_index[15];
			/* Index number for the next descriptor that will be written by the NSS in the N2H0 descriptor ring (NSS owned) */
	uint8_t num_phys_ports;
	uint8_t reserved1[3];	/* Reserved for future use */
	uint32_t h2n_hlos_index[16];
			/* Index number for the next descriptor that will be written by the HLOS in the H2N0 descriptor ring (HLOS owned) */
	volatile uint32_t n2h_hlos_index[15];
			/* Index number for the next descriptor that will be read by the HLOS in the N2H0 descriptor ring (HLOS owned) */
	uint32_t c2c_start;	/* Reserved for future use */
};
#endif /* __NSS_HLOS_IF_H */
