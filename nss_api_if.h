/* * Copyright (c) 2013 Qualcomm Atheros, Inc. * */

/**
 * na_api_if.h
 *	NSS driver APIs and Declarations.
 */

#ifndef __NSS_API_IF_H
#define __NSS_API_IF_H

#include <linux/if_ether.h>
#include <linux/skbuff.h>

/**
 * Custom types recognised within the Network Accelerator (Linux independent)
 */
typedef uint8_t mac_addr_t[6];
typedef uint32_t ipv4_addr_t;
typedef uint32_t ipv6_addr_t[4];

#define IN6_ADDR_TO_IPV6_ADDR(ipv6, in6) \
	{ \
		((uint32_t *)ipv6)[0] = in6.in6_u.u6_addr32[0]; \
		((uint32_t *)ipv6)[1] = in6.in6_u.u6_addr32[1]; \
		((uint32_t *)ipv6)[2] = in6.in6_u.u6_addr32[2]; \
		((uint32_t *)ipv6)[3] = in6.in6_u.u6_addr32[3]; \
	}
#define IPV6_ADDR_TO_IN6_ADDR(in6, ipv6) \
	{ \
		in6.in6_u.u6_addr32[0] = ((uint32_t *)ipv6)[0]; \
		in6.in6_u.u6_addr32[1] = ((uint32_t *)ipv6)[1]; \
		in6.in6_u.u6_addr32[2] = ((uint32_t *)ipv6)[2]; \
		in6.in6_u.u6_addr32[3] = ((uint32_t *)ipv6)[3]; \
	}

#define IPV6_ADDR_OCTAL_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define IPV6_ADDR_TO_OCTAL(ipv6) ((uint16_t *)ipv6)[0], ((uint16_t *)ipv6)[1], ((uint16_t *)ipv6)[2], ((uint16_t *)ipv6)[3], ((uint16_t *)ipv6)[4], ((uint16_t *)ipv6)[5], ((uint16_t *)ipv6)[6], ((uint16_t *)ipv6)[7]

#define IS_VIRTUAL_INTERFACE(num) ((num) >= ubi32_na.num_physical_interfaces)
#define IS_PHYSICAL_INTERFACE(num) ((num) < ubi32_na.num_physical_interfaces)
#define INTERFACE_NUMBER_TO_VIRTUAL(num) ((num) - ubi32_na.num_physical_interfaces)

/**
 * IPv4 rule sync reasons.
 */
#define NSS_IPV4_RULE_SYNC_REASON_STATS 0
					/** Sync is to synchronize stats */
#define NSS_IPV4_RULE_SYNC_REASON_FLUSH 1
					/** Sync is to flush a cache entry */
#define NSS_IPV4_RULE_SYNC_REASON_EVICT 2
					/** Sync is to evict a cache entry */
#define NSS_IPV4_RULE_SYNC_REASON_DESTROY 3
					/** Sync is to destroy a cache entry (requested by host OS) */
#define NSS_IPV4_RULE_SYNC_REASON_PPPOE_DESTROY 4
					/** Sync is to destroy a cache entry which belongs to a particular PPPoE session */

/**
 * IPv4 connection creation structure.
 */
struct nss_ipv4_create {
	int32_t src_interface_num;
	int32_t dest_interface_num;
	int protocol;
	uint32_t flags;
	uint32_t from_mtu;
	uint32_t to_mtu;
	uint32_t src_ip;
	int32_t src_port;
	uint32_t src_ip_xlate;
	int32_t src_port_xlate;
	uint32_t dest_ip;
	int32_t dest_port;
	uint32_t dest_ip_xlate;
	int32_t dest_port_xlate;
	uint8_t src_mac[ETH_ALEN];
	uint8_t dest_mac[ETH_ALEN];
	uint8_t src_mac_xlate[ETH_ALEN];
	uint8_t dest_mac_xlate[ETH_ALEN];
	uint8_t flow_window_scale;
	uint32_t flow_max_window;
	uint32_t flow_end;
	uint32_t flow_max_end;
	uint16_t flow_pppoe_session_id;
	uint8_t flow_pppoe_remote_mac[ETH_ALEN];
	uint8_t return_window_scale;
	uint32_t return_max_window;
	uint32_t return_end;
	uint32_t return_max_end;
	uint16_t return_pppoe_session_id;
	uint8_t return_pppoe_remote_mac[ETH_ALEN];
	uint8_t spo_needed;
	uint32_t param_a0;
	uint32_t param_a1;
	uint32_t param_a2;
	uint32_t param_a3;
	uint32_t param_a4;
};

/**
 * IPv4 connection flags.
 */
#define NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK 0x1
 					/** Indicates that we should not check sequence numbers */

/**
 * IPv4 connection destruction structure.
 */
struct nss_ipv4_destroy {
	int protocol;
	uint32_t src_ip;
	int32_t src_port;
	uint32_t dest_ip;
	int32_t dest_port;
};

/**
 * IPv6 rule sync reasons.
 */
#define NSS_IPV6_RULE_SYNC_REASON_STATS 0
					/** Sync is to synchronize stats */
#define NSS_IPV6_RULE_SYNC_REASON_FLUSH 1
					/** Sync is to flush a cache entry */
#define NSS_IPV6_RULE_SYNC_REASON_EVICT 2
					/** Sync is to evict a cache entry */
#define NSS_IPV6_RULE_SYNC_REASON_DESTROY 3
					/** Sync is to destroy a cache entry (requested by host OS) */
#define NSS_IPV6_RULE_SYNC_REASON_PPPOE_DESTROY 4
					/** Sync is to destroy a cache entry which belongs to a particular PPPoE session */

/**
 * IPv6 connection creation structure.
 */
struct nss_ipv6_create {
	int32_t src_interface_num;
	int32_t dest_interface_num;
	int protocol;
	uint32_t flags;
	uint32_t from_mtu;
	uint32_t to_mtu;
	uint32_t src_ip[4];
	int32_t src_port;
	uint32_t dest_ip[4];
	int32_t dest_port;
	uint8_t src_mac[ETH_ALEN];
	uint8_t dest_mac[ETH_ALEN];
	uint8_t flow_window_scale;
	uint32_t flow_max_window;
	uint32_t flow_end;
	uint32_t flow_max_end;
	uint16_t flow_pppoe_session_id;
	uint8_t flow_pppoe_remote_mac[ETH_ALEN];
	uint8_t return_window_scale;
	uint32_t return_max_window;
	uint32_t return_end;
	uint32_t return_max_end;
	uint16_t return_pppoe_session_id;
	uint8_t return_pppoe_remote_mac[ETH_ALEN];
};

/**
 * IPv6 connection flags.
 */
#define NSS_IPV6_CREATE_FLAG_NO_SEQ_CHECK 0x1
 					/** Indicates that we should not check sequence numbers */

/**
 * IPv6 connection destruction structure.
 */
struct nss_ipv6_destroy {
	int protocol;
	uint32_t src_ip[4];
	int32_t src_port;
	uint32_t dest_ip[4];
	int32_t dest_port;
};

/**
 * Rule sync reasons.
 */
#define NSS_L2SWITCH_RULE_SYNC_REASON_STATS 0
					/**  Sync is to synchronize stats */
#define NSS_L2SWITCH_RULE_SYNC_REASON_FLUSH 1
					/**  Sync is to flush a cache entry */
#define NSS_L2SWITCH_RULE_SYNC_REASON_EVICT 2
					/**  Sync is to evict a cache entry */
#define NSS_L2SWITCH_RULE_SYNC_REASON_DESTROY 3
					/**  Sync is to destroy a cache entry (requested by host OS) */

/**
 * l2 switch entry creation structure.
 */
struct nss_l2switch_create {
	uint16_t addr[3];
	uint8_t state;
	uint8_t priority;
	int32_t interface_num;
	uint16_t port_no;
	uint16_t port_id;
};

/**
 * l2 switch entry destruction structure.
 */
struct nss_l2switch_destroy {
	int32_t interface_num;
	uint16_t addr[3];
};

/**
 * IPsec Tx rule create
 */
struct nss_ipsec_tx_create {
	uint32_t spi;
	uint32_t replay;
	uint32_t src_addr;
	uint32_t dest_addr;
	uint32_t ses_idx;
};

/**
 * IPsec Tx rule destroy
 */
struct nss_ipsec_tx_destroy {
	uint32_t ses_idx;
};

/**
 * IPsec Rx rule create
 */
struct nss_ipsec_rx_create {
	uint32_t spi;
	uint32_t replay;
	uint32_t src_addr;
	uint32_t dest_addr;
	uint32_t ses_idx;
};

/**
 * IPsec Rx rule destroy
 */
struct nss_ipsec_rx_destroy {
	uint32_t ses_idx;
};

/**
 * struct nss_ipv4_sync
 *	Update packet stats (bytes / packets seen over a connection) and also keep alive.
 *
 * NOTE: The addresses here are NON-NAT addresses, i.e. the true endpoint addressing.
 * 'src' is the creator of the connection.
 */
struct nss_ipv4_sync {
	int protocol;			/** IP protocol number (IPPROTO_...) */
	ipv4_addr_t src_addr;		/** Non-NAT source address, i.e. the creator of the connection */
	int32_t src_port;		/** Non-NAT source port */
	ipv4_addr_t src_addr_xlate;	/** NAT translated source address, i.e. the creator of the connection */
	int32_t src_port_xlate;		/** NAT translated source port */
	ipv4_addr_t dest_addr;		/** Non-NAT destination address, i.e. the to whom the connection was created */
	int32_t dest_port;		/** Non-NAT destination port */
	ipv4_addr_t dest_addr_xlate;	/** NAT translated destination address, i.e. the to whom the connection was created */
	int32_t dest_port_xlate;	/** NAT translated destination port */
	uint32_t flow_max_window;
	uint32_t flow_end;
	uint32_t flow_max_end;
	uint32_t flow_packet_count;
	uint32_t flow_byte_count;
	uint32_t return_max_window;
	uint32_t return_end;
	uint32_t return_max_end;
	uint32_t return_packet_count;
	uint32_t return_byte_count;
	unsigned long int delta_jiffies;
					/** Time in Linux jiffies to be added to the current timeout to keep the connection alive */
	uint8_t reason;			/** Reason of synchronization */
	uint32_t param_a0;
	uint32_t param_a1;
	uint32_t param_a2;
	uint32_t param_a3;
	uint32_t param_a4;
};

/**
 * struct nss_ipv6_sync
 *	Update packet stats (bytes / packets seen over a connection) and also keep alive.
 *
 * NOTE: The addresses here are NON-NAT addresses, i.e. the true endpoint addressing.
 * 'src' is the creator of the connection.
 */
struct nss_ipv6_sync {
	int protocol;			/** IP protocol number (IPPROTO_...) */
	ipv6_addr_t src_addr;		/** Non-NAT source address, i.e. the creator of the connection */
	int32_t src_port;		/** Non-NAT source port */
	ipv6_addr_t dest_addr;		/** Non-NAT destination address, i.e. the to whom the connection was created */
	int32_t dest_port;		/** Non-NAT destination port */
	uint32_t flow_max_window;
	uint32_t flow_end;
	uint32_t flow_max_end;
	uint32_t flow_packet_count;
	uint32_t flow_byte_count;
	uint32_t return_max_window;
	uint32_t return_end;
	uint32_t return_max_end;
	uint32_t return_packet_count;
	uint32_t return_byte_count;
	unsigned long int delta_jiffies;
					/** Time in Linux jiffies to be added to the current timeout to keep the connection alive */
	uint8_t final_sync;		/** Non-zero when the NA has ceased to accelerate the given connection */
	uint8_t evicted;		/** Non-zero if connection evicted */
};

/**
 * struct nss_l2switch_sync
 *	Update packet stats (bytes / packets seen over a connection) and also keep alive.
 */
struct nss_l2switch_sync {
	uint16_t addr[3];
	uint8_t reason;			/** Reason of synchronization */
	void *dev;
	unsigned long int delta_jiffies;
					/** Time in Linux jiffies to be added to the current timeout to keep the connection alive */
};

/*
 * struct nss_gmac_sync
 * The NA per-GMAC statistics sync structure.
 */
struct nss_gmac_sync {
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

/**
 * type nss_tx_status_t
 *	Tx command status
 */
typedef enum {
	NSS_TX_SUCCESS = 0,
	NSS_TX_FAILURE,
	NSS_TX_FAILURE_NOT_READY,
} nss_tx_status_t;

/**
 * type nss_state_t
 *	NSS state status
 */
typedef enum {
	NSS_STATE_UNINITIALIZED = 0,
	NSS_STATE_INITIALIZED
} nss_state_t;

/**
 * type nss_core_id_t
 *	NSS core id
 */
typedef enum {
	NSS_CORE_0 = 0,
	NSS_CORE_1,
	NSS_CORE_MAX
} nss_core_id_t;

/**
 * type nss_gmac_event_t
 *	NSS GMAC ebvent type
 */
typedef enum {
	NSS_GMAC_EVENT_STATS,
	NSS_GMAC_EVENT_OTHER,
	NSS_GMAC_EVENT_MAX
} nss_gmac_event_t;

/**
 * General utilities
 */
extern int32_t nss_interface_number_get(void *nss_ctx, void *dev);
extern nss_state_t nss_state_get(void *nss_ctx);

typedef void (*nss_connection_expire_all_callback_t)(void);
extern void nss_connection_expire_all_register(nss_connection_expire_all_callback_t event_callback);
extern void nss_connection_expire_all_unregister(void);

/**
 * Methods provided by NSS device driver for use by connection tracking logic for IPv4.
 */
typedef void (*nss_ipv4_sync_callback_t)(struct nss_ipv4_sync *unis);
extern void *nss_register_ipv4_mgr(nss_ipv4_sync_callback_t event_callback);
extern void nss_unregister_ipv4_mgr(void);
extern nss_tx_status_t nss_create_ipv4_rule(void *nss_ctx, struct nss_ipv4_create *unic);
extern nss_tx_status_t nss_destroy_ipv4_rule(void *nss_ctx, struct nss_ipv4_destroy *unid);

/**
 * Methods provided by NSS device driver for use by connection tracking logic for IPv6.
 */
typedef void (*nss_ipv6_sync_callback_t)(struct nss_ipv6_sync *unis);
extern void *nss_register_ipv6_mgr(nss_ipv6_sync_callback_t event_callback);
extern void nss_unregister_ipv6_mgr(void);
extern nss_tx_status_t nss_create_ipv6_rule(void *nss_ctx, struct nss_ipv6_create *unic);
extern nss_tx_status_t nss_destroy_ipv6_rule(void *nss_ctx, struct nss_ipv6_destroy *unid);

/**
 * Methods provided by NSS device driver for use by connection tracking logic for l2 switch.
 */
typedef void (*nss_l2switch_sync_callback_t)(struct nss_l2switch_sync *unls);
extern void *nss_register_l2switch_mgr(nss_l2switch_sync_callback_t event_callback);
extern void nss_unregister_l2switch_mgr(void);
extern nss_tx_status_t nss_create_l2switch_rule(void *nss_ctx, struct nss_l2switch_create *unlc);
extern nss_tx_status_t nss_destroy_l2switch_rule(void *nss_ctx, struct nss_l2switch_destroy *unld);
extern nss_tx_status_t nss_destroy_all_l2switch_rules(void *nss_ctx);

/**
 * Methods provided by NSS device driver for use by crypto driver
 */
typedef void (*nss_crypto_callback_t)(void *ctx, void *buf, uint32_t buf_paddr, uint16_t len);
extern void *nss_register_crypto_if(nss_crypto_callback_t crypto_callback, void *ctx);
extern void nss_unregister_crypto_if(void);
extern nss_tx_status_t nss_crypto_if_open(void *ctx, uint8_t *buf, uint32_t len);
extern nss_tx_status_t nss_crypto_if_close(void *ctx, uint32_t eng);
extern nss_tx_status_t nss_crypto_if_tx(void *nss_ctx, void *buf, uint32_t buf_paddr, uint16_t len);

/**
 * Methods provided by NSS device driver for use by GMAC driver
 */
typedef void (*nss_phys_if_event_callback_t)(void *if_ctx, nss_gmac_event_t ev_type, void *buf, uint32_t len);
typedef void (*nss_phys_if_rx_callback_t)(void *if_ctx, void *os_buf);
extern void *nss_register_phys_if(uint32_t if_num, nss_phys_if_rx_callback_t rx_callback,
					nss_phys_if_event_callback_t event_callback, void *if_ctx);
extern void nss_unregister_phys_if(uint32_t if_num);
extern nss_tx_status_t nss_phys_if_tx(void *nss_ctx, struct sk_buff *os_buf, uint32_t if_num);
extern nss_tx_status_t nss_phys_if_open(void *nss_ctx, uint32_t tx_desc_ring, uint32_t rx_desc_ring, uint32_t if_num);
extern nss_tx_status_t nss_phys_if_close(void *nss_ctx, uint32_t if_num);
extern nss_tx_status_t nss_phys_if_link_state(void *nss_ctx, uint32_t link_state, uint32_t if_num);
extern nss_tx_status_t nss_phys_if_mac_addr(void *ctx, uint8_t *addr, uint32_t if_num);
extern nss_tx_status_t nss_phys_if_change_mtu(void *ctx, uint32_t mtu, uint32_t if_num);

/**
 * Methods provided by NSS driver for use by IPsec stack
 */
typedef void (*nss_ipsec_callback_t)(void *ctx, void *os_buf);
extern void *nss_register_ipsec_if(nss_ipsec_callback_t crypto_callback, void *ctx);
extern void nss_unregister_ipsec_if(void);
extern nss_tx_status_t nss_create_ipsec_tx_rule(void *nss_ctx, struct nss_ipsec_tx_create *nitc);
extern nss_tx_status_t nss_destroy_ipsec_tx_rule(void *nss_ctx, struct nss_ipsec_tx_destroy *nitd);
extern nss_tx_status_t nss_create_ipsec_rx_rule(void *nss_ctx, struct nss_ipsec_rx_create *nirc);
extern nss_tx_status_t nss_destroy_ipsec_rx_rule(void *nss_ctx, struct nss_ipsec_rx_destroy *nird);

/**
 * Methods provided by NSS driver for use by NSS Profiler
 */

/**
 * Note: Memory pointed by buf is owned by caller (i.e. NSS driver)
 *	NSS driver does not interpret "buf". It is up to profiler to make sense of it.
 */
typedef void (*nss_profiler_callback_t)(void *ctx, uint8_t *buf, uint16_t len);

/**
 * NOTE: Caller must provide valid core_id that is being profiled. This function must be called once for each core.
 *	Context (ctx) will be provided back to caller in the registered callback function
 */
extern void *nss_register_profiler_if(nss_profiler_callback_t profiler_callback, nss_core_id_t core_id, void *ctx);
extern void nss_unregister_profiler_if(nss_core_id_t core_id);

/**
 * NOTE: Valid context must be provided (for the right core). This context was returned during registration.
 */
extern nss_tx_status_t nss_profiler_send(void *ctx, uint8_t *buf, uint32_t len);

#endif /** __NSS_API_IF_H */
