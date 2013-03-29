/* * Copyright (c) 2013 Qualcomm Atheros, Inc. * */

/**
 * na_core.h
 *	NSS driver core header file.
 */

#ifndef __NSS_CORE_H
#define __NSS_CORE_H

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "nss_hlos_if.h"
#include "nss_api_if.h"

/**
 * NSS debug macros
 */
#if (CONFIG_NSS_DEBUG_LEVEL < 1)
#define nss_assert(fmt, args...)
#else
#define nss_assert(c) BUG_ON(!(c));
#endif

#if (CONFIG_NSS_DEBUG_LEVEL < 2)
#define nss_warning(fmt, args...)
#else
#define nss_warning(fmt, args...) printk(KERN_WARNING "nss:"fmt, ##args)
#endif

#if (CONFIG_NSS_DEBUG_LEVEL < 3)
#define nss_info(fmt, args...)
#else
#define nss_info(fmt, args...) printk(KERN_INFO "nss:"fmt, ##args)
#endif

#if (CONFIG_NSS_DEBUG_LEVEL < 4)
#define nss_trace(fmt, args...)
#else
#define nss_trace(fmt, args...) printk(KERN_DEBUG "nss:"fmt, ##args)
#endif

/**
 * NSS max devices supported
 */
#define NSS_MAX_CORES CONFIG_NSS_MAX_CORES
#define NSS_MAX_INT_PER_NSS_CORE CONFIG_NSS_MAX_INT_PER_NSS_CORE
#define NSS_MAX_PHYSICAL_INTERFACES CONFIG_NSS_MAX_PHYSICAL_INTERFACES
#define NSS_MAX_VIRTUAL_INTERFACES CONFIG_NSS_MAX_VIRTUAL_INTERFACES
#define NSS_MAX_NET_INTERFACES (NSS_MAX_PHYSICAL_INTERFACES + NSS_MAX_VIRTUAL_INTERFACES)

/**
 * N2H/H2N Queue IDs
 */
#define NSS_IF_EMPTY_BUFFER_QUEUE 0
#define NSS_IF_DATA_QUEUE 1
#define NSS_IF_CMD_QUEUE 1

/**
 * Default payload size for NSS buffers
 */
#define NSS_NBUF_PAYLOAD_SIZE 1792

/**
 * NSS Interrupt Causes
 */
#define NSS_INTR_CAUSE_INVALID 0
#define NSS_INTR_CAUSE_QUEUE 1
#define NSS_INTR_CAUSE_NON_QUEUE 2

/**
 * NSS Core Status
 */
#define NSS_CORE_STATUS_SUCCESS 0
#define NSS_CORE_STATUS_FAILURE 1

/**
 * NSS context magic
 */
#define NSS_CTX_MAGIC 0xDEDEDEDE

/**
 * Interrupt cause processing weights
 */
#define NSS_EMPTY_BUFFER_SOS_PROCESSING_WEIGHT 64
#define NSS_DATA_COMMAND_BUFFER_PROCESSING_WEIGHT 64
#define NSS_EMPTY_BUFFER_RETURN_PROCESSING_WEIGHT 64
#define NSS_TX_UNBLOCKED_PROCESSING_WEIGHT 1

/**
 * Statistics struct
 */
#define IPV4_CONNECTION_ENTRIES 256
#define IPV6_CONNECTION_ENTRIES 256
#define L2SWITCH_CONNECTION_ENTRIES 64
#define NSS_PPPOE_NUM_SESSION_PER_INTERFACE 8
					/* Number of maximum simultaneous PPPoE sessions per physical interface */
#define NSS_PPPOE_NUM_SESSION_TOTAL (NSS_MAX_PHYSICAL_INTERFACES * NSS_PPPOE_NUM_SESSION_PER_INTERFACE)
					/* Number of total PPPoE sessions */


struct nss_ipv4_statistics {
	uint8_t protocol;			/* Protocol number */
	int32_t flow_interface;			/* Flow interface number */
	uint32_t flow_mtu;			/* MTU of flow interface */
	uint32_t flow_ip;			/* Flow IP address */
	uint32_t flow_ip_xlate;			/* Flow IP address after NAT translation */
	uint32_t flow_ident;			/* Flow ident (e.g. port) */
	uint32_t flow_ident_xlate;		/* Flow ident (e.g. port) after NAT translation */
	uint16_t flow_pppoe_session_id;		/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];	/* Flow direction`s PPPoE Server MAC address */
	uint64_t flow_accelerated_rx_packets;
						/* Number of flow interface RX packets accelerated */
	uint64_t flow_accelerated_rx_bytes;
						/* Number of flow interface RX bytes accelerated */
	uint64_t flow_accelerated_tx_packets;
						/* Number of flow interface TX packets accelerated */
	uint64_t flow_accelerated_tx_bytes;
						/* Number of flow interface TX bytes accelerated */
	int32_t return_interface;		/* Return interface number */
	uint32_t return_mtu;			/* MTU of return interface */
	uint32_t return_ip;			/* Return IP address */
	uint32_t return_ip_xlate;		/* Return IP address after NAT translation */
	uint32_t return_ident;			/* Return ident (e.g. port) */
	uint32_t return_ident_xlate;		/* Return ident (e.g. port) after NAT translation */
	uint16_t return_pppoe_session_id;	/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];	/* Return direction's PPPoE Server MAC address */
	uint64_t return_accelerated_rx_packets;
						/* Number of return interface RX packets accelerated */
	uint64_t return_accelerated_rx_bytes;
						/* Number of return interface RX bytes accelerated */
	uint64_t return_accelerated_tx_packets;
						/* Number of return interface TX packets accelerated */
	uint64_t return_accelerated_tx_bytes;
						/* Number of return interface TX bytes accelerated */
	uint64_t last_sync;			/* Last sync time as jiffies */
};

struct nss_ipv6_statistics {
	uint8_t protocol;			/* Protocol number */
	int32_t flow_interface;			/* Flow interface number */
	uint32_t flow_mtu;			/* MTU of flow interface */
	uint32_t flow_ip[4];			/* Flow IP address */
	uint32_t flow_ident;			/* Flow ident (e.g. port) */
	uint16_t flow_pppoe_session_id;		/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];	/* Flow direction`s PPPoE Server MAC address */
	uint64_t flow_accelerated_rx_packets;
						/* Number of flow interface RX packets accelerated */
	uint64_t flow_accelerated_rx_bytes;
						/* Number of flow interface RX bytes accelerated */
	uint64_t flow_accelerated_tx_packets;
						/* Number of flow interface TX packets accelerated */
	uint64_t flow_accelerated_tx_bytes;
						/* Number of flow interface TX bytes accelerated */
	uint32_t return_ip[4];			/* Return IP address */
	uint32_t return_ident;			/* Return ident (e.g. port) */
	int32_t return_interface;		/* Return interface number */
	uint32_t return_mtu;			/* MTU of return interface */
	uint16_t return_pppoe_session_id;	/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];	/* Return direction's PPPoE Server MAC address */
	uint64_t return_accelerated_rx_packets;
						/* Number of return interface RX packets accelerated */
	uint64_t return_accelerated_rx_bytes;
						/* Number of return interface RX bytes accelerated */
	uint64_t return_accelerated_tx_packets;
						/* Number of return interface TX packets accelerated */
	uint64_t return_accelerated_tx_bytes;
						/* Number of return interface TX bytes accelerated */
	uint64_t last_sync;			/* Last sync time as jiffies */
};

struct nss_l2switch_statistics {
	int32_t interface_num;		/* Linux net device structure */
	uint32_t rx_packet_count;	/* Number of packets RX'd */
	uint32_t rx_byte_count;		/* Number of bytes RX'd */
	uint64_t last_sync;		/* Last sync time as jiffies */
	uint16_t addr[3];		/* MAC Adress */
};

struct nss_gmac_statistics {
	uint64_t rx_bytes;		/** Number of RX bytes */
	uint64_t rx_packets;		/** Number of RX packets */
	uint64_t rx_errors;		/** Number of RX errors */
	uint64_t rx_receive_errors;	/** Number of RX receive errors */
	uint64_t rx_overflow_errors;	/** Number of RX overflow errors */
	uint64_t rx_descriptor_errors;	/** Number of RX descriptor errors */
	uint64_t rx_watchdog_timeout_errors;
					/** Number of RX watchdog timeout errors */
	uint64_t rx_crc_errors;		/** Number of RX CRC errors */
	uint64_t rx_late_collision_errors;
					/** Number of RX late collision errors */
	uint64_t rx_dribble_bit_errors;	/** Number of RX dribble bit errors */
	uint64_t rx_length_errors;	/** Number of RX length errors */
	uint64_t rx_ip_header_errors;	/** Number of RX IP header errors */
	uint64_t rx_ip_payload_errors;	/** Number of RX IP payload errors */
	uint64_t rx_no_buffer_errors;	/** Number of RX no-buffer errors */
	uint64_t rx_transport_csum_bypassed;
					/** Number of RX packets where the transport checksum was bypassed */
	uint64_t tx_bytes;		/** Number of TX bytes */
	uint64_t tx_packets;		/** Number of TX packets */
	uint64_t tx_collisions;		/** Number of TX collisions */
	uint64_t tx_errors;		/** Number of TX errors */
	uint64_t tx_jabber_timeout_errors;
					/** Number of TX jabber timeout errors */
	uint64_t tx_frame_flushed_errors;
					/** Number of TX frame flushed errors */
	uint64_t tx_loss_of_carrier_errors;
					/** Number of TX loss of carrier errors */
	uint64_t tx_no_carrier_errors;	/** Number of TX no carrier errors */
	uint64_t tx_late_collision_errors;
					/** Number of TX late collision errors */
	uint64_t tx_excessive_collision_errors;
					/** Number of TX excessive collision errors */
	uint64_t tx_excessive_deferral_errors;
					/** Number of TX excessive deferral errors */
	uint64_t tx_underflow_errors;	/** Number of TX underflow errors */
	uint64_t tx_ip_header_errors;	/** Number of TX IP header errors */
	uint64_t tx_ip_payload_errors;	/** Number of TX IP payload errors */
	uint64_t tx_dropped;		/** Number of TX dropped packets */
	uint64_t hw_errs[10];		/** GMAC DMA error counters */
	uint64_t rx_missed;		/** Number of RX packets missed by the DMA */
	uint64_t fifo_overflows;	/** Number of RX FIFO overflows signalled by the DMA */
	uint64_t gmac_total_ticks;	/** Total clock ticks spend inside the GMAC */
	uint32_t gmac_worst_case_ticks;	/** Worst case iteration of the GMAC in ticks */
	uint64_t gmac_iterations;	/** Number of iterations around the GMAC */
};

struct nss_pppoe_statistics {
	struct nss_pppoe_statistics *next;
					/* Next statistic structure */
	uint16_t pppoe_session_id;	/* PPPoE session ID on which statistics based */
	uint8_t pppoe_remote_mac[ETH_ALEN];
					/* PPPoE server MAC address */
	uint64_t ipv4_accelerated_rx_packets;
					/* Number of IPv4 RX packets accelerated */
	uint64_t ipv4_accelerated_rx_bytes;
					/* Number of IPv4 RX bytes accelerated */
	uint64_t ipv4_accelerated_tx_packets;
					/* Number of IPv4 TX packets accelerated */
	uint64_t ipv4_accelerated_tx_bytes;
					/* Number of IPv4 TX bytes accelerated */
	uint64_t ipv6_accelerated_rx_packets;
					/* Number of IPv6 RX packets accelerated */
	uint64_t ipv6_accelerated_rx_bytes;
					/* Number of IPv6 RX packets accelerated */
	uint64_t ipv6_accelerated_tx_packets;
					/* Number of IPv6 TX packets accelerated */
	uint64_t ipv6_accelerated_tx_bytes;
					/* Number of IPv6 TX bytes accelerated */
	uint64_t exception_events[NSS_EXCEPTION_EVENT_PPPOE_LAST];
					/* Exception events based on this PPPoE session */
};

struct nss_private {
	struct nss_ctx_instance *nss_ctx;
	uint32_t magic;			/** Used to confirm this private area is an NA private area */
	uint32_t status;
	int32_t interface_num;		/** Interface number */
	uint64_t host_rx_packets;	/** Number of RX packets received by host OS */
	uint64_t host_rx_bytes;		/** Number of RX bytes received by host OS */
	uint64_t host_tx_packets;	/** Number of TX packets sent by host OS */
	uint64_t host_tx_bytes;		/** Number of TX bytes sent by host OS */
	uint64_t ipv4_accelerated_rx_packets;
					/** Accelerated IPv4 RX packets */
	uint64_t ipv4_accelerated_rx_bytes;
					/** Accelerated IPv4 RX bytes */
	uint64_t ipv4_accelerated_tx_packets;
					/** Accelerated IPv4 TX packets */
	uint64_t ipv4_accelerated_tx_bytes;
					/** Accelerated IPv4 TX bytes */
	uint64_t ipv6_accelerated_rx_packets;
					/** Accelerated IPv6 RX packets */
	uint64_t ipv6_accelerated_rx_bytes;
					/** Accelerated IPv6 RX bytes */
	uint64_t ipv6_accelerated_tx_packets;
					/** Accelerated IPv6 TX packets */
	uint64_t ipv6_accelerated_tx_bytes;
					/** Accelerated IPv6 TX bytes */
	uint64_t exception_events_unknown[NSS_EXCEPTION_EVENT_UNKNOWN_LAST];
					/** Unknown protocol exception events */
	uint64_t exception_events_ipv4[NSS_EXCEPTION_EVENT_IPV4_LAST];
					/** IPv4 protocol exception events */
	uint64_t exception_events_ipv6[NSS_EXCEPTION_EVENT_IPV6_LAST];
					/** IPv6 protocol exception events */
};

/**
 * NSS core state
 */
enum nss_core_state {
	NSS_CORE_STATE_UNINITIALIZED = 0,
	NSS_CORE_STATE_INITIALIZED
};

/*
 * Forward declarations
 */
struct nss_top_instance;
struct nss_ctx_instance;
struct int_ctx_instance;

/**
 * Interrupt context instance (one per IRQ per NSS core)
 */
struct int_ctx_instance {
	struct nss_ctx_instance *nss_ctx;
					/** Back pointer to NSS context of core that
					owns this interrupt */
	uint32_t irq;			/** HLOS IRQ number */
	uint32_t shift_factor;		/** Shift factor for this IRQ number */
	uint32_t int_cause;		/** Interrupt cause carried forward to BH */
	struct tasklet_struct bh;	/** Bottom half handler */
};

/**
 * H2N descriptor ring information
 */
struct hlos_h2n_desc_rings {
	struct h2n_desc_if_instance desc_ring;
	spinlock_t lock;
	uint32_t tx_q_full_cnt;
	uint32_t flags;
};

#define NSS_H2N_DESC_RING_FLAGS_TX_STOPPED 0x1

/**
 * NSS context instance (one per NSS core)
 */
struct nss_ctx_instance {
	struct nss_top_instance *nss_top;
					/** Back pointer to NSS Top */
	uint32_t id;			/** Core ID for this instance */
	uint32_t nmap;			/** Pointer to NSS CSM registers */
	uint32_t vmap;			/** Virt mem pointer to virtual register map */
	uint32_t nphys;			/** Phys mem pointer to CSM register map */
	uint32_t vphys;			/** Phys mem pointer to virtual register map */
	enum nss_core_state state;	/** State of NSS core */
	uint32_t c2c_start;		/** C2C start address */
	struct int_ctx_instance int_ctx[NSS_MAX_INT_PER_NSS_CORE];
					/** Interrupt context instances */
	struct hlos_h2n_desc_rings h2n_desc_rings[16];
	struct n2h_desc_if_instance n2h_desc_if[15];
	uint32_t magic;
};

/**
 * Main NSS context structure (singleton)
 */
struct nss_top_instance {
	uint8_t num_nss;
	uint8_t num_phys_ports;
	spinlock_t lock;
	spinlock_t stats_lock;
	struct nss_ctx_instance nss[NSS_MAX_CORES];

	/**
	 * Network processing handler core id
	 */
	uint8_t ipv4_handler_id;
	uint8_t ipv6_handler_id;
	uint8_t l2switch_handler_id;
	uint8_t crypto_handler_id;
	uint8_t ipsec_handler_id;
	uint8_t wlan_handler_id;
	uint8_t phys_if_handler_id[4];
	spinlock_t cm_lock;
	spinlock_t crypto_lock;
	spinlock_t ipsec_lock;
	spinlock_t wlan_lock;
	spinlock_t phys_if_lock[NSS_MAX_PHYSICAL_INTERFACES];
	spinlock_t profiler_lock[NSS_MAX_CORES];
	nss_ipv4_sync_callback_t ipv4_sync;
	nss_ipv6_sync_callback_t ipv6_sync;
	nss_l2switch_sync_callback_t l2switch_sync;
	nss_connection_expire_all_callback_t conn_expire;
	nss_crypto_callback_t crypto_callback;
	nss_phys_if_rx_callback_t phys_if_rx_callback[NSS_MAX_PHYSICAL_INTERFACES];
	nss_phys_if_event_callback_t phys_if_event_callback[NSS_MAX_PHYSICAL_INTERFACES];
	nss_profiler_callback_t profiler_callback[NSS_MAX_CORES];
	void *crypto_ctx;
	void *phys_if_ctx[NSS_MAX_PHYSICAL_INTERFACES];
	void *profiler_ctx[NSS_MAX_CORES];
	uint64_t nbuf_alloc_err;
	uint64_t tx_q_full_cnt;
					/** Private data hold for virtual interfaces */
	bool napi_active;		/** Flag indicating if NAPI is currently active or not */
	bool netdevice_notifier;	/** Flag indicating if netdevice notifier is registered */
	uint32_t cache_dev_major;	/** Major number of char device */
	uint64_t last_rx_jiffies;	/** Time of the last RX message from the NA in jiffies */
	uint64_t ipv4_accelerated_rx_packets;
					/** Accelerated IPv4 RX packets */
	uint64_t ipv4_accelerated_rx_bytes;
					/** Accelerated IPv4 RX bytes */
	uint64_t ipv4_accelerated_tx_packets;
					/** Accelerated IPv4 TX packets */
	uint64_t ipv4_accelerated_tx_bytes;
					/** Accelerated IPv4 TX bytes */
	uint64_t ipv4_connection_create_requests;
					/** Number of IPv4 connection create requests */
	uint64_t ipv4_connection_create_collisions;
					/** Number of IPv4 connection create requests that collided with existing entries */
	uint64_t ipv4_connection_create_invalid_interface;
					/** Number of IPv4 connection create requests that had invalid interface */
	uint64_t ipv4_connection_destroy_requests;
					/** Number of IPv4 connection destroy requests */
	uint64_t ipv4_connection_destroy_misses;
					/** Number of IPv4 connection destroy requests that missed the cache */
	uint64_t ipv4_connection_hash_hits;
					/** Number of IPv4 connection hash hits */
	uint64_t ipv4_connection_hash_reorders;
					/** Number of IPv4 connection hash reorders */
	uint64_t ipv4_connection_flushes;
					/** Number of IPv4 connection flushes */
	uint64_t ipv4_connection_evictions;
					/** Number of IPv4 connection evictions */
	uint64_t ipv6_accelerated_rx_packets;
					/** Accelerated IPv6 RX packets */
	uint64_t ipv6_accelerated_rx_bytes;
					/** Accelerated IPv6 RX bytes */
	uint64_t ipv6_accelerated_tx_packets;
					/** Accelerated IPv6 TX packets */
	uint64_t ipv6_accelerated_tx_bytes;
					/** Accelerated IPv6 TX bytes */
	uint64_t ipv6_connection_create_requests;
					/** Number of IPv6 connection create requests */
	uint64_t ipv6_connection_create_collisions;
					/** Number of IPv6 connection create requests that collided with existing entries */
	uint64_t ipv6_connection_create_invalid_interface;
					/** Number of IPv6 connection create requests that had invalid interface */
	uint64_t ipv6_connection_destroy_requests;
					/** Number of IPv6 connection destroy requests */
	uint64_t ipv6_connection_destroy_misses;
					/** Number of IPv6 connection destroy requests that missed the cache */
	uint64_t ipv6_connection_hash_hits;
					/** Number of IPv6 connection hash hits */
	uint64_t ipv6_connection_hash_reorders;
					/** Number of IPv6 connection hash reorders */
	uint64_t ipv6_connection_flushes;
					/** Number of IPv6 connection flushes */
	uint64_t ipv6_connection_evictions;
					/** Number of IPv6 connection evictions */
	uint32_t l2switch_rx_packet_count;
					/** Number of packets RX'd */
	uint32_t l2switch_rx_byte_count;
					/** Number of bytes RX'd */
	uint32_t l2switch_virtual_rx_packet_count;
					/* Number of packets RX'd from virtual hosts */
	uint32_t l2switch_virtual_rx_byte_count;
					/* Number of bytes RX'd from virtual hosts */
	uint32_t l2switch_physical_rx_packet_count;
					/* Number of packets RX'd from physical hosts */
	uint32_t l2switch_physical_rx_byte_count;
					/* Number of bytes RX'd from physical hosts */
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
	uint32_t l2switch_hash_hits;
					/* Number of l2 switch entry hash hits */
	uint32_t l2switch_hash_reorders;
					/* Number of l2 switch entry hash reorders */
	uint32_t l2switch_flushes;
					/* Number of l2 switch entry flushes */
	uint64_t l2switch_evictions;
					/* Number of l2 switch entry evictions */
	uint32_t pppoe_session_create_requests;
					/* Number of PPPoE session create requests */
	uint32_t pppoe_session_create_failures;
					/* Number of PPPoE session create failures */
	uint32_t pppoe_session_destroy_requests;
					/* Number of PPPoE session destroy requests */
	uint32_t pppoe_session_destroy_misses;
					/* Number of PPPoE session destroy requests that missed the cache */
	uint64_t pe_queue_dropped;	/* Number of packets dropped because the PE queue is too full */
	uint64_t pe_total_ticks;	/* Total clock ticks spend inside the PE */
	uint32_t pe_worst_case_ticks;	/* Worst case iteration of the PE in ticks */
	uint64_t pe_iterations;		/* Number of iterations around the PE */
	uint64_t except_queue_dropped;	/* Number of packets dropped because the exception queue is too full */
	uint64_t except_total_ticks;	/* Total clock ticks spend inside the PE */
	uint32_t except_worst_case_ticks;
					/* Worst case iteration of the exception path in ticks */
	uint64_t except_iterations;	/* Number of iterations around the PE */
	uint32_t l2switch_queue_dropped;
					/* Number of packets dropped because the L2 switch queue is too full */
	uint64_t l2switch_total_ticks;	/* Total clock ticks spend inside the L2 switch */
	uint32_t l2switch_worst_case_ticks;
					/* Worst case iteration of the L2 switch in ticks */
	uint64_t l2switch_iterations;	/* Number of iterations around the L2 switch */
	uint64_t pbuf_alloc_fails;	/* Number of pbuf allocations that have failed */
	uint64_t pbuf_payload_alloc_fails;
					/* Number of pbuf allocations that have failed because there were no free payloads */
	struct nss_gmac_statistics nss_gmac_statistics[NSS_MAX_PHYSICAL_INTERFACES];
	struct nss_ipv4_statistics nss_ipv4_statistics[IPV4_CONNECTION_ENTRIES];
	struct nss_ipv6_statistics nss_ipv6_statistics[IPV6_CONNECTION_ENTRIES];
	struct nss_l2switch_statistics nss_l2switch_statistics[L2SWITCH_CONNECTION_ENTRIES];
	struct nss_pppoe_statistics nss_pppoe_statistics[NSS_PPPOE_NUM_SESSION_TOTAL];
					/* PPPoE interface statistics array */
	struct nss_pppoe_statistics *nss_pppoe_statistics_head;
					/* Head of PPPoE interface statistics */
};

extern void nss_core_handle_bh (unsigned long ctx);
extern int32_t nss_core_send_buffer (struct nss_ctx_instance *nss_ctx, uint32_t if_num,
					struct sk_buff *nbuf, uint16_t qid,
					uint8_t buffer_type, uint16_t flags);
extern int32_t nss_core_send_crypto(struct nss_ctx_instance *nss_ctx, void *buf, uint32_t buf_paddr, uint16_t len);
extern void nss_rx_handle_status_pkt(struct nss_ctx_instance *nss_ctx, struct sk_buff *nbuf);
extern void nss_rx_handle_crypto_buf(struct nss_ctx_instance *nss_ctx, uint32_t buf, uint32_t paddr, uint32_t len);

#endif /** __NSS_CORE_H */
