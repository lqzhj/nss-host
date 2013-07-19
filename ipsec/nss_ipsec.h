/*
 * Copyright © 2013 - Qualcomm Atheros
 */
#ifndef __NSS_IPSEC_H
#define __NSS_IPSEC_H

#define NSS_IPSEC_DBG_DUMP_LIMIT	64
#define NSS_IPSEC_MAX_IV_LEN		16
#define NSS_IPSEC_ENCAP_RULE_SZ		sizeof(struct nss_ipsec_encap_rule)
#define NSS_IPSEC_DECAP_RULE_SZ		sizeof(struct nss_ipsec_decap_rule)
#define NSS_IPSEC_IPHDR_SZ		sizeof(struct nss_ipsec_ipv4_hdr)
#define NSS_IPSEC_ESPHDR_SZ		sizeof(struct nss_ipsec_esp_hdr)
#define NSS_IPSEC0_ENCAP_INTERFACE	8
#define NSS_IPSEC0_DECAP_INTERFACE	9

/**
 * @brief IPsec rule types
 */
enum nss_ipsec_rule_type {
	NSS_IPSEC_RULE_TYPE_ENCAP_INSERT = 1,	/**< insert an encap rule */
	NSS_IPSEC_RULE_TYPE_ENCAP_DELETE = 2,	/**< delete an encap rule */
	NSS_IPSEC_RULE_TYPE_DECAP_INSERT = 3,	/**< insert an decap rule */
	NSS_IPSEC_RULE_TYPE_DECAP_DELETE = 4,	/**< delete an decap rule */
};


/**
 * @brief IPv4 header
 */
struct nss_ipsec_ipv4_hdr {
        uint8_t ver_ihl;	/**< version and header length */
        uint8_t tos;		/**< type of service */
        uint16_t tot_len;	/**< total length of the payload */
        uint16_t id;		/**< packet sequence number */
        uint16_t frag_off;	/**< fragmentation offset */
        uint8_t ttl;		/**< time to live */
        uint8_t protocol;	/**< next header protocol (TCP, UDP, ESP etc.) */
        uint16_t checksum;	/**< IP checksum */
        uint32_t src_ip;	/**< source IP address */
        uint32_t dst_ip;	/**< destination IP address */
};

/**
 * @brief ESP (Encapsulating Security Payload) header
 */
struct nss_ipsec_esp_hdr {
	uint32_t spi;				/**< security Parameter Index */
	uint32_t seq_no;			/**< esp sequence number */
	uint8_t iv[NSS_IPSEC_MAX_IV_LEN];	/**< iv for esp header */
};

/**
 * @brief TCP (Transmission Control Protocol)  header
 */
struct nss_ipsec_tcp_hdr {
	uint16_t src_port;	/**< source port */
	uint16_t dst_port;	/**< destination port */
	uint32_t seq_no;	/**< tcp sequence number */
	uint32_t ack_no;	/**< acknowledgment number */
	uint16_t flags;		/**< tcp flags */
	uint16_t window_size;	/**< tcp window size */
	uint16_t checksum;	/**< tcp checksum */
	uint16_t urgent;	/**< location where urgent data ends */
};

/**
 * @brief UDP header
 */
struct nss_ipsec_udp_hdr {
	uint16_t src_port;	/**< source port */
	uint16_t dst_port;	/**< destination port */
	uint16_t len;		/**< payload length */
	uint16_t checksum;	/**< udp checksum */
};

/**
 * @brief ipsec rule match entry, this is used for building the 5-tuple
 * 	  to match incoming packets.
 */
struct nss_ipsec_match_entry {
	struct nss_ipsec_ipv4_hdr ip;		/**< inner IPv4 header */
	union {
		struct nss_ipsec_tcp_hdr tcp;	/**< inner TCP header */
		struct nss_ipsec_udp_hdr udp;	/**< inner UDP header */
		struct nss_ipsec_esp_hdr esp;	/**< outer ESP header */
	} next_hdr;
};

/**
 * @brief IPsec data to use after a match with the packet's 5-tuple succeeds
 * 	  this contains the headers to wrap the packet
 */
struct nss_ipsec_match_data {
	struct nss_ipsec_ipv4_hdr ip;		/**< outer ipv4 header to use */
	struct nss_ipsec_esp_hdr esp;		/**< outer esp header to use */
};

/**
 * @brief Encap rule structure for insertion
 */
struct nss_ipsec_encap_rule {
	struct nss_ipsec_match_entry entry;	/**< match entry, used for deriving the index */
	struct nss_ipsec_match_data data;	/**< match data, used after deriving the index */
	uint32_t crypto_sid;			/**< crypto session index for the flow */
};

/**
 * @brief Decap rule structure for insertion
 */
struct nss_ipsec_decap_rule {
	struct nss_ipsec_match_entry entry;	/**< match entry, used for deriving the index */
	uint32_t crypto_sid;			/**< crypto session index */
};
#endif /* __NSS_IPSEC_IF_H */
