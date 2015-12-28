/*
 * ********************************************************************************
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 **********************************************************************************
 */

#ifndef __NSS_IPSECMGR_PRIV_H
#define __NSS_IPSECMGR_PRIV_H

#include <nss_api_if.h>
#include <nss_ipsec.h>
#include <nss_ipsecmgr.h>

#define nss_ipsecmgr_info_always(s, ...) pr_info("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)

#define nss_ipsecmgr_error(s, ...) pr_alert("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#define nss_ipsecmgr_warn(s, ...) pr_warn("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)

#if defined(CONFIG_DYNAMIC_DEBUG)
/*
 * Compile messages for dynamic enable/disable
 */
#define nss_ipsecmgr_info(s, ...) pr_debug("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#define nss_ipsecmgr_trace(s, ...) pr_debug("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)

#else
/*
 * Statically compile messages at different levels
 */
#define nss_ipsecmgr_info(s, ...) {	\
	if (NSS_IPSECMGR_DEBUG_LEVEL > NSS_IPSECMGR_DEBUG_LVL_INFO) {	\
		pr_notice("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__);	\
	}	\
}
#define nss_ipsecmgr_trace(s, ...) {	\
	if (NSS_IPSECMGR_DEBUG_LEVEL > NSS_IPSECMGR_DEBUG_LVL_TRACE) {	\
		pr_info("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__);	\
	}	\
}

#endif /* !CONFIG_DYNAMIC_DEBUG */

#define NSS_IPSECMGR_MAX_KEY_WORDS 5 /* word */
#define NSS_IPSECMGR_MAX_KEY_BYTES (NSS_IPSECMGR_MAX_KEY_WORDS * sizeof(uint32_t))
#define NSS_IPSECMGR_MAX_KEY_BITS (NSS_IPSECMGR_MAX_KEY_WORDS * sizeof(uint32_t) * BITS_PER_BYTE)
#define NSS_IPSECMGR_CHK_POW2(x) (__builtin_constant_p(x) && !(~(x - 1) & (x >> 1)))


#define NSS_IPSECMGR_MAX_SA NSS_CRYPTO_MAX_IDXS /* Max SAs */
#if (~(NSS_IPSECMGR_MAX_SA - 1) & (NSS_IPSEC_MAX_SA >> 1))
#error "NSS_IPSECMGR_MAX_SA is not a power of 2"
#endif

#define NSS_IPSECMGR_MAX_FLOW 256 /* Max flows */
#if (~(NSS_IPSECMGR_MAX_FLOW - 1) & (NSS_IPSECMGR_MAX_FLOW >> 1))
#error "NSS_IPSECMGR_MAX_FLOW is not a power of 2"
#endif

#define NSS_IPSECMGR_MAX_SUBNET 16 /* Max subnets */
#if (~(NSS_IPSECMGR_MAX_SUBNET - 1) & (NSS_IPSECMGR_MAX_SUBNET >> 1))
#error "NSS_IPSECMGR_MAX_SUBNET is not a power of 2"
#endif

#define NSS_IPSECMGR_MAX_NETMASK 32 /* Max ipv4 subnets */
#if (~(NSS_IPSECMGR_MAX_NETMASK - 1) & (NSS_IPSECMGR_MAX_NETMASK >> 1))
#error "NSS_IPSECMGR_MAX_NETMASK is not a power of 2"
#endif

#define NSS_IPSECMGR_NETMASK_BITMAP BITS_TO_LONGS(NSS_IPSECMGR_MAX_NETMASK)

#define NSS_IPSECMGR_GENMASK(hi, lo) ((~0 >> (31 - hi)) << lo)

struct nss_ipsecmgr_ref;
struct nss_ipsecmgr_key;
struct nss_ipsecmgr_priv;
/*
 * IPsec manager key length for
 *  - SA entries
 *  - Flow entries
 *  - Subnet entries
 */
enum nss_ipsecmgr_key_len {
	NSS_IPSECMGR_KEY_LEN_NONE = 0,
	NSS_IPSECMGR_KEY_LEN_IPV4_SA = 4,		/* 16 bytes */
	NSS_IPSECMGR_KEY_LEN_IPV4_SUBNET = 2,		/* 8 bytes */
	NSS_IPSECMGR_KEY_LEN_ENCAP_IPV4_FLOW = 3,	/* 12 bytes */
	NSS_IPSECMGR_KEY_LEN_DECAP_IPV4_FLOW = 4,	/* 16 bytes */
	NSS_IPSECMGR_KEY_LEN_MAX = NSS_IPSECMGR_MAX_KEY_WORDS
};

/*
 * IPsec manager key map for header fields to key elements
 */
enum nss_ipsecmgr_key_pos {
	NSS_IPSECMGR_KEY_POS_IP_VER = 0,		/* IP version, bits[0:7] */
	NSS_IPSECMGR_KEY_POS_IP_PROTO = 8,		/* IPv4 Proto, bits[8:15] */
	NSS_IPSECMGR_KEY_POS_IPV4_DST = 32,		/* IPv4 DST, bits[32:63] */
	NSS_IPSECMGR_KEY_POS_IPV4_SRC = 64,		/* IPv4 SIP, bits[64:95] */
	NSS_IPSECMGR_KEY_POS_ESP_SPI = 96,		/* ESP SPI, bits[96:127] */
};

/*
 * bits to mask within a key_word data, min - 0 & max - 31
 */
enum nss_ipsecmgr_key_mask {
	NSS_IPSECMGR_KEY_MASK_IP_VER = NSS_IPSECMGR_GENMASK(7, 0),		/* IP version, #bits - 8 */
	NSS_IPSECMGR_KEY_MASK_IP_PROTO = NSS_IPSECMGR_GENMASK(15, 8),	/* IP protocol, #bits - 8 */
	NSS_IPSECMGR_KEY_MASK_IPV4_DST = NSS_IPSECMGR_GENMASK(31, 0),	/* IPv4 dst, #bits - 32 */
	NSS_IPSECMGR_KEY_MASK_IPV4_SRC = NSS_IPSECMGR_GENMASK(31, 0),	/* IPv4 src, #bits - 32 */
	NSS_IPSECMGR_KEY_MASK_ESP_SPI = NSS_IPSECMGR_GENMASK(31, 0),		/* ESP spi #bits - 32 */
};

struct nss_ipsecmgr_ref;
struct nss_ipsecmgr_key;

typedef void (*nss_ipsecmgr_ref_update_t)(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref, struct nss_ipsec_msg *nim);
typedef void (*nss_ipsecmgr_ref_free_t)(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref);
typedef struct nss_ipsecmgr_ref *(*nss_ipsecmgr_db_op_t)(void *db, struct nss_ipsecmgr_key *key);

/*
 * Key byte stream for lookup
 */
struct nss_ipsecmgr_key {
	uint32_t data[NSS_IPSECMGR_MAX_KEY_WORDS];	/* Value N-bits */
	uint32_t mask[NSS_IPSECMGR_MAX_KEY_WORDS];	/* Mask N-bits */
	uint32_t len;					/* Length of the key */
};

/*
 * IPsec manager reference object
 */
struct nss_ipsecmgr_ref {
	struct list_head head;			/* parent "ref" */
	struct list_head node;			/* child "ref" */
	uint32_t id;				/* identifier */

	nss_ipsecmgr_ref_update_t update;	/* update function */
	nss_ipsecmgr_ref_free_t free;		/* free function */
};

/*
 * IPsec manager SA entry
 */
struct nss_ipsecmgr_sa_entry {
	struct list_head node;			/* list instance */

	struct nss_ipsecmgr_ref ref;		/* ref instance */
	struct nss_ipsecmgr_key key;		/* key instance */

	struct nss_ipsecmgr_sa sa;		/* SA instance */
	struct nss_ipsecmgr_sa_data data;	/* SA data */
};

/*
 * IPsec manager SA entry table
 */
struct nss_ipsecmgr_sa_db {
	struct list_head entries[NSS_IPSECMGR_MAX_SA];
};

/*
 * IPsec manager flow entry
 */
struct nss_ipsecmgr_flow_entry {
	struct list_head node;		/* list object */
	struct nss_ipsecmgr_ref ref;	/* reference object */
	struct nss_ipsecmgr_key key;	/* key object */

	struct nss_ipsec_msg nim;	/* IPsec message */
};

/*
 * Flow retry
 */
struct nss_ipsecmgr_flow_retry {
	struct list_head node;
	struct nss_ipsecmgr_key key;
	uint32_t ref_id;
};

/*
 * IPsec manager flow database
 */
struct nss_ipsecmgr_flow_db {
	struct list_head entries[NSS_IPSECMGR_MAX_FLOW];
};

/*
 * IPsec manager subnet entry
 */
struct nss_ipsecmgr_subnet_entry {
	struct list_head node;		/* list node */
	struct nss_ipsecmgr_ref ref;	/* reference node */
	struct nss_ipsecmgr_key key;	/* key */

	struct nss_ipsec_msg nim;	/* IPsec message */
};

/*
 * IPsec netmask entry
 */
struct nss_ipsecmgr_netmask_entry {
	uint32_t count;
	struct list_head subnets[NSS_IPSECMGR_MAX_SUBNET];
};

/*
 * IPsec netmask database
 *
 * Note: this database is searched using bit positions present in bitmap
 * where each bit in bitmap table represents a entry in the mask entry
 * table
 */
struct nss_ipsecmgr_netmask_db {
	unsigned long bitmap[NSS_IPSECMGR_NETMASK_BITMAP];
	struct nss_ipsecmgr_netmask_entry *entries[NSS_IPSECMGR_MAX_NETMASK];
};

/*
 * IPsec manager private context
 */
struct nss_ipsecmgr_priv {
	struct net_device *dev;			/* back pointer to tunnel device */
	rwlock_t lock;				/* lock for all DB operations */

	struct nss_ipsecmgr_sa_db sa_db;	/* SA database */
	struct nss_ipsecmgr_flow_db flow_db;	/* flow database */
	struct nss_ipsecmgr_netmask_db net_db;	/* Subnet mask database */

	void *cb_ctx;				/* callback context */
	nss_ipsecmgr_data_cb_t data_cb;		/* data callback function */
	nss_ipsecmgr_event_cb_t event_cb;	/* event callback function */

	struct nss_ctx_instance *nss_ctx;	/* NSS context */
	uint32_t nss_ifnum;			/* NSS interface for sending data */
};

/*
 * nss_ipsecmgr_ref_get_id()
 * 	return the reference objects id
 */
static inline uint32_t nss_ipsecmgr_ref_get_id(struct nss_ipsecmgr_ref *ref)
{
	return ref->id;
}

/*
 * nss_ipsecmgr_ref_is_updated()
 * 	return true if reference objects id is updated
 */
static inline bool nss_ipsecmgr_ref_is_updated(struct nss_ipsecmgr_ref *ref)
{
	return ref->id > 1;
}

/*
 * nss_ipsecmgr_ref_is_empty()
 * 	check if the SA has any reference
 */
static inline bool nss_ipsecmgr_ref_is_empty(struct nss_ipsecmgr_ref *ref)
{
	return list_empty(&ref->head);
}

/*
 * nss_ipsecmgr_key_reset()
 * 	Reset the IPsec key
 */
static inline void nss_ipsecmgr_key_reset(struct nss_ipsecmgr_key *key)
{
	memset(key, 0, sizeof(struct nss_ipsecmgr_key));
}

/*
 * nss_ipsecmgr_key_write_8()
 * 	write 8-bit value from the specified position using mask
 */
static inline void nss_ipsecmgr_key_write_8(struct nss_ipsecmgr_key *key, uint8_t v, const uint16_t p)
{
	uint32_t *data, *mask;


	data = &key->data[BIT_WORD(p)];
	mask = &key->mask[BIT_WORD(p)];

	/*
	 * clear data with mask, update data & save mask
	 */
	switch (p % BITS_PER_LONG) {
	case 0: /* bits[0:7] */
		*data &= ~NSS_IPSECMGR_GENMASK(7, 0);
		*data |= v;
		*mask |= NSS_IPSECMGR_GENMASK(7, 0);
		break;
	case 8: /* bits[8:15] */
		*data &= ~NSS_IPSECMGR_GENMASK(15, 8);
		*data |= (v << 8);
		*mask |= NSS_IPSECMGR_GENMASK(15, 8);
		break;
	case 16: /* bits[16:23] */
		*data &= ~NSS_IPSECMGR_GENMASK(23, 16);
		*data |= (v << 16);
		*mask |= NSS_IPSECMGR_GENMASK(23, 16);
		break;
	case 24: /* bits[24:31] */
		*data &= ~NSS_IPSECMGR_GENMASK(31, 24);
		*data |= (v << 24);
		*mask |= NSS_IPSECMGR_GENMASK(31, 24);
		break;
	default:
		*data = 0;
		*mask = 0;
		break;
	}
}

/*
 * nss_ipsecmgr_key_write_16()
 * 	write 16-bit value from the specified position using mask
 */
static inline void nss_ipsecmgr_key_write_16(struct nss_ipsecmgr_key *key, uint16_t v, const uint16_t p)
{
	/* uint32_t shift = p % BITS_PER_LONG; */
	uint32_t *data, *mask;

	data = &key->data[BIT_WORD(p)];
	mask = &key->mask[BIT_WORD(p)];

	/*
	 * clear data with mask, update data & save mask
	 */
	switch (p % BITS_PER_LONG) {
	case 0: /* bits[0:15] */
		*data &= ~NSS_IPSECMGR_GENMASK(15, 0);
		*data |= v;
		*mask |= NSS_IPSECMGR_GENMASK(15, 0);
		break;
	case 16: /* bits[16:31] */
		*data &= ~NSS_IPSECMGR_GENMASK(31, 16);
		*data |= (v << 16);
		*mask |= NSS_IPSECMGR_GENMASK(31, 16);
		break;
	default:
		*data = 0;
		*mask = 0;
		break;
	}
}

/*
 * nss_ipsecmgr_key_write_32()
 * 	write 32-bit value from the specified position using mask
 */
static inline void nss_ipsecmgr_key_write_32(struct nss_ipsecmgr_key *key, uint32_t v, const uint16_t p)
{
	uint32_t *data, *mask;

	data = &key->data[BIT_WORD(p)];
	mask = &key->mask[BIT_WORD(p)];

	/*
	 * save data & mask, bits[0:31]
	 */
	*data = v;
	*mask = NSS_IPSECMGR_GENMASK(31, 0);
}

/*
 * nss_ipsecmgr_key_write()
 * 	write value from the specified position using mask
 */
static inline void nss_ipsecmgr_key_write(struct nss_ipsecmgr_key *key, uint32_t v, uint32_t m, const uint16_t p)
{
	key->data[BIT_WORD(p)] = v;
	key->mask[BIT_WORD(p)] = m;
}

/*
 * nss_ipsecmgr_key_read()
 * 	read value from the specified position using mask
 */
static inline void nss_ipsecmgr_key_read(struct nss_ipsecmgr_key *key, uint32_t *v, uint32_t *m, const uint16_t p)
{
	*v = key->data[BIT_WORD(p)];
	*m = key->mask[BIT_WORD(p)];
}

/*
 * nss_ipsecmgr_write_key_mask()
 * 	write a mask starting from position
 */
static inline void nss_ipsecmgr_key_write_mask(struct nss_ipsecmgr_key *key, uint32_t m, const uint16_t p)
{
	key->mask[BIT_WORD(p)] = m;
}

/*
 * nss_ipsecmgr_key_lshift_mask()
 * 	left shift mask by an amount 's'
 */
static inline void nss_ipsecmgr_key_lshift_mask(struct nss_ipsecmgr_key *key, uint32_t s, const uint16_t p)
{
	key->mask[BIT_WORD(p)] <<= s;
}

/*
 * nss_ipsecmgr_key_cmp_data()
 * 	compare source key with destination key
 *
 * Note: this applies the source mask before comparison
 */
static inline bool nss_ipsecmgr_key_cmp(struct nss_ipsecmgr_key *s_key, struct nss_ipsecmgr_key *d_key)
{
	uint32_t *mask = s_key->mask;
	uint32_t *src = s_key->data;
	uint32_t *dst = d_key->data;
	int len = s_key->len;
	uint32_t val_0;
	uint32_t val_1;
	bool status;

	for (status = 0; !status && len; len--, mask++, src++, dst++) {
		/*
		 * the data for comparison should be used after
		 * masking the bits corresponding to that word
		 */
		val_0 = *src & *mask;
		val_1 = *dst & *mask;

		status |= val_0 ^ val_1;
	}

	return status == 0;
}

/*
 * nss_ipsecmgr_key_data2idx()
 * 	convert word stream to index based on table size
 */
static inline uint32_t nss_ipsecmgr_key_data2idx(struct nss_ipsecmgr_key *key, const uint32_t table_sz)
{
	uint32_t *data = key->data;
	uint32_t *mask = key->mask;
	uint32_t len = key->len;
	uint32_t idx;
	uint32_t val;

	/*
	 * bug on if table_sz is not
	 * - a constant
	 * - and a power of 2
	 */
	BUG_ON(!NSS_IPSECMGR_CHK_POW2(table_sz));

	for (idx = 0; len; len--, mask++, data++) {
		val = *data & *mask;
		idx ^= val;
	}

	return idx & (table_sz - 1);
}

/*
 * Initialize the various databases
 */
static inline void nss_ipsecmgr_init_flow_db(struct nss_ipsecmgr_flow_db *flow_db)
{
	struct list_head *head;
	int i;

	/*
	 * initialize the flow database
	 */
	head = flow_db->entries;
	for (i = 0; i < NSS_IPSECMGR_MAX_FLOW; i++, head++) {
		INIT_LIST_HEAD(head);
	}

}

static inline void nss_ipsecmgr_init_sa_db(struct nss_ipsecmgr_sa_db *sa_db)
{
	struct list_head *head;
	int i;

	/*
	 * initialize the SA database
	 */
	head = sa_db->entries;
	for (i = 0; i < NSS_IPSECMGR_MAX_SA; i++, head++) {
		INIT_LIST_HEAD(head);
	}

}

static inline void nss_ipsecmgr_init_netmask_db(struct nss_ipsecmgr_netmask_db *net_db)
{
	memset(net_db, 0, sizeof(struct nss_ipsecmgr_netmask_db));
}

static inline void nss_ipsecmgr_init_subnet_db(struct nss_ipsecmgr_netmask_entry *netmask)
{
	struct list_head *head;
	int i;

	/*
	 * initialize the subnet database
	 */
	head = netmask->subnets;
	for (i = 0; i < NSS_IPSECMGR_MAX_SUBNET; i++, head++) {
		INIT_LIST_HEAD(head);
	}
}

/*
 * Reference Object API(s)
 */
void nss_ipsecmgr_ref_init(struct nss_ipsecmgr_ref *ref, nss_ipsecmgr_ref_update_t update, nss_ipsecmgr_ref_free_t free);
void nss_ipsecmgr_ref_add(struct nss_ipsecmgr_ref *child, struct nss_ipsecmgr_ref *parent);
void nss_ipsecmgr_ref_update(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref, struct nss_ipsec_msg *nim);
void nss_ipsecmgr_ref_free(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref);
bool nss_ipsecmgr_ref_is_child(struct nss_ipsecmgr_ref *child, struct nss_ipsecmgr_ref *parent);

/*
 * Encap flow API(s)
 */
void nss_ipsecmgr_init_encap_flow(struct nss_ipsec_msg *nim, enum nss_ipsec_msg_type type, struct nss_ipsecmgr_priv *priv);
void nss_ipsecmgr_copy_encap_v4_flow(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_encap_v4_tuple *flow);
void nss_ipsecmgr_encap_v4_flow2key(struct nss_ipsecmgr_encap_v4_tuple *flow, struct nss_ipsecmgr_key *key);
void nss_ipsecmgr_encap_v4_sel2key(struct nss_ipsec_rule_sel *sel, struct nss_ipsecmgr_key *key);

/*
 * Decap flow API(s)
 */
void nss_ipsecmgr_init_decap_flow(struct nss_ipsec_msg *nim, enum nss_ipsec_msg_type type, struct nss_ipsecmgr_priv *priv);
void nss_ipsecmgr_copy_decap_v4_flow(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_sa_v4 *flow);
void nss_ipsecmgr_decap_v4_flow2key(struct nss_ipsecmgr_sa_v4 *flow, struct nss_ipsecmgr_key *key);
void nss_ipsecmgr_decap_v4_sel2key(struct nss_ipsec_rule_sel *sel, struct nss_ipsecmgr_key *key);

/*
 * flow alloc/lookup API(s)
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_flow_alloc(void *db, struct nss_ipsecmgr_key *key);
struct nss_ipsecmgr_ref *nss_ipsecmgr_flow_lookup(void *db, struct nss_ipsecmgr_key *key);

/*
 * Subnet API(s)
 */
void nss_ipsecmgr_copy_v4_subnet(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_ref *subnet_ref);
void nss_ipsecmgr_v4_subnet2key(struct nss_ipsecmgr_encap_v4_subnet *subnet, struct nss_ipsecmgr_key *key);
void nss_ipsecmgr_v4_subnet_sel2key(struct nss_ipsec_rule_sel *sel, struct nss_ipsecmgr_key *key);

/*
 * Subnet alloc/lookup API(s)
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_subnet_alloc(void *db, struct nss_ipsecmgr_key *key);
struct nss_ipsecmgr_ref *nss_ipsecmgr_subnet_lookup(void *db, struct nss_ipsecmgr_key *key);
struct nss_ipsecmgr_ref *nss_ipsecmgr_v4_subnet_match(void *db, struct nss_ipsecmgr_key *sel);

/*
 * SA API(s)
 */
void nss_ipsecmgr_copy_v4_sa(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_sa_v4 *sa);
void nss_ipsecmgr_copy_sa_data(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_sa_data *data);
void nss_ipsecmgr_v4_sa2key(struct nss_ipsecmgr_sa_v4 *sa, struct nss_ipsecmgr_key *key);

/*
 * SA alloc/lookup/flush API(s)
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_sa_alloc(void *db, struct nss_ipsecmgr_key *key);
struct nss_ipsecmgr_ref *nss_ipsecmgr_sa_lookup(void *db, struct nss_ipsecmgr_key *key);
void nss_ipsecmgr_sa_flush_all(struct nss_ipsecmgr_priv *priv);

#endif /* __NSS_IPSECMGR_PRIV_H */
