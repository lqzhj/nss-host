/*
 **************************************************************************
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
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

/* nss_ipsecmgr_subnet.c
 *	NSS IPsec manager subnet rules
 */

#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <linux/version.h>
#include <nss_crypto_if.h>
#include <nss_ipsecmgr.h>

#include "nss_ipsecmgr_priv.h"

static inline uint32_t nss_ipsecmgr_netmask2idx(struct nss_ipsecmgr_key *key)
{
	uint32_t mask, data;

	nss_ipsecmgr_key_read(key, &data, &mask, NSS_IPSECMGR_KEY_POS_IPV4_DST);
	return ffs(mask) - 1;
}

/*
 * nss_ipsecmgr_netmask_free()
 * 	deallocate a netmask entry
 */
static bool nss_ipsecmgr_netmask_free(struct nss_ipsecmgr_netmask_db *db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_netmask_entry *entry;
	uint32_t idx;

	idx = nss_ipsecmgr_netmask2idx(key);

	entry = db->entries[idx];
	BUG_ON(!entry);

	if (--entry->count) {
		return false;
	}

	clear_bit(idx, db->bitmap);
	db->entries[idx] = NULL;

	kfree(entry);
	return true;
}

/*
 * nss_ipsecmgr_subnet_update()
 * 	update the subnet with its associated data
 */
static void nss_ipsecmgr_subnet_update(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref, struct nss_ipsec_msg *nim)
{
	struct nss_ipsecmgr_subnet_entry *subnet;

	subnet = container_of(ref, struct nss_ipsecmgr_subnet_entry, ref);

	memcpy(&subnet->nim, nim, sizeof(struct nss_ipsec_msg));
}

/*
 * nss_ipsecmgr_subnet_free()
 * 	free the associated subnet entry and notify NSS
 */
static void nss_ipsecmgr_subnet_free(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref)
{
	struct nss_ipsecmgr_subnet_entry *subnet;

	subnet = container_of(ref, struct nss_ipsecmgr_subnet_entry, ref);

	BUG_ON(nss_ipsecmgr_ref_is_empty(ref) == false);

	/*
	 * detach it from the netmask entry database and
	 * check if the netmask entry is empty. The netmask
	 * entry will get freed if there are no further entries
	 * available
	 */
	list_del(&subnet->node);
	nss_ipsecmgr_netmask_free(&priv->net_db, &subnet->key);

	kfree(subnet);
}

/*
 * nss_ipsecmgr_netmask_lookup()
 * 	lookup a netmask entry
 */
static inline struct nss_ipsecmgr_netmask_entry *nss_ipsecmgr_netmask_lookup(struct nss_ipsecmgr_netmask_db *db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_netmask_entry *entry;
	uint32_t idx;

	idx = nss_ipsecmgr_netmask2idx(key);

	entry = db->entries[idx];
	if (entry) {
		return entry;
	}

	return NULL;
}

/*
 * nss_ipsecmgr_netmask_alloc()
 * 	allocate a netmask entry
 */
static struct nss_ipsecmgr_netmask_entry *nss_ipsecmgr_netmask_alloc(struct nss_ipsecmgr_netmask_db *db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_netmask_entry *entry;
	int idx;

	entry = nss_ipsecmgr_netmask_lookup(db, key);
	if (entry) {
		entry->count++;
		return entry;
	}

	entry = kzalloc(sizeof(struct nss_ipsecmgr_netmask_entry), GFP_ATOMIC);
	if (!entry) {
		return NULL;
	}

	nss_ipsecmgr_init_subnet_db(entry);
	entry->count = 1;

	idx = nss_ipsecmgr_netmask2idx(key);
	set_bit(idx, db->bitmap);
	db->entries[idx] = entry;

	return entry;
}


/*
 * nss_ipsecmgr_copy_v4_subnet()
 * 	copy v4_subnet nim
 */
void nss_ipsecmgr_copy_v4_subnet(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_ref *ref)
{
	struct nss_ipsecmgr_subnet_entry *entry;
	struct nss_ipsec_rule_data *data;
	struct nss_ipsec_rule_oip *oip;

	entry = container_of(ref, struct nss_ipsecmgr_subnet_entry, ref);

	oip = &entry->nim.msg.push.oip;
	data = &entry->nim.msg.push.data;

	memcpy(&nim->msg.push.oip, oip, sizeof(struct nss_ipsec_rule_oip));
	memcpy(&nim->msg.push.data, data, sizeof(struct nss_ipsec_rule_data));
}

/*
 * nss_ipsecmgr_v4_subnet_sel2key()
 * 	convert subnet selector to key
 */
void nss_ipsecmgr_v4_subnet_sel2key(struct nss_ipsec_rule_sel *sel, struct nss_ipsecmgr_key *key)
{
	nss_ipsecmgr_key_reset(key);

	nss_ipsecmgr_key_write_8(key, 4 /* ipv4 */, NSS_IPSECMGR_KEY_POS_IP_VER);
	nss_ipsecmgr_key_write_8(key, sel->ipv4_proto, NSS_IPSECMGR_KEY_POS_IP_PROTO);
	nss_ipsecmgr_key_write_32(key, sel->ipv4_dst, NSS_IPSECMGR_KEY_POS_IPV4_DST);

	key->len = NSS_IPSECMGR_KEY_LEN_IPV4_SUBNET;
}

/*
 * nss_ipsecmgr_v4_subnet2key()
 *      convert an v4 subnet into a key
 */
void nss_ipsecmgr_v4_subnet2key(struct nss_ipsecmgr_encap_v4_subnet *net, struct nss_ipsecmgr_key *key)
{
	nss_ipsecmgr_key_reset(key);

	nss_ipsecmgr_key_write_8(key, 4 /* ipv4 */, NSS_IPSECMGR_KEY_POS_IP_VER);
	nss_ipsecmgr_key_write_8(key, (uint8_t)net->protocol, NSS_IPSECMGR_KEY_POS_IP_PROTO);
	nss_ipsecmgr_key_write(key, net->dst_subnet, net->dst_mask, NSS_IPSECMGR_KEY_POS_IPV4_DST);

	key->len = NSS_IPSECMGR_KEY_LEN_IPV4_SUBNET;
}

/*
 * nss_ipsecmgr_v4_subnet_match()
 * 	peform a v4 subnet based match in netmask database
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_v4_subnet_match(void *net_db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_netmask_db *db = net_db;
	struct nss_ipsecmgr_key tmp_key;
	struct nss_ipsecmgr_ref *ref;
	int i;

	memcpy(&tmp_key, key, sizeof(struct nss_ipsecmgr_key));

	/*
	 * cycle through the bitmap for each subnet
	 */
	for_each_set_bit(i, db->bitmap, NSS_IPSECMGR_MAX_NETMASK) {

		BUG_ON(db->entries[i] == NULL);
		BUG_ON(db->entries[i]->count == 0);

		/*
		 * set the key with the right mask for hash index computation;
		 * each subnet index has its associated mask value
		 */
		nss_ipsecmgr_key_lshift_mask(&tmp_key, i, NSS_IPSECMGR_KEY_POS_IPV4_DST);

		ref = nss_ipsecmgr_subnet_lookup(db, &tmp_key);
		if (ref) {
			return ref;
		}
	}

	return NULL;
}

/*
 * nss_ipsecmgr_subnet_lookup()
 * 	lookup a subnet entry
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_subnet_lookup(void *net_db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_netmask_db *db = net_db;
	struct nss_ipsecmgr_netmask_entry *netmask;
	struct nss_ipsecmgr_subnet_entry *entry;
	struct list_head *head;
	int idx;

	netmask = nss_ipsecmgr_netmask_lookup(db, key);
	if (!netmask) {
		return NULL;
	}

	BUG_ON(netmask->count == 0);

	idx = nss_ipsecmgr_key_data2idx(key, NSS_IPSECMGR_MAX_SUBNET);
	head = &netmask->subnets[idx];

	list_for_each_entry(entry, head, node) {
		if (nss_ipsecmgr_key_cmp(&entry->key, key)) {
			return &entry->ref;
		}
	}

	return NULL;
}

/*
 * nss_ipsecmgr_subnet_alloc()
 *      allocate a subnet entry
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_subnet_alloc(void *net_db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_netmask_db *db = net_db;
	struct nss_ipsecmgr_netmask_entry *netmask;
	struct nss_ipsecmgr_subnet_entry *subnet;
	struct nss_ipsecmgr_ref *ref;
	uint32_t idx;

	ref = nss_ipsecmgr_subnet_lookup(db, key);
	if (ref) {
		return ref;
	}

	netmask = nss_ipsecmgr_netmask_alloc(db, key);
	if (!netmask) {
		return NULL;
	}

	subnet = kzalloc(sizeof(struct nss_ipsecmgr_subnet_entry), GFP_ATOMIC);
	if (!subnet) {
		return NULL;
	}

	INIT_LIST_HEAD(&subnet->node);
	nss_ipsecmgr_ref_init(&subnet->ref, nss_ipsecmgr_subnet_update, nss_ipsecmgr_subnet_free);

	memcpy(&subnet->key, key, sizeof(struct nss_ipsecmgr_key));

	idx = nss_ipsecmgr_key_data2idx(key, NSS_IPSECMGR_MAX_SUBNET);
	list_add(&subnet->node, &netmask->subnets[idx]);

	return &subnet->ref;
}
