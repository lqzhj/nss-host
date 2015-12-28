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
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTUOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/of.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <asm/atomic.h>

#include <nss_api_if.h>
#include <nss_ipsec.h>
#include <nss_ipsecmgr.h>
#include <nss_crypto_if.h>

#include "nss_ipsecmgr_priv.h"

/*
 * SA operation info
 */
struct nss_ipsecmgr_sa_info {
	struct nss_ipsec_msg nim;
	struct nss_ipsecmgr_key sa_key;
	struct nss_ipsecmgr_key child_key;

	void *child_db;
	/* nss_ipsecmgr_db_op_t child_alloc; */
	/* nss_ipsecmgr_db_op_t child_lookup; */

	struct nss_ipsecmgr_ref * (*child_alloc)(void *db, struct nss_ipsecmgr_key *key);
	struct nss_ipsecmgr_ref * (*child_lookup)(void *db, struct nss_ipsecmgr_key *key);
};

/*
 * nss_ipsecmgr_sa_free()
 * 	deallocate the SA if there are no references
 */
static void nss_ipsecmgr_sa_free(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref)
{
	struct nss_ipsecmgr_sa_entry *entry = container_of(ref, struct nss_ipsecmgr_sa_entry, ref);

	if (!nss_ipsecmgr_ref_is_empty(ref)) {
		return;
	}

	/*
	 * there should be no references remove it from
	 * the sa_db and free the entry
	 */
	list_del_init(&entry->node);
	kfree(entry);
}

/*
 * nss_ipsecmgr_sa_del()
 * 	delete sa/child from the reference chain
 */
static bool nss_ipsecmgr_sa_del(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_sa_info *info)
{
	struct nss_ipsecmgr_ref *sa_ref, *child_ref;

	/*
	 * lock database
	 */
	write_lock_bh(&priv->lock);

	/*
	 * search the flow for deletion
	 */
	child_ref = info->child_lookup(info->child_db, &info->child_key);
	if (!child_ref) {
		/*
		 * unlock device
		 */
		write_unlock_bh(&priv->lock);

		nss_ipsecmgr_warn("%p:failed to lookup child_entry\n", priv->dev);
		nss_ipsecmgr_trace("%p:child_lookup(%p), child_db(%p)", priv, info->child_lookup, info->child_db);
		return false;
	}

	/*
	 * search the SA in sa_db
	 */
	sa_ref = nss_ipsecmgr_sa_lookup(&priv->sa_db, &info->sa_key);
	if (!sa_ref) {
		write_unlock_bh(&priv->lock);

		nss_ipsecmgr_warn("%p:failed to lookup sa_entry\n", priv->dev);
		return false;
	}

	/*
	 * Remove the reference if it is associated the SA
	 */
	if (nss_ipsecmgr_ref_is_child(child_ref, sa_ref)) {
		nss_ipsecmgr_ref_free(priv, child_ref);
	}

	/*
	 * This deallocates the SA if there are no further references
	 */
	nss_ipsecmgr_sa_free(priv, sa_ref);

	write_unlock_bh(&priv->lock);
	return true;
}

/*
 * nss_ipsecmgr_sa_add()
 * 	add sa/child from the reference chain
 */
static bool nss_ipsecmgr_sa_add(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_sa_info *info)
{
	struct nss_ipsecmgr_ref *sa_ref, *child_ref;

	BUG_ON(!info->child_alloc);
	BUG_ON(!info->child_lookup);
	BUG_ON(!info->child_db);

	/*
	 * lock database
	 */
	write_lock_bh(&priv->lock);

	/*
	 * allocate a flow, this returns either a new flow or an existing
	 * one incase it is found
	 */
	child_ref = info->child_alloc(info->child_db, &info->child_key);
	if (!child_ref) {
		/*
		 * unlock device
		 */
		write_unlock_bh(&priv->lock);

		nss_ipsecmgr_warn("%p:failed to alloc child_entry\n", priv->dev);
		nss_ipsecmgr_trace("%p:child_alloc(%p), child_db(%p)", priv, info->child_alloc, info->child_db);
		return false;
	}

	/*
	 * allocate a SA, when flow alloc is successful. This returns either
	 * new SA or an existing one incase it is found
	 */
	sa_ref = nss_ipsecmgr_sa_alloc(&priv->sa_db, &info->sa_key);
	if (!sa_ref) {
		/*
		 * release the flow and unlock device
		 */
		nss_ipsecmgr_ref_free(priv, child_ref);
		write_unlock_bh(&priv->lock);

		nss_ipsecmgr_warn("%p:failed to alloc sa_entry\n", priv->dev);
		return false;
	}

	/*
	 * add child to parent
	 */
	nss_ipsecmgr_ref_add(child_ref, sa_ref);

	/*
	 * Trigger the notification chain for the child
	 * Note: if there is change in any data then the trigger
	 * will update the NSS for the change
	 */
	nss_ipsecmgr_ref_update(priv, child_ref, &info->nim);

	write_unlock_bh(&priv->lock);
	return true;
}

/*
 * nss_ipsecmgr_sa_alloc()
 * 	allocate the SA if there is none in the DB
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_sa_alloc(void *sa_db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_sa_db *db = sa_db;
	struct nss_ipsecmgr_sa_entry *sa;
	struct nss_ipsecmgr_ref *ref;
	int idx;

	/*
	 * Search the object in the database first
	 */
	ref = nss_ipsecmgr_sa_lookup(db, key);
	if (ref) {
		return ref;
	}

	/*
	 * Object doesn't exist, allocate it
	 */
	sa = kzalloc(sizeof(struct nss_ipsecmgr_sa_entry), GFP_ATOMIC);
	if (!sa) {
		nss_ipsecmgr_error("failed to alloc sa_entry\n");
		return NULL;
	}

	/*
	 * Initialize the list node & ref nodes
	 */
	INIT_LIST_HEAD(&sa->node);
	nss_ipsecmgr_ref_init(&sa->ref, NULL, nss_ipsecmgr_sa_free);

	/*
	 * copy key data
	 */
	memcpy(&sa->key, key, sizeof(struct nss_ipsecmgr_key));

	/*
	 * Add the object to database
	 */
	idx = nss_ipsecmgr_key_data2idx(key, NSS_CRYPTO_MAX_IDXS);
	list_add(&sa->node, &db->entries[idx]);

	return &sa->ref;
}

/*
 * nss_ipsecmgr_sa_copy()
 * 	update the SA entry with the SA data
 */
void nss_ipsecmgr_copy_v4_sa(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_sa_v4 *sa)
{
	struct nss_ipsec_rule_oip *oip = &nim->msg.push.oip;

	oip->ipv4_dst = sa->dst_ip;
	oip->ipv4_src = sa->src_ip;
	oip->ipv4_ttl = sa->ttl;
	oip->esp_spi = sa->spi_index;
}

/*
 * nss_ipsecmgr_sa_copy()
 * 	update the SA entry with the SA data
 */
void nss_ipsecmgr_copy_sa_data(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_sa_data *sa_data)
{
	struct nss_ipsec_rule_data *data = &nim->msg.push.data;

	data->crypto_index = (uint16_t)sa_data->crypto_index;
	/* data->window_size = sa_data->esp.replay_win; */
	data->nat_t_req = sa_data->esp.nat_t_req;

	data->cipher_algo = nss_crypto_get_cipher(data->crypto_index);
	data->auth_algo = nss_crypto_get_auth(data->crypto_index);

	data->esp_icv_len = sa_data->esp.icv_len;
	data->esp_seq_skip = sa_data->esp.seq_skip;
	data->use_pattern = sa_data->use_pattern;
}

/*
 * nss_ipsecmgr_v4_sa2key()
 * 	convert a SA into a key
 */
void nss_ipsecmgr_v4_sa2key(struct nss_ipsecmgr_sa_v4 *sa, struct nss_ipsecmgr_key *key)
{
	nss_ipsecmgr_key_reset(key);

	nss_ipsecmgr_key_write_8(key, 4 /* v4 */, NSS_IPSECMGR_KEY_POS_IP_VER);
	nss_ipsecmgr_key_write_8(key, IPPROTO_ESP, NSS_IPSECMGR_KEY_POS_IP_PROTO);
	nss_ipsecmgr_key_write_32(key, sa->dst_ip, NSS_IPSECMGR_KEY_POS_IPV4_DST);
	nss_ipsecmgr_key_write_32(key, sa->src_ip, NSS_IPSECMGR_KEY_POS_IPV4_SRC);
	nss_ipsecmgr_key_write_32(key, sa->spi_index, NSS_IPSECMGR_KEY_POS_ESP_SPI);

	key->len = NSS_IPSECMGR_KEY_LEN_IPV4_SA;
}

/*
 * nss_ipsecmgr_sa_lookup()
 * 	lookup the SA in the sa_db
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_sa_lookup(void *sa_db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_sa_db *db = sa_db;
	struct nss_ipsecmgr_sa_entry *entry;
	struct list_head *head;
	int idx;

	idx = nss_ipsecmgr_key_data2idx(key, NSS_CRYPTO_MAX_IDXS);
	head = &db->entries[idx];

	list_for_each_entry(entry, head, node) {
		if (nss_ipsecmgr_key_cmp(&entry->key, key)) {
			return &entry->ref;
		}
	}

	return NULL;
}

/*
 * nss_ipsecmgr_sa_flush_all()
 * 	remove all SA and its corresponding references
 */
void nss_ipsecmgr_sa_flush_all(struct nss_ipsecmgr_priv *priv)
{
	struct nss_ipsecmgr_sa_db *sa_db = &priv->sa_db;
	struct nss_ipsecmgr_sa_entry *entry;
	struct list_head *head;
	int i;

	/*
	 * lock database
	 */
	write_lock_bh(&priv->lock);

	/*
	 * walk the SA database for each entry and delete the attached SA
	 */
	for (i = 0, head = sa_db->entries; i < NSS_IPSECMGR_MAX_SA; i++, head++) {
		while (!list_empty(head)) {
			entry = list_first_entry(head, struct nss_ipsecmgr_sa_entry, node);
			nss_ipsecmgr_ref_free(priv, &entry->ref);
		}
	}

	/*
	 * unlock database
	 */
	write_unlock_bh(&priv->lock);
}

/*
 * nss_ipsecmgr_encap_add()
 * 	add encap flow/subnet to an existing or new SA
 */
bool nss_ipsecmgr_encap_add(struct net_device *tun, struct nss_ipsecmgr_encap_flow *flow,
				struct nss_ipsecmgr_sa *sa, struct nss_ipsecmgr_sa_data *data)
{
	struct nss_ipsecmgr_priv *priv = netdev_priv(tun);
	struct nss_ipsecmgr_sa_info info;


	nss_ipsecmgr_info("%p:encap_add initiated\n", tun);

	memset(&info, 0, sizeof(struct nss_ipsecmgr_sa_info));
	nss_ipsecmgr_init_encap_flow(&info.nim, NSS_IPSEC_MSG_TYPE_ADD_RULE, priv);

	switch (flow->type) {
	case NSS_IPSECMGR_FLOW_TYPE_V4_TUPLE:

		nss_ipsecmgr_copy_encap_v4_flow(&info.nim, &flow->data.v4_tuple);
		nss_ipsecmgr_copy_v4_sa(&info.nim, &sa->data.v4);
		nss_ipsecmgr_copy_sa_data(&info.nim, data);

		nss_ipsecmgr_encap_v4_flow2key(&flow->data.v4_tuple, &info.child_key);
		nss_ipsecmgr_v4_sa2key(&sa->data.v4, &info.sa_key);

		info.child_db = &priv->flow_db;
		info.child_alloc = nss_ipsecmgr_flow_alloc;
		info.child_lookup = nss_ipsecmgr_flow_lookup;
		break;

	case NSS_IPSECMGR_FLOW_TYPE_V4_SUBNET:

		nss_ipsecmgr_copy_v4_sa(&info.nim, &sa->data.v4);
		nss_ipsecmgr_copy_sa_data(&info.nim, data);

		nss_ipsecmgr_v4_subnet2key(&flow->data.v4_subnet, &info.child_key);
		nss_ipsecmgr_v4_sa2key(&sa->data.v4, &info.sa_key);

		info.child_db = &priv->net_db;
		info.child_alloc = nss_ipsecmgr_subnet_alloc;
		info.child_lookup = nss_ipsecmgr_subnet_lookup;
		break;

	default:
		nss_ipsecmgr_warn("%p:unknown flow type(%d)\n", tun, flow->type);
		return false;
	}


	return nss_ipsecmgr_sa_add(priv, &info);
}
EXPORT_SYMBOL(nss_ipsecmgr_encap_add);

/*
 * nss_ipsecmgr_encap_del()
 * 	del encap flow/subnet to an existing SA
 *
 * Note: if this is the only/last flow or subnet in the SA then
 * the SA will be also be deallocated
 */
bool nss_ipsecmgr_encap_del(struct net_device *tun, struct nss_ipsecmgr_encap_flow *flow, struct nss_ipsecmgr_sa *sa)
{
	struct nss_ipsecmgr_priv *priv = netdev_priv(tun);
	struct nss_ipsecmgr_sa_info info;

	nss_ipsecmgr_info("%p:encap_del initiated\n", tun);

	memset(&info, 0, sizeof(struct nss_ipsecmgr_sa_info));
	nss_ipsecmgr_init_encap_flow(&info.nim, NSS_IPSEC_MSG_TYPE_DEL_RULE, priv);

	switch (flow->type) {
	case NSS_IPSECMGR_FLOW_TYPE_V4_TUPLE:

		nss_ipsecmgr_copy_encap_v4_flow(&info.nim, &flow->data.v4_tuple);
		nss_ipsecmgr_copy_v4_sa(&info.nim, &sa->data.v4);

		nss_ipsecmgr_encap_v4_flow2key(&flow->data.v4_tuple, &info.child_key);
		nss_ipsecmgr_v4_sa2key(&sa->data.v4, &info.sa_key);

		info.child_db = &priv->flow_db;
		info.child_alloc = nss_ipsecmgr_flow_alloc;
		info.child_lookup = nss_ipsecmgr_flow_lookup;
		break;

	case NSS_IPSECMGR_FLOW_TYPE_V4_SUBNET:

		nss_ipsecmgr_copy_v4_sa(&info.nim, &sa->data.v4);

		nss_ipsecmgr_v4_subnet2key(&flow->data.v4_subnet, &info.child_key);
		nss_ipsecmgr_v4_sa2key(&sa->data.v4, &info.sa_key);

		info.child_db = &priv->net_db;
		info.child_alloc = nss_ipsecmgr_subnet_alloc;
		info.child_lookup = nss_ipsecmgr_subnet_lookup;
		break;

	default:
		nss_ipsecmgr_warn("%p:unknown flow type(%d)\n", tun, flow->type);
		return false;
	}


	return nss_ipsecmgr_sa_del(priv, &info);
}
EXPORT_SYMBOL(nss_ipsecmgr_encap_del);


/*
 * nss_ipsecmgr_decap_add()
 * 	add decap flow/subnet to an existing or new SA
 *
 * Note: In case of decap rule, sa become flow for lookup into flow table
 */
bool nss_ipsecmgr_decap_add(struct net_device *tun, struct nss_ipsecmgr_sa *sa, struct nss_ipsecmgr_sa_data *data)
{
	struct nss_ipsecmgr_priv *priv = netdev_priv(tun);
	struct nss_ipsecmgr_sa_info info;

	nss_ipsecmgr_info("%p:decap_add initiated\n", tun);

	memset(&info, 0, sizeof(struct nss_ipsecmgr_sa_info));
	nss_ipsecmgr_init_decap_flow(&info.nim, NSS_IPSEC_MSG_TYPE_ADD_RULE, priv);

	switch (sa->type) {
	case NSS_IPSECMGR_SA_TYPE_V4:

		nss_ipsecmgr_copy_decap_v4_flow(&info.nim, &sa->data.v4);
		nss_ipsecmgr_copy_v4_sa(&info.nim, &sa->data.v4);
		nss_ipsecmgr_copy_sa_data(&info.nim, data);

		nss_ipsecmgr_decap_v4_flow2key(&sa->data.v4, &info.child_key);
		nss_ipsecmgr_v4_sa2key(&sa->data.v4, &info.sa_key);
		break;

	default:
		nss_ipsecmgr_warn("%p:unknown flow type(%d)\n", tun, sa->type);
		return false;
	}

	info.child_db = &priv->flow_db;
	info.child_alloc = nss_ipsecmgr_flow_alloc;
	info.child_lookup = nss_ipsecmgr_flow_lookup;

	return nss_ipsecmgr_sa_add(priv, &info);
}
EXPORT_SYMBOL(nss_ipsecmgr_decap_add);

/*
 * nss_ipsecmgr_sa_flush()
 * 	flush sa and all associated references.
 */
bool nss_ipsecmgr_sa_flush(struct net_device *tun, struct nss_ipsecmgr_sa *sa)
{
	struct nss_ipsecmgr_priv *priv = netdev_priv(tun);
	struct nss_ipsecmgr_key sa_key;
	struct nss_ipsecmgr_ref *sa_ref;

	switch (sa->type) {
	case NSS_IPSECMGR_SA_TYPE_V4:
		nss_ipsecmgr_v4_sa2key(&sa->data.v4, &sa_key);
		break;

	default:
		nss_ipsecmgr_warn("%p:Unsupported sa type (type - %d)\n", tun, sa->type);
		return false;
	}

	/*
	 * lock database
	 */
	write_lock_bh(&priv->lock);

	/*
	 * search the SA in sa_db
	 */
	sa_ref = nss_ipsecmgr_sa_lookup(&priv->sa_db, &sa_key);
	if (!sa_ref) {
		write_unlock_bh(&priv->lock);
		nss_ipsecmgr_warn("%p:failed to lookup SA\n", priv);
		return false;
	}

	/*
	 * remove the reference from its associated SA
	 */
	nss_ipsecmgr_ref_free(priv, sa_ref);

	/*
	 * unlock database
	 */
	write_unlock_bh(&priv->lock);

	return true;
}
EXPORT_SYMBOL(nss_ipsecmgr_sa_flush);
