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

static void nss_ipsecmgr_flow_resp(void *app_data, struct nss_ipsec_msg *nim)
{
	/*
	 * XXX: The following should be done
	 * - The flow database should be looked up based on the ENCAP or DECAP
	 * - The flow entry should be searched and marked offloaded to NSS
	 * - Any additional entry data should be created
	 */
	return;
}

/*
 * nss_ipsecmgr_flow_update()
 * 	update the flow with its associated data and notify NSS
 */
static void nss_ipsecmgr_flow_update(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref, struct nss_ipsec_msg *nim)
{
	struct nss_ipsecmgr_flow_entry *flow;
	struct nss_ipsec_rule_sel local_sel;
	struct nss_ipsec_rule_sel *flow_sel;

	flow = container_of(ref, struct nss_ipsecmgr_flow_entry, ref);
	flow_sel = &flow->nim.msg.push.sel;

	/*
	 * Create a local copy of flow selector
	 */
	memcpy(&local_sel, flow_sel, sizeof(struct nss_ipsec_rule_sel));
	memcpy(&flow->nim, nim, sizeof(struct nss_ipsec_msg));

	/*
	 * If, this flow is only getting updated with a new SA contents. We
	 * need to make sure that the existing selector remains the same
	 */
	if (nss_ipsecmgr_ref_is_updated(ref)) {
		memcpy(flow_sel, &local_sel, sizeof(struct nss_ipsec_rule_sel));
	}

	if (nss_ipsec_tx_msg(priv->nss_ctx, &flow->nim) != NSS_TX_SUCCESS) {
		/*
		 * XXX: Stop the TX queue and add this "entry"
		 * to pending queue
		 */
		nss_ipsecmgr_error("%p:unable to send the flow_update message\n", ref);
		return;
	}
}

/*
 * nss_ipsecmgr_flow_free()
 * 	free the associated flow entry and notify NSS
 */
static void nss_ipsecmgr_flow_free(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref)
{
	struct nss_ipsecmgr_flow_entry *flow = container_of(ref, struct nss_ipsecmgr_flow_entry, ref);

	/*
	 * update the common message structure
	 */
	flow->nim.cm.type = NSS_IPSEC_MSG_TYPE_DEL_RULE;

	if (nss_ipsec_tx_msg(priv->nss_ctx, &flow->nim) != NSS_TX_SUCCESS) {
		/*
		 * XXX: add this "entry" to pending queue
		 */
		nss_ipsecmgr_error("%p:unable to flow_free message\n", ref);
		return;
	}

	list_del_init(&flow->node);
	kfree(flow);
	return;
}

/*
 * nss_ipsecmgr_init_encap_flow()
 * 	initiallize the encap flow with a particular type
 */
void nss_ipsecmgr_init_encap_flow(struct nss_ipsec_msg *nim, enum nss_ipsec_msg_type type, struct nss_ipsecmgr_priv *priv)
{
	memset(nim, 0, sizeof(struct nss_ipsec_msg));
	nss_ipsec_msg_init(nim, NSS_IPSEC_ENCAP_IF_NUMBER, type, NSS_IPSEC_MSG_LEN, nss_ipsecmgr_flow_resp, priv->dev);
}

/*
 * nss_ipsecmgr_init_decap_flow()
 * 	initiallize the decap flow with a particular type
 */
void nss_ipsecmgr_init_decap_flow(struct nss_ipsec_msg *nim, enum nss_ipsec_msg_type type, struct nss_ipsecmgr_priv *priv)
{
	memset(nim, 0, sizeof(struct nss_ipsec_msg));
	nss_ipsec_msg_init(nim, NSS_IPSEC_DECAP_IF_NUMBER, type, NSS_IPSEC_MSG_LEN, nss_ipsecmgr_flow_resp, priv->dev);
}

/*
 * nss_ipsecmgr_copy_encap_v4_flow()
 * 	copy flow data into the selector
 */
void nss_ipsecmgr_copy_encap_v4_flow(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_encap_v4_tuple *flow)
{
	struct nss_ipsec_rule_sel *sel = &nim->msg.push.sel;

	sel->ipv4_dst = flow->dst_ip;
	sel->ipv4_src = flow->src_ip;
	sel->ipv4_proto = flow->protocol;

	sel->esp_spi = 0;
	sel->dst_port = 0;
	sel->src_port = 0;
}

/*
 * nss_ipsecmgr_copy_decap_v4_flow()
 * 	copy decap flow
 */
void nss_ipsecmgr_copy_decap_v4_flow(struct nss_ipsec_msg *nim, struct nss_ipsecmgr_sa_v4 *flow)
{
	struct nss_ipsec_rule_sel *sel = &nim->msg.push.sel;

	sel->ipv4_dst = flow->dst_ip;
	sel->ipv4_src = flow->src_ip;
	sel->ipv4_proto = IPPROTO_ESP;
	sel->esp_spi = flow->spi_index;

	sel->dst_port = 0;
	sel->src_port = 0;
}

/*
 * nss_ipsecmgr_encap_v4_flow2key()
 * 	convert an encap v4_flow into a key
 */
void nss_ipsecmgr_encap_v4_flow2key(struct nss_ipsecmgr_encap_v4_tuple *flow, struct nss_ipsecmgr_key *key)
{
	nss_ipsecmgr_key_reset(key);

	nss_ipsecmgr_key_write_8(key, 4 /* v4 */, NSS_IPSECMGR_KEY_POS_IP_VER);
	nss_ipsecmgr_key_write_8(key, flow->protocol, NSS_IPSECMGR_KEY_POS_IP_PROTO);
	nss_ipsecmgr_key_write_32(key, flow->dst_ip, NSS_IPSECMGR_KEY_POS_IPV4_DST);
	nss_ipsecmgr_key_write_32(key, flow->src_ip, NSS_IPSECMGR_KEY_POS_IPV4_SRC);

	key->len = NSS_IPSECMGR_KEY_LEN_ENCAP_IPV4_FLOW;
}

/*
 * nss_ipsecmgr_decap_v4_flow2key()
 * 	convert a decap flow into a key
 */
void nss_ipsecmgr_decap_v4_flow2key(struct nss_ipsecmgr_sa_v4 *flow, struct nss_ipsecmgr_key *key)
{
	nss_ipsecmgr_key_reset(key);

	nss_ipsecmgr_key_write_8(key, 4 /* v4 */, NSS_IPSECMGR_KEY_POS_IP_VER);
	nss_ipsecmgr_key_write_8(key, IPPROTO_ESP, NSS_IPSECMGR_KEY_POS_IP_PROTO);
	nss_ipsecmgr_key_write_32(key, flow->dst_ip, NSS_IPSECMGR_KEY_POS_IPV4_DST);
	nss_ipsecmgr_key_write_32(key, flow->src_ip, NSS_IPSECMGR_KEY_POS_IPV4_SRC);
	nss_ipsecmgr_key_write_32(key, flow->spi_index, NSS_IPSECMGR_KEY_POS_ESP_SPI);

	key->len = NSS_IPSECMGR_KEY_LEN_DECAP_IPV4_FLOW;
}

/*
 * nss_ipsecmgr_encap_v4_sel2key()
 * 	convert a selector to key
 */
void nss_ipsecmgr_encap_v4_sel2key(struct nss_ipsec_rule_sel *sel, struct nss_ipsecmgr_key *key)
{
	nss_ipsecmgr_key_reset(key);

	nss_ipsecmgr_key_write_8(key, 4 /* v4 */, NSS_IPSECMGR_KEY_POS_IP_VER);
	nss_ipsecmgr_key_write_8(key, sel->ipv4_proto, NSS_IPSECMGR_KEY_POS_IP_PROTO);
	nss_ipsecmgr_key_write_32(key, sel->ipv4_dst, NSS_IPSECMGR_KEY_POS_IPV4_DST);
	nss_ipsecmgr_key_write_32(key, sel->ipv4_src, NSS_IPSECMGR_KEY_POS_IPV4_SRC);

	key->len = NSS_IPSECMGR_KEY_LEN_ENCAP_IPV4_FLOW;
}

/*
 * nss_ipsecmgr_decap_v4_sel2key()
 * 	convert a selector to key
 */
void nss_ipsecmgr_decap_v4_sel2key(struct nss_ipsec_rule_sel *sel, struct nss_ipsecmgr_key *key)
{
	nss_ipsecmgr_key_reset(key);

	nss_ipsecmgr_key_write_8(key, 4 /* v4 */, NSS_IPSECMGR_KEY_POS_IP_VER);
	nss_ipsecmgr_key_write_8(key, IPPROTO_ESP, NSS_IPSECMGR_KEY_POS_IP_PROTO);
	nss_ipsecmgr_key_write_32(key, sel->ipv4_dst, NSS_IPSECMGR_KEY_POS_IPV4_DST);
	nss_ipsecmgr_key_write_32(key, sel->ipv4_src, NSS_IPSECMGR_KEY_POS_IPV4_SRC);
	nss_ipsecmgr_key_write_32(key, sel->esp_spi, NSS_IPSECMGR_KEY_POS_ESP_SPI);

	key->len = NSS_IPSECMGR_KEY_LEN_DECAP_IPV4_FLOW;
}

/*
 * nss_ipsecmgr_flow_lookup()
 * 	lookup flow in flow_db
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_flow_lookup(void *flow_db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_flow_db *db = flow_db;
	struct nss_ipsecmgr_flow_entry *entry;
	struct list_head *head;
	int idx;

	idx = nss_ipsecmgr_key_data2idx(key, NSS_IPSECMGR_MAX_FLOW);
	head = &db->entries[idx];

	list_for_each_entry(entry, head, node) {
		if (nss_ipsecmgr_key_cmp(&entry->key, key)) {
			return &entry->ref;
		}
	}

	return NULL;
}

/*
 * nss_ipsecmgr_flow_alloc()
 * 	allocate a flow entry
 */
struct nss_ipsecmgr_ref *nss_ipsecmgr_flow_alloc(void *flow_db, struct nss_ipsecmgr_key *key)
{
	struct nss_ipsecmgr_flow_db *db = flow_db;
	struct nss_ipsecmgr_flow_entry *flow;
	struct nss_ipsecmgr_ref *ref;
	int idx;

	ref = nss_ipsecmgr_flow_lookup(db, key);
	if (ref) {
		return ref;
	}

	flow = kzalloc(sizeof(struct nss_ipsecmgr_flow_entry), GFP_ATOMIC);
	if (!flow) {
		nss_ipsecmgr_error("failed to alloc flow_entry\n");
		return NULL;
	}

	INIT_LIST_HEAD(&flow->node);
	nss_ipsecmgr_ref_init(&flow->ref, nss_ipsecmgr_flow_update, nss_ipsecmgr_flow_free);

	memcpy(&flow->key, key, sizeof(struct nss_ipsecmgr_key));

	idx = nss_ipsecmgr_key_data2idx(key, NSS_IPSECMGR_MAX_FLOW);
	list_add(&flow->node, &db->entries[idx]);

	return &flow->ref;
}
