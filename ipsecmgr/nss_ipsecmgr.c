/*
 **************************************************************************
 * Copyright (c) 2014-2016, The Linux Foundation. All rights reserved.
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

/* nss_ipsecmgr.c
 *	NSS to HLOS IPSec Manager
 */
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/of.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <asm/atomic.h>

#include <nss_api_if.h>
#include <nss_ipsec.h>
#include <nss_ipsecmgr.h>
#include <nss_crypto_if.h>

#include "nss_ipsecmgr_priv.h"

extern bool nss_cmn_get_nss_enabled(void);

/*
 **********************
 * Helper Functions
 **********************
 */

/*
 * nss_ipsecmgr_ref_no_update()
 * 	dummy functions for object owner when there is no update
 */
static void nss_ipsecmgr_ref_no_update(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *child, struct nss_ipsec_msg *nim)
{
	nss_ipsecmgr_trace("ref_no_update triggered for child (%p)\n", child);
	return;
}

/*
 * nss_ipsecmgr_ref_no_free()
 * 	dummy functions for object owner when there is no free
 */
static void nss_ipsecmgr_ref_no_free(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref)
{
	nss_ipsecmgr_trace("%p:ref_no_free triggered\n", ref);
	return;
}

/*
 * nss_ipsecmgr_v4_hdr2sel()
 * 	convert v4_hdr to message sel
 */
static inline void nss_ipsecmgr_v4_hdr2sel(struct iphdr *iph, struct nss_ipsec_rule_sel *sel)
{
	sel->ipv4_dst = ntohl(iph->daddr);
	sel->ipv4_src = ntohl(iph->saddr);
	sel->ipv4_proto = iph->protocol;
}

/*
 * nss_ipsecmgr_offload_encap_flow()
 * 	check if the flow can be offloaded to NSS for encapsulation
 */
static bool nss_ipsecmgr_offload_encap_flow(struct nss_ipsecmgr_priv *priv, struct sk_buff *skb)
{
	struct nss_ipsecmgr_ref *subnet_ref, *flow_ref;
	struct nss_ipsecmgr_key subnet_key, flow_key;
	struct nss_ipsec_rule_sel *sel;
	struct nss_ipsec_msg nim;

	nss_ipsecmgr_init_encap_flow(&nim, NSS_IPSEC_MSG_TYPE_ADD_RULE, priv);

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		sel = &nim.msg.push.sel;

		nss_ipsecmgr_v4_hdr2sel(ip_hdr(skb), sel);
		nss_ipsecmgr_encap_v4_sel2key(sel, &flow_key);

		/*
		 * flow lookup is done with read lock
		 */
		read_lock(&priv->lock);
		flow_ref = nss_ipsecmgr_flow_lookup(&priv->flow_db, &flow_key);
		read_unlock(&priv->lock);

		/*
		 * if flow is found then proceed with the TX
		 */
		if (flow_ref) {
			return true;
		}
		/*
		 * flow table miss results in lookup in the subnet table. If,
		 * a match is found then a rule is inserted in NSS for encapsulating
		 * this flow.
		 */
		nss_ipsecmgr_v4_subnet_sel2key(sel, &subnet_key);

		/*
		 * write lock as it can update the flow database
		 */
		write_lock(&priv->lock);

		subnet_ref = nss_ipsecmgr_v4_subnet_match(&priv->net_db, &subnet_key);
		if (!subnet_ref) {
			write_unlock(&priv->lock);
			return false;
		}

		/*
		 * copy nim data from subnet entry
		 */
		nss_ipsecmgr_copy_v4_subnet(&nim, subnet_ref);

		/*
		 * if, the same flow was added in between then flow alloc will return the
		 * same flow. The only side affect of this will be NSS getting duplicate
		 * add requests and thus rejecting one of them
		 */

		flow_ref = nss_ipsecmgr_flow_alloc(&priv->flow_db, &flow_key);
		if (!flow_ref) {
			write_unlock(&priv->lock);
			return false;
		}

		/*
		 * add reference to subnet and trigger an update
		 */
		nss_ipsecmgr_ref_add(flow_ref, subnet_ref);
		nss_ipsecmgr_ref_update(priv, flow_ref, &nim);

		write_unlock(&priv->lock);

		break;

	default:
		nss_ipsecmgr_warn("%p:protocol(%d) offload not supported\n", priv->dev, ntohs(skb->protocol));
		return false;
	}

	return true;
}

/*
 **********************
 * Netdev ops
 **********************
 */

/*
 * nss_ipsecmgr_tunnel_open()
 * 	open the tunnel for usage
 */
static int nss_ipsecmgr_tunnel_open(struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv;

	priv = netdev_priv(dev);

	netif_start_queue(dev);

	return 0;
}

/*
 * nss_ipsecmgr_tunnel_stop()
 * 	stop the IPsec tunnel
 */
static int nss_ipsecmgr_tunnel_stop(struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv;

	priv = netdev_priv(dev);

	netif_stop_queue(dev);

	return 0;
}

/*
 * nss_ipsecmgr_tunnel_xmit()
 * 	tunnel transmit function
 */
static netdev_tx_t nss_ipsecmgr_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv;
	bool expand_skb = false;
	int nhead, ntail;

	priv = netdev_priv(dev);
	nhead = dev->needed_headroom;
	ntail = dev->needed_tailroom;

	/*
	 * Check if skb is non-linear
	 */
	if (skb_is_nonlinear(skb)) {
		nss_ipsecmgr_error("%p: NSS IPSEC does not support fragments %p\n", priv->nss_ctx, skb);
		goto fail;
	}

	/*
	 * Check if skb is shared
	 */
	if (unlikely(skb_shared(skb))) {
		nss_ipsecmgr_error("%p: Shared skb is not supported: %p\n", priv->nss_ctx, skb);
		goto fail;
	}

	/*
	 * Check if packet is given starting from network header
	 */
	if (skb->data != skb_network_header(skb)) {
		nss_ipsecmgr_error("%p: 'Skb data is not starting from IP header", priv->nss_ctx);
		goto fail;
	}

	/*
	 * For all these cases
	 * - create a writable copy of buffer
	 * - increase the head room
	 * - increase the tail room
	 */
	if (skb_cloned(skb) || (skb_headroom(skb) < nhead) || (skb_tailroom(skb) < ntail)) {
		expand_skb = true;
	}

	if (expand_skb && pskb_expand_head(skb, nhead, ntail, GFP_KERNEL)) {
		nss_ipsecmgr_error("%p: unable to expand buffer\n", priv->nss_ctx);
		goto fail;
	}

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		BUG_ON(ip_hdr(skb)->ttl == 0);
		break;

	case htons(ETH_P_IPV6):
		BUG_ON(ipv6_hdr(skb)->hop_limit == 0);
		break;

	default:
		goto fail;
	}

	/*
	 * check whether the IPsec encapsulation can be offloaded to NSS
	 * 	if the flow matches a subnet rule, then a new flow rule is added to NSS
	 * 	if the flow doesn't match any subnet, then the packet is dropped
	 */
	if (!nss_ipsecmgr_offload_encap_flow(priv, skb)) {
		nss_ipsecmgr_warn("%p:failed to accelerate flow\n", dev);
		goto fail;
	}

	/*
	 * Send the packet down
	 */
	if (nss_ipsec_tx_buf(skb, NSS_IPSEC_ENCAP_IF_NUMBER) != 0) {
		/*
		 * TODO: NEED TO STOP THE QUEUE
		 */
		goto fail;
	}

	return NETDEV_TX_OK;

fail:
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/*
 * nss_ipsecmgr_tunnel_stats()
 * 	get tunnel statistics
 */
static struct net_device_stats *nss_ipsecmgr_tunnel_stats(struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	/* struct nss_ipsecmgr_priv *priv; */
	/* struct nss_ipsec_sa *sa; */
	/* uint32_t i; */

	memset(stats, 0, sizeof(struct net_device_stats));

#if 0
	priv = netdev_priv(dev);
	for (i = 0, sa = &priv->sa_tbl[0]; i < NSS_IPSEC_MAX_SA; i++, sa++) {
		if (atomic_read(&sa->user) == 0) {
			continue;
		}

		switch (sa->type) {
		case NSS_IPSECMGR_RULE_TYPE_ENCAP:
			stats->tx_packets += sa->stats.pkts.processed;
			stats->tx_dropped += sa->stats.pkts.dropped;
			break;

		case NSS_IPSECMGR_RULE_TYPE_DECAP:
			stats->rx_packets += sa->stats.pkts.processed;
			stats->rx_dropped += sa->stats.pkts.dropped;
			break;

		default:
			nss_ipsecmgr_error("unknown ipsec rule type\n");
			break;
		}
	}
#endif
	return stats;
}

/* NSS IPsec tunnel operation */
static const struct net_device_ops nss_ipsecmgr_tunnel_ops = {
	.ndo_open = nss_ipsecmgr_tunnel_open,
	.ndo_stop = nss_ipsecmgr_tunnel_stop,
	.ndo_start_xmit = nss_ipsecmgr_tunnel_xmit,
	.ndo_get_stats = nss_ipsecmgr_tunnel_stats,
};

/*
 * nss_ipsecmgr_tunnel_free()
 * 	free an existing IPsec tunnel interface
 */
static void nss_ipsecmgr_tunnel_free(struct net_device *dev)
{
	nss_ipsecmgr_info("IPsec tunnel device(%s) freed\n", dev->name);

	free_netdev(dev);
}

/*
 * nss_ipsecmr_setup_tunnel()
 * 	setup the IPsec tunnel
 */
static void nss_ipsecmgr_tunnel_setup(struct net_device *dev)
{
	dev->addr_len = ETH_ALEN;
	dev->mtu = NSS_IPSECMGR_TUN_MTU(ETH_DATA_LEN);

	dev->hard_header_len = NSS_IPSECMGR_TUN_MAX_HDR_LEN;
	dev->needed_headroom = NSS_IPSECMGR_TUN_HEADROOM;
	dev->needed_tailroom = NSS_IPSECMGR_TUN_TAILROOM;

	dev->type = NSS_IPSEC_ARPHRD_IPSEC;

	dev->ethtool_ops = NULL;
	dev->header_ops = NULL;
	dev->netdev_ops = &nss_ipsecmgr_tunnel_ops;

	dev->destructor = nss_ipsecmgr_tunnel_free;

	/*
	 * get the MAC address from the ethernet device
	 */
	random_ether_addr(dev->dev_addr);

	memset(dev->broadcast, 0xff, dev->addr_len);
	memcpy(dev->perm_addr, dev->dev_addr, dev->addr_len);
}

/*
 * nss_ipsecmgr_buf_receive()
 *	receive NSS exception packets
 */
static void nss_ipsecmgr_buf_receive(struct net_device *dev, struct sk_buff *skb, __attribute((unused)) struct napi_struct *napi)
{
	struct nss_ipsecmgr_priv *priv;
	nss_ipsecmgr_data_cb_t cb_fn;
	void *cb_ctx;
	struct iphdr *ip;

	BUG_ON(dev == NULL);
	BUG_ON(skb == NULL);

	/* hold the device till we process it */
	dev_hold(dev);

	/*
	 * XXX:need to ensure that the dev being accessed is not deleted
	 */
	priv = netdev_priv(dev);

	skb->dev = dev;

	cb_fn = priv->data_cb;
	cb_ctx = priv->cb_ctx;

	/*
	 * if tunnel creator gave a callback then send the packet without
	 * any modifications to him
	 */
	if (cb_fn && cb_ctx) {
		cb_fn(cb_ctx, skb);
		goto done;
	}

	ip = (struct iphdr *)skb->data;
	if (unlikely((ip->version != IPVERSION) || (ip->ihl != 5))) {
		nss_ipsecmgr_error("dropping packets(IP version:%x, Header len:%x)\n", ip->version, ip->ihl);
		dev_kfree_skb_any(skb);
		goto done;
	}
#if 0
	/*
	 * Receiving an ESP packet indicates that NSS has performed the encapsulation
	 * but the post-routing rule is not present. This condition can't be taken care
	 * in Host we should flush the ENCAP rules and free the packet. This will force
	 * subsequent packets to follow the Slow path IPsec thus recreating the rules
	 */
	if (unlikely(ip->protocol == IPPROTO_ESP)) {
		nss_ipsecmgr_sa_flush(dev, NSS_IPSECMGR_RULE_TYPE_ENCAP);
		dev_kfree_skb_any(skb);
		goto done;
	}
#endif

	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);

	skb->pkt_type = PACKET_HOST;
	skb->protocol = cpu_to_be16(ETH_P_IP);
	skb->skb_iif = dev->ifindex;

	netif_receive_skb(skb);
done:
	/* release the device as we are done */
	dev_put(dev);
}

/*
 * nss_ipsecmgr_event_recieve()
 * 	asynchronous event reception
 */
static void nss_ipsecmgr_event_recieve(void *app_data, struct nss_ipsec_msg *nim)
{
	struct net_device *tun_dev = (struct net_device *)app_data;
	struct nss_ipsecmgr_priv *priv;
	struct net_device *dev;

	BUG_ON(tun_dev == NULL);
	BUG_ON(nim == NULL);

	return;

	/*
	 * this holds the ref_cnt for the device
	 */
	dev = dev_get_by_index(&init_net, nim->tunnel_id);
	if (!dev) {
		nss_ipsecmgr_error("event received on deallocated I/F (%d)\n", nim->tunnel_id);
		return;
	}

	BUG_ON(dev != tun_dev);

	priv = netdev_priv(dev);

	/*
	 * XXX: process the events recevied from NSS
	 */

	dev_put(dev);
}

/*
 * nss_ipsecmgr_ref_init()
 * 	initiaize the reference object
 */
void nss_ipsecmgr_ref_init(struct nss_ipsecmgr_ref *ref, nss_ipsecmgr_ref_update_t update, nss_ipsecmgr_ref_free_t free)
{
	INIT_LIST_HEAD(&ref->head);
	INIT_LIST_HEAD(&ref->node);

	ref->update = update ? update : nss_ipsecmgr_ref_no_update;
	ref->free = free ? free : nss_ipsecmgr_ref_no_free;
}

/*
 * nss_ipsecmgr_ref_add()
 * 	add child reference to parent chain
 */
void nss_ipsecmgr_ref_add(struct nss_ipsecmgr_ref *child, struct nss_ipsecmgr_ref *parent)
{
	/*
	 * if child is already part of an existing chain then remove it before
	 * adding it to the new one. In case this is a new entry then the list
	 * init during alloc would ensure that the "del_init" operation results
	 * in a no-op
	 */
	list_del_init(&child->node);
	list_add(&child->node, &parent->head);
}

/*
 * nss_ipsecmgr_ref_update()
 * 	update the "ref" object and link it to the parent
 */
void nss_ipsecmgr_ref_update(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *child, struct nss_ipsec_msg *nim)
{
	struct nss_ipsecmgr_ref *entry;

	child->id++;
	child->update(priv, child, nim);

	/*
	 * If, there are references to associated with this
	 * object then notify them about the change. This allows
	 * the "ref" objects to trigger notifications to NSS for
	 * updates to SA
	 */
	list_for_each_entry(entry, &child->head, node) {
		nss_ipsecmgr_ref_update(priv, entry, nim);
	}
}

/*
 * nss_ipsecmgr_ref_free()
 * 	Free all references from the "ref" object
 *
 * Note: If, the "ref" has child references then it
 * will walk the child reference chain first and issue
 * free for each of the associated "child ref" objects.
 * At the end it will invoke free for the "parent" ref
 * object.
 *
 * +-------+   +-------+   +-------+
 * |  SA1  +--->   SA2 +--->  SA3  |
 * +---+---+   +---+---+   +-------+
 *     |
 * +---V---+   +-------+   +-------+
 * | Flow1 +---> Sub1  +---> Flow4 |
 * +-------+   +---+---+   +-------+
 *                 |
 *             +---v---+
 *             | Flow2 |
 *             +---+---+
 *                 |
 *             +---v---+
 *             | Flow3 |
 *             +-------+
 */
void nss_ipsecmgr_ref_free(struct nss_ipsecmgr_priv *priv, struct nss_ipsecmgr_ref *ref)
{
	struct nss_ipsecmgr_ref *entry;

	while (!list_empty(&ref->head)) {
		entry = list_first_entry(&ref->head, struct nss_ipsecmgr_ref, node);
		nss_ipsecmgr_ref_free(priv, entry);
	}

	list_del_init(&ref->node);
	ref->free(priv, ref);
}

/*
 * nss_ipsecmgr_ref_is_child()
 * 	return true if the child is direct sibling of parent
 */
bool nss_ipsecmgr_ref_is_child(struct nss_ipsecmgr_ref *child, struct nss_ipsecmgr_ref *parent)
{
	struct nss_ipsecmgr_ref *entry;

	list_for_each_entry(entry, &parent->head, node) {
		if (entry == child) {
			return true;
		}
	}

	return false;
}

/*
 * nss_ipsecmgr_tunnel_add()
 * 	add a IPsec pseudo tunnel device
 */
struct net_device *nss_ipsecmgr_tunnel_add(struct nss_ipsecmgr_callback *cb)
{
	struct nss_ipsecmgr_priv *priv;
	struct net_device *dev;
	int status;

	dev = alloc_netdev(sizeof(struct nss_ipsecmgr_priv), NSS_IPSECMGR_TUN_NAME, nss_ipsecmgr_tunnel_setup);
	if (!dev) {
		nss_ipsecmgr_error("unable to allocate a tunnel device\n");
		return NULL;
	}

	priv = netdev_priv(dev);
	priv->dev = dev;
	priv->cb_ctx = cb->ctx;
	priv->data_cb = cb->data_fn;
	priv->event_cb = cb->event_fn;
	priv->nss_ctx = nss_ipsec_get_context();
	priv->nss_ifnum = nss_ipsec_get_interface(priv->nss_ctx);
	if (priv->nss_ifnum < 0) {
		nss_ipsecmgr_error("Invalid nss interface :%d\n", priv->nss_ifnum);
		goto fail;
	}

	rwlock_init(&priv->lock);
	nss_ipsecmgr_init_sa_db(&priv->sa_db);
	nss_ipsecmgr_init_netmask_db(&priv->net_db);
	nss_ipsecmgr_init_flow_db(&priv->flow_db);

	status = rtnl_is_locked() ? register_netdevice(dev) : register_netdev(dev);
	if (status < 0) {
		nss_ipsecmgr_error("register net dev failed :%d\n", priv->nss_ifnum);
		goto fail;
	}

	nss_ipsec_data_register(priv->nss_ifnum, nss_ipsecmgr_buf_receive, dev, 0);
	nss_ipsec_notify_register(NSS_IPSEC_ENCAP_IF_NUMBER, nss_ipsecmgr_event_recieve, dev);
	nss_ipsec_notify_register(NSS_IPSEC_DECAP_IF_NUMBER, nss_ipsecmgr_event_recieve, dev);

	return dev;
fail:
	free_netdev(dev);
	return NULL;
}
EXPORT_SYMBOL(nss_ipsecmgr_tunnel_add);


/*
 * nss_ipsecmgr_del_tunnel()
 * 	delete an existing IPsec tunnel
 */
bool nss_ipsecmgr_tunnel_del(struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv = netdev_priv(dev);

	/*
	 * Unregister the callbacks from the HLOS as we are no longer
	 * interested in exception data & async messages
	 */
	nss_ipsec_data_unregister(priv->nss_ctx, priv->nss_ifnum);

	nss_ipsec_notify_unregister(priv->nss_ctx, NSS_IPSEC_ENCAP_IF_NUMBER);
	nss_ipsec_notify_unregister(priv->nss_ctx, NSS_IPSEC_DECAP_IF_NUMBER);

	priv->data_cb = NULL;
	priv->event_cb = NULL;

	nss_ipsecmgr_sa_flush_all(priv);

	/*
	 * The unregister should start here but the expectation is that the free would
	 * happen when the reference count goes down to '0'
	 */
	rtnl_is_locked() ? unregister_netdevice(dev) : unregister_netdev(dev);

	return true;
}
EXPORT_SYMBOL(nss_ipsecmgr_tunnel_del);

/*
 * nss_ipsecmgr_init()
 *	module init
 */
static int __init nss_ipsecmgr_init(void)
{
	if (!nss_cmn_get_nss_enabled()) {
		nss_ipsecmgr_info_always("NSS is not enabled in this platform\n");
		return 0;
	}

	nss_ipsecmgr_info_always("NSS IPsec manager loaded: Build date %s\n", __DATE__);
	return 0;
}

/*
 * nss_ipsecmgr_exit()
 * 	module exit
 */
static void __exit nss_ipsecmgr_exit(void)
{
	nss_ipsecmgr_info_always("NSS IPsec manager unloaded\n");
}

module_init(nss_ipsecmgr_init);
module_exit(nss_ipsecmgr_exit);
