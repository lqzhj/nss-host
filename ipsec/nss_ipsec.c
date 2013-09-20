/* Copyright (c) 2013, Qualcomm Atheros Inc.
 *
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
 *
 *
 */

/**
 * @file NSS IPsec offload manager
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/if.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/dst.h>

#include <nss_api_if.h>
#include <nss_cfi_if.h>
#include "nss_ipsec.h"

#define nss_ipsec_skb_tunnel_dev(skb) 	(((struct nss_ipsec_skb_cb *)skb->cb)->tunnel_dev)
#define nss_ipsec_skb_eth_dev(skb) 	(((struct nss_ipsec_skb_cb *)skb->cb)->eth_dev)
/*
 * This is used by KLIPS for communicate the device along with the
 * packet. We need this to derive the mapping of the incoming flow
 * to the IPsec tunnel
 */
struct nss_ipsec_skb_cb {
	struct net_device *tunnel_dev;
	struct net_device *eth_dev;
};

/**
 * @brief IPsec tunnel entry
 */
struct nss_ipsec_tunnel {
	struct list_head list;		/**< list of registered tunnels */

	uint8_t name[IFNAMSIZ];		/**< IPsec interface name from HLOS */

	struct net_device *dev;		/**< tunnel device entry for the interface */
	struct net_device *eth_dev;	/**< physical device entry for the tunnel interface */
};

/*
 * tunnel list head, the protection is required for accessing the
 * list. The integrity of the object will require some type of
 * reference count so that delete doesn't happen when the create
 * is working on it.
 */
LIST_HEAD(tunnel_head);

uint8_t ifname_base[] = "ipsec";
void *gbl_nss_ctx = NULL;
struct net_device *gbl_except_dev = NULL;

#define NSS_IPSEC_IFNAME_BASE_SZ	(sizeof(ifname_base) - 1)

/*
 * nss_ipsec_get_tunnel_by_dev()
 * 	retrieve the tunnel using the device pointer
 */
static struct nss_ipsec_tunnel *nss_ipsec_get_tunnel_by_dev(struct net_device *dev)
{
	struct nss_ipsec_tunnel *tunnel;
	struct list_head *cur;

	list_for_each(cur, &tunnel_head) {
		tunnel = (struct nss_ipsec_tunnel *)cur;

		if (tunnel->dev == dev) {
			return tunnel;
		}
	}

	return NULL;
}

/*
 * nss_ipsec_check_outer_ip()
 * 	verify if the outer IP header is valid
 *
 * NOTE: the valid outer IP headers are specific to IPsec and
 * cannot be performed in conjunction with other non-IPsec protocols
 */
static inline int nss_ipsec_check_outer_ip(struct nss_ipsec_ipv4_hdr *ip)
{
	/*
	 * IP options are not supported
	 */
	if (ip->ver_ihl != 0x45) {
		nss_cfi_dbg("outer IPv4 header mismatch:ver_ihl - %d\n", ip->ver_ihl);
		return -1;
	}

	/*
	 * supported outer IP protocols for Fast path
	 */
	switch(ip->protocol) {
	case IPPROTO_ESP:
		return 0;
	default:
		return -1;
	}
}

/*
 * nss_ipsec_check_inner_ip()
 * 	verify if the inner IP header is valid
 */
static inline int nss_ipsec_check_inner_ip(struct nss_ipsec_ipv4_hdr *ip)
{
	/*
	 * IP options are not supported
	 */
	if (ip->ver_ihl != 0x45) {
		nss_cfi_dbg("inner IPv4 header mismatch:ver_ihl - %d\n", ip->ver_ihl);
		return -1;
	}

	/*
	 * supported inner IP protocols for Fast path
	 */
	switch(ip->protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		return 0;
	default:
		return -1;
	}
}

/*
 * nss_ipsec_get_next_hdr()
 * 	return the next header based upon the ip protocol type
 */
static inline uint32_t nss_ipsec_get_next_hdr(struct nss_ipsec_ipv4_hdr *ip, uint8_t **next_hdr)
{
	/*
	 * location of the next header
	 */
	*next_hdr = (uint8_t *)ip + NSS_IPSEC_IPHDR_SZ;

	/*
	 * size of the next header
	 */
	switch(ip->protocol) {
	case IPPROTO_TCP:
		return sizeof(struct nss_ipsec_tcp_hdr);
	case IPPROTO_UDP:
		return sizeof(struct nss_ipsec_udp_hdr);
	case IPPROTO_ESP:
		return sizeof(struct nss_ipsec_esp_hdr);
	/*
	 * we should never get here
	 */
	default:
		nss_cfi_err("unknown protocol for next hdr\n");
		return 0;
	}
}

/*
 * nss_ipsec_get_if_idx()
 * 	return the interface index number from the interface name
 *
 * get device index from interface name e.g., 'ipsec0' has the index
 * 0 and 'ipsec1' has index 1
 */
static int32_t nss_ipsec_get_if_idx(uint8_t *ifname)
{
	uint32_t idx;

	if (strncmp(ifname, ifname_base, NSS_IPSEC_IFNAME_BASE_SZ) != 0) {
		return -1;
	}

	ifname += NSS_IPSEC_IFNAME_BASE_SZ;

	for (idx = 0; (*ifname >= '0') && (*ifname <= '9'); ifname++) {
		idx = (*ifname - '0') + (idx * 10);
	}

	return idx;
}

/*
 * nss_ipsec_get_mac_addr()
 * 	return mac address for a given IP address
 *
 * NOTE: this uses neighbour table lookups
 *
 */
static int nss_ipsec_get_mac_addr(uint32_t ip_addr, uint8_t *mac_addr)
{
	struct neighbour *neigh;
	struct rtable *rt;
	struct dst_entry *dst;

	/*
	 * Get the MAC addresses that correspond to source and destination host addresses.
	 * We look up the rtable entries and, from its neighbour structure, obtain the hardware address.
	 * This means we will also work if the neighbours are routers too.
	 */
	rt = ip_route_output(&init_net, htonl(ip_addr), 0, 0, 0);
	if (IS_ERR(rt)) {
		nss_cfi_err("get_mac_addr: route entry missing\n");
		goto fail;
	}

	dst = (struct dst_entry *)rt;

	rcu_read_lock();
	neigh = dst_get_neighbour_noref(dst);
	if (!neigh) {
		rcu_read_unlock();
		dst_release(dst);
		nss_cfi_err("get_mac_addr: neighbour entry missing\n");
		goto fail;
	}
	if (!(neigh->nud_state & NUD_VALID)) {
		rcu_read_unlock();
		dst_release(dst);
		nss_cfi_err("get_mac_addr: neighbour state not valid - 0x%x\n", neigh->nud_state);
		goto fail;
	}

	if (!neigh->dev) {
		rcu_read_unlock();
		dst_release(dst);
		nss_cfi_err("get_mac_addr: neighbour device missing\n");
		goto fail;
	 }

	memcpy(mac_addr, neigh->ha, (size_t)neigh->dev->addr_len);
	rcu_read_unlock();

	dst_release(dst);

	if (is_multicast_ether_addr(mac_addr)) {
		nss_cfi_dbg("MAC address is multicast/broadcast - ignoring\n");
		goto fail;
	}

	return 0;

fail:
	return -1;
}

/*
 * nss_ipsec_except()
 * 	ipsec exception routine for handling exceptions from NSS IPsec package
 *
 * exception function called by NSS HLOS driver when it receives
 * a packet for exception with the interface number for decap
 */
static void nss_ipsec_except(void *ctx, void *buf)
{
	struct net_device *dev = gbl_except_dev;
	struct sk_buff *skb = (struct sk_buff *)buf;
	struct nss_ipsec_ipv4_hdr *inner_ip;

	inner_ip = (struct nss_ipsec_ipv4_hdr *)skb->data;

	nss_cfi_dbg_skb(skb, NSS_IPSEC_DBG_DUMP_LIMIT);

	if (nss_ipsec_check_inner_ip(inner_ip) < 0) {
		nss_cfi_dbg("unkown ipv4 header\n");
		return;
	}

	skb_reset_network_header(skb);
	skb->pkt_type = PACKET_HOST;
	skb->protocol = cpu_to_be16(ETH_P_IP);
	skb->dev = dev;
	skb->skb_iif = dev->ifindex;

	netif_receive_skb(skb);
}

/*
 * nss_ipsec_get_tunnel()
 * 	return the associated tunnel state
 *
 * retreive the tunnel from net_device if no tunnels are found which means
 * this the first time we are seeing this skb from this IPsec interface,
 * go ahead and create a new tunnel
 */
static struct nss_ipsec_tunnel* nss_ipsec_get_tunnel(struct net_device *dev, struct net_device *eth_dev)
{
	struct nss_ipsec_tunnel *tunnel;
	int32_t idx;

	tunnel = nss_ipsec_get_tunnel_by_dev(dev);
	if (tunnel) {
		return tunnel;
	}

	idx = nss_ipsec_get_if_idx(dev->name);
	if (idx < 0) {
		nss_cfi_err("unable to get num from - (%s) where base is (%s)\n", dev->name, ifname_base);
		return NULL;
	}

	tunnel = kzalloc(sizeof(struct nss_ipsec_tunnel), GFP_ATOMIC);
	if (!tunnel) {
		nss_cfi_err("unable to allocate tunnel for NSS IPsec offload\n");
		return NULL;
	}

	nss_cfi_info("index found - %d\n", idx);

	strncpy(tunnel->name, dev->name, IFNAMSIZ);

	/*
	 * XXX: we need to register a notifier so that we can delete our state,
	 */
	tunnel->dev = dev;
	tunnel->eth_dev = eth_dev;

	/*
	 * exception is indicated using the first registered tunnel
	 */
	if (!gbl_except_dev)  {
		gbl_except_dev = dev;
	}

	list_add(&tunnel->list, &tunnel_head);

	nss_cfi_info("registered tunnel for %s\n", tunnel->name);

	return tunnel;
}

/*
 * nss_ipsec_encap_ipv4_rule()
 * 	insert a ESP rule for NSS to process outgoing IPsec packets
 */
static int32_t nss_ipsec_encap_ipv4_rule(struct nss_ipsec_tunnel *tunnel, struct nss_ipsec_ipv4_hdr *ip)
{
	struct nss_ipv4_create esp_rule = {0};
	nss_tx_status_t status;
	uint32_t eth_ifnum;
	void *ipv4_mgr_ctx;

	/*
	 * gbl_nss_ctx is for pushing IPsec rules on NSS core 1.
	 * ipv4_mgr_ctx is for pushing IPv4 rules on NSS core 0.
	 */
	ipv4_mgr_ctx = nss_get_ipv4_mgr_ctx();
	if (ipv4_mgr_ctx == NULL) {
		nss_cfi_err("IPv4 connection manager ctx is NULL, not pushing IPv4 rule\n");
		goto fail;
	}

	eth_ifnum = nss_get_interface_number(gbl_nss_ctx, tunnel->eth_dev);

	esp_rule.src_interface_num  = NSS_C2C_TX_INTERFACE;
	esp_rule.dest_interface_num = eth_ifnum;

	esp_rule.protocol = IPPROTO_ESP;

	esp_rule.from_mtu = tunnel->dev->mtu;
	esp_rule.to_mtu = tunnel->eth_dev->mtu;

	esp_rule.src_ip = ntohl(ip->src_ip);
	esp_rule.src_ip_xlate = ntohl(ip->src_ip);

	esp_rule.dest_ip = ntohl(ip->dst_ip);
	esp_rule.dest_ip_xlate = ntohl(ip->dst_ip);

	esp_rule.src_port = 0;
	esp_rule.src_port_xlate = 0;
	esp_rule.dest_port = 0;
	esp_rule.dest_port_xlate = 0;

	memcpy(esp_rule.src_mac, tunnel->dev->dev_addr, ETH_ALEN);

	nss_cfi_dbg("src ip %x src_mac ", esp_rule.src_ip);
	nss_cfi_dbg_data(esp_rule.src_mac, ETH_ALEN, ':');

	if (nss_ipsec_get_mac_addr(esp_rule.dest_ip, esp_rule.dest_mac) < 0) {
		nss_cfi_err("error retriving the MAC address for ip = 0x%x\n", ip->dst_ip);
		goto fail;
	}

	nss_cfi_dbg("dest ip %x dest_mac ",esp_rule.dest_ip);
	nss_cfi_dbg_data(esp_rule.dest_mac, ETH_ALEN, ':');

	status = nss_tx_create_ipv4_rule(ipv4_mgr_ctx, &esp_rule);
	if (status != NSS_TX_SUCCESS) {
		nss_cfi_err("unable to create ESP rule for encap - %d\n", status);
		goto fail;
	}

	return 0;
fail:
	return -EINVAL;
}

/*
 * nss_ipsec_decap_ipv4_rule()
 * 	insert a ESP rule for NSS to process incoming IPsec packets
 */
static int32_t nss_ipsec_decap_ipv4_rule(struct nss_ipsec_tunnel *tunnel, struct nss_ipsec_ipv4_hdr *ip)
{
	struct nss_ipv4_create esp_rule = {0};
	nss_tx_status_t status;
	uint32_t eth_ifnum;
	void *ipv4_mgr_ctx;

	/*
	 * gbl_nss_ctx is for pushing IPsec rules on NSS core 1.
	 * ipv4_mgr_ctx is for pushing IPv4 rules on NSS core 0.
	 */
	ipv4_mgr_ctx = nss_get_ipv4_mgr_ctx();
	if (ipv4_mgr_ctx == NULL) {
		nss_cfi_err("IPv4 connection manager ctx is NULL, not pushing IPv4 rule\n");
		goto fail;
	}

	eth_ifnum = nss_get_interface_number(gbl_nss_ctx, tunnel->eth_dev);

	esp_rule.src_interface_num  = eth_ifnum;
	esp_rule.dest_interface_num = NSS_C2C_TX_INTERFACE;

	esp_rule.protocol = IPPROTO_ESP;

	esp_rule.from_mtu = tunnel->dev->mtu;
	esp_rule.to_mtu = tunnel->eth_dev->mtu;

	esp_rule.src_ip = ntohl(ip->src_ip);
	esp_rule.src_ip_xlate = ntohl(ip->src_ip);

	esp_rule.dest_ip = ntohl(ip->dst_ip);
	esp_rule.dest_ip_xlate = ntohl(ip->dst_ip);

	esp_rule.src_port = 0;
	esp_rule.src_port_xlate = 0;
	esp_rule.dest_port = 0;
	esp_rule.dest_port_xlate = 0;

	memcpy(esp_rule.dest_mac, tunnel->dev->dev_addr, ETH_ALEN);

	nss_cfi_dbg("dest ip %x dest_mac ",esp_rule.dest_ip);
	nss_cfi_dbg_data(esp_rule.dest_mac, ETH_ALEN, ':');

	if (nss_ipsec_get_mac_addr(esp_rule.src_ip, esp_rule.src_mac) < 0) {
		nss_cfi_err("error retriving the MAC address for ip = 0x%x\n", ip->src_ip);
		goto fail;
	}

	nss_cfi_dbg("src ip %x src_mac ", esp_rule.src_ip);
	nss_cfi_dbg_data(esp_rule.src_mac, ETH_ALEN, ':');

	status = nss_tx_create_ipv4_rule(ipv4_mgr_ctx, &esp_rule);
	if (status != NSS_TX_SUCCESS) {
		nss_cfi_err("unable to create ESP rule for decap - %d\n", status);
		goto fail;
	}

	return 0;
fail:
	return -EINVAL;
}

/*
 * nss_ipsec_encap_rule_insert()
 *	add an encapsulation SA rule to NSS IPsec
 *
 * Encap rule insertion API, this will add a new SA rule to the NSS ipsec_encap
 * SA table if there was no entry for this tuple.
 */
static int32_t nss_ipsec_encap_rule_insert(struct sk_buff *skb, uint32_t crypto_sid)
{
	struct nss_ipsec_encap_rule rule = {{{0}}};
	struct nss_ipsec_ipv4_hdr *outer_ip;
	struct nss_ipsec_ipv4_hdr *inner_ip;
	struct nss_ipsec_tunnel *tunnel;
	struct net_device *eth_dev;
	struct net_device *dev;
	uint32_t inner_next_sz;
	uint32_t outer_next_sz;
	uint8_t *inner_next;
	uint8_t *outer_next;
	nss_tx_status_t status;

	dev = nss_ipsec_skb_tunnel_dev(skb);
	eth_dev = nss_ipsec_skb_eth_dev(skb);

	outer_ip = (struct nss_ipsec_ipv4_hdr *)skb->data;

	nss_cfi_dbg("tunnel_dev - %s, eth_dev - %s, hard_header_len - %d\n",
			dev->name, eth_dev->name, dev->hard_header_len);
	/**
	 * Note: Only ESP encap is supported for now, AH or AH over ESP will continue
	 * to use slow path through host
	 */
	if (nss_ipsec_check_outer_ip(outer_ip) < 0) {
		nss_cfi_dbg_skb(skb, NSS_IPSEC_DBG_DUMP_LIMIT);
		nss_cfi_dbg("unsupported outer IP protocol (%d)\n", outer_ip->protocol);
		goto fail;
	}

	inner_ip = (struct nss_ipsec_ipv4_hdr *)(skb->data + NSS_IPSEC_IPHDR_SZ + NSS_IPSEC_ESPHDR_SZ);

	/**
	 * Note: unsupported protocols like ICMP, etc., will not handled in fast path
	 * and will continue to use the slow path through host. For all those case
	 * silently reject any fast path rule insertion
	 */
	if (nss_ipsec_check_inner_ip(inner_ip) < 0) {
		nss_cfi_dbg_skb(skb, NSS_IPSEC_DBG_DUMP_LIMIT);
		nss_cfi_dbg("unsupported inner IP protocol (%d)\n", inner_ip->protocol);
		goto fail;
	}

	tunnel = nss_ipsec_get_tunnel(dev, eth_dev);
	if (!tunnel) {
		nss_cfi_err("unable to register a new tunnel\n");
		goto fail;
	}

	inner_next_sz = nss_ipsec_get_next_hdr(inner_ip, &inner_next);
	outer_next_sz = nss_ipsec_get_next_hdr(outer_ip, &outer_next);

	/*
	 * IP header + TCP or UDP header
	 */
	memcpy(&rule.entry.ip, inner_ip, NSS_IPSEC_IPHDR_SZ);
	memcpy(&rule.entry.next_hdr, inner_next, inner_next_sz);

	/*
	 * IP header + ESP header
	 */
	memcpy(&rule.data.ip, outer_ip, NSS_IPSEC_IPHDR_SZ);
	memcpy(&rule.data.esp, outer_next, outer_next_sz);

	/*
	 * crypto session id to use with this rule
	 */
	rule.crypto_sid = crypto_sid;

	status = nss_tx_ipsec_rule(gbl_nss_ctx, /* nss context */
					NSS_IPSEC0_ENCAP_INTERFACE, /* interface number */
					NSS_IPSEC_RULE_TYPE_ENCAP_INSERT, /* rule type */
					(uint8_t *)&rule, /* rule object */
					NSS_IPSEC_ENCAP_RULE_SZ); /* rule size */
	if (status != NSS_TX_SUCCESS) {
		nss_cfi_err("unable to create SA rule for encap - %d\n", status);
		goto fail;
	}

	status = nss_ipsec_encap_ipv4_rule(tunnel, outer_ip);
	if (status < 0) {
		nss_cfi_err("unable to create ESP rule\n");
		goto fail;
	}

	return 0;
fail:
	return -EINVAL;
}

/*
 * nss_ipsec_decap_rule_insert()
 * 	add a decapsulation SA rule to NSS IPsec
 *
 * Decap rule insertion API, this will add a new SA rule to the NSS ipsec_decap
 * SA table if there was no entry for this tuple.
 */
static int32_t nss_ipsec_decap_rule_insert(struct sk_buff *skb, uint32_t crypto_sid)
{
	struct nss_ipsec_decap_rule rule = {{{0}}};
	struct nss_ipsec_ipv4_hdr *outer_ip;
	struct nss_ipsec_ipv4_hdr *inner_ip;
	struct nss_ipsec_tunnel *tunnel;
	struct net_device *eth_dev;
	struct net_device *dev;
	uint32_t outer_next_sz;
	uint8_t *outer_next;
	nss_tx_status_t status;

	dev = nss_ipsec_skb_tunnel_dev(skb);
	eth_dev = nss_ipsec_skb_eth_dev(skb);

	nss_cfi_dbg("tunnel_dev - %s, eth_dev - %s, hard_header_len - %d\n",
			dev->name, eth_dev->name, dev->hard_header_len);


	outer_ip = (struct nss_ipsec_ipv4_hdr *)skb_network_header(skb);

	/**
	 * Note: Only ESP encap is supported for now, AH or AH over ESP will continue
	 * to use slow path through host
	 */
	if (nss_ipsec_check_outer_ip(outer_ip) < 0) {
		nss_cfi_dbg_skb(skb, NSS_IPSEC_DBG_DUMP_LIMIT);
		nss_cfi_dbg("unsupported outer IP protocol (%d)\n", outer_ip->protocol);
		goto fail;
	}

	/**
	 * KLIPS strips the IPv4 header before giving it to crypto
	 */
	inner_ip = (struct nss_ipsec_ipv4_hdr *)(skb->data + NSS_IPSEC_ESPHDR_SZ);

	/**
	 * Note: we are operating on the decrypted packet so that we can filter out
	 * unsupported protcols like ICMP which would otherwise caused a rule insertion
	 * in the tables for these non fast path frames
	 */
	if (nss_ipsec_check_inner_ip(inner_ip) < 0) {
		nss_cfi_dbg_skb(skb, NSS_IPSEC_DBG_DUMP_LIMIT);
		nss_cfi_dbg("unsupported inner IP protocol (%d)\n", inner_ip->protocol);
		goto fail;
	}

	tunnel = nss_ipsec_get_tunnel(dev, eth_dev);
	if (!tunnel) {
		nss_cfi_err("unable to register a new tunnel\n");
		goto fail;
	}

	skb->skb_iif = tunnel->dev->ifindex;

	outer_next_sz = nss_ipsec_get_next_hdr(outer_ip, &outer_next);

	memcpy(&rule.entry.ip, outer_ip, NSS_IPSEC_IPHDR_SZ);
	memcpy(&rule.entry.next_hdr, outer_next, outer_next_sz);

	/* crypto session id to use with this rule */
	rule.crypto_sid = crypto_sid;

	status = nss_tx_ipsec_rule(gbl_nss_ctx,	/* nss context */
					NSS_IPSEC0_DECAP_INTERFACE,	/* interface number */
					NSS_IPSEC_RULE_TYPE_DECAP_INSERT, /* rule type */
					(uint8_t *)&rule, /* rule object */
					NSS_IPSEC_DECAP_RULE_SZ); /* rule size */
	if (status != NSS_TX_SUCCESS) {
		nss_cfi_err("unable to create SA rule for decap - %d\n", status);
		goto fail;
	}

	status = nss_ipsec_decap_ipv4_rule(tunnel, outer_ip);
	if (status < 0) {
		nss_cfi_err("unable to create pre-routing rule\n");
		goto fail;
	}

	return 0;
fail:
	return -EINVAL;
}

int __init nss_ipsec_init_module(void)
{
	nss_cfi_info("NSS IPsec (platform - IPQ806x , Build - %s:%s) loaded\n", __DATE__, __TIME__);

	gbl_nss_ctx = nss_register_ipsec_if(NSS_C2C_TX_INTERFACE, nss_ipsec_except, &tunnel_head);
	if (gbl_nss_ctx == NULL) {
		nss_cfi_err("Unable to register IPsec with NSS driver\n");
		return -1;
	}

	nss_cfi_ocf_register_ipsec(nss_ipsec_encap_rule_insert, nss_ipsec_decap_rule_insert);

	return 0;
}

void __exit nss_ipsec_exit_module(void)
{
	nss_unregister_ipsec_if(NSS_C2C_TX_INTERFACE);
	nss_cfi_info("module unloaded\n");
}

EXPORT_SYMBOL(nss_ipsec_encap_rule_insert);
EXPORT_SYMBOL(nss_ipsec_decap_rule_insert);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Qualcomm Atheros");
MODULE_DESCRIPTION("NSS IPsec offload manager");

module_init(nss_ipsec_init_module);
module_exit(nss_ipsec_exit_module);

