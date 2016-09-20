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

/*
 * nss_bridge_mgr.c
 *	NSS to HLOS Bridge Interface manager
 */
#include <linux/etherdevice.h>
#include <nss_api_if.h>

#if (NSS_BRIDGE_MGR_DEBUG_LEVEL < 1)
#define nss_bridge_mgr_assert(fmt, args...)
#else
#define nss_bridge_mgr_assert(c) BUG_ON(!(c))
#endif /* NSS_BRIDGE_MGR_DEBUG_LEVEL */

/*
 * Compile messages for dynamic enable/disable
 */
#if defined(CONFIG_DYNAMIC_DEBUG)
#define nss_bridge_mgr_warn(s, ...) \
		pr_debug("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#define nss_bridge_mgr_info(s, ...) \
		pr_debug("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#define nss_bridge_mgr_trace(s, ...) \
		pr_debug("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#else /* CONFIG_DYNAMIC_DEBUG */
/*
 * Statically compile messages at different levels
 */
#if (NSS_BRIDGE_MGR_DEBUG_LEVEL < 2)
#define nss_bridge_mgr_warn(s, ...)
#else
#define nss_bridge_mgr_warn(s, ...) \
		pr_warn("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#endif

#if (NSS_BRIDGE_MGR_DEBUG_LEVEL < 3)
#define nss_bridge_mgr_info(s, ...)
#else
#define nss_bridge_mgr_info(s, ...) \
		pr_notice("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#endif

#if (NSS_BRIDGE_MGR_DEBUG_LEVEL < 4)
#define nss_bridge_mgr_trace(s, ...)
#else
#define nss_bridge_mgr_trace(s, ...) \
		pr_info("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#endif
#endif /* CONFIG_DYNAMIC_DEBUG */

#define NSS_BRIDGE_MAX_DEVICES	4

/*
 * Spinlock to protect bridge private instance
 */
DEFINE_SPINLOCK(nss_bridge_spinlock);

/*
 * bridge manager private structure
 * TODO: support unlimit number of bridges and let NSS FW decide
 */
struct nss_bridge_pvt {
	struct net_device *dev;
	uint32_t ifnum;
	uint32_t mtu;
	uint8_t dev_addr[ETH_ALEN];
} bridge_pvt[NSS_BRIDGE_MAX_DEVICES];

/*
 * nss_bridge_mgr_find_instance()
 */
static struct nss_bridge_pvt *nss_bridge_mgr_find_instance(
						struct net_device *dev)
{
	int i;

	if (!netif_is_bridge_master(dev)) {
		return NULL;
	}

	/*
	 * Do we have it on record?
	 */
	spin_lock_bh(&nss_bridge_spinlock);
	for (i = 0; i < NSS_BRIDGE_MAX_DEVICES; i++) {
		if (bridge_pvt[i].dev == dev) {
			spin_unlock_bh(&nss_bridge_spinlock);
			return &bridge_pvt[i];
		}
	}

	spin_unlock_bh(&nss_bridge_spinlock);
	return NULL;
}

/*
 * nss_bridge_mgr_changemtu_event()
 */
static int nss_bridge_mgr_changemtu_event(struct netdev_notifier_info *info)
{
	struct net_device *dev = netdev_notifier_info_to_dev(info);
	struct nss_bridge_pvt *b_pvt = nss_bridge_mgr_find_instance(dev);

	if (!b_pvt)
		return NOTIFY_DONE;

	spin_lock_bh(&nss_bridge_spinlock);
	if (b_pvt->mtu == dev->mtu) {
		spin_unlock_bh(&nss_bridge_spinlock);
		return NOTIFY_DONE;
	}
	spin_unlock_bh(&nss_bridge_spinlock);

	nss_bridge_mgr_trace("MTU changed to %d, send message to NSS\n", dev->mtu);

	if (nss_bridge_tx_set_mtu_msg(b_pvt->ifnum, dev->mtu) != NSS_TX_SUCCESS) {
		nss_bridge_mgr_warn("Failed to send change MTU message to NSS\n");
		return NOTIFY_BAD;
	}

	spin_lock_bh(&nss_bridge_spinlock);
	if (b_pvt->dev == dev) {
		b_pvt->mtu = dev->mtu;
	}
	spin_unlock_bh(&nss_bridge_spinlock);

	return NOTIFY_DONE;
}

/*
 * int nss_bridge_mgr_changeaddr_event()
 */
static int nss_bridge_mgr_changeaddr_event(struct netdev_notifier_info *info)
{
	struct net_device *dev = netdev_notifier_info_to_dev(info);
	struct nss_bridge_pvt *b_pvt = nss_bridge_mgr_find_instance(dev);

	if (!b_pvt)
		return NOTIFY_DONE;

	if (!memcmp(b_pvt->dev_addr, dev->dev_addr, ETH_ALEN)) {
		nss_bridge_mgr_trace("MAC are the same..skip processing it\n");
		return NOTIFY_DONE;
	}

	nss_bridge_mgr_trace("MAC changed to %pM, update NSS\n", dev->dev_addr);

	if (nss_bridge_tx_set_mac_addr_msg(b_pvt->ifnum, dev->dev_addr) != NSS_TX_SUCCESS) {
		nss_bridge_mgr_warn("Failed to send change MAC address message to NSS\n");
		return NOTIFY_BAD;
	}

	spin_lock_bh(&nss_bridge_spinlock);
	if (b_pvt->dev == dev) {
		ether_addr_copy(b_pvt->dev_addr, dev->dev_addr);
	}
	spin_unlock_bh(&nss_bridge_spinlock);

	return NOTIFY_DONE;
}

/*
 * nss_bridge_mgr_changeupper_event()
 */
static int nss_bridge_mgr_changeupper_event(struct netdev_notifier_info *info)
{
	struct net_device *dev = netdev_notifier_info_to_dev(info);
	struct netdev_notifier_changeupper_info *cu_info = info;
	struct nss_bridge_pvt *b_pvt;
	uint32_t slave_ifnum;

	/*
	 * Check if the master pointer is valid
	 */
	if (!cu_info->master)
		return NOTIFY_DONE;

	/*
	 * Only care about interfaces known by NSS
	 */
	slave_ifnum = nss_cmn_get_interface_number_by_dev(dev);
	if (slave_ifnum < 0) {
		return NOTIFY_DONE;
	}

	b_pvt = nss_bridge_mgr_find_instance(cu_info->upper_dev);
	if (!b_pvt)
		return NOTIFY_DONE;

	if (cu_info->linking) {
		nss_bridge_mgr_trace("Interface %s joining bridge %s\n" , dev->name, cu_info->upper_dev->name);
		if (nss_bridge_tx_join_msg(b_pvt->ifnum, dev) != NSS_TX_SUCCESS) {
			return NOTIFY_BAD;
		}
	} else {
		nss_bridge_mgr_trace("Interface %s leaving bridge %s\n" , dev->name, cu_info->upper_dev->name);
		if (nss_bridge_tx_leave_msg(b_pvt->ifnum, dev) != NSS_TX_SUCCESS) {
			return NOTIFY_BAD;
		}
	}

	return NOTIFY_DONE;
}

/*
 * nss_bridge_mgr_register_event()
 */
static int nss_bridge_mgr_register_event(struct netdev_notifier_info *info)
{
	struct net_device *dev = netdev_notifier_info_to_dev(info);
	struct nss_bridge_pvt *b_pvt;
	int i, ifnum;

	if (!netif_is_bridge_master(dev))
		return NOTIFY_DONE;

	spin_lock_bh(&nss_bridge_spinlock);
	for (i = 0; i < NSS_BRIDGE_MAX_DEVICES; i++) {
		if (!bridge_pvt[i].dev) {
			break;
		}
	}

	if (i == NSS_BRIDGE_MAX_DEVICES) {
		spin_unlock_bh(&nss_bridge_spinlock);
		nss_bridge_mgr_warn("%p: exceeded max supported instances %d\n", dev, NSS_BRIDGE_MAX_DEVICES);
		return NOTIFY_DONE;
	}

	b_pvt = &bridge_pvt[i];
	b_pvt->dev = dev;
	spin_unlock_bh(&nss_bridge_spinlock);

	ifnum = nss_dynamic_interface_alloc_node(NSS_DYNAMIC_INTERFACE_TYPE_BRIDGE);
	if (ifnum < 0) {
		nss_bridge_mgr_warn("%p: failed to alloc bridge di\n", dev);
		spin_lock_bh(&nss_bridge_spinlock);
		b_pvt->dev = NULL;
		spin_unlock_bh(&nss_bridge_spinlock);
		return NOTIFY_BAD;
	}

	if (!nss_bridge_register(ifnum)) {
		nss_bridge_mgr_warn("%p: failed to register bridge di to NSS", dev);
		goto fail;
	}

	if (nss_bridge_tx_set_mac_addr_msg(ifnum, dev->dev_addr) != NSS_TX_SUCCESS) {
		nss_bridge_mgr_warn("%p: failed to set mac_addr msg\n", dev);
		goto fail;
	}

	if (nss_bridge_tx_set_mtu_msg(ifnum, dev->mtu) != NSS_TX_SUCCESS) {
		nss_bridge_mgr_warn("%p: failed to set mtu msg\n", dev);
		goto fail;
	}

	/*
	 * All done, take a snapshot of the current mtu and mac addrees
	 */
	spin_lock_bh(&nss_bridge_spinlock);
	if (b_pvt->dev != dev) {
		spin_unlock_bh(&nss_bridge_spinlock);
		goto free_di;
	}
	b_pvt->ifnum = ifnum;
	b_pvt->mtu = dev->mtu;
	ether_addr_copy(b_pvt->dev_addr, dev->dev_addr);
	spin_unlock_bh(&nss_bridge_spinlock);

	return NOTIFY_DONE;

fail:
	spin_lock_bh(&nss_bridge_spinlock);
	b_pvt->dev = NULL;
	spin_unlock_bh(&nss_bridge_spinlock);

free_di:
	if (nss_dynamic_interface_dealloc_node(ifnum, NSS_DYNAMIC_INTERFACE_TYPE_BRIDGE) != NSS_TX_SUCCESS) {
		nss_bridge_mgr_warn("%p: dealloc bridge di failed\n", dev);
	}
	return NOTIFY_BAD;
}

/*
 * nss_bridge_mgr_unregister_event()
 */
static int nss_bridge_mgr_unregister_event(struct netdev_notifier_info *info)
{
	struct net_device *dev = netdev_notifier_info_to_dev(info);
	struct nss_bridge_pvt *b_pvt;

	if (!netif_is_bridge_master(dev))
		return NOTIFY_DONE;

	/*
	 * Do we have it on record?
	 */
	b_pvt = nss_bridge_mgr_find_instance(dev);
	if (!b_pvt) {
		return NOTIFY_DONE;
	}

	spin_lock_bh(&nss_bridge_spinlock);
	b_pvt->dev = NULL;
	spin_unlock_bh(&nss_bridge_spinlock);

	nss_bridge_mgr_trace("Bridge %s unregsitered. Freeing bridge di %d\n", dev->name, b_pvt->ifnum);
	if (nss_dynamic_interface_dealloc_node(b_pvt->ifnum, NSS_DYNAMIC_INTERFACE_TYPE_BRIDGE) != NSS_TX_SUCCESS) {
		nss_bridge_mgr_trace("%p: dealloc bridge di failed\n", dev);
	}

	return NOTIFY_DONE;
}

/*
 * nss_bridge_mgr_netdevice_event()
 */
static int nss_bridge_mgr_netdevice_event(struct notifier_block *unused,
				unsigned long event, void *ptr)
{
	struct netdev_notifier_info *info = (struct netdev_notifier_info *)ptr;

	switch (event) {
	case NETDEV_CHANGEUPPER:
		return nss_bridge_mgr_changeupper_event(info);
	case NETDEV_CHANGEADDR:
		return nss_bridge_mgr_changeaddr_event(info);
	case NETDEV_CHANGEMTU:
		return nss_bridge_mgr_changemtu_event(info);
	case NETDEV_REGISTER:
		return nss_bridge_mgr_register_event(info);
	case NETDEV_UNREGISTER:
		return nss_bridge_mgr_unregister_event(info);
	}

	/*
	 * Notify done for all the events we don't care
	 */
	return NOTIFY_DONE;
}


static struct notifier_block nss_bridge_mgr_netdevice_nb __read_mostly = {
	.notifier_call = nss_bridge_mgr_netdevice_event,
};

/*
 * nss_bridge_mgr_init_module()
 *	bridge_mgr module init function
 */
int __init nss_bridge_mgr_init_module(void)
{
	/*
	 * Monitor bridge activity only on supported platform
	 */
	if (!of_machine_is_compatible("qcom,ipq807x"))
		return 0;

	memset(&bridge_pvt, 0, sizeof(bridge_pvt));
	register_netdevice_notifier(&nss_bridge_mgr_netdevice_nb);
	nss_bridge_mgr_info("Module (Build %s) loaded\n", NSS_CLIENT_BUILD_ID);

	return 0;
}

/*
 * nss_bridge_mgr_exit_module()
 *	bridge_mgr module exit function
 */
void __exit nss_bridge_mgr_exit_module(void)
{
	unregister_netdevice_notifier(&nss_bridge_mgr_netdevice_nb);
	nss_bridge_mgr_info("Module unloaded\n");
}

module_init(nss_bridge_mgr_init_module);
module_exit(nss_bridge_mgr_exit_module);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("NSS bridge manager");
