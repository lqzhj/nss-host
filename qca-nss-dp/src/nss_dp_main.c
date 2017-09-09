/*
 **************************************************************************
 * Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/ethtool.h>
#if defined(NSS_DP_PPE_SUPPORT)
#include <ref/ref_vsi.h>
#endif

#include "nss_dp_dev.h"
#include "edma.h"

/* Global data */
struct nss_dp_global_ctx dp_global_ctx;
struct nss_dp_data_plane_ctx dp_global_data_plane_ctx[NSS_DP_MAX_PHY_PORTS];

/*
 * nss_dp_do_ioctl()
 */
static int32_t nss_dp_do_ioctl(struct net_device *netdev, struct ifreq *ifr,
						   int32_t cmd)
{
	int ret = -EINVAL;
	struct nss_dp_dev *dp_priv;

	if (!netdev || !ifr)
		return ret;

	dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);

	/* TODO: Perform private ioctl operations */

	return 0;
}

/*
 * nss_dp_change_mtu()
 */
static int32_t nss_dp_change_mtu(struct net_device *netdev, int32_t newmtu)
{
	int ret = -EINVAL;
	struct nss_dp_dev *dp_priv;

	if (!netdev)
		return ret;

	dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);

	/* Let the underlying data plane decide if the newmtu is applicable */
	if (dp_priv->data_plane_ops->change_mtu(dp_priv->dpc, newmtu)) {
		netdev_dbg(netdev, "Data plane change mtu failed\n");
		return ret;
	}

	netdev->mtu = newmtu;

	return 0;
}

/*
 * nss_dp_set_mac_address()
 */
static int32_t nss_dp_set_mac_address(struct net_device *netdev, void *macaddr)
{
	struct nss_dp_dev *dp_priv;
	struct sockaddr *addr = (struct sockaddr *)macaddr;
	int ret = 0;

	if (!netdev)
		return -EINVAL;

	dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);

	netdev_dbg(netdev, "AddrFamily: %d, %0x:%0x:%0x:%0x:%0x:%0x\n",
			addr->sa_family, addr->sa_data[0], addr->sa_data[1],
			addr->sa_data[2], addr->sa_data[3], addr->sa_data[4],
			addr->sa_data[5]);

	ret = eth_prepare_mac_addr_change(netdev, macaddr);
	if (ret)
		return ret;

	if (dp_priv->data_plane_ops->mac_addr(dp_priv->dpc, macaddr)) {
		netdev_dbg(netdev, "Data plane set MAC address failed\n");
		return -EAGAIN;
	}

	eth_commit_mac_addr_change(netdev, macaddr);

	dp_priv->gmac_hal_ops->setmacaddr(dp_priv->gmac_hal_ctx,
			(uint8_t *)addr->sa_data);

	return 0;
}

/*
 * nss_dp_get_stats64()
 */
static struct rtnl_link_stats64 *nss_dp_get_stats64(struct net_device *netdev,
					     struct rtnl_link_stats64 *stats)
{
	struct nss_dp_dev *dp_priv;

	if (!netdev)
		return stats;

	dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);

	dp_priv->gmac_hal_ops->getndostats(dp_priv->gmac_hal_ctx, stats);

	return stats;
}

/*
 * nss_dp_xmit()
 */
static netdev_tx_t nss_dp_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nss_dp_dev *dp_priv;

	if (!skb || !netdev)
		return NETDEV_TX_OK;

	if (skb->len < ETH_HLEN) {
		netdev_dbg(netdev, "skb->len < ETH_HLEN\n");
		goto drop;
	}

	dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);

	netdev_dbg(netdev, "Tx packet, len %d\n", skb->len);

	if (likely(!dp_priv->data_plane_ops->xmit(dp_priv->dpc, skb)))
		return NETDEV_TX_OK;

drop:
	netdev_dbg(netdev, "dropping skb\n");
	dev_kfree_skb_any(skb);
	netdev->stats.tx_dropped++;

	return NETDEV_TX_OK;
}

/*
 * nss_dp_close()
 */
static int nss_dp_close(struct net_device *netdev)
{
	struct nss_dp_dev *dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);

	if (!dp_priv)
		return -EINVAL;

	netif_stop_queue(netdev);
	netif_carrier_off(netdev);

	/* Call soc_hal_ops to stop GMAC tx/rx/intr */
	dp_priv->gmac_hal_ops->stop(dp_priv->gmac_hal_ctx);

	/* Notify data plane link is going down */
	if (dp_priv->data_plane_ops->link_state(dp_priv->dpc, 0)) {
		netdev_dbg(netdev, "Data plane set link failed\n");
		return -EAGAIN;
	}

	/* TODO: Stop phy related stuff */

#if defined(NSS_DP_PPE_SUPPORT)
	/* Notify data plane to unassign VSI */
	if (dp_priv->data_plane_ops->vsi_unassign(dp_priv->dpc, dp_priv->vsi)) {
		netdev_dbg(netdev, "Data plane vsi unassign failed\n");
		return -EAGAIN;
	}
#endif

	/* Notify data plane to close */
	if (dp_priv->data_plane_ops->close(dp_priv->dpc)) {
		netdev_dbg(netdev, "Data plane close failed\n");
		return -EAGAIN;
	}

	clear_bit(__NSS_DP_UP, &dp_priv->flags);

	return 0;
}

/*
 * nss_dp_open()
 */
static int nss_dp_open(struct net_device *netdev)
{
	struct nss_dp_dev *dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);
	if (!dp_priv)
		return -EINVAL;

	netif_carrier_off(netdev);

	/* Call soc_hal_ops to bring up GMAC */
	if (dp_priv->gmac_hal_ops->start(dp_priv->gmac_hal_ctx)) {
		netdev_dbg(netdev, "GMAC Start failed\n");
		return -EINVAL;
	}

	/*
	 * Call data plane init if it has not been done yet
	 */
	if (!(dp_priv->drv_flags & NSS_DP_PRIV_FLAG(INIT_DONE))) {
		if (dp_priv->data_plane_ops->init(dp_priv->dpc)) {
			netdev_dbg(netdev, "Data plane init failed\n");
			return -ENOMEM;
		}

		dp_priv->drv_flags |= NSS_DP_PRIV_FLAG(INIT_DONE);
	}

	/*
	 * Inform the Linux Networking stack about the hardwar capability of
	 * checksum offloading and other features. Each data_plane is
	 * responsible to maintain the feature set it supports
	 */
	dp_priv->data_plane_ops->set_features(dp_priv->dpc);

	set_bit(__NSS_DP_UP, &dp_priv->flags);
	netif_start_queue(netdev);

#if defined(NSS_DP_PPE_SUPPORT)
	if (dp_priv->data_plane_ops->vsi_assign(dp_priv->dpc, dp_priv->vsi)) {
		netdev_dbg(netdev, "Data plane vsi assign failed\n");
		return -EAGAIN;
	}
#endif

	if (dp_priv->data_plane_ops->mac_addr(dp_priv->dpc, netdev->dev_addr)) {
		netdev_dbg(netdev, "Data plane set MAC address failed\n");
		return -EAGAIN;
	}

	if (dp_priv->data_plane_ops->change_mtu(dp_priv->dpc, netdev->mtu)) {
		netdev_dbg(netdev, "Data plane change mtu failed\n");
		return -EAGAIN;
	}

	if (dp_priv->data_plane_ops->open(dp_priv->dpc, 0, 0, 0)) {
		netdev_dbg(netdev, "Data plane open failed\n");
		return -EAGAIN;
	}

	netif_start_queue(netdev);
	netif_carrier_on(netdev);

	return 0;
}

/*
 * Netdevice operations
 */
static const struct net_device_ops nss_dp_netdev_ops = {
	.ndo_open = &nss_dp_open,
	.ndo_stop = &nss_dp_close,
	.ndo_start_xmit = &nss_dp_xmit,
	.ndo_get_stats64 = &nss_dp_get_stats64,
	.ndo_set_mac_address = &nss_dp_set_mac_address,
	.ndo_validate_addr = &eth_validate_addr,
	.ndo_change_mtu = &nss_dp_change_mtu,
	.ndo_do_ioctl = &nss_dp_do_ioctl,
};

/*
 * nss_dp_get_ethtool_stats()
 */
static void nss_dp_get_ethtool_stats(struct net_device *netdev,
				struct ethtool_stats *stats, uint64_t *data)
{
	struct nss_dp_dev *dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);

	dp_priv->gmac_hal_ops->getethtoolstats(dp_priv->gmac_hal_ctx, data);
}

/*
 * nss_dp_get_strset_count()
 */
static int32_t nss_dp_get_strset_count(struct net_device *netdev, int32_t sset)
{
	struct nss_dp_dev *dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);

	return dp_priv->gmac_hal_ops->getssetcount(dp_priv->gmac_hal_ctx, sset);
}

/*
 * nss_dp_get_strings()
 */
static void nss_dp_get_strings(struct net_device *netdev, uint32_t stringset,
			uint8_t *data)
{
	struct nss_dp_dev *dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);

	dp_priv->gmac_hal_ops->getstrings(dp_priv->gmac_hal_ctx, stringset,
					  data);
}

/**
 * nss_dp_get_settings()
 */
static int32_t nss_dp_get_settings(struct net_device *netdev,
			      struct ethtool_cmd *ecmd)
{
	struct nss_dp_dev *dp_priv = (struct nss_dp_dev *)netdev_priv(netdev);
	uint32_t speed;

	ecmd->mdio_support = 0;
	ecmd->lp_advertising = 0;
	ecmd->autoneg = AUTONEG_DISABLE;
	speed = dp_priv->gmac_hal_ops->getspeed(dp_priv->gmac_hal_ctx);
	ethtool_cmd_speed_set(ecmd, speed);
	ecmd->duplex = dp_priv->gmac_hal_ops->getduplex(dp_priv->gmac_hal_ctx);
	ecmd->port = PORT_TP;
	ecmd->transceiver = XCVR_EXTERNAL;

	return 0;
}

/*
 * Ethtool operations
 */
struct ethtool_ops nss_dp_ethtool_ops = {
	.get_strings = &nss_dp_get_strings,
	.get_sset_count = &nss_dp_get_strset_count,
	.get_ethtool_stats = &nss_dp_get_ethtool_stats,
	.get_link = &ethtool_op_get_link,
	.get_settings = &nss_dp_get_settings,
};

/*
 * nss_dp_of_get_pdata()
 */
static int32_t nss_dp_of_get_pdata(struct device_node *np,
				   struct net_device *netdev,
				   struct gmac_hal_platform_data *hal_pdata)
{
	uint8_t *maddr;
	struct nss_dp_dev *dp_priv;
	struct resource memres_devtree = {0};

	dp_priv = netdev_priv(netdev);

	if (of_property_read_u32(np, "qcom,id", &dp_priv->macid)) {
		pr_err("%s: error reading id\n", np->name);
		return -EFAULT;
	}

	if (dp_priv->macid > NSS_DP_MAX_PHY_PORTS || !dp_priv->macid) {
		pr_err("%s: invalid macid %d\n", np->name, dp_priv->macid);
		return -EFAULT;
	}

	dp_priv->phy_mii_type = of_get_phy_mode(np);

	/* TODO: Read IRQ...etc in */

	maddr = (uint8_t *)of_get_mac_address(np);
	if (maddr && is_valid_ether_addr(maddr)) {
		ether_addr_copy(netdev->dev_addr, maddr);
	} else {
		random_ether_addr(netdev->dev_addr);
		pr_info("GMAC%d(%p) Invalid MAC@ - using %pM\n", dp_priv->macid,
						dp_priv, netdev->dev_addr);
	}

	if (of_property_read_u32(np, "qcom,mactype", &hal_pdata->mactype)) {
		pr_err("%s: error reading mactype\n", np->name);
		return -EFAULT;
	}

	if (of_address_to_resource(np, 0, &memres_devtree) != 0)
		return -EFAULT;

	netdev->base_addr = memres_devtree.start;
	hal_pdata->reg_len = resource_size(&memres_devtree);
	hal_pdata->netdev = netdev;

	return 0;
}

/*
 * nss_dp_probe()
 */
static int32_t nss_dp_probe(struct platform_device *pdev)
{
	struct net_device *netdev;
	struct nss_dp_dev *dp_priv;
	struct device_node *np = pdev->dev.of_node;
	struct gmac_hal_platform_data gmac_hal_pdata;
	int32_t ret = 0;
#if defined(NSS_DP_PPE_SUPPORT)
	uint32_t vsi_id;
	fal_port_t port_id;
#endif

	/* TODO: See if we need to do some SoC level common init */

	netdev = alloc_etherdev(sizeof(struct nss_dp_dev));
	if (!netdev) {
		pr_info("alloc_etherdev() failed\n");
		return -ENOMEM;
	}

	dp_priv = netdev_priv(netdev);
	memset((void *)dp_priv, 0, sizeof(struct nss_dp_dev));

	dp_priv->pdev = pdev;
	dp_priv->netdev = netdev;
	netdev->watchdog_timeo = 5 * HZ;
	netdev->netdev_ops = &nss_dp_netdev_ops;
	netdev->ethtool_ops = &nss_dp_ethtool_ops;

	ret = nss_dp_of_get_pdata(np, netdev, &gmac_hal_pdata);
	if (ret != 0) {
		free_netdev(netdev);
		return ret;
	}

	/* Use EDMA data plane as default */
	dp_priv->data_plane_ops = &nss_dp_edma_ops;
	dp_priv->dpc = &dp_global_data_plane_ctx[dp_priv->macid-1];
	dp_priv->dpc->dev = netdev;
	dp_priv->ctx = &dp_global_ctx;

	/* TODO:locks init */

	/*
	 * HAL's init function will return the pointer to the HAL context
	 * (private to hal), which dp will store in its data structures.
	 * The subsequent hal_ops calls expect the DP to pass the HAL
	 * context pointer as an argument
	 */
	if (gmac_hal_pdata.mactype == GMAC_HAL_TYPE_QCOM)
		dp_priv->gmac_hal_ops = &qcom_hal_ops;
	else if (gmac_hal_pdata.mactype == GMAC_HAL_TYPE_10G)
		dp_priv->gmac_hal_ops = &syn_hal_ops;

	if (!dp_priv->gmac_hal_ops) {
		netdev_dbg(netdev, "Unsupported Mac type:%d for %s\n",
				gmac_hal_pdata.mactype, netdev->name);
		free_netdev(netdev);
		return -EFAULT;
	}

	dp_priv->gmac_hal_ctx = dp_priv->gmac_hal_ops->init(&gmac_hal_pdata);
	if (!(dp_priv->gmac_hal_ctx)) {
		free_netdev(netdev);
		return -EFAULT;
	}

	/* TODO: PHY related work */

#if defined(NSS_DP_PPE_SUPPORT)
	/* Get port's default VSI */
	port_id = dp_priv->macid;
	if (ppe_port_vsi_get(0, port_id, &vsi_id)) {
		netdev_dbg(netdev, "failed to get port's default VSI\n");
		free_netdev(netdev);
		return -EFAULT;
	}

	dp_priv->vsi = vsi_id;
#endif

	/* TODO: Features: CSUM, tx/rx offload... configure */

	/* Register the network interface */
	ret = register_netdev(netdev);
	if (ret) {
		netdev_dbg(netdev, "Error registering netdevice %s\n",
								netdev->name);
		dp_priv->gmac_hal_ops->exit(dp_priv->gmac_hal_ctx);
		free_netdev(netdev);
		return ret;
	}

	dp_global_ctx.nss_dp[dp_priv->macid - 1] = dp_priv;

	netdev_dbg(netdev, "Init NSS DP GMAC%d interface %s: (base = 0x%lx)\n",
			dp_priv->macid,
			netdev->name,
			netdev->base_addr);

	return 0;
}

/*
 * nss_dp_remove()
 */
static int nss_dp_remove(struct platform_device *pdev)
{
	uint32_t i;
	struct nss_dp_dev *dp_priv;
	struct nss_gmac_hal_ops *hal_ops;

	for (i = 0; i < NSS_DP_MAX_PHY_PORTS; i++) {
		dp_priv = dp_global_ctx.nss_dp[i];
		if (!dp_priv)
			continue;

		hal_ops = dp_priv->gmac_hal_ops;
		/* TODO: Remove PHY */
		unregister_netdev(dp_priv->netdev);
		hal_ops->exit(dp_priv->gmac_hal_ctx);
		free_netdev(dp_priv->netdev);
		dp_global_ctx.nss_dp[i] = NULL;
	}

	return 0;
}

static struct of_device_id nss_dp_dt_ids[] = {
	{ .compatible = "qcom,nss-dp" },
	{},
};
MODULE_DEVICE_TABLE(of, nss_dp_dt_ids);

static struct platform_driver nss_dp_drv = {
	.probe = nss_dp_probe,
	.remove = nss_dp_remove,
	.driver = {
		   .name = "nss-dp",
		   .owner = THIS_MODULE,
		   .of_match_table = of_match_ptr(nss_dp_dt_ids),
		  },
};

/*
 * nss_dp_init()
 */
int __init nss_dp_init(void)
{
	int ret;

	/*
	 * Bail out on not supported platform
	 * TODO: Handle this properly with SoC ops
	 */
	if (!of_machine_is_compatible("qcom,ipq807x"))
		return 0;
	/*
	 * TODO Move this to soc_ops
	 */
	ret = edma_init();
	if (ret) {
		pr_info("EDMA init failed\n");
		return -EFAULT;
	}

	ret = platform_driver_register(&nss_dp_drv);
	if (ret)
		pr_info("NSS DP platform drv register failed\n");

	pr_info("**********************************************************\n");
	pr_info("* NSS Data Plane driver\n");
	pr_info("**********************************************************\n");

	return ret;
}

/*
 * nss_dp_exit()
 */
void __exit nss_dp_exit(void)
{

	/*
	 * TODO Move this to soc_ops
	 */
	edma_cleanup();
	platform_driver_unregister(&nss_dp_drv);
}

module_init(nss_dp_init);
module_exit(nss_dp_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("NSS Data Plane Network Driver");
