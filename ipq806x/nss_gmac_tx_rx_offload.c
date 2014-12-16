/*
 * Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * @file
 * This is the network dependent layer to handle network related functionality.
 * This file is tightly coupled to neworking frame work of linux kernel.
 * The functionality carried out in this file should be treated as an
 * example only if the underlying operating system is not Linux.
 *
 * @note Many of the functions other than the device specific functions
 *  changes for operating system other than Linux 2.6.xx
 *-----------------------------REVISION HISTORY----------------------------------
 * Qualcomm Atheros    		15/Feb/2013			Created
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/bitops.h>
#include <linux/phy.h>

#include <nss_gmac_dev.h>
#include <nss_gmac_network_interface.h>


static int nss_gmac_slowpath_if_open(void *app_data, uint32_t tx_desc_ring, uint32_t rx_desc_ring, uint32_t mode)
{
	return NSS_GMAC_SUCCESS;
}

static int nss_gmac_slowpath_if_close(void *app_data)
{
	return NSS_GMAC_SUCCESS;
}

static int nss_gmac_slowpath_if_link_state(void *app_data, uint32_t link_state)
{
	return NSS_GMAC_SUCCESS;
}

static int nss_gmac_slowpath_if_mac_addr(void *app_data, uint8_t *addr)
{
	return NSS_GMAC_SUCCESS;
}
static int nss_gmac_slowpath_if_change_mtu(void *app_data, uint32_t mtu)
{
	return NSS_GMAC_SUCCESS;
}

static int nss_gmac_slowpath_if_xmit(void *app_data, struct sk_buff *os_buf)
{
	return NSS_GMAC_FAILURE;
}

struct nss_gmac_data_plane_ops nss_gmac_slowpath_ops = {
	.open		= nss_gmac_slowpath_if_open,
	.close		= nss_gmac_slowpath_if_close,
	.link_state	= nss_gmac_slowpath_if_link_state,
	.mac_addr	= nss_gmac_slowpath_if_mac_addr,
	.change_mtu	= nss_gmac_slowpath_if_change_mtu,
	.xmit		= nss_gmac_slowpath_if_xmit,
};

/**
 * @brief Save GMAC statistics
 * @param[in] pointer to gmac context
 * @param[in] pointer to gmac statistics
 * @return Returns void.
 */
static void nss_gmac_copy_stats(struct nss_gmac_dev *gmacdev,
				struct nss_gmac_stats *gstat)
{
	BUG_ON(!spin_is_locked(&gmacdev->stats_lock));

	gmacdev->nss_stats.rx_bytes += gstat->rx_bytes;
	gmacdev->nss_stats.rx_packets += gstat->rx_packets;
	gmacdev->nss_stats.rx_errors += gstat->rx_errors;
	gmacdev->nss_stats.rx_receive_errors += gstat->rx_receive_errors;
	gmacdev->nss_stats.rx_overflow_errors += gstat->rx_overflow_errors;
	gmacdev->nss_stats.rx_descriptor_errors += gstat->rx_descriptor_errors;
	gmacdev->nss_stats.rx_watchdog_timeout_errors +=
		gstat->rx_watchdog_timeout_errors;
	gmacdev->nss_stats.rx_crc_errors += gstat->rx_crc_errors;
	gmacdev->nss_stats.rx_late_collision_errors +=
		gstat->rx_late_collision_errors;
	gmacdev->nss_stats.rx_dribble_bit_errors += gstat->rx_dribble_bit_errors;
	gmacdev->nss_stats.rx_length_errors += gstat->rx_length_errors;
	gmacdev->nss_stats.rx_ip_header_errors += gstat->rx_ip_header_errors;
	gmacdev->nss_stats.rx_ip_payload_errors += gstat->rx_ip_payload_errors;
	gmacdev->nss_stats.rx_no_buffer_errors += gstat->rx_no_buffer_errors;
	gmacdev->nss_stats.rx_transport_csum_bypassed +=
		gstat->rx_transport_csum_bypassed;
	gmacdev->nss_stats.tx_bytes += gstat->tx_bytes;
	gmacdev->nss_stats.tx_packets += gstat->tx_packets;
	gmacdev->nss_stats.tx_collisions += gstat->tx_collisions;
	gmacdev->nss_stats.tx_errors += gstat->tx_errors;
	gmacdev->nss_stats.tx_jabber_timeout_errors +=
		gstat->tx_jabber_timeout_errors;
	gmacdev->nss_stats.tx_frame_flushed_errors +=
		gstat->tx_frame_flushed_errors;
	gmacdev->nss_stats.tx_loss_of_carrier_errors +=
		gstat->tx_loss_of_carrier_errors;
	gmacdev->nss_stats.tx_no_carrier_errors += gstat->tx_no_carrier_errors;
	gmacdev->nss_stats.tx_late_collision_errors +=
		gstat->tx_late_collision_errors;
	gmacdev->nss_stats.tx_excessive_collision_errors +=
		gstat->tx_excessive_collision_errors;
	gmacdev->nss_stats.tx_excessive_deferral_errors +=
		gstat->tx_excessive_deferral_errors;
	gmacdev->nss_stats.tx_underflow_errors += gstat->tx_underflow_errors;
	gmacdev->nss_stats.tx_ip_header_errors += gstat->tx_ip_header_errors;
	gmacdev->nss_stats.tx_ip_payload_errors += gstat->tx_ip_payload_errors;
	gmacdev->nss_stats.tx_dropped += gstat->tx_dropped;
	gmacdev->nss_stats.hw_errs[0] += gstat->hw_errs[0];
	gmacdev->nss_stats.hw_errs[1] += gstat->hw_errs[1];
	gmacdev->nss_stats.hw_errs[2] += gstat->hw_errs[2];
	gmacdev->nss_stats.hw_errs[3] += gstat->hw_errs[3];
	gmacdev->nss_stats.hw_errs[4] += gstat->hw_errs[4];
	gmacdev->nss_stats.hw_errs[5] += gstat->hw_errs[5];
	gmacdev->nss_stats.hw_errs[6] += gstat->hw_errs[6];
	gmacdev->nss_stats.hw_errs[7] += gstat->hw_errs[7];
	gmacdev->nss_stats.hw_errs[8] += gstat->hw_errs[8];
	gmacdev->nss_stats.hw_errs[9] += gstat->hw_errs[9];
	gmacdev->nss_stats.rx_missed += gstat->rx_missed;
	gmacdev->nss_stats.fifo_overflows += gstat->fifo_overflows;
	gmacdev->nss_stats.rx_scatter_errors += gstat->rx_scatter_errors;
	gmacdev->nss_stats.gmac_total_ticks += gstat->gmac_total_ticks;
	gmacdev->nss_stats.gmac_worst_case_ticks += gstat->gmac_worst_case_ticks;
	gmacdev->nss_stats.gmac_iterations += gstat->gmac_iterations;
}


/**
 * @brief Stats Callback to receive statistics from NSS
 * @param[in] pointer to gmac context
 * @param[in] pointer to gmac statistics
 * @return Returns void.
 */
static void nss_gmac_stats_receive(struct nss_gmac_dev *gmacdev,
					struct nss_gmac_stats *gstat)
{
	struct net_device *netdev = NULL;

	netdev = (struct net_device *)gmacdev->netdev;

	if (!test_bit(__NSS_GMAC_UP, &gmacdev->flags)) {
		return;
	}

	spin_lock(&gmacdev->stats_lock);

	nss_gmac_copy_stats(gmacdev, gstat);

	gmacdev->stats.rx_packets += gstat->rx_packets;
	gmacdev->stats.rx_bytes += gstat->rx_bytes;
	gmacdev->stats.rx_errors += gstat->rx_errors;
	gmacdev->stats.rx_dropped += gstat->rx_errors;
	gmacdev->stats.rx_length_errors += gstat->rx_length_errors;
	gmacdev->stats.rx_over_errors += gstat->rx_overflow_errors;
	gmacdev->stats.rx_crc_errors += gstat->rx_crc_errors;
	gmacdev->stats.rx_frame_errors += gstat->rx_dribble_bit_errors;
	gmacdev->stats.rx_fifo_errors += gstat->fifo_overflows;
	gmacdev->stats.rx_missed_errors += gstat->rx_missed;
	gmacdev->stats.collisions += gstat->tx_collisions
		+ gstat->rx_late_collision_errors;
	gmacdev->stats.tx_packets += gstat->tx_packets;
	gmacdev->stats.tx_bytes += gstat->tx_bytes;
	gmacdev->stats.tx_errors += gstat->tx_errors;
	gmacdev->stats.tx_dropped += gstat->tx_dropped;
	gmacdev->stats.tx_carrier_errors += gstat->tx_loss_of_carrier_errors
		+ gstat->tx_no_carrier_errors;
	gmacdev->stats.tx_fifo_errors += gstat->tx_underflow_errors;
	gmacdev->stats.tx_window_errors += gstat->tx_late_collision_errors;

	spin_unlock(&gmacdev->stats_lock);
}


/**
 * NSS Driver interface APIs
 */

/**
 * @brief Rx Callback to receive frames from NSS
 * @param[in] pointer to net device context
 * @param[in] pointer to skb
 * @return Returns void
 */
void nss_gmac_receive(struct net_device *netdev, struct sk_buff *skb, struct napi_struct *napi)
{
	struct nss_gmac_dev *gmacdev;

	BUG_ON(netdev == NULL);

	gmacdev = netdev_priv(netdev);

	BUG_ON(gmacdev->netdev != netdev);

	skb->dev = netdev;
	skb->protocol = eth_type_trans(skb, netdev);
	nss_gmac_trace(gmacdev,
			"%s: Rx on gmac%d, packet len %d, CSUM %d",
			__func__, gmacdev->macid, skb->len, skb->ip_summed);

	napi_gro_receive(napi, skb);
}


/**
 * @brief Event Callback to receive events from NSS
 * @param[in] pointer to net device context
 * @param[in] event type
 * @param[in] pointer to buffer
 * @param[in] length of buffer
 * @return Returns void
 */
void nss_gmac_event_receive(void *if_ctx, int ev_type,
				void *os_buf, uint32_t len)
{
	struct net_device *netdev = NULL;
	struct nss_gmac_dev *gmacdev = NULL;

	netdev = (struct net_device *)if_ctx;
	gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);
	BUG_ON(!gmacdev);

	switch (ev_type) {
	case NSS_GMAC_EVENT_STATS:
		nss_gmac_stats_receive(gmacdev, (struct nss_gmac_stats *)os_buf);
		break;

	default:
		nss_gmac_info(gmacdev, "%s: Unknown Event from NSS",
				__func__);
		break;
	}
}


/**
 * @brief Notify linkup event to NSS
 * @param[in] pointer to gmac context
 * @return Returns void.
 */
static void nss_notify_linkup(struct nss_gmac_dev *gmacdev)
{
	uint32_t link = 0;

	if (!test_bit(__NSS_GMAC_UP, &gmacdev->flags)) {
		return;
	}

	link = 0x1;
	if (gmacdev->speed == SPEED1000) {
		link |= 0x4;
	} else if (gmacdev->speed == SPEED100) {
		link |= 0x2;
	}

	gmacdev->data_plane_ops->link_state(gmacdev->data_plane_ctx, link);
}

/**
 * This function checks for completion of PHY init
 * and proceeds to initialize mac based on parameters
 * read from PHY registers. It indicates presence of carrier to OS.
 * @param[in] pointer to gmac context
 * @return Returns void.
 */
void nss_gmac_linkup(struct nss_gmac_dev *gmacdev)
{
	struct net_device *netdev = gmacdev->netdev;
	uint32_t gmac_tx_desc = 0, gmac_rx_desc = 0;
	uint32_t mode = NSS_GMAC_MODE0;

	nss_gmac_spare_ctl(gmacdev);

	if (nss_gmac_check_phy_init(gmacdev) != 0) {
		gmacdev->link_state = LINKDOWN;
		return;
	}

	gmacdev->link_state = LINKUP;
	if (nss_gmac_dev_set_speed(gmacdev) != 0) {
		return;
	}

	if (gmacdev->first_linkup_done == 0) {
		nss_gmac_disable_interrupt_all(gmacdev);
		nss_gmac_reset(gmacdev);
		nss_gmac_clear_interrupt(gmacdev);

		/* Program Tx/Rx descriptor base addresses */
		nss_gmac_init_tx_desc_base(gmacdev);
		nss_gmac_init_rx_desc_base(gmacdev);
		nss_gmac_dma_bus_mode_init(gmacdev, DmaBusModeVal);
		nss_gmac_dma_axi_bus_mode_init(gmacdev, DmaAxiBusModeVal);
		nss_gmac_dma_control_init(gmacdev, DmaOMR);
		nss_gmac_disable_mmc_tx_interrupt(gmacdev, 0xFFFFFFFF);
		nss_gmac_disable_mmc_rx_interrupt(gmacdev, 0xFFFFFFFF);
		nss_gmac_disable_mmc_ipc_rx_interrupt(gmacdev, 0xFFFFFFFF);

		/* Restore the Jumbo support settings as per corresponding interface mtu */
		nss_gmac_linux_change_mtu(gmacdev->netdev, gmacdev->netdev->mtu);
		gmacdev->first_linkup_done = 1;
	}

	nss_gmac_mac_init(gmacdev);

	if (gmacdev->data_plane_ops->open(gmacdev->data_plane_ctx, gmac_tx_desc,
						gmac_rx_desc, mode) != NSS_GMAC_SUCCESS) {
		nss_gmac_info(gmacdev, "%s: data plane open command un-successful", __func__);
		gmacdev->link_state = LINKDOWN;
		return;
	}
	nss_gmac_info(gmacdev, "%s: data plane open command successfully issued", __func__);

	nss_notify_linkup(gmacdev);

	netif_carrier_on(netdev);
}


/**
 * Save current state of link and
 * indicate absence of carrier to OS.
 * @param[in] nss_gmac_dev *
 * @return Returns void.
 */
void nss_gmac_linkdown(struct nss_gmac_dev *gmacdev)
{
	struct net_device *netdev = gmacdev->netdev;

	nss_gmac_msg("%s Link %s", netdev->name, "down");

	gmacdev->link_state = LINKDOWN;
	gmacdev->duplex_mode = 0;
	gmacdev->speed = 0;

	if (test_bit(__NSS_GMAC_UP, &gmacdev->flags)) {
		netif_carrier_off(netdev);

		gmacdev->data_plane_ops->link_state(gmacdev->data_plane_ctx, 0);
	}
}


/**
 * @brief Link state change callback
 * @param[in] struct net_device *
 * @return Returns void.
 */
void nss_gmac_adjust_link(struct net_device *netdev)
{
	int32_t status = 0;
	struct nss_gmac_dev *gmacdev = NULL;

	gmacdev = netdev_priv(netdev);

	if (!test_bit(__NSS_GMAC_UP, &gmacdev->flags)) {
		return;
	}

	status = nss_gmac_check_link(gmacdev);
	mutex_lock(&gmacdev->link_mutex);
	if (status == LINKUP && gmacdev->link_state == LINKDOWN) {
		nss_gmac_linkup(gmacdev);
	} else if (status == LINKDOWN && gmacdev->link_state == LINKUP) {
		nss_gmac_linkdown(gmacdev);
	}
	mutex_unlock(&gmacdev->link_mutex);
}

void nss_gmac_start_up(struct nss_gmac_dev *gmacdev)
{
	if (!gmacdev->data_plane_ops) {
		nss_gmac_info(gmacdev, "%s: offload is not enabled, bring up gmac with slowpath", __func__);
		gmacdev->data_plane_ops = &nss_gmac_slowpath_ops;
	}

	if (test_bit(__NSS_GMAC_LINKPOLL, &gmacdev->flags)) {
		if (!IS_ERR_OR_NULL(gmacdev->phydev)) {
			nss_gmac_info(gmacdev, "%s: start phy 0x%x", __func__, gmacdev->phydev->phy_id);
			phy_start(gmacdev->phydev);
			phy_start_aneg(gmacdev->phydev);
		} else {
			nss_gmac_info(gmacdev, "%s: Invalid PHY device for a link polled interface", __func__);
		}
		return;
	}
	nss_gmac_info(gmacdev, "%s: Force link up", __func__);
	/*
	 * Force link up if link polling is disabled
	 */
	mutex_lock(&gmacdev->link_mutex);
	nss_gmac_linkup(gmacdev);
	mutex_unlock(&gmacdev->link_mutex);
}

/**
 * @brief Function to transmit a given packet on the wire.
 *
 * Whenever Linux Kernel has a packet ready to be transmitted, this function is called.
 * The function prepares a packet and prepares the descriptor and
 * enables/resumes the transmission.
 * @param[in] pointer to sk_buff structure.
 * @param[in] pointer to net_device structure.
 * @return NETDEV_TX_xxx
 */
int32_t nss_gmac_linux_xmit_frames(struct sk_buff *skb, struct net_device *netdev)
{
	int msg_status = 0;
	struct nss_gmac_dev *gmacdev = NULL;

	BUG_ON(skb == NULL);
	if (skb->len < ETH_HLEN) {
		nss_gmac_info(gmacdev, "%s: skb->len < ETH_HLEN",
				__func__);
		goto drop;
	}

	gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);
	BUG_ON(gmacdev == NULL);
	BUG_ON(gmacdev->netdev != netdev);

	nss_gmac_trace(gmacdev, "%s:Tx packet, len %d, CSUM %d",
			__func__, skb->len, skb->ip_summed);

	msg_status = gmacdev->data_plane_ops->xmit(gmacdev->data_plane_ctx, skb);

	if (likely(msg_status == NSS_GMAC_SUCCESS)) {
		goto tx_done;
	}

drop:
	/*
	 * Now drop it
	 */
	nss_gmac_info(gmacdev, "dropping skb");
	dev_kfree_skb_any(skb);
	netdev->stats.tx_dropped++;

tx_done:
	return NETDEV_TX_OK;
}

/**
 * @brief Function used when the interface is opened for use.
 *
 * We register nss_gmac_linux_open function to linux open(). Basically this
 * function prepares the the device for operation. This function is called
 * whenever ifconfig (in Linux) activates the device (for example
 * "ifconfig eth0 up"). This function registers system resources needed.
 *	- Disables interrupts
 *	- Starts Linux network queue interface
 *	- Checks for NSS init completion and determines initial link status
 *	- Starts timer to detect cable plug/unplug
 * @param[in] pointer to net_device structure.
 * @return Returns 0 on success and error status upon failure.
 */
int nss_gmac_linux_open(struct net_device *netdev)
{
	struct device *dev = NULL;
	struct nss_gmac_dev *gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);
	struct nss_gmac_global_ctx *ctx = NULL;

	if (!gmacdev) {
		return -EINVAL;
	}

	dev = &netdev->dev;
	ctx = gmacdev->ctx;

	netif_carrier_off(netdev);


	/**
	 * Now platform dependent initialization.
	 */
	nss_gmac_disable_interrupt_all(gmacdev);

	gmacdev->speed = SPEED100;
	gmacdev->duplex_mode = FULLDUPLEX;

	/**
	 * Lets read the version of ip in to device structure
	 */
	nss_gmac_read_version(gmacdev);

	/*
	 * Inform the Linux Networking stack about the hardware
	 * capability of checksum offloading and other features.
	 */
	netdev->features |= NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_TSO | NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_UFO | NETIF_F_TSO6;
	netdev->hw_features |= NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_TSO | NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_UFO | NETIF_F_TSO6;
	netdev->vlan_features |= NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_TSO | NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_UFO | NETIF_F_TSO6;
	netdev->wanted_features |= NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_TSO | NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_UFO | NETIF_F_TSO6;

	/**
	 * Set GMAC state to UP before link state is checked
	 */
	test_and_set_bit(__NSS_GMAC_UP, &gmacdev->flags);
	netif_start_queue(netdev);

	gmacdev->link_state = LINKDOWN;

	nss_gmac_start_up(gmacdev);

	gmacdev->data_plane_ops->mac_addr(gmacdev->data_plane_ctx, (uint8_t *)gmacdev->netdev->dev_addr);

	return 0;
}

/**
 * @brief Function used when the interface is closed.
 *
 * This function is registered to linux stop() function. This function is
 * called whenever ifconfig (in Linux) closes the device (for example
 * "ifconfig eth0 down"). This releases all the system resources allocated
 * during open call.
 *	- Disable the device interrupts
 *	- Send a link change event to NSS GMAC driver.
 *	- Stop the Linux network queue interface
 *	- Cancel timer rgistered for cable plug/unplug tracking
 * @param[in] pointer to net_device structure.
 * @return Returns 0 on success and error status upon failure.
 */
int nss_gmac_linux_close(struct net_device *netdev)
{
	struct nss_gmac_dev *gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);

	if (!gmacdev) {
		return -EINVAL;
	}

	test_and_set_bit(__NSS_GMAC_CLOSING, &gmacdev->flags);

	netif_stop_queue(netdev);
	netif_carrier_off(netdev);

	nss_gmac_rx_disable(gmacdev);
	nss_gmac_tx_disable(gmacdev);

	nss_gmac_disable_interrupt_all(gmacdev);
	gmacdev->data_plane_ops->link_state(gmacdev->data_plane_ctx, 0);

	if (!IS_ERR_OR_NULL(gmacdev->phydev)) {
		phy_stop(gmacdev->phydev);
	}

	test_and_clear_bit(__NSS_GMAC_UP, &gmacdev->flags);
	test_and_clear_bit(__NSS_GMAC_CLOSING, &gmacdev->flags);

	gmacdev->data_plane_ops->close(gmacdev->data_plane_ctx);

	return 0;
}

/**
 * @brief Function to handle a Tx Hang.
 * This is a software hook (Linux) to handle transmitter hang if any.
 * @param[in] pointer to net_device structure
 * @return void.
 */
void nss_gmac_linux_tx_timeout(struct net_device *netdev)
{
	struct nss_gmac_dev *gmacdev = NULL;

	gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);
	BUG_ON(gmacdev == NULL);

	if (gmacdev->gmac_power_down == 0) {
		/* If Mac is in powerdown */
		nss_gmac_info(gmacdev,
				"%s TX time out during power down is ignored",
				netdev->name);
		return;
	}

	netif_carrier_off(netdev);
	nss_gmac_disable_dma_tx(gmacdev);
	nss_gmac_flush_tx_fifo(gmacdev);
	nss_gmac_enable_dma_tx(gmacdev);
	netif_carrier_on(netdev);
	netif_start_queue(netdev);
}


/**
 * @brief Function to change the Maximum Transfer Unit.
 * @param[in] pointer to net_device structure.
 * @param[in] New value for maximum frame size.
 * @return Returns 0 on success Errorcode on failure.
 */
int32_t nss_gmac_linux_change_mtu(struct net_device *netdev, int32_t newmtu)
{
	struct nss_gmac_dev *gmacdev = NULL;

	gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);
	if (!gmacdev) {
		return -EINVAL;
	}

	if (newmtu > NSS_GMAC_JUMBO_MTU) {
		return -EINVAL;
	}

	if (gmacdev->data_plane_ops->change_mtu(gmacdev->data_plane_ctx, newmtu) != NSS_GMAC_SUCCESS) {
		return -EAGAIN;
	}

	if (newmtu <= NSS_GMAC_NORMAL_FRAME_MTU) {
		nss_gmac_jumbo_frame_disable(gmacdev);
		nss_gmac_twokpe_frame_disable(gmacdev);
	} else if (newmtu <= NSS_GMAC_MINI_JUMBO_FRAME_MTU) {
		nss_gmac_jumbo_frame_disable(gmacdev);
		nss_gmac_twokpe_frame_enable(gmacdev);
	} else if (newmtu <= NSS_GMAC_FULL_JUMBO_FRAME_MTU) {
		nss_gmac_jumbo_frame_enable(gmacdev);
	}

	netdev->mtu = newmtu;
	return 0;
}

/*
 * nss_gmac_is_in_open_state()
 *	Return if a gmac is opened or not
 */
bool nss_gmac_is_in_open_state(struct net_device *netdev)
{
	struct nss_gmac_dev *gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);
	if (test_bit(__NSS_GMAC_UP, &gmacdev->flags)) {
		return true;
	}
	return false;
}

/*
 * nss_gmac_register_offload()
 *
 * @param[netdev] netdev instance that is going to register
 * @param[dp_ops] dataplan ops for chaning mac addr/mtu/link status
 * @param[ctx] passing the ctx of this nss_phy_if to gmac
 *
 * @return Return SUCCESS or FAILURE
 */
int nss_gmac_override_data_plane(struct net_device *netdev,
				struct nss_gmac_data_plane_ops *dp_ops,
				void *ctx)
{
	struct nss_gmac_dev *gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);
	BUG_ON(!gmacdev);

	if (!dp_ops->open || !dp_ops->close || !dp_ops->link_state
		|| !dp_ops->mac_addr || !dp_ops->change_mtu || !dp_ops->xmit) {
		nss_gmac_info(gmacdev, "%s: All the op functions must be present, reject this registeration", __func__);
		return NSS_GMAC_FAILURE;
	}

	/*
	 * If this gmac is up, close the netdev to force TX/RX stop
	 */
	if (test_bit(__NSS_GMAC_UP, &gmacdev->flags)) {
		nss_gmac_linux_close(netdev);
	}
	/* Recored the data_plane_ctx, data_plane_ops */
	gmacdev->data_plane_ctx = ctx;
	gmacdev->data_plane_ops = dp_ops;
	gmacdev->first_linkup_done = 0;

	return NSS_GMAC_SUCCESS;
}

void nss_gmac_start_data_plane(struct net_device *netdev, void *ctx)
{
	struct nss_gmac_dev *gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);
	struct nss_gmac_global_ctx *global_ctx = gmacdev->ctx;

	if (test_bit(__NSS_GMAC_UP, &gmacdev->flags)) {
		nss_gmac_warn(gmacdev, "This netdev already up, something is wrong\n");
		return;
	}
	if (gmacdev->data_plane_ctx == ctx) {
		nss_gmac_info(gmacdev, "Data plane cookie matches, let's start the netdev again\n");
		queue_delayed_work(global_ctx->gmac_workqueue, &gmacdev->gmacwork, NSS_GMAC_LINK_CHECK_TIME);
	}
}
/*
 * gmac_unregister_nss_if()
 *
 * @param[if_num] gmac device id - 0~3
 */
void nss_gmac_restore_data_plane(struct net_device *netdev)
{
	struct nss_gmac_dev *gmacdev = (struct nss_gmac_dev *)netdev_priv(netdev);

	/*
	 * If this gmac is up, close the netdev to force TX/RX stop
	 */
	if (test_bit(__NSS_GMAC_UP, &gmacdev->flags)) {
		nss_gmac_linux_close(netdev);
	}
	gmacdev->data_plane_ctx = netdev;
	gmacdev->data_plane_ops = &nss_gmac_slowpath_ops ;
}

/*
 * nss_gmac_get_netdev_by_macid()
 *	return the net device of the corrsponding macid if exist
 */
struct net_device *nss_gmac_get_netdev_by_macid(int macid)
{
	struct nss_gmac_dev *gmacdev = ctx.nss_gmac[macid];
	if (!gmacdev) {
		return NULL;
	}
	return gmacdev->netdev;
}

/*
 * nss_gmac_open_work()
 *	Schedule delayed work to open the netdev again
 */
void nss_gmac_open_work(struct work_struct *work)
{
	struct nss_gmac_dev *gmacdev = container_of(to_delayed_work(work), struct nss_gmac_dev, gmacwork);

	nss_gmac_info(gmacdev, "Do the network up in delayed queue %s\n", gmacdev->netdev->name);
	nss_gmac_linux_open(gmacdev->netdev);
}

EXPORT_SYMBOL(nss_gmac_is_in_open_state);
EXPORT_SYMBOL(nss_gmac_start_data_plane);
EXPORT_SYMBOL(nss_gmac_override_data_plane);
EXPORT_SYMBOL(nss_gmac_restore_data_plane);
EXPORT_SYMBOL(nss_gmac_receive);
EXPORT_SYMBOL(nss_gmac_event_receive);
EXPORT_SYMBOL(nss_gmac_get_netdev_by_macid);
