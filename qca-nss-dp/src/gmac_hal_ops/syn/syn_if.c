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
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/io.h>
#include <nss_dp_hal_if.h>
#include <nss_dp_dev.h>
#include "syn_dev.h"

#define SYN_STAT(m)	offsetof(struct syn_stats, m)

struct syn_ethtool_stats {
	uint8_t stat_string[ETH_GSTRING_LEN];
	uint64_t stat_offset;
};

/*
 * Array of strings describing statistics
 */
static const struct syn_ethtool_stats syn_gstrings_stats[] = {
	{"rx_frame", SYN_STAT(rx_frame_ctr)},
	{"rx_pause", SYN_STAT(rx_pause_ctr)},
	{"rx_broadcast", SYN_STAT(rx_broadcast_ctr)},
	{"rx_multicast", SYN_STAT(rx_multicast_ctr)},
	{"rx_unicast", SYN_STAT(rx_unicast_ctr)},
	{"rx_fifo_overflow", SYN_STAT(rx_fifo_overflow_ctr)},
	{"rx_undersize", SYN_STAT(rx_undersize_ctr)},
	{"rx_oversize", SYN_STAT(rx_oversize_ctr)},
	{"rx_vlan", SYN_STAT(rx_vlan_ctr)},
	{"rx_lpi_usec_ctr", SYN_STAT(rx_lpi_usec_ctr)},
	{"rx_discard_frame_ctr", SYN_STAT(rx_discard_frame_ctr)},
	{"rx_pkt64", SYN_STAT(rx_pkt64_ctr)},
	{"rx_pkt65to127", SYN_STAT(rx_pkt65to127_ctr)},
	{"rx_pkt128to255", SYN_STAT(rx_pkt128to255_ctr)},
	{"rx_pkt256to511", SYN_STAT(rx_pkt256to511_ctr)},
	{"rx_pkt512to1023", SYN_STAT(rx_pkt512to1023_ctr)},
	{"rx_pkt1024tomax", SYN_STAT(rx_pkt1024tomax_ctr)},
	{"rx_crc_err", SYN_STAT(rx_crc_err_ctr)},
	{"rx_runt_err", SYN_STAT(rx_runt_err_ctr)},
	{"rx_jabber_err", SYN_STAT(rx_jabber_err_ctr)},
	{"rx_len_err", SYN_STAT(rx_len_err_ctr)},
	{"tx_frame", SYN_STAT(tx_frame_ctr)},
	{"tx_pause", SYN_STAT(tx_pause_ctr)},
	{"tx_broadcast", SYN_STAT(tx_broadcast_ctr)},
	{"tx_broadcast_gb", SYN_STAT(tx_broadcast_gb_ctr)},
	{"tx_multicast", SYN_STAT(tx_multicast_ctr)},
	{"tx_multicast_gb", SYN_STAT(tx_multicast_gb_ctr)},
	{"tx_underflow_err", SYN_STAT(tx_underflow_err_ctr)},
	{"tx_vlan", SYN_STAT(tx_vlan_ctr)},
	{"tx_unicast", SYN_STAT(tx_unicast_ctr)},
	{"tx_pkt64", SYN_STAT(tx_pkt64_ctr)},
	{"tx_pkt65to127", SYN_STAT(tx_pkt65to127_ctr)},
	{"tx_pkt128to255", SYN_STAT(tx_pkt128to255_ctr)},
	{"tx_pkt256to511", SYN_STAT(tx_pkt256to511_ctr)},
	{"tx_pkt512to1023", SYN_STAT(tx_pkt512to1023_ctr)},
	{"tx_pkt1024tomax", SYN_STAT(tx_pkt1024tomax_ctr)},
	{"tx_lpi_usec_ctr", SYN_STAT(tx_lpi_usec_ctr)},
};

/*
 * Array of strings describing private flag names
 */
static const char *const syn_strings_priv_flags[] = {
	"test",
};

#define SYN_STATS_LEN	ARRAY_SIZE(syn_gstrings_stats)
#define SYN_PRIV_FLAGS_LEN	ARRAY_SIZE(syn_strings_priv_flags)


/*
 * syn_rx_flow_control()
 */
static void syn_rx_flow_control(struct nss_gmac_hal_dev *nghd,
				     bool enabled)
{
	BUG_ON(nghd == NULL);

	if (enabled)
		syn_set_rx_flow_ctrl(nghd);
	else
		syn_clear_rx_flow_ctrl(nghd);
}

/*
 * syn_tx_flow_control()
 */
static void syn_tx_flow_control(struct nss_gmac_hal_dev *nghd,
				     bool enabled)
{
	BUG_ON(nghd == NULL);

	if (enabled)
		syn_set_tx_flow_ctrl(nghd);
	else
		syn_clear_tx_flow_ctrl(nghd);
}

/*
 * syn_get_mmc_stats()
 */
static void syn_get_mmc_stats(struct nss_gmac_hal_dev *nghd)
{
	BUG_ON(nghd == NULL);

	syn_get_rx_stats(nghd);
	syn_get_tx_stats(nghd);
	return;
}

/*
 * syn_get_max_frame_size()
 */
static uint32_t syn_get_max_frame_size(struct nss_gmac_hal_dev *nghd)
{
	uint32_t data;

	BUG_ON(nghd == NULL);

	data = hal_read_reg(nghd->mac_base, SYN_MAC_RX_CONFIG);
	data &= SYN_MAC_MAX_FRAME_SIZE_BITMASK;
	data = data >> SYN_MAC_MAX_FRAME_SIZE_BITPOS;

	return data;
}

/*
 * syn_set_max_frame_size()
 */
static void syn_set_max_frame_size(struct nss_gmac_hal_dev *nghd,
					uint32_t val)
{
	uint32_t data = 0;

	BUG_ON(nghd == NULL);

	if (val > SYN_MAC_DEFAULT_MAX_FRAME_SIZE) {
		data = hal_read_reg(nghd->mac_base,
				SYN_MAC_RX_CONFIG);
		data &= (~(SYN_MAC_MAX_FRAME_SIZE_BITMASK <<
					SYN_MAC_MAX_FRAME_SIZE_BITPOS));
		data |= val;
		hal_write_reg(nghd->mac_base, SYN_MAC_TX_CONFIG,
				data);
	}
}

/*
 * syn_set_mac_speed()
 */
static int32_t syn_set_mac_speed(struct nss_gmac_hal_dev *nghd,
				   uint32_t mac_speed)
{
	uint32_t val;
	uint32_t speed;

	BUG_ON(nghd == NULL);

	switch (mac_speed) {
	case SPEED_10000:
		speed = SYN_MAC_SPEED_10G;
		break;
	case SPEED_2500:
		speed = SYN_MAC_SPEED_2_5G;
		break;
	case SPEED_1000:
		speed = SYN_MAC_SPEED_1G;
		break;
	default:
		return -1;
	}

	/* TODO: Disable GMACn Tx/Rx clk */
	/* TODO: set clock divider */
	/* TODO: Enable GMACn Tx/Rx clk */

	/* Set speed */
	val = hal_read_reg(nghd->mac_base, SYN_MAC_TX_CONFIG);
	val = val &
		(~(SYN_MAC_SPEED_BITMASK << SYN_MAC_SPEED_BITPOS));
	val |= (speed << SYN_MAC_SPEED_BITPOS);
	hal_write_reg(nghd->mac_base, SYN_MAC_TX_CONFIG, val);

	return 0;
}

/*
 * syn_get_mac_speed()
 */
static uint32_t syn_get_mac_speed(struct nss_gmac_hal_dev *nghd)
{
	uint32_t val;
	uint32_t speed;

	BUG_ON(nghd == NULL);

	/* get speed */
	val = hal_read_reg(nghd->mac_base, SYN_MAC_TX_CONFIG);
	speed = val & (SYN_MAC_SPEED_BITMASK << SYN_MAC_SPEED_BITPOS);
	speed = speed >> SYN_MAC_SPEED_BITPOS;

	switch (speed) {
	case SYN_MAC_SPEED_10G:
		return SPEED_10000;
	case SYN_MAC_SPEED_2_5G:
		return SPEED_2500;
	}

	return SPEED_1000;
}

/*
 * syn_set_duplex_mode()
 */
static void syn_set_duplex_mode(struct nss_gmac_hal_dev *nghd,
				uint8_t duplex_mode)
{
	struct net_device *netdev = nghd->netdev;

	if (duplex_mode == DUPLEX_HALF)
		netdev_dbg(netdev, "Synopsis GMAC works in Full Duplex mode only.\n");
}

/*
 * syn_get_duplex_mode()
 */
static uint8_t syn_get_duplex_mode(struct nss_gmac_hal_dev *nghd)
{
	/*
	 * Synopsis GMAC works in Full Duplex mode only.
	 */
	return DUPLEX_FULL;
}

/*
 * syn_get_netdev_stats()
 */
static void syn_get_netdev_stats(struct nss_gmac_hal_dev *nghd,
		struct rtnl_link_stats64 *stats)
{
	struct syn_hal_dev *shd;
	struct syn_stats *hal_stats;

	BUG_ON(nghd == NULL);

	shd = (struct syn_hal_dev *)nghd;
	hal_stats = &(shd->stats);

	syn_get_rx_stats(nghd);
	syn_get_tx_stats(nghd);

	stats->rx_packets = hal_stats->rx_unicast_ctr
		+ hal_stats->rx_broadcast_ctr + hal_stats->rx_multicast_ctr;
	stats->tx_packets = hal_stats->tx_unicast_ctr
		+ hal_stats->tx_broadcast_ctr + hal_stats->tx_multicast_ctr;
	stats->rx_bytes = hal_stats->rx_bytes_ctr;
	stats->tx_bytes = hal_stats->tx_bytes_ctr;
	stats->multicast =
		hal_stats->rx_multicast_ctr;
	stats->rx_dropped =
		hal_stats->rx_discard_frame_ctr;
	stats->rx_length_errors =
		hal_stats->rx_len_err_ctr;
	stats->rx_crc_errors =
		hal_stats->rx_crc_err_ctr;
	stats->rx_fifo_errors =
		hal_stats->rx_fifo_overflow_ctr;
}

/*
 * syn_get_eth_stats()
 */
static void syn_get_eth_stats(struct nss_gmac_hal_dev *nghd,
				   uint64_t *data)
{
	struct syn_hal_dev *shd;
	struct syn_stats *stats;
	uint8_t *p = NULL;
	int i;

	BUG_ON(nghd == NULL);

	shd = (struct syn_hal_dev *)nghd;
	stats = &(shd->stats);


	syn_get_rx_stats(nghd);
	syn_get_tx_stats(nghd);

	for (i = 0; i < SYN_STATS_LEN; i++) {
		p = ((uint8_t *)(stats) +
				syn_gstrings_stats[i].stat_offset);
		data[i] = *(uint32_t *)p;
	}
}

/*
 * syn_get_strset_count()
 */
static int32_t syn_get_strset_count(struct nss_gmac_hal_dev *nghd,
					 int32_t sset)
{
	struct net_device *netdev;

	BUG_ON(nghd == NULL);

	netdev = nghd->netdev;

	switch (sset) {
	case ETH_SS_STATS:
		return SYN_STATS_LEN;

	case ETH_SS_PRIV_FLAGS:
		return SYN_PRIV_FLAGS_LEN;
	}

	netdev_dbg(netdev, "%s: Invalid string set\n", __func__);
	return -EPERM;
}

/*
 * syn_get_strings()
 */
static int32_t syn_get_strings(struct nss_gmac_hal_dev *nghd,
				    int32_t stringset, uint8_t *data)
{
	struct net_device *netdev;
	int i;

	BUG_ON(nghd == NULL);

	netdev = nghd->netdev;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < SYN_STATS_LEN; i++) {
			memcpy(data, syn_gstrings_stats[i].stat_string,
				ETH_GSTRING_LEN);
			data += ETH_GSTRING_LEN;
		}
		break;

	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < SYN_PRIV_FLAGS_LEN; i++) {
			memcpy(data, syn_strings_priv_flags[i],
				ETH_GSTRING_LEN);
			data += ETH_GSTRING_LEN;
		}

		break;
	default:
		netdev_dbg(netdev, "%s: Invalid string set\n", __func__);
		return -EPERM;
	}

	return 0;
}

/*
 * syn_send_pause_frame()
 */
static void syn_send_pause_frame(struct nss_gmac_hal_dev *nghd)
{
	BUG_ON(nghd == NULL);

	syn_send_tx_pause_frame(nghd);
}

/*
 * syn_start
 */
static int32_t syn_start(struct nss_gmac_hal_dev *nghd)
{
	BUG_ON(nghd == NULL);

	syn_tx_enable(nghd);
	syn_rx_enable(nghd);
	syn_set_full_duplex(nghd);
	if (syn_set_mac_speed(nghd, SPEED_10000))
		return -1;

	syn_set_mmc_stats(nghd);

	netdev_dbg(nghd->netdev,
			"%s: mac_base:0x%p tx_enable:0x%x rx_enable:0x%x\n",
			__func__,
			nghd->mac_base,
			hal_read_reg(nghd->mac_base,
				SYN_MAC_TX_CONFIG),
			hal_read_reg(nghd->mac_base,
				SYN_MAC_RX_CONFIG));

	return 0;
}

/*
 * syn_stop
 */
static int32_t syn_stop(struct nss_gmac_hal_dev *nghd)
{
	BUG_ON(nghd == NULL);

	syn_tx_disable(nghd);
	syn_rx_disable(nghd);

	netdev_dbg(nghd->netdev, "%s: Stopping mac_base:0x%p\n", __func__,
		   nghd->mac_base);

	return 0;
}

/*
 * syn_init()
 */
static void *syn_init(struct gmac_hal_platform_data *gmacpdata)
{
	struct syn_hal_dev *shd = NULL;
	struct net_device *ndev = NULL;
	struct nss_dp_dev *dp_priv = NULL;
	struct resource *res;

	ndev = gmacpdata->netdev;
	dp_priv = netdev_priv(ndev);

	res = platform_get_resource(dp_priv->pdev, IORESOURCE_MEM, 0);
	if (!res) {
		netdev_dbg(ndev, "Resource get failed.\n");
		return NULL;
	}

	if (!devm_request_mem_region(&dp_priv->pdev->dev, res->start,
				     resource_size(res), ndev->name)) {
		netdev_dbg(ndev, "Request mem region failed. Returning...\n");
		return NULL;
	}

	shd = (struct syn_hal_dev *)devm_kzalloc(&dp_priv->pdev->dev,
					sizeof(struct syn_hal_dev),
					GFP_KERNEL);
	if (!shd) {
		netdev_dbg(ndev, "kzalloc failed. Returning...\n");
		return NULL;
	}

	/* Save netdev context in syn HAL context */
	shd->nghd.netdev = gmacpdata->netdev;

	/* Populate the mac base addresses */
	shd->nghd.mac_base =
		devm_ioremap_nocache(&dp_priv->pdev->dev, res->start,
				     resource_size(res));
	if (!shd->nghd.mac_base) {
		netdev_dbg(ndev, "ioremap fail.\n");
		return NULL;
	}

	spin_lock_init(&shd->nghd.slock);

	netdev_dbg(ndev, "ioremap OK.Size 0x%x Ndev base 0x%lx macbase 0x%p\n",
			gmacpdata->reg_len,
			ndev->base_addr,
			shd->nghd.mac_base);

	return (struct nss_gmac_hal_dev *)shd;
}

/*
 * syn_set_mac_address()
 */
static void syn_set_mac_address(struct nss_gmac_hal_dev *nghd,
				     uint8_t *macaddr)
{
	uint32_t data;

	BUG_ON(nghd == NULL);

	data = (macaddr[5] << 8) | macaddr[4] | SYN_MAC_ADDR_RSVD_BIT;
	hal_write_reg(nghd->mac_base, SYN_MAC_ADDR0_HIGH, data);
	data = (macaddr[3] << 24) | (macaddr[2] << 16) | (macaddr[1] << 8)
		| macaddr[0];
	hal_write_reg(nghd->mac_base, SYN_MAC_ADDR0_LOW, data);
}

/*
 * syn_get_mac_address()
 */
static void syn_get_mac_address(struct nss_gmac_hal_dev *nghd,
				     uint8_t *macaddr)
{
	uint32_t data;

	BUG_ON(nghd == NULL);

	data = hal_read_reg(nghd->mac_base, SYN_MAC_ADDR0_HIGH);
	macaddr[5] = (data >> 8) & 0xff;
	macaddr[4] = (data) & 0xff;

	data = hal_read_reg(nghd->mac_base, SYN_MAC_ADDR0_LOW);
	macaddr[3] = (data >> 24) & 0xff;
	macaddr[2] = (data >> 16) & 0xff;
	macaddr[1] = (data >> 8) & 0xff;
	macaddr[0] = (data) & 0xff;
}

struct nss_gmac_hal_ops syn_hal_ops = {
	.init = &syn_init,
	.start = &syn_start,
	.stop = &syn_stop,
	.setmacaddr = &syn_set_mac_address,
	.getmacaddr = &syn_get_mac_address,
	.rxflowcontrol = &syn_rx_flow_control,
	.txflowcontrol = &syn_tx_flow_control,
	.setspeed = &syn_set_mac_speed,
	.getspeed = &syn_get_mac_speed,
	.setduplex = &syn_set_duplex_mode,
	.getduplex = &syn_get_duplex_mode,
	.getstats = &syn_get_mmc_stats,
	.setmaxframe = &syn_set_max_frame_size,
	.getmaxframe = &syn_get_max_frame_size,
	.getndostats = &syn_get_netdev_stats,
	.getssetcount = &syn_get_strset_count,
	.getstrings = &syn_get_strings,
	.getethtoolstats = &syn_get_eth_stats,
	.sendpause = &syn_send_pause_frame,
};
