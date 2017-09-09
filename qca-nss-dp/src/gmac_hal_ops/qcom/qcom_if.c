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
#include "qcom_dev.h"

#define QCOM_STAT(m) offsetof(struct qcom_stats, m)

/*
 * Ethtool stats pointer structure
 */
struct qcom_ethtool_stats {
	uint8_t stat_string[ETH_GSTRING_LEN];
	uint32_t stat_offset;
};

/*
 * Array of strings describing statistics
 */
static const struct qcom_ethtool_stats qcom_gstrings_stats[] = {
	{"rx_broadcast", QCOM_STAT(rx_broadcast)},
	{"rx_pause", QCOM_STAT(rx_pause)},
	{"rx_multicast", QCOM_STAT(rx_multicast)},
	{"rx_fcserr", QCOM_STAT(rx_fcserr)},
	{"rx_alignerr", QCOM_STAT(rx_alignerr)},
	{"rx_runt", QCOM_STAT(rx_runt)},
	{"rx_frag", QCOM_STAT(rx_frag)},
	{"rx_jmbfcserr", QCOM_STAT(rx_jmbfcserr)},
	{"rx_jmbalignerr", QCOM_STAT(rx_jmbalignerr)},
	{"rx_pkt64", QCOM_STAT(rx_pkt64)},
	{"rx_pkt65to127", QCOM_STAT(rx_pkt65to127)},
	{"rx_pkt128to255", QCOM_STAT(rx_pkt128to255)},
	{"rx_pkt256to511", QCOM_STAT(rx_pkt256to511)},
	{"rx_pkt512to1023", QCOM_STAT(rx_pkt512to1023)},
	{"rx_pkt1024to1518", QCOM_STAT(rx_pkt1024to1518)},
	{"rx_pkt1519tox", QCOM_STAT(rx_pkt1519tox)},
	{"rx_toolong", QCOM_STAT(rx_toolong)},
	{"rx_pktgoodbyte_l", QCOM_STAT(rx_pktgoodbyte_l)},
	{"rx_pktgoodbyte_h", QCOM_STAT(rx_pktgoodbyte_h)},
	{"rx_pktbadbyte_l", QCOM_STAT(rx_pktbadbyte_l)},
	{"rx_pktbadbyte_h", QCOM_STAT(rx_pktbadbyte_h)},
	{"rx_unicast", QCOM_STAT(rx_unicast)},
	{"tx_broadcast", QCOM_STAT(tx_broadcast)},
	{"tx_pause", QCOM_STAT(tx_pause)},
	{"tx_multicast", QCOM_STAT(tx_multicast)},
	{"tx_underrun", QCOM_STAT(tx_underrun)},
	{"tx_pkt64", QCOM_STAT(tx_pkt64)},
	{"tx_pkt65to127", QCOM_STAT(tx_pkt65to127)},
	{"tx_pkt128to255", QCOM_STAT(tx_pkt128to255)},
	{"tx_pkt256to511", QCOM_STAT(tx_pkt256to511)},
	{"tx_pkt512to1023", QCOM_STAT(tx_pkt512to1023)},
	{"tx_pkt1024to1518", QCOM_STAT(tx_pkt1024to1518)},
	{"tx_pkt1519tox", QCOM_STAT(tx_pkt1519tox)},
	{"tx_pktbyte_l", QCOM_STAT(tx_pktbyte_l)},
	{"tx_pktbyte_h", QCOM_STAT(tx_pktbyte_h)},
	{"tx_collisions", QCOM_STAT(tx_collisions)},
	{"tx_abortcol", QCOM_STAT(tx_abortcol)},
	{"tx_multicol", QCOM_STAT(tx_multicol)},
	{"tx_singlecol", QCOM_STAT(tx_singlecol)},
	{"tx_exesdeffer", QCOM_STAT(tx_exesdeffer)},
	{"tx_deffer", QCOM_STAT(tx_deffer)},
	{"tx_latecol", QCOM_STAT(tx_latecol)},
	{"tx_unicast", QCOM_STAT(tx_unicast)},
};

/*
 * Array of strings describing private flag names
 */
static const char * const qcom_strings_priv_flags[] = {
	"linkpoll",
	"tstamp",
	"tsmode",
};

#define QCOM_STATS_LEN ARRAY_SIZE(qcom_gstrings_stats)
#define QCOM_PRIV_FLAGS_LEN ARRAY_SIZE(qcom_strings_priv_flags)

/*
 * qcom_set_mac_speed()
 */
static int32_t qcom_set_mac_speed(struct nss_gmac_hal_dev *nghd,
				uint32_t mac_speed)
{
	/* TODO: Disable GMACn Tx/Rx clk */
	/* TODO: set clock divider */
	/* TODO: Enable GMACn Tx/Rx clk */

	uint32_t speed;

	switch (mac_speed) {
	case SPEED_1000:
		speed = QCOM_MAC_SPEED_1000;
		break;
	case SPEED_100:
		speed = QCOM_MAC_SPEED_100;
		break;
	case SPEED_10:
		speed = QCOM_MAC_SPEED_10;
		break;
	default:
		return -1;
	}

	/* Set speed */
	hal_write_reg(nghd->mac_base, QCOM_MAC_SPEED, speed);

	return 0;
}

/*
 * qcom_get_mac_speed()
 */
static uint32_t qcom_get_mac_speed(struct nss_gmac_hal_dev *nghd)
{
	uint32_t speed;

	/* Get speed */
	speed = hal_read_reg(nghd->mac_base, QCOM_MAC_SPEED);

	if (speed == QCOM_MAC_SPEED_100)
		return SPEED_100;
	else if (speed == QCOM_MAC_SPEED_10)
		return SPEED_10;

	return SPEED_1000;
}

/*
 * qcom_set_duplex_mode()
 */
static void qcom_set_duplex_mode(struct nss_gmac_hal_dev *nghd,
				uint8_t duplex_mode)
{
	struct net_device *netdev = nghd->netdev;

	switch (duplex_mode) {
	case DUPLEX_FULL:
		qcom_set_full_duplex(nghd);
		break;

	case DUPLEX_HALF:
		qcom_set_half_duplex(nghd);
		break;

	default:
		netdev_dbg(netdev, "%s: Invalid duplex mode %d\n", __func__,
								duplex_mode);
	}
}

/*
 * qcom_get_duplex_mode()
 */
static uint8_t qcom_get_duplex_mode(struct nss_gmac_hal_dev *nghd)
{
	if (hal_check_reg_bits(nghd->mac_base, QCOM_MAC_ENABLE, QCOM_DUPLEX))
		return DUPLEX_FULL;

	return DUPLEX_HALF;
}

/*
 * qcom_rx_flow_control()
 */
static void qcom_rx_flow_control(struct nss_gmac_hal_dev *nghd, bool enabled)
{
	if (enabled)
		qcom_set_rx_flow_ctrl(nghd);
	else
		qcom_clear_rx_flow_ctrl(nghd);
}

/*
 * qcom_tx_flow_control()
 */
static void qcom_tx_flow_control(struct nss_gmac_hal_dev *nghd, bool enabled)
{
	if (enabled)
		qcom_set_tx_flow_ctrl(nghd);
	else
		qcom_clear_rx_flow_ctrl(nghd);
}


/*
 * qcom_get_mib_stats()
 */
static void qcom_get_mib_stats(struct nss_gmac_hal_dev *nghd)
{
	qcom_get_rx_stats(nghd);
	qcom_get_tx_stats(nghd);
}

/*
 * qcom_set_maxframe()
 */
static void qcom_set_maxframe(struct nss_gmac_hal_dev *nghd, uint32_t maxframe)
{
	uint32_t data;

	/* Set JUMBO size to update MIB counter rx_toolong */
	qcom_set_mac_jumbosize(nghd, maxframe);

	/* Set MAX FRAME size */
	data = hal_read_reg(nghd->mac_base, QCOM_MAC_CTRL2);
	data &= ~QCOM_MAXFR_POS;
	maxframe = maxframe << QCOM_MAXFR_LSB;
	data |= maxframe;
	hal_write_reg(nghd->mac_base, QCOM_MAC_CTRL2, data);
}

/*
 * qcom_get_maxframe()
 */
static uint32_t qcom_get_maxframe(struct nss_gmac_hal_dev *nghd)
{
	int32_t maxframe = 0;

	maxframe = hal_read_reg(nghd->mac_base, QCOM_MAC_CTRL2);
	maxframe &= QCOM_MAXFR_POS;
	maxframe = maxframe >> QCOM_MAXFR_LSB;

	return maxframe;
}

/*
 * qcom_get_netdev_stats()
 */
static void qcom_get_netdev_stats(struct nss_gmac_hal_dev *nghd,
		struct rtnl_link_stats64 *stats)
{
	struct qcom_hal_dev *qhd = (struct qcom_hal_dev *)nghd;
	struct qcom_stats *hal_stats = &(qhd->stats);

	qcom_get_mib_stats(nghd);

	stats->rx_packets = hal_stats->rx_unicast + hal_stats->rx_broadcast
				+ hal_stats->rx_multicast;
	stats->tx_packets = hal_stats->tx_unicast + hal_stats->tx_broadcast
				+ hal_stats->tx_multicast;
	stats->rx_bytes = (hal_stats->rx_pktgoodbyte_h << 32) |
			   hal_stats->rx_pktgoodbyte_l;
	stats->tx_bytes = (hal_stats->tx_pktbyte_h << 32) |
			   hal_stats->tx_pktbyte_l;

	/* RX errors */
	stats->rx_crc_errors = hal_stats->rx_fcserr + hal_stats->rx_jmbfcserr;
	stats->rx_frame_errors = hal_stats->rx_alignerr +
				 hal_stats->rx_jmbalignerr;
	stats->rx_fifo_errors = hal_stats->rx_runt;
	stats->rx_errors = stats->rx_crc_errors + stats->rx_frame_errors +
			   stats->rx_fifo_errors;

	stats->rx_dropped = hal_stats->rx_toolong + stats->rx_errors;

	/* TX errors */
	stats->tx_fifo_errors = hal_stats->tx_underrun;
	stats->tx_aborted_errors = hal_stats->tx_abortcol;
	stats->tx_errors = stats->tx_fifo_errors + stats->tx_aborted_errors;

	stats->collisions = hal_stats->tx_collisions;
	stats->multicast = hal_stats->rx_multicast;
}

/*
 * qcom_get_strset_count()
 *	Get string set count for ethtool operations
 */
int32_t qcom_get_strset_count(struct nss_gmac_hal_dev *nghd, int32_t sset)
{
	struct net_device *netdev = nghd->netdev;

	switch (sset) {
	case ETH_SS_STATS:
		return QCOM_STATS_LEN;
	case ETH_SS_PRIV_FLAGS:
		return QCOM_PRIV_FLAGS_LEN;
	}

	netdev_dbg(netdev, "%s: Invalid string set\n", __func__);
	return -EPERM;
}

/*
 * qcom_get_strings()
 *	Get strings
 */
int32_t qcom_get_strings(struct nss_gmac_hal_dev *nghd, int32_t sset,
						uint8_t *data)
{
	struct net_device *netdev = nghd->netdev;
	int i;

	switch (sset) {
	case ETH_SS_STATS:
		for (i = 0; i < QCOM_STATS_LEN; i++) {
			memcpy(data, qcom_gstrings_stats[i].stat_string,
				ETH_GSTRING_LEN);
			data += ETH_GSTRING_LEN;
		}
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < QCOM_PRIV_FLAGS_LEN; i++) {
			memcpy(data, qcom_strings_priv_flags[i],
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
 * qcom_get_eth_stats()
 */
static void qcom_get_eth_stats(struct nss_gmac_hal_dev *nghd, uint64_t *data)
{
	struct qcom_hal_dev *qhd = (struct qcom_hal_dev *)nghd;
	struct qcom_stats *stats = &(qhd->stats);
	uint8_t *p;
	int i;

	qcom_get_mib_stats(nghd);

	for (i = 0; i < QCOM_STATS_LEN; i++) {
		p = (uint8_t *)stats + qcom_gstrings_stats[i].stat_offset;
		data[i] = *(uint32_t *)p;
	}
}

/*
 * qcom_send_pause_frame()
 */
static void qcom_send_pause_frame(struct nss_gmac_hal_dev *nghd)
{
	qcom_set_ctrl2_test_pause(nghd);
}

/*
 * qcom_stop_pause_frame()
 */
static void qcom_stop_pause_frame(struct nss_gmac_hal_dev *nghd)
{
	qcom_reset_ctrl2_test_pause(nghd);
}

/*
 * qcom_start()
 */
static int32_t qcom_start(struct nss_gmac_hal_dev *nghd)
{
	qcom_set_full_duplex(nghd);

	/* TODO: Read speed from dts */

	if (qcom_set_mac_speed(nghd, SPEED_1000))
		return -1;

	qcom_set_mib_ctrl(nghd, QCOM_MIB_ENABLE | QCOM_MIB_RD_CLR);

	qcom_tx_enable(nghd);
	qcom_rx_enable(nghd);

	netdev_dbg(nghd->netdev,
			"%s: mac_base:0x%p mac_enable:0x%x mib_ctrl:0x%x\n",
			__func__,
			nghd->mac_base,
			hal_read_reg(nghd->mac_base, QCOM_MAC_ENABLE),
			hal_read_reg(nghd->mac_base, QCOM_MAC_MIB_CTRL));
	return 0;
}

/*
 * qcom_stop()
 */
static int32_t qcom_stop(struct nss_gmac_hal_dev *nghd)
{
	qcom_tx_disable(nghd);
	qcom_rx_disable(nghd);
	qcom_clear_mib_ctrl(nghd);

	pr_info("%s: mac_base:0x%p mac_enable:0x%x mib_ctrl:0x%x\n",
			__func__, nghd->mac_base,
			hal_read_reg(nghd->mac_base, QCOM_MAC_ENABLE),
			hal_read_reg(nghd->mac_base, QCOM_MAC_MIB_CTRL));
	return 0;
}

/*
 * qcom_init()
 */
static void *qcom_init(struct gmac_hal_platform_data *gmacpdata)
{
	struct qcom_hal_dev *qhd = NULL;
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

	qhd = (struct qcom_hal_dev *)devm_kzalloc(&dp_priv->pdev->dev,
				sizeof(struct qcom_hal_dev), GFP_KERNEL);
	if (!qhd) {
		netdev_dbg(ndev, "kzalloc failed. Returning...\n");
		return NULL;
	}

	/* Save netdev context in QCOM HAL context */
	qhd->nghd.netdev = gmacpdata->netdev;

	/* Populate the mac base addresses */
	qhd->nghd.mac_base = devm_ioremap_nocache(&dp_priv->pdev->dev,
						res->start, resource_size(res));
	if (!qhd->nghd.mac_base) {
		netdev_dbg(ndev, "ioremap fail.\n");
		return NULL;
	}

	spin_lock_init(&qhd->nghd.slock);

	netdev_dbg(ndev, "ioremap OK.Size 0x%x Ndev base 0x%lx macbase 0x%p\n",
			gmacpdata->reg_len,
			ndev->base_addr,
			qhd->nghd.mac_base);

	return (struct nss_gmac_hal_dev *)qhd;
}

/*
 * qcom_get_mac_address()
 */
static void qcom_get_mac_address(struct nss_gmac_hal_dev *nghd,
				 uint8_t *macaddr)
{
	uint32_t data = hal_read_reg(nghd->mac_base, QCOM_MAC_ADDR0);
	macaddr[5] = (data >> 8) & 0xff;
	macaddr[4] = (data) & 0xff;

	data = hal_read_reg(nghd->mac_base, QCOM_MAC_ADDR1);
	macaddr[0] = (data >> 24) & 0xff;
	macaddr[1] = (data >> 16) & 0xff;
	macaddr[2] = (data >> 8) & 0xff;
	macaddr[3] = (data) & 0xff;
}

/*
 * qcom_set_mac_address()
 */
static void qcom_set_mac_address(struct nss_gmac_hal_dev *nghd,
				uint8_t *macaddr)
{
	uint32_t data = (macaddr[5] << 8) | macaddr[4];
	hal_write_reg(nghd->mac_base, QCOM_MAC_ADDR0, data);
	data = (macaddr[0] << 24) | (macaddr[1] << 16)
		| (macaddr[2] << 8) | macaddr[3];
	hal_write_reg(nghd->mac_base, QCOM_MAC_ADDR1, data);
}

/*
 * MAC hal_ops base structure
 */
struct nss_gmac_hal_ops qcom_hal_ops = {
	.init = &qcom_init,
	.start = &qcom_start,
	.stop = &qcom_stop,
	.setmacaddr = &qcom_set_mac_address,
	.getmacaddr = &qcom_get_mac_address,
	.rxflowcontrol = &qcom_rx_flow_control,
	.txflowcontrol = &qcom_tx_flow_control,
	.setspeed = &qcom_set_mac_speed,
	.getspeed = &qcom_get_mac_speed,
	.setduplex = &qcom_set_duplex_mode,
	.getduplex = &qcom_get_duplex_mode,
	.getstats = &qcom_get_mib_stats,
	.setmaxframe = &qcom_set_maxframe,
	.getmaxframe = &qcom_get_maxframe,
	.getndostats = &qcom_get_netdev_stats,
	.getssetcount = &qcom_get_strset_count,
	.getstrings = &qcom_get_strings,
	.getethtoolstats = &qcom_get_eth_stats,
	.sendpause = &qcom_send_pause_frame,
	.stoppause = &qcom_stop_pause_frame,
};
