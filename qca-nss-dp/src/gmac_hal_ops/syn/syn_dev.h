/*
 **************************************************************************
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF0
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#ifndef __SYN_DEV_H__
#define __SYN_DEV_H__

#include "syn_reg.h"

/*
 *  HAL stats for Syn MAC chips
 */
struct syn_stats {
	uint64_t rx_bytes_ctr;		/* Rx bytes */
	uint64_t rx_frame_ctr;		/* Rx frames */
	uint64_t rx_pause_ctr;		/* Rx pause frame */
	uint64_t rx_multicast_ctr;	/* Rx multicast frame */
	uint64_t rx_broadcast_ctr;	/* Rx broadcast frame */
	uint64_t rx_unicast_ctr;	/* Rx unicast frame */
	uint64_t rx_fifo_overflow_ctr;	/* Rx fifo overflow */
	uint64_t rx_undersize_ctr;	/* Rx undersize frame */
	uint64_t rx_oversize_ctr;	/* Rx oversize frame */
	uint64_t rx_vlan_ctr;		/* Rx vlan frame */
	uint64_t rx_lpi_usec_ctr;	/* Rx lpi */
	uint64_t rx_discard_frame_ctr;	/* Rx discard frame */
	uint64_t rx_pkt64_ctr;		/* Rx 64 bytes packet */
	uint64_t rx_pkt65to127_ctr;	/* Rx 65-127 bytes packet */
	uint64_t rx_pkt128to255_ctr;	/* Rx 128-255 bytes packet */
	uint64_t rx_pkt256to511_ctr;	/* Rx 256-511 bytes packet */
	uint64_t rx_pkt512to1023_ctr;	/* Rx 512-1023 bytes packet */
	uint64_t rx_pkt1024tomax_ctr;	/* Rx >1024 bytes packet */
	uint64_t rx_crc_err_ctr;	/* Rx crc error */
	uint64_t rx_runt_err_ctr;	/* Rx runt error */
	uint64_t rx_jabber_err_ctr;	/* Rx jabber error */
	uint64_t rx_len_err_ctr;	/* Rx len error */
	uint64_t tx_bytes_ctr;		/* Tx bytes */
	uint64_t tx_frame_ctr;		/* Tx frames */
	uint64_t tx_pause_ctr;		/* Tx pause frame */
	uint64_t tx_broadcast_ctr;	/* Tx broadcast frame */
	uint64_t tx_broadcast_gb_ctr;	/* Tx broadcast good frame */
	uint64_t tx_multicast_ctr;	/* Tx multicast frame */
	uint64_t tx_multicast_gb_ctr;	/* Tx multicast good frame */
	uint64_t tx_underflow_err_ctr;	/* Tx overflow */
	uint64_t tx_vlan_ctr;		/* Tx vlan frame */
	uint64_t tx_unicast_ctr;	/* Tx unicast frame */
	uint64_t tx_pkt64_ctr;		/* Tx 64 bytes packet */
	uint64_t tx_pkt65to127_ctr;	/* Tx 65-127 bytes packet */
	uint64_t tx_pkt128to255_ctr;	/* Tx 128-255 bytes packet */
	uint64_t tx_pkt256to511_ctr;	/* Tx 256-511 bytes packet */
	uint64_t tx_pkt512to1023_ctr;	/* Tx 512-1023 bytes packet */
	uint64_t tx_pkt1024tomax_ctr;	/* Tx >1024 bytes packet */
	uint64_t tx_lpi_usec_ctr;	/* Tx lpi */
};

/*
 * Subclass for base nss_gmac_haldev
 */
struct syn_hal_dev {
	struct nss_gmac_hal_dev nghd;	/* Base class */
	struct syn_stats stats;		/* Stats structure */
};

/*
 * syn_set_rx_flow_ctrl()
 */
static inline void syn_set_rx_flow_ctrl(
		struct nss_gmac_hal_dev *nghd)
{
	hal_set_reg_bits(nghd, SYN_MAC_RX_FLOW_CTL,
			SYN_MAC_RX_FLOW_ENABLE);
}

/*
 * syn_clear_rx_flow_ctrl()
 */
static inline void syn_clear_rx_flow_ctrl(
		struct nss_gmac_hal_dev *nghd)
{
	hal_clear_reg_bits(nghd, SYN_MAC_RX_FLOW_CTL,
			SYN_MAC_RX_FLOW_ENABLE);
}

/*
 * syn_set_tx_flow_ctrl()
 */
static inline void syn_set_tx_flow_ctrl(
		struct nss_gmac_hal_dev *nghd)
{
	hal_set_reg_bits(nghd, SYN_MAC_Q0_TX_FLOW_CTL,
			SYN_MAC_TX_FLOW_ENABLE);
}

/*
 * syn_send_tx_pause_frame()
 */
static inline void syn_send_tx_pause_frame(
		struct nss_gmac_hal_dev *nghd)
{
	hal_set_reg_bits(nghd, SYN_MAC_Q0_TX_FLOW_CTL,
			SYN_MAC_TX_FLOW_ENABLE);
	hal_set_reg_bits(nghd, SYN_MAC_Q0_TX_FLOW_CTL,
			SYN_MAC_TX_PAUSE_SEND);
}

/*
 * syn_clear_tx_flow_ctrl()
 */
static inline void syn_clear_tx_flow_ctrl(
		struct nss_gmac_hal_dev *nghd)
{
	hal_clear_reg_bits(nghd, SYN_MAC_Q0_TX_FLOW_CTL,
			SYN_MAC_TX_FLOW_ENABLE);
}

/*
 * syn_clear_mac_ctrl()
 */
static inline void syn_clear_mac_ctrl(
		struct nss_gmac_hal_dev *nghd)
{
	hal_write_reg(nghd->mac_base, SYN_MAC_TX_CONFIG, 0);
	hal_write_reg(nghd->mac_base, SYN_MAC_RX_CONFIG, 0);
}

/*
 * syn_rx_enable()
 */
static inline void syn_rx_enable(struct nss_gmac_hal_dev *nghd)
{
	hal_set_reg_bits(nghd, SYN_MAC_RX_CONFIG, SYN_MAC_RX_ENABLE);
	hal_set_reg_bits(nghd, SYN_MAC_PACKET_FILTER, SYN_MAC_RX_ENABLE);
}

/*
 * syn_rx_disable()
 */
static inline void syn_rx_disable(struct nss_gmac_hal_dev *nghd)
{
	hal_clear_reg_bits(nghd, SYN_MAC_RX_CONFIG, SYN_MAC_RX_ENABLE);
}

/*
 * syn_tx_enable()
 */
static inline void syn_tx_enable(struct nss_gmac_hal_dev *nghd)
{
	hal_set_reg_bits(nghd, SYN_MAC_TX_CONFIG, SYN_MAC_TX_ENABLE);
}

/*
 * syn_tx_disable()
 */
static inline void syn_tx_disable(struct nss_gmac_hal_dev *nghd)
{
	hal_clear_reg_bits(nghd, SYN_MAC_TX_CONFIG,
			SYN_MAC_TX_ENABLE);
}

/*
 * syn_set_mmc_stats()
 */
static inline void syn_set_mmc_stats(struct nss_gmac_hal_dev *nghd)
{
	hal_set_reg_bits(nghd, SYN_MAC_MMC_CTL,
			SYN_MAC_MMC_RSTONRD);
}

/*
 * syn_rx_jumbo_frame_enable()
 */
static inline void syn_rx_jumbo_frame_enable(
		struct nss_gmac_hal_dev *nghd)
{
	hal_set_reg_bits(nghd, SYN_MAC_RX_CONFIG,
			SYN_MAC_JUMBO_FRAME_ENABLE);
}

/*
 * syn_rx_jumbo_frame_disable()
 */
static inline void syn_rx_jumbo_frame_disable(
		struct nss_gmac_hal_dev *nghd)
{
	hal_clear_reg_bits(nghd, SYN_MAC_RX_CONFIG,
			SYN_MAC_JUMBO_FRAME_ENABLE);
}

/*
 * syn_set_full_duplex()
 */
static inline void syn_set_full_duplex(
		struct nss_gmac_hal_dev *nghd)
{
	/* TBD */
	return;
}

/*
 * syn_set_half_duplex()
 */
static inline void syn_set_half_duplex(
		struct nss_gmac_hal_dev *nghd)
{
	/* TBD */
	return;
}

/*
 * syn_get_stat()
 */
static inline void syn_get_stat(struct nss_gmac_hal_dev *nghd,
				     uint64_t *stat, uint32_t regoffset)
{
	*(stat) += (uint64_t)hal_read_reg(nghd->mac_base, regoffset);
}

static inline void syn_get_stat64(struct nss_gmac_hal_dev *nghd,
				       uint64_t *stat,
				       uint32_t regoffset_hi,
				       uint32_t regoffset_lo)
{
	uint64_t stats_new = 0;

	stats_new = hal_read_reg(nghd->mac_base, regoffset_hi);
	stats_new = stats_new << 32;
	stats_new |= hal_read_reg(nghd->mac_base, regoffset_lo);
	*(stat) += stats_new;
}
/*
 * syn_get_rx_stats()
 */
static void syn_get_rx_stats(struct nss_gmac_hal_dev *nghd)
{
	struct syn_hal_dev *shd = (struct syn_hal_dev *)nghd;
	struct syn_stats *stats = &(shd->stats);

	syn_get_stat64(nghd, &stats->rx_broadcast_ctr,
			    SYN_MAC_MMC_RX_BCAST_HI,
			    SYN_MAC_MMC_RX_BCAST_LO);
	syn_get_stat64(nghd, &stats->rx_multicast_ctr,
			    SYN_MAC_MMC_RX_MCAST_HI,
			    SYN_MAC_MMC_RX_MCAST_LO);
	syn_get_stat64(nghd, &stats->rx_unicast_ctr,
			    SYN_MAC_MMC_RX_UNICAST_HI,
			    SYN_MAC_MMC_RX_UNICAST_LO);
	syn_get_stat64(nghd, &stats->rx_pause_ctr,
			    SYN_MAC_MMC_RX_PAUSE_FRAME_HI,
			    SYN_MAC_MMC_RX_PAUSE_FRAME_LO);
	syn_get_stat64(nghd, &stats->rx_frame_ctr,
			    SYN_MAC_MMC_RX_FRAME_HI,
			    SYN_MAC_MMC_RX_FRAME_LO);
	syn_get_stat64(nghd, &stats->rx_bytes_ctr,
			    SYN_MAC_MMC_RX_BYTES_HI,
			    SYN_MAC_MMC_RX_BYTES_LO);
	syn_get_stat64(nghd, &stats->rx_fifo_overflow_ctr,
			    SYN_MAC_MMC_RX_FIFO_OVERFLOW_HI,
			    SYN_MAC_MMC_RX_FIFO_OVERFLOW_LO);
	syn_get_stat(nghd, &stats->rx_undersize_ctr,
			    SYN_MAC_MMC_RX_UNDERSIZE);
	syn_get_stat(nghd, &stats->rx_oversize_ctr,
			  SYN_MAC_MMC_RX_OVERSIZE);
	syn_get_stat64(nghd, &stats->rx_vlan_ctr,
			    SYN_MAC_MMC_RX_VLAN_FRAME_HI,
			    SYN_MAC_MMC_RX_VLAN_FRAME_LO);
	syn_get_stat64(nghd, &stats->rx_lpi_usec_ctr,
			    SYN_MAC_MMC_RX_LPI_USEC_CTR_HI,
			    SYN_MAC_MMC_RX_LPI_USEC_CTR_LO);
	syn_get_stat64(nghd, &stats->rx_discard_frame_ctr,
			    SYN_MAC_MMC_RX_DISCARD_FRAME_HI,
			    SYN_MAC_MMC_RX_DISCARD_FRAME_LO);
	syn_get_stat64(nghd, &stats->rx_crc_err_ctr,
			    SYN_MAC_MMC_RX_CRC_ERR_HI,
			    SYN_MAC_MMC_RX_CRC_ERR_LO);
	syn_get_stat(nghd, &stats->rx_runt_err_ctr,
			  SYN_MAC_MMC_RX_RUNT_ERR);
	syn_get_stat(nghd, &stats->rx_jabber_err_ctr,
			  SYN_MAC_MMC_RX_JABBER_ERR);
	syn_get_stat64(nghd, &stats->rx_len_err_ctr,
			    SYN_MAC_MMC_RX_LEN_ERR_HI,
			    SYN_MAC_MMC_RX_LEN_ERR_LO);
	syn_get_stat64(nghd, &stats->rx_pkt64_ctr,
			    SYN_MAC_MMC_RX_PKT64_HI,
			    SYN_MAC_MMC_RX_PKT64_LO);
	syn_get_stat64(nghd, &stats->rx_pkt65to127_ctr,
			    SYN_MAC_MMC_RX_PKT65TO127_HI,
			    SYN_MAC_MMC_RX_PKT65TO127_LO);
	syn_get_stat64(nghd, &stats->rx_pkt128to255_ctr,
			    SYN_MAC_MMC_RX_PKT128TO255_HI,
			    SYN_MAC_MMC_RX_PKT128TO255_LO);
	syn_get_stat64(nghd, &stats->rx_pkt256to511_ctr,
			    SYN_MAC_MMC_RX_PKT256TO511_HI,
			    SYN_MAC_MMC_RX_PKT256TO511_LO);
	syn_get_stat64(nghd, &stats->rx_pkt512to1023_ctr,
			    SYN_MAC_MMC_RX_PKT512TO1023_HI,
			    SYN_MAC_MMC_RX_PKT512TO1023_LO);
	syn_get_stat64(nghd, &stats->rx_pkt1024tomax_ctr,
			    SYN_MAC_MMC_RX_PKT1024TOMAX_HI,
			    SYN_MAC_MMC_RX_PKT1024TOMAX_LO);
}

/*
 * syn_get_tx_stats()
 */
static void syn_get_tx_stats(struct nss_gmac_hal_dev *nghd)
{
	struct syn_hal_dev *shd = (struct syn_hal_dev *)nghd;
	struct syn_stats *stats = &(shd->stats);

	syn_get_stat64(nghd, &stats->tx_lpi_usec_ctr,
			    SYN_MAC_MMC_TX_LPI_USEC_CTR_HI,
			    SYN_MAC_MMC_TX_LPI_USEC_CTR_LO);
	syn_get_stat64(nghd, &stats->tx_broadcast_ctr,
			    SYN_MAC_MMC_TX_BCAST_HI,
			    SYN_MAC_MMC_TX_BCAST_LO);
	syn_get_stat64(nghd, &stats->tx_broadcast_gb_ctr,
			    SYN_MAC_MMC_TX_BCAST_GB_HI,
			    SYN_MAC_MMC_TX_BCAST_GB_LO);
	syn_get_stat64(nghd, &stats->tx_multicast_ctr,
			    SYN_MAC_MMC_TX_MCAST_HI,
			    SYN_MAC_MMC_TX_MCAST_LO);
	syn_get_stat64(nghd, &stats->tx_multicast_gb_ctr,
			    SYN_MAC_MMC_TX_MCAST_GB_HI,
			    SYN_MAC_MMC_TX_MCAST_GB_LO);
	syn_get_stat64(nghd, &stats->tx_unicast_ctr,
			    SYN_MAC_MMC_TX_UNICAST_HI,
			    SYN_MAC_MMC_TX_UNICAST_LO);
	syn_get_stat64(nghd, &stats->tx_frame_ctr,
			    SYN_MAC_MMC_TX_FRAME_HI,
			    SYN_MAC_MMC_TX_FRAME_LO);
	syn_get_stat64(nghd, &stats->tx_bytes_ctr,
			    SYN_MAC_MMC_TX_BYTES_HI,
			    SYN_MAC_MMC_TX_BYTES_LO);
	syn_get_stat64(nghd, &stats->tx_pause_ctr,
			    SYN_MAC_MMC_TX_PAUSE_FRAME_HI,
			    SYN_MAC_MMC_TX_PAUSE_FRAME_LO);
	syn_get_stat64(nghd, &stats->tx_underflow_err_ctr,
			    SYN_MAC_MMC_TX_UNDERFLOW_ERR_HI,
			    SYN_MAC_MMC_TX_UNDERFLOW_ERR_LO);
	syn_get_stat64(nghd, &stats->tx_vlan_ctr,
			    SYN_MAC_MMC_TX_VLAN_HI,
			    SYN_MAC_MMC_TX_VLAN_LO);
	syn_get_stat64(nghd, &stats->tx_pkt64_ctr,
			    SYN_MAC_MMC_TX_PKT64_HI,
			    SYN_MAC_MMC_TX_PKT64_LO);
	syn_get_stat64(nghd, &stats->tx_pkt65to127_ctr,
			    SYN_MAC_MMC_TX_PKT65TO127_HI,
			    SYN_MAC_MMC_TX_PKT65TO127_LO);
	syn_get_stat64(nghd, &stats->tx_pkt128to255_ctr,
			    SYN_MAC_MMC_TX_PKT128TO255_HI,
			    SYN_MAC_MMC_TX_PKT128TO255_LO);
	syn_get_stat64(nghd, &stats->tx_pkt256to511_ctr,
			    SYN_MAC_MMC_TX_PKT256TO511_HI,
			    SYN_MAC_MMC_TX_PKT256TO511_LO);
	syn_get_stat64(nghd, &stats->tx_pkt512to1023_ctr,
			    SYN_MAC_MMC_TX_PKT512TO1023_HI,
			    SYN_MAC_MMC_TX_PKT512TO1023_LO);
	syn_get_stat64(nghd, &stats->tx_pkt1024tomax_ctr,
			    SYN_MAC_MMC_TX_PKT1024TOMAX_HI,
			    SYN_MAC_MMC_TX_PKT1024TOMAX_LO);
}

#endif /*__SYN_DEV_H__*/
