/* * Copyright (c) 2013 Qualcomm Atheros, Inc. */
/*
 * @file
 * This file defines the APIs for accessing global NSS GMAC
 * software interface register space.
 * ------------------------REVISION HISTORY-----------------------------
 * Qualcomm Atheros         01/Mar/2013              Created
 */

#include <linux/types.h>
#include <mach/msm_nss_gmac.h>

#include <nss_gmac_dev.h>
#include <nss_gmac_clocks.h>

/**
 * @brief Emulation specific initialization.
 *
 * @param[in] nss_gmac_dev *
 * @return void
 */
void nss_gmac_spare_ctl(nss_gmac_dev *gmacdev)
{
	uint32_t val;
	uint32_t count;
	uint32_t id = gmacdev->macid;
	uint32_t *nss_base = (uint32_t *)(gmacdev->ctx->nss_base);

	if (!gmacdev->emulation) {
		return;
	}

	val = 1 << id;
	nss_gmac_set_reg_bits(nss_base, NSS_ETH_SPARE_CTL, val);

	val = nss_gmac_read_reg(nss_base, NSS_ETH_SPARE_CTL);
	nss_gmac_info(gmacdev, "NSS_ETH_SPARE_CTL - 0x%x", val);

	val = 1 << id;
	nss_gmac_clear_reg_bits(nss_base, NSS_ETH_SPARE_CTL, val);

	val = nss_gmac_read_reg(nss_base, NSS_ETH_SPARE_CTL);
	nss_gmac_info(gmacdev,
		      "NSS_ETH_SPARE_CTL - 0x%x after clear for gmac %d", val,
		      id);

	val = nss_gmac_read_reg(nss_base, NSS_ETH_SPARE_STAT);
	nss_gmac_info(gmacdev,
		      "NSS_ETH_SPARE_STAT - 0x%x; gmac %d spare ctl reset...",
		      val, id);
	count = 0;
	while ((val & (1 << id)) != (1 << id)) {
		mdelay(10);
		val = nss_gmac_read_reg(nss_base,
					NSS_ETH_SPARE_STAT);
		if (count++ > 20) {
			nss_gmac_info(gmacdev,
				      "!!!!!! Timeout waiting for NSS_ETH_SPARE_STAT bit to set.");
			break;
		}
	}
}


/**
 * @brief QSGMII Init for Emulation
 *
 * @param[in] nss_gmac_dev *
 * @return void
 */
static void nss_gmac_rumi_qsgmii_init(nss_gmac_dev *gmacdev)
{
	nss_gmac_dev *gmac1_dev;
	uint16_t phy_reg_val;
	uint32_t *qsgmii_base;
	uint8_t *nss_base;

	nss_gmac_info(gmacdev, "%s:", __FUNCTION__);

	gmac1_dev = gmacdev->ctx->nss_gmac[1];
	qsgmii_base = gmacdev->ctx->qsgmii_base;
	nss_base = (uint8_t *)(gmacdev->ctx->nss_base);

	/*
	 * _SGMII: Set only bit 3, with no polling for reset completion
	 * inside status register for GMAC2
	 */
	nss_gmac_info(gmacdev,"Eth2: spare_ctl_reg value before setting = 0x%x",
		      nss_gmac_read_reg((uint32_t *)nss_base, NSS_ETH_SPARE_CTL));
	nss_gmac_set_reg_bits((uint32_t *)nss_base, NSS_ETH_SPARE_CTL, 0x8);
	nss_gmac_info(gmacdev,"Eth2: spare_ctl_reg value after setting = 0x%x",
		      nss_gmac_read_reg((uint32_t *)nss_base, NSS_ETH_SPARE_CTL));

	nss_gmac_info(gmac1_dev, "%s: GMAC1's MACBASE = 0x%x",__FUNCTION__, gmac1_dev->mac_base);
	
	/* Put PHY in SGMII Mode */
	nss_gmac_write_reg(qsgmii_base, QSGMII_PHY_MODE_CTL, 0x0);

	/* Set SERDES signal detects for channel2, bypass SDO */
	nss_gmac_write_reg(qsgmii_base, PCS_QSGMII_CTL, 0x4213B);

	/* SERDES Configuration, drive strength settings through GMAC1's MDIO */

	/* Configure SERDES to SGMII-1+SGMII-2 mode */
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1, 0x8241);
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x3, 0xB909);

	/* Writes to SERDES registers using MDIO debug registers */
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1D, 0x10);
	phy_reg_val = nss_gmac_mii_rd_reg(gmac1_dev, 0x0, 0x1E);

	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1D, 0x10);
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1E, 0x2000);
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1D, 0x10);
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1E, 0x0);
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1D, 0x10);

	phy_reg_val = nss_gmac_mii_rd_reg(gmac1_dev, 0x0, 0x1E);

	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1D, 0x0A);
	phy_reg_val = nss_gmac_mii_rd_reg(gmac1_dev, 0x0, 0x1E);

	nss_gmac_info(gmacdev, "Reg 1A reset val:  0x%x",phy_reg_val);

	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1D, 0x0A);
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1E, 0x3F9);
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x1D, 0x0A);

	phy_reg_val = nss_gmac_mii_rd_reg(gmac1_dev, 0x0, 0x1E);

	nss_gmac_info(gmacdev, "Reg 1A after programming:  0x%x", phy_reg_val);
	nss_gmac_mii_wr_reg(gmac1_dev, 0x0, 0x18, 0x30);

	/* Put PCS in SGMII Mode */
	nss_gmac_write_reg(qsgmii_base, PCS_QSGMII_SGMII_MODE, 0x0);

	/* Channel 2 force speed */
	nss_gmac_write_reg(qsgmii_base, PCS_ALL_CH_CTL, 0xF0000600);
}


/**
 * @brief QSGMII dev init
 *
 * @param[in] nss_gmac_dev *
 * @return void
 */
void nss_gmac_qsgmii_dev_init(nss_gmac_dev *gmacdev)
{
	uint32_t val;
	uint32_t id = gmacdev->macid;
	uint8_t *nss_base = (uint8_t *)(gmacdev->ctx->nss_base);

	if (gmacdev->emulation) {
		nss_gmac_rumi_qsgmii_init(gmacdev);
	}

	/* Enable clk for GMACn */
	val = 0;
	if ((gmacdev->phy_mii_type == GMAC_INTF_SGMII) || (gmacdev->phy_mii_type == GMAC_INTF_QSGMII)) {
		val |= GMACn_QSGMII_RX_CLK(id) | GMACn_QSGMII_TX_CLK(id);
	}

	nss_gmac_set_reg_bits((uint32_t *)nss_base, NSS_QSGMII_CLK_CTL, val);

	val = nss_gmac_read_reg((uint32_t *)nss_base, NSS_QSGMII_CLK_CTL);
	nss_gmac_info(gmacdev,"%s: NSS_QSGMII_CLK_CTL(0x%x) - 0x%x",
		      __FUNCTION__, NSS_QSGMII_CLK_CTL, val);
}


/**
 * @brief Clear all NSS GMAC interface registers.
 * @return returns 0 on success.
 */
static void nss_gmac_clear_all_regs(uint32_t *nss_base)
{
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_ETH_CLK_GATE_CTL, 0xFFFFFFFF);
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_ETH_CLK_DIV0, 0xFFFFFFFF);
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_ETH_CLK_DIV1, 0xFFFFFFFF);
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_ETH_CLK_SRC_CTL, 0xFFFFFFFF);
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_ETH_CLK_INV_CTL, 0xFFFFFFFF);
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_GMAC0_CTL, 0xFFFFFFFF);
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_GMAC1_CTL, 0xFFFFFFFF);
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_GMAC2_CTL, 0xFFFFFFFF);
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_GMAC3_CTL, 0xFFFFFFFF);
	nss_gmac_clear_reg_bits((uint32_t *)nss_base,
				NSS_QSGMII_CLK_CTL, 0xFFFFFFFF);
}


/**
 * @brief QSGMII common init
 *
 * @param[in] nss_gmac_dev *
 * @return void
 */
static void nss_gmac_qsgmii_common_init(uint32_t *qsgmii_base)
{
	if (nss_gmac_get_phy_profile() == NSS_GMAC_PHY_PROFILE_QS) {
		/* Configure QSGMII Block for QSGMII mode */

		/* Put PHY in QSGMII Mode */
		nss_gmac_write_reg(qsgmii_base, QSGMII_PHY_MODE_CTL, QSGMII_PHY_MODE_QSGMII);

		/* Put PCS in QSGMII Mode */
		nss_gmac_write_reg(qsgmii_base, PCS_QSGMII_SGMII_MODE, PCS_QSGMII_MODE_QSGMII);
		return;
	}

	/* Configure QSGMII Block for 3xSGMII mode */

	/* Put PHY in SGMII Mode */
	nss_gmac_write_reg(qsgmii_base, QSGMII_PHY_MODE_CTL, QSGMII_PHY_MODE_SGMII);

	/* Put PCS in SGMII Mode */
	nss_gmac_write_reg(qsgmii_base, PCS_QSGMII_SGMII_MODE, PCS_QSGMII_MODE_SGMII);
}


/*
 * @brief Initialization commom to all GMACs.
 * @return returns 0 on success.
 */
int32_t nss_gmac_common_init(struct nss_gmac_global_ctx *ctx)
{
	volatile uint32_t val;

	ctx->nss_base = (uint8_t *)ioremap_nocache(NSS_REG_BASE, NSS_REG_LEN);
	if (!ctx->nss_base) {
		nss_gmac_msg("Error mapping NSS GMAC registers");
		return -EIO;
	}
	nss_gmac_msg("%s: NSS base ioremap OK.", __FUNCTION__);

	ctx->qsgmii_base = (uint32_t *)ioremap_nocache(QSGMII_REG_BASE, QSGMII_REG_LEN);
	if (!ctx->qsgmii_base) {
		nss_gmac_msg("Error mapping QSGMII registers");
		iounmap(ctx->nss_base);
		ctx->nss_base = NULL;
		return -EIO;
	}
	nss_gmac_msg("%s: QSGMII base ioremap OK, vaddr = 0x%p", __FUNCTION__, ctx->qsgmii_base);

	nss_gmac_clear_all_regs((uint32_t *)ctx->nss_base);

	/*
	 * Deaassert GMAC AHB reset
	 */
	nss_gmac_clear_reg_bits((uint32_t *)(MSM_CLK_CTL_BASE), GMAC_AHB_RESET, 0x1);

	/* Bypass MACSEC */
	nss_gmac_set_reg_bits((uint32_t *)(ctx->nss_base), NSS_MACSEC_CTL, 0x7);

	val = nss_gmac_read_reg((uint32_t *)(ctx->nss_base), NSS_MACSEC_CTL);
	nss_gmac_msg("%s:NSS_MACSEC_CTL(0x%x) - 0x%x",
		     __FUNCTION__, NSS_MACSEC_CTL, val);

	nss_gmac_qsgmii_common_init(ctx->qsgmii_base);

	/*
	 * Initialize ACC_GMAC_CUST field of NSS_ACC_REG register
	 * for GMAC and MACSEC memories.
	 */
	nss_gmac_clear_reg_bits((uint32_t *)(MSM_CLK_CTL_BASE), NSS_ACC_REG, GMAC_ACC_CUST_MASK);

	return 0;
}

/**
 * @brief Global common deinitialization.
 * @return void
 */
void nss_gmac_common_deinit(struct nss_gmac_global_ctx *ctx)
{
	nss_gmac_msg("%s: \n", __FUNCTION__);

	nss_gmac_clear_all_regs((uint32_t *)ctx->nss_base);

	if (ctx->qsgmii_base) {
		iounmap(ctx->qsgmii_base);
		ctx->qsgmii_base = NULL;
	}

	if (ctx->nss_base) {
		iounmap(ctx->nss_base);
		ctx->nss_base = NULL;
	}
}

/*
 * @brief Return clock divider value for QSGMII PHY.
 * @param[in] nss_gmac_dev *
 * @return returns QSGMII clock divider value.
 */
static uint32_t clk_div_qsgmii(nss_gmac_dev *gmacdev)
{
	uint32_t div;

	switch (gmacdev->speed) {
	case SPEED1000:
		div = QSGMII_CLK_DIV_1000;
		break;

	case SPEED100:
		div = QSGMII_CLK_DIV_100;
		break;

	case SPEED10:
		div = QSGMII_CLK_DIV_10;
		break;

	default:
		div = QSGMII_CLK_DIV_1000;
		break;
	}

	return div;
}

/**
 * @brief Return clock divider value for SGMII PHY.
 * @param[in] nss_gmac_dev *
 * @return returns SGMII clock divider value.
 */
static uint32_t clk_div_sgmii(nss_gmac_dev *gmacdev)
{
	uint32_t div;

	switch (gmacdev->speed) {
	case SPEED1000:
		div = SGMII_CLK_DIV_1000;
		break;

	case SPEED100:
		div = SGMII_CLK_DIV_100;
		break;

	case SPEED10:
		div = SGMII_CLK_DIV_10;
		break;

	default:
		div = SGMII_CLK_DIV_1000;
		break;
	}

	return div;
}

/**
 * @brief Return clock divider value for RGMII PHY.
 * @param[in] nss_gmac_dev *
 * @return returns RGMII clock divider value.
 */
static uint32_t clk_div_rgmii(nss_gmac_dev *gmacdev)
{
	uint32_t div;

	switch (gmacdev->speed) {
	case SPEED1000:
		div = RGMII_CLK_DIV_1000;
		break;

	case SPEED100:
		div = RGMII_CLK_DIV_100;
		break;

	case SPEED10:
		div = RGMII_CLK_DIV_10;
		break;

	default:
		div = RGMII_CLK_DIV_1000;
		break;
	}

	return div;
}

/**
 * @brief Set GMAC speed.
 * @param[in] nss_gmac_dev *
 * @return returns 0 on success.
 */
int32_t nss_gmac_dev_set_speed(nss_gmac_dev *gmacdev)
{
	uint32_t val;
	uint32_t id = gmacdev->macid;
	uint32_t div;
	uint32_t clk;
	uint32_t *nss_base = (uint32_t *)(gmacdev->ctx->nss_base);

	switch (gmacdev->phy_mii_type) {
	case GMAC_INTF_RGMII:
		div = clk_div_rgmii(gmacdev);
		break;

	case GMAC_INTF_SGMII:
		div = clk_div_sgmii(gmacdev);
		break;

	case GMAC_INTF_QSGMII:
		div = clk_div_qsgmii(gmacdev);
		break;

	default:
		return -EINVAL;
		nss_gmac_info(gmacdev, "%s: Invalid MII type", __FUNCTION__);
		break;
	}

	clk = 0;
	/* Disable GMACn Tx/Rx clk */
	if (gmacdev->phy_mii_type == GMAC_INTF_RGMII) {
		clk |= GMACn_RGMII_RX_CLK(id) | GMACn_RGMII_TX_CLK(id);
	} else {
		clk |= GMACn_GMII_RX_CLK(id) | GMACn_GMII_TX_CLK(id);
	}
	nss_gmac_clear_reg_bits(nss_base, NSS_ETH_CLK_GATE_CTL, clk);

	/* set clock divider */
	val = nss_gmac_read_reg(nss_base, NSS_ETH_CLK_DIV0);
	val &= ~GMACn_CLK_DIV(id, GMACn_CLK_DIV_SIZE);
	val |= GMACn_CLK_DIV(id, div);
	nss_gmac_write_reg(nss_base, NSS_ETH_CLK_DIV0, val);

	/* Enable GMACn Tx/Rx clk */
	nss_gmac_set_reg_bits(nss_base, NSS_ETH_CLK_GATE_CTL, clk);

	val = nss_gmac_read_reg(nss_base, NSS_ETH_CLK_DIV0);
	nss_gmac_info(gmacdev, "%s:NSS_ETH_CLK_DIV0(0x%x) - 0x%x",
		      __FUNCTION__, NSS_ETH_CLK_DIV0, val);

	return 0;
}

/**
 * @brief GMAC device initializaton.
 * @param[in] nss_gmac_dev *
 * @return void
 */
void nss_gmac_dev_init(nss_gmac_dev *gmacdev)
{
	uint32_t val = 0;
	uint32_t id = gmacdev->macid;
	uint32_t *nss_base = (uint32_t *)(gmacdev->ctx->nss_base);

	/* 
	 * Initialize wake and sleep counter values of
	 * GMAC memory footswitch control.
	 */
	nss_gmac_set_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_FS(id) , GMAC_FS_S_W_VAL);


	/*
	 * Bring up GMAC core clock
	 */
	/* a) Program GMAC_COREn_CLK_SRC_CTL register */
	nss_gmac_clear_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC_CTL(id),
				GMAC_DUAL_MN8_SEL |
				GMAC_CLK_ROOT_ENA |
				GMAC_CLK_LOW_PWR_ENA);
	nss_gmac_set_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC_CTL(id),
			      GMAC_CLK_ROOT_ENA);

	/* b) Program M & D values in GMAC_COREn_CLK_SRC[0,1]_MD register. */
	nss_gmac_write_reg(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC0_MD(id), 0);
	nss_gmac_write_reg(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC1_MD(id), 0);
	nss_gmac_set_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC0_MD(id),
			      GMAC_CORE_CLK_M_VAL | GMAC_CORE_CLK_D_VAL);
	nss_gmac_set_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC1_MD(id),
			      GMAC_CORE_CLK_M_VAL | GMAC_CORE_CLK_D_VAL);

	/* c) Program N values on GMAC_COREn_CLK_SRC[0,1]_NS register */
	nss_gmac_write_reg(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC0_NS(id), 0);
	nss_gmac_write_reg(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC1_NS(id), 0);
	nss_gmac_set_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC0_NS(id),
			      GMAC_CORE_CLK_N_VAL
			      | GMAC_CORE_CLK_MNCNTR_EN
			      | GMAC_CORE_CLK_MNCNTR_MODE_DUAL
			      | GMAC_CORE_CLK_PRE_DIV_SEL_BYP
			      | GMAC_CORE_CLK_SRC_SEL_PLL0);
	nss_gmac_set_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_SRC1_NS(id),
			      GMAC_CORE_CLK_N_VAL
			      | GMAC_CORE_CLK_MNCNTR_EN
			      | GMAC_CORE_CLK_MNCNTR_MODE_DUAL
			      | GMAC_CORE_CLK_PRE_DIV_SEL_BYP
			      | GMAC_CORE_CLK_SRC_SEL_PLL0);

	/* d) Un-halt GMACn clock */
	nss_gmac_clear_reg_bits(MSM_CLK_CTL_BASE, CLK_HALT_NSSFAB0_NSSFAB1_STATEA,
				GMACn_CORE_CLK_HALT(id));

	/* e) CLK_COREn_CLK_CTL: select branch enable and disable clk invert */
	nss_gmac_clear_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_CTL(id), GMAC_CLK_INV);
	nss_gmac_set_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_CLK_CTL(id), GMAC_CLK_BRANCH_EN);


	/* Set GMACn Ctl */
	val = GMAC_IFG_CTL(GMAC_IFG) | GMAC_IFG_LIMIT(GMAC_IFG) | GMAC_CSYS_REQ;
	if (gmacdev->phy_mii_type == GMAC_INTF_RGMII) {
		val |= GMAC_PHY_RGMII;
	} else {
		val &= ~GMAC_PHY_RGMII;
	}
	nss_gmac_set_reg_bits(nss_base, NSS_GMACn_CTL(id), val);

	val = nss_gmac_read_reg(nss_base, NSS_GMACn_CTL(id));
	nss_gmac_info(gmacdev, "%s: NSS_GMAC%d_CTL(0x%x) - 0x%x",
		      __FUNCTION__, id, NSS_GMACn_CTL(id), val);

	/*
	 * Optionally enable/disable MACSEC bypass.
	 * We are doing this in nss_gmac_plat_init()
	 */

	/*
	 * Deassert GMACn power on reset
	 */
	nss_gmac_clear_reg_bits(MSM_CLK_CTL_BASE, GMAC_COREn_RESET(id), 0x1);

	/* Select Tx/Rx CLK source */
	val = 0;
	if (id == 0 || id == 1) {
		if (gmacdev->phy_mii_type == GMAC_INTF_RGMII) {
			val |= (1 << id);
		}
	} else {
		if (gmacdev->phy_mii_type == GMAC_INTF_SGMII) {
			val |= (1 << id);
		}
	}

	nss_gmac_set_reg_bits(nss_base, NSS_ETH_CLK_SRC_CTL, val);

	/* Enable xGMII clk for GMACn */
	val = 0;
	if (gmacdev->phy_mii_type == GMAC_INTF_RGMII) {
		val |= GMACn_RGMII_RX_CLK(id) | GMACn_RGMII_TX_CLK(id);
	} else {
		val |= GMACn_GMII_RX_CLK(id) | GMACn_GMII_TX_CLK(id);
	}

	/* Optionally configure RGMII CDC delay */

	/* Enable PTP clock */
	val |= GMACn_PTP_CLK(id);
	nss_gmac_set_reg_bits(nss_base, NSS_ETH_CLK_GATE_CTL, val);

	if ((gmacdev->phy_mii_type == GMAC_INTF_SGMII)
	     || (gmacdev->phy_mii_type == GMAC_INTF_QSGMII)) {
		nss_gmac_qsgmii_dev_init(gmacdev);
		nss_gmac_info(gmacdev, "SGMII Specific Init for GMAC%d Done!", id);
	}

	val = nss_gmac_read_reg(nss_base, NSS_ETH_CLK_GATE_CTL);
	nss_gmac_info(gmacdev, "%s:NSS_ETH_CLK_GATE_CTL(0x%x) - 0x%x",
		      __FUNCTION__, NSS_ETH_CLK_GATE_CTL, val);

	val = nss_gmac_read_reg(nss_base, NSS_ETH_CLK_SRC_CTL);
	nss_gmac_info(gmacdev, "%s:NSS_ETH_CLK_SRC_CTL(0x%x) - 0x%x",
		      __FUNCTION__, NSS_ETH_CLK_SRC_CTL, val);

	/* Read status registers */
	val = nss_gmac_read_reg(nss_base, NSS_ETH_CLK_ROOT_STAT);
	nss_gmac_info(gmacdev, "%s:CLK_ROOT_STAT - 0x%x", __FUNCTION__, val);

	val = nss_gmac_read_reg(nss_base, NSS_QSGMII_CLK_CTL);
	nss_gmac_info(gmacdev, "%s:QSGMII_CLK_CTL - 0x%x", __FUNCTION__, val);

}
