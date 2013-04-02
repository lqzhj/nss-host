/* * Copyright (c) 2013 Qualcomm Atheros, Inc. * */

/**
 * nss_hal_pvt.c
 *	NSS HAL private APIs.
 */

#include "nss_hal_pvt.h"
#include "nss_clocks.h"

/*
 * clk_reg_write_32()
 *	Write clock register
 */
static inline void clk_reg_write_32(void *addr, uint32_t val)
{
	writel(val, addr);
}

/*
 * __nss_hal_common_reset
 *	Do reset/clock configuration common to all cores
 *
 * WARNING: This function is a place holder. It will be updated soon.
 */
void __nss_hal_common_reset(void)
{
	/*
	 * Enable NSS Fabric1 clock
	 * PLL0 (800 MHZ) and div is set to 4. (effective clk fre is 200 MHZ).
	 */
	clk_reg_write_32(NSSFB1_CLK_SRC0_NS, 0x1a);
	clk_reg_write_32(NSSFB1_CLK_SRC1_NS, 0x1a);

	/*
	 * NSS Fabric1 Branch enable and fabric clock gating enabled.
	 */
	clk_reg_write_32(NSSFB1_CLK_CTL, 0x50);

	/*
	 * Enable NSS Fabric0 clock
	 * PLL0 (800 MHZ) and div is set to 2. (effective clk fre is 400 MHZ).
	 */
	clk_reg_write_32(NSSFB0_CLK_SRC0_NS, 0x0a);
	clk_reg_write_32(NSSFB0_CLK_SRC1_NS, 0x0a);

	/*
	 * NSS Fabric0 Branch enable and fabric clock gating enabled.
	 */
	clk_reg_write_32(NSSFB0_CLK_CTL, 0x50);

	/*
	 * Enable NSS TCM clock
	 * Enable TCM clock root source.
	 */
	clk_reg_write_32(NSSTCM_CLK_SRC_CTL, 0x2);

	/*
	 * PLL0 (800 MHZ) and div is set to 2. (effective clk fre is 400 MHZ).
	 */
	clk_reg_write_32(NSSTCM_CLK_SRC0_NS, 0xa);
	clk_reg_write_32(NSSTCM_CLK_SRC1_NS, 0xa);

	/*
	 * NSS TCM Branch enable and fabric clock gating enabled.
	 */
	clk_reg_write_32(NSSTCM_CLK_CTL, 0x50);

	/*
	 * Enable global NSS clock branches.
	 * NSS global Fab Branch enable and fabric clock gating enabled.
	 */
	clk_reg_write_32(NSSFAB_GLOBAL_BUS_NS, 0xf);

	/*
	 * clock source is pll0_out_main (800 MHZ). SRC_SEL is 2 (3'b010)
	 * src_div selected is Div-6 (4'b0101).
	 */
	clk_reg_write_32(NSSFPB_CLK_SRC0_NS, 0x2a);
	clk_reg_write_32(NSSFPB_CLK_SRC1_NS, 0x2a);

	/*
	 * NSS FPB block granch & clock gating enabled.
	 */
	clk_reg_write_32(NSSFPB_CLK_CTL, 0x50);

	/*
	 * Send reset interrupt to NSS
	 */
	clk_reg_write_32(NSS_RESET, 0x0);
}

/*
 * __nss_hal_core_reset
 *
 * WARNING: This function is a place holder. It will be updated soon.
 */
void __nss_hal_core_reset(uint32_t core_id, uint32_t map, uint32_t addr)
{
	/*
	 * UBI coren clock branch enable.
	 */
	clk_reg_write_32(UBI32_COREn_CLK_SRC_CTL(core_id), 0x02);

	/*
	 * M val is 0x01 and NOT_2D value is 0xfd.
	 */
	clk_reg_write_32(UBI32_COREn_CLK_SRC0_MD(core_id), 0x100fd);
	clk_reg_write_32(UBI32_COREn_CLK_SRC1_MD(core_id), 0x100fd);

	/*
	 * Dual edge, pll0, NOT(N_M) = 0xfe.
	 */
	clk_reg_write_32(UBI32_COREn_CLK_SRC0_NS(core_id), 0x00fe0142);
	clk_reg_write_32(UBI32_COREn_CLK_SRC1_NS(core_id), 0x00fe0142);

	/*
	 * UBI32 coren clock control branch.
	 */
	clk_reg_write_32(UBI32_COREn_CLK_FS(core_id), 0x4f);

	/*
	 * UBI32 coren clock control branch.
	 */
	clk_reg_write_32(UBI32_COREn_CLK_CTL(core_id), 0x10);

	/*
	 * Enable mpt clock
	 */
	clk_reg_write_32(UBI32_MPT0_CLK_CTL, 0x10);

	/*
	 * Remove ubi32 clamp
	 */
	clk_reg_write_32(UBI32_COREn_RESET_CLAMP(core_id), 0x0);

	/*
	* Apply ubi32 core reset
	*/
	nss_write_32(map, NSS_REGS_RESET_CTRL_OFFSET, 1);

	/*
	 * Program address configuration
	 */
	nss_write_32(map, NSS_REGS_CORE_AMC_OFFSET, 1);
	nss_write_32(map, NSS_REGS_CORE_BAR_OFFSET, 0x3c000000);
	nss_write_32(map, NSS_REGS_CORE_BOOT_ADDR_OFFSET, addr);

	/*
	 * Crypto, GMAC and C2C interrupts are level sensitive
	 */
	nss_write_32(map, NSS_REGS_CORE_INT_STAT2_TYPE_OFFSET, 0xFFFF);
	nss_write_32(map, NSS_REGS_CORE_INT_STAT3_TYPE_OFFSET, 0x3FC000);

	/*
	 * De-assert ubi32 core reset
	 */
	nss_write_32(map, NSS_REGS_RESET_CTRL_OFFSET, 0);
}
