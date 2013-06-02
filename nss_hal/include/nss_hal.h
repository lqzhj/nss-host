/* * Copyright (c) 2013 Qualcomm Atheros, Inc. * */

/**
 * nss_hal.h
 *	NSS HAL public declarations.
 */

#ifndef __NSS_HAL_H
#define __NSS_HAL_H

#include <nss_hal_pvt.h>

/*
 * nss_hal_common_reset()
 */
static inline void nss_hal_common_reset(uint32_t *clk_src)
{
	__nss_hal_common_reset(clk_src);
}

/*
 * nss_hal_core_reset()
 */
static inline void nss_hal_core_reset(uint32_t core_id, uint32_t map, uint32_t addr, uint32_t clk_src)
{
	__nss_hal_core_reset(core_id, map, addr, clk_src);
}

/*
 * nss_hal_read_interrupt_cause()
 */
static inline void nss_hal_read_interrupt_cause(uint32_t map, uint32_t irq, uint32_t shift_factor, uint32_t *cause)
{
	__nss_hal_read_interrupt_cause(map, irq, shift_factor, cause);
}

/*
 * nss_hal_clear_interrupt_cause()
 */
static inline void nss_hal_clear_interrupt_cause(uint32_t map, uint32_t irq, uint32_t shift_factor, uint32_t cause)
{
	__nss_hal_clear_interrupt_cause(map, irq, shift_factor, cause);
}

/*
 * nss_hal_disable_interrupt()
 */
static inline void nss_hal_disable_interrupt(uint32_t map, uint32_t irq, uint32_t shift_factor, uint32_t cause)
{
	__nss_hal_disable_interrupt(map, irq, shift_factor, cause);
}

/*
 * nss_hal_enable_interrupt()
 */
static inline void nss_hal_enable_interrupt(uint32_t map, uint32_t irq, uint32_t shift_factor, uint32_t cause)
{
	__nss_hal_enable_interrupt(map, irq, shift_factor, cause);
}

/*
 * nss_hal_send_interrupt()
 */
static inline void nss_hal_send_interrupt(uint32_t map, uint32_t irq, uint32_t cause)
{
	__nss_hal_send_interrupt(map, irq, cause);
}

#endif /* __NSS_HAL_H */
