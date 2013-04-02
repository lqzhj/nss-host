/* * Copyright (c) 2013 Qualcomm Atheros, Inc. * */

/**
 * nss_hal_pvt.h
 *	NSS HAL private declarations.for IPQ806x platform
 */

#ifndef __NSS_HAL_PVT_H
#define __NSS_HAL_PVT_H

#include "nss_regs.h"
#include <linux/types.h>

#define NSS_HAL_SUPPORTED_INTERRUPTS (NSS_REGS_N2H_INTR_STATUS_EMPTY_BUFFER_QUEUE | \
					NSS_REGS_N2H_INTR_STATUS_DATA_COMMAND_QUEUE | \
					NSS_REGS_N2H_INTR_STATUS_EMPTY_BUFFERS_SOS)

/*
 * __nss_hal_read_interrupt_cause()
 */
static inline void __nss_hal_read_interrupt_cause(uint32_t map, uint32_t irq __attribute__ ((unused)), uint32_t shift_factor, uint32_t *cause)
{
	uint32_t value = nss_read_32(map, NSS_REGS_N2H_INTR_STATUS_OFFSET);
	*cause = (((value)>> shift_factor) & 0x7FFF);
}

/*
 * __nss_hal_clear_interrupt_cause()
 */
static inline void __nss_hal_clear_interrupt_cause(uint32_t map, uint32_t irq __attribute__ ((unused)), uint32_t shift_factor, uint32_t cause)
{
	nss_write_32(map, NSS_REGS_N2H_INTR_CLR_OFFSET, (cause << shift_factor));
}

/*
 * __nss_hal_disable_interrupt()
 */
static inline void __nss_hal_disable_interrupt(uint32_t map, uint32_t irq __attribute__ ((unused)), uint32_t shift_factor, uint32_t cause)
{
	nss_write_32(map, NSS_REGS_N2H_INTR_MASK_CLR_OFFSET, (cause << shift_factor));
}

/*
 * __nss_hal_enable_interrupt()
 */
static inline void __nss_hal_enable_interrupt(uint32_t map, uint32_t irq __attribute__ ((unused)), uint32_t shift_factor, uint32_t cause)
{
	nss_write_32(map, NSS_REGS_N2H_INTR_MASK_SET_OFFSET, (cause << shift_factor));
}

/*
 * __nss_hal_send_interrupt()
 */
static inline void __nss_hal_send_interrupt(uint32_t map, uint32_t irq __attribute__ ((unused)), uint32_t cause)
{
	nss_write_32(map, NSS_REGS_C2C_INTR_SET_OFFSET, cause);
}

extern void __nss_hal_core_reset(uint32_t core_id, uint32_t map, uint32_t addr);
extern void __nss_hal_common_reset(void);

#endif /* __NSS_HAL_PVT_H */
