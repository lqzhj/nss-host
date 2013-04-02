/* * Copyright (c) 2013 Qualcomm Atheros, Inc. * */

/*
 * nss_init.c
 *	NSS init APIs
 *
 */

#include "nss_core.h"
#include <nss_hal.h>

#include <linux/module.h>
#include <linux/platform_device.h>
#include <mach/msm_nss.h>

/*
 * Global declarations
 */

/*
 * Top level nss context structure
 */
struct nss_top_instance nss_top_main;

/*
 * File local/Static variables/functions
 */

/*
 * nss_handle_irq()
 *	HLOS interrupt handler for nss interrupts
 */
static irqreturn_t nss_handle_irq (int irq, void *ctx)
{
	struct int_ctx_instance *int_ctx = (struct int_ctx_instance *) ctx;

	/*
	 * Disable IRQ until our bottom half re-enables it
	 */
	disable_irq_nosync(irq);

	/*
	 * Schedule tasklet to process interrupt cause
	 */
	tasklet_schedule(&int_ctx->bh);
	return IRQ_HANDLED;
}

/*
 * nss_probe()
 *	HLOS device probe callback
 */
static int __devinit nss_probe (struct platform_device *nss_dev)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_ctx_instance *nss_ctx = &nss_top->nss[nss_dev->id];
	struct nss_platform_data *npd = (struct nss_platform_data *) nss_dev->dev.platform_data;
	int err, i;

	nss_ctx->nss_top = nss_top;
	nss_ctx->id = nss_dev->id;

	/*
	 * Get virtual and physical memory addresses for nss logical/hardware address maps
	 */

	/*
	 * Virtual address of CSM space
	 */
	nss_ctx->nmap = npd->nmap;
	nss_assert(nss_ctx->nmap);

	/*
	 * Physical address of CSM space
	 */
	nss_ctx->nphys = npd->nphys;
	nss_assert(nss_ctx->nphys);

	/*
	 * Virtual address of logical registers space
	 */
	nss_ctx->vmap = npd->vmap;
	nss_assert(nss_ctx->vmap);

	/*
	 * Physical address of logical registers space
	 */
	nss_ctx->vphys = npd->vphys;
	nss_assert(nss_ctx->vphys);
	nss_info("nss:%d:vphys =%x, vmap =%x, nphys=%x, nmap =%x", nss_dev->id, nss_ctx->vphys, nss_ctx->vmap, nss_ctx->nphys, nss_ctx->nmap);

	/*
	 * request for IRQs
	 *
	 * WARNING: CPU affinities should be set using OS supported methods
	 */
	nss_ctx->int_ctx[0].nss_ctx = nss_ctx;
	nss_ctx->int_ctx[0].shift_factor = 0;
	nss_ctx->int_ctx[0].irq = npd->irq[0];
	err = request_irq(npd->irq[0], nss_handle_irq, IRQF_DISABLED, "nss", &nss_ctx->int_ctx[0]);
	if (err) {
		nss_warning("%d: IRQ0 request failed", nss_dev->id);
		return err;
	}

	/*
	 * Register bottom halves for NSS core interrupt
	 */
	tasklet_init(&nss_ctx->int_ctx[0].bh, nss_core_handle_bh, (unsigned long)&nss_ctx->int_ctx[0]);

	/*
	 * Enable interrupts for NSS core
	 */
	nss_hal_enable_interrupt(nss_ctx->nmap, nss_ctx->int_ctx[0].irq,
					nss_ctx->int_ctx[0].shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);

	/*
	 * Check if second interrupt is supported on this nss core
	 */
	if (npd->num_irq > 1) {
		nss_info("%d: This NSS core supports two interrupts", nss_dev->id);
		nss_ctx->int_ctx[1].nss_ctx = nss_ctx;
		nss_ctx->int_ctx[1].shift_factor = 15;
		nss_ctx->int_ctx[1].irq = npd->irq[1];
		err = request_irq(npd->irq[1], nss_handle_irq, IRQF_DISABLED, "nss", &nss_ctx->int_ctx[1]);
		if (err) {
			nss_warning("%d: IRQ1 request failed for nss", nss_dev->id);
			nss_hal_disable_interrupt(nss_ctx->nmap, nss_ctx->int_ctx[0].irq,
					nss_ctx->int_ctx[0].shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);
			tasklet_kill(&nss_ctx->int_ctx[0].bh);
			free_irq(nss_ctx->int_ctx[0].irq, &nss_ctx->int_ctx[0]);
			return err;
		}

		/*
		 * Register bottom halves for NSS0 interrupts
		 */
		tasklet_init(&nss_ctx->int_ctx[1].bh, nss_core_handle_bh, (unsigned long)&nss_ctx->int_ctx[1]);

		nss_hal_enable_interrupt(nss_ctx->nmap, nss_ctx->int_ctx[1].irq,
				nss_ctx->int_ctx[1].shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);
	}

	spin_lock_bh(&(nss_top->lock));

	/*
	 * Check functionalities are supported by this NSS core
	 */
	if (npd->ipv4_enabled == NSS_FEATURE_ENABLED) {
		nss_top->ipv4_handler_id = nss_dev->id;
	}

	if (npd->ipv6_enabled == NSS_FEATURE_ENABLED) {
		nss_top->ipv6_handler_id = nss_dev->id;
	}

	if (npd->l2switch_enabled == NSS_FEATURE_ENABLED) {
		nss_top->l2switch_handler_id = nss_dev->id;
	}

	if (npd->crypto_enabled == NSS_FEATURE_ENABLED) {
		nss_top->crypto_handler_id = nss_dev->id;
	}

	if (npd->ipsec_enabled == NSS_FEATURE_ENABLED) {
		nss_top->ipsec_handler_id = nss_dev->id;
	}

	if (npd->wlan_enabled == NSS_FEATURE_ENABLED) {
		nss_top->wlan_handler_id = nss_dev->id;
	}

	if (npd->gmac_enabled[0] == NSS_FEATURE_ENABLED) {
		nss_top->phys_if_handler_id[0] = nss_dev->id;
	}

	if (npd->gmac_enabled[1] == NSS_FEATURE_ENABLED) {
		nss_top->phys_if_handler_id[1] = nss_dev->id;
	}

	if (npd->gmac_enabled[2] == NSS_FEATURE_ENABLED) {
		nss_top->phys_if_handler_id[2] = nss_dev->id;
	}

	if (npd->gmac_enabled[3] == NSS_FEATURE_ENABLED) {
		nss_top->phys_if_handler_id[3] = nss_dev->id;
	}

	spin_unlock_bh(&(nss_top->lock));

#ifdef CONFIG_MACH_IPQ806X_RUMI3
	/*
	 * Clear the whole TCM
	 * NOTE: This is required on RUMI as TCM does not seem to
	 * reset properly on RUMI
	 */
	for (i = 0; i < (16 * 1024); i++) {
		*((uint32_t *)nss_ctx->vmap + i) = 0;
	}
#endif

	/*
	 * Initialize decongestion callbacks to NULL
	 */
	for (i = 0; i< NSS_MAX_CLIENTS; i++) {
		nss_ctx->queue_decongestion_callback[i] = NULL;
		nss_ctx->queue_decongestion_ctx[i] = NULL;
	}

	spin_lock_init(&(nss_ctx->decongest_cb_lock));
	nss_ctx->magic = NSS_CTX_MAGIC;

	/*
	 * Enable clocks and bring NSS core out of reset
	 */
	nss_hal_core_reset(nss_dev->id, nss_ctx->nmap, npd->rst_addr);
	nss_info("%p: All resources initialized and nss core%d have been brought out of reset", nss_ctx, nss_dev->id);
	return 0;
}

/*
 * nss_remove()
 *	HLOS device remove callback
 */
static int __devexit nss_remove (struct platform_device *nss_dev)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_ctx_instance *nss_ctx = &nss_top->nss[nss_dev->id];

	/*
	 * Disable interrupts and bottom halves in HLOS
	 * Disable interrupts from NSS to HLOS
	 */
	nss_hal_disable_interrupt(nss_ctx->nmap, nss_ctx->int_ctx[0].irq,
					nss_ctx->int_ctx[0].shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);
	tasklet_kill(&nss_ctx->int_ctx[0].bh);
	free_irq(nss_ctx->int_ctx[0].irq, &nss_ctx->int_ctx[0]);

	/*
	 * Check if second interrupt is supported
	 * If so then clear resources for second interrupt as well
	 */
	if (nss_ctx->int_ctx[1].irq) {
		nss_hal_disable_interrupt(nss_ctx->nmap, nss_ctx->int_ctx[1].irq,
					nss_ctx->int_ctx[1].shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);
		tasklet_kill(&nss_ctx->int_ctx[1].bh);
		free_irq(nss_ctx->int_ctx[1].irq, &nss_ctx->int_ctx[1]);
	}

	nss_info("%p: All resources freed for nss core%d", nss_ctx, nss_dev->id);
	return 0;
}

/*
 * nss_driver
 *	Platform driver structure for NSS
 */
struct platform_driver nss_driver = {
	.probe	= nss_probe,
	.remove	= __devexit_p(nss_remove),
	.driver	= {
		.name	= "qca-nss",
		.owner	= THIS_MODULE,
	},
};

/*
 * nss_init()
 *	Registers nss driver
 */
static int __init nss_init(void)
{
	nss_info("Init NSS driver");

	/*
	 * Perform clock init common to all NSS cores
	 */
	nss_hal_common_reset();

	/*
	 * Enable spin locks
	 */
	spin_lock_init(&(nss_top_main.lock));
	spin_lock_init(&(nss_top_main.stats_lock));

	/*
	 * Register platform_driver
	 */
	return platform_driver_register(&nss_driver);
}

/*
 * nss_cleanup()
 *	Unregisters nss driver
 */
static void __exit nss_cleanup(void)
{
	nss_info("Exit NSS driver");
	platform_driver_unregister(&nss_driver);
}

module_init(nss_init);
module_exit(nss_cleanup);

MODULE_DESCRIPTION("QCA NSS Driver");
MODULE_AUTHOR("Qualcomm Atheros Inc");
MODULE_LICENSE("Dual BSD/GPL");
