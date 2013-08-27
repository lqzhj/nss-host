/*
 **************************************************************************
 * Copyright (c) 2013, Qualcomm Atheros, Inc.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

/*
 * nss_init.c
 *	NSS init APIs
 *
 */

#include "nss_core.h"
#include <nss_hal.h>

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/device.h>
#include <mach/msm_nss.h>

#include <linux/sysctl.h>
#include <linux/regulator/consumer.h>

/*
 * Declare module parameters
 */
static int load0 = 0x40000000;
module_param(load0, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(load0, "NSS Core 0 load address");

static int entry0 = 0x40000000;
module_param(entry0, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(load0, "NSS Core 0 entry address");

static char *string0 = "nss0";
module_param(string0, charp, 0);
MODULE_PARM_DESC(string0, "NSS Core 0 identification string");

static int load1 = 0x40100000;
module_param(load1, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(load0, "NSS Core 1 load address");

static int entry1 = 0x40100000;
module_param(entry1, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(load0, "NSS Core 1 entry address");

static char *string1 = "nss1";
module_param(string1, charp, 0);
MODULE_PARM_DESC(string1, "NSS Core 1 identification string");


/*
 * Global declarations
 */


/*
 * Define for RPM Nominal and Turbo for NSS
 */
#define NSS_NOM_VCC  1050000
#define NSS_TURB_VCC 1150000

/*
 * Global Handlers for the nss regulators
 */
struct regulator *nss0_vreg;

/*
 * Top level nss context structure
 */
struct nss_top_instance nss_top_main;
struct nss_cmd_buffer nss_cmd_buf;

/*
 * File local/Static variables/functions
 */

static const struct net_device_ops nss_netdev_ops;
static const struct ethtool_ops nss_ethtool_ops;

/*
 * nss_dummy_netdev_setup()
 *	Dummy setup for net_device handler
 */
static void nss_dummy_netdev_setup(struct net_device *ndev)
{
	return;
}

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
	napi_schedule(&int_ctx->napi);
	return IRQ_HANDLED;
}

/*
 * nss_probe()
 *	HLOS device probe callback
 */
static int __devinit nss_probe(struct platform_device *nss_dev)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_ctx_instance *nss_ctx = &nss_top->nss[nss_dev->id];
	struct nss_platform_data *npd = (struct nss_platform_data *) nss_dev->dev.platform_data;
	struct netdev_priv_instance *ndev_priv;
	int i, err = 0;

	nss_ctx->nss_top = nss_top;
	nss_ctx->id = nss_dev->id;

	nss_info("%p: NSS_DEV_ID %s \n", nss_ctx, dev_name(&nss_dev->dev));

	/*
	 * Both NSS cores controlled by same regulator, Hook only Once
	 */
	if (!nss_dev->id) {
		nss0_vreg = devm_regulator_get(&nss_dev->dev, "VDD_UBI0");

		if (IS_ERR(nss0_vreg)) {

			err = PTR_ERR(nss0_vreg);
			nss_info("%p: Regulator %s get failed, err=%d\n", nss_ctx, dev_name(&nss_dev->dev), err);
			return err;

		} else {

			nss_info("%p: Regulator %s get success\n", nss_ctx, dev_name(&nss_dev->dev));

			err = regulator_enable(nss0_vreg);
			if (err) {
				nss_info("%p: Regulator %s enable voltage failed, err=%d\n", nss_ctx, dev_name(&nss_dev->dev), err);
				return err;
			}

			err = regulator_set_voltage(nss0_vreg, NSS_NOM_VCC, NSS_NOM_VCC);
			if (err) {
				nss_info("%p: Regulator %s set voltage failed, err=%d\n", nss_ctx, dev_name(&nss_dev->dev), err);
				return err;
			}


		}
	}

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
	nss_info("%d:ctx=%p, vphys=%x, vmap=%x, nphys=%x, nmap=%x",
			nss_dev->id, nss_ctx, nss_ctx->vphys, nss_ctx->vmap, nss_ctx->nphys, nss_ctx->nmap);

	/*
	 * Register netdevice handlers
	 */
	nss_ctx->int_ctx[0].ndev = alloc_netdev(sizeof(struct netdev_priv_instance),
					"qca-nss-dev%d", nss_dummy_netdev_setup);
	if (nss_ctx->int_ctx[0].ndev == NULL) {
		nss_warning("%p: Could not allocate net_device #0", nss_ctx);
		err = -ENOMEM;
		goto err_init_0;
	}

	nss_ctx->int_ctx[0].ndev->netdev_ops = &nss_netdev_ops;
	nss_ctx->int_ctx[0].ndev->ethtool_ops = &nss_ethtool_ops;
	err = register_netdev(nss_ctx->int_ctx[0].ndev);
	if (err) {
		nss_warning("%p: Could not register net_device #0", nss_ctx);
		goto err_init_1;
	}

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
		goto err_init_2;
	}

	/*
	 * Register NAPI for NSS core interrupt #0
	 */
	ndev_priv = netdev_priv(nss_ctx->int_ctx[0].ndev);
	ndev_priv->int_ctx = &nss_ctx->int_ctx[0];
	netif_napi_add(nss_ctx->int_ctx[0].ndev, &nss_ctx->int_ctx[0].napi, nss_core_handle_napi, 64);
	napi_enable(&nss_ctx->int_ctx[0].napi);
	nss_ctx->int_ctx[0].napi_active = true;

	/*
	 * Check if second interrupt is supported on this nss core
	 */
	if (npd->num_irq > 1) {
		nss_info("%d: This NSS core supports two interrupts", nss_dev->id);

		/*
		 * Register netdevice handlers
		 */
		nss_ctx->int_ctx[1].ndev = alloc_netdev(sizeof(struct netdev_priv_instance),
						"qca-nss-dev%d", nss_dummy_netdev_setup);
		if (nss_ctx->int_ctx[1].ndev == NULL) {
			nss_warning("%p: Could not allocate net_device #1", nss_ctx);
			err = -ENOMEM;
			goto err_init_3;
		}

		nss_ctx->int_ctx[1].ndev->netdev_ops = &nss_netdev_ops;
		nss_ctx->int_ctx[1].ndev->ethtool_ops = &nss_ethtool_ops;
		err = register_netdev(nss_ctx->int_ctx[1].ndev);
		if (err) {
			nss_warning("%p: Could not register net_device #1", nss_ctx);
			goto err_init_4;
		}

		nss_ctx->int_ctx[1].nss_ctx = nss_ctx;
		nss_ctx->int_ctx[1].shift_factor = 15;
		nss_ctx->int_ctx[1].irq = npd->irq[1];
		err = request_irq(npd->irq[1], nss_handle_irq, IRQF_DISABLED, "nss", &nss_ctx->int_ctx[1]);
		if (err) {
			nss_warning("%d: IRQ1 request failed for nss", nss_dev->id);
			goto err_init_5;
		}

		/*
		 * Register NAPI for NSS core interrupt #1
		 */
		ndev_priv = netdev_priv(nss_ctx->int_ctx[1].ndev);
		ndev_priv->int_ctx = &nss_ctx->int_ctx[1];
		netif_napi_add(nss_ctx->int_ctx[1].ndev, &nss_ctx->int_ctx[1].napi, nss_core_handle_napi, 64);
		napi_enable(&nss_ctx->int_ctx[1].napi);
		nss_ctx->int_ctx[1].napi_active = true;
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

	/*
	 * Initialize decongestion callbacks to NULL
	 */
	for (i = 0; i< NSS_MAX_CLIENTS; i++) {
		nss_ctx->queue_decongestion_callback[i] = 0;
		nss_ctx->queue_decongestion_ctx[i] = 0;
	}

	spin_lock_init(&(nss_ctx->decongest_cb_lock));
	nss_ctx->magic = NSS_CTX_MAGIC;

	nss_info("%p: Reseting NSS core %d now", nss_ctx, nss_ctx->id);

	/*
	 * Enable clocks and bring NSS core out of reset
	 */
	nss_hal_core_reset(nss_dev->id, nss_ctx->nmap, nss_ctx->load, nss_top->clk_src);

	/*
	 * Enable interrupts for NSS core
	 */
	nss_hal_enable_interrupt(nss_ctx->nmap, nss_ctx->int_ctx[0].irq,
					nss_ctx->int_ctx[0].shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);

	if (npd->num_irq > 1) {
		nss_hal_enable_interrupt(nss_ctx->nmap, nss_ctx->int_ctx[1].irq,
					nss_ctx->int_ctx[1].shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);
	}

	nss_info("%p: All resources initialized and nss core%d has been brought out of reset", nss_ctx, nss_dev->id);
	goto err_init_0;

err_init_5:
	unregister_netdev(nss_ctx->int_ctx[1].ndev);
err_init_4:
	free_netdev(nss_ctx->int_ctx[1].ndev);
err_init_3:
	free_irq(npd->irq[0], &nss_ctx->int_ctx[0]);
err_init_2:
	unregister_netdev(nss_ctx->int_ctx[0].ndev);
err_init_1:
	free_netdev(nss_ctx->int_ctx[0].ndev);
err_init_0:
	return err;
}

/*
 * nss_remove()
 *	HLOS device remove callback
 */
static int __devexit nss_remove(struct platform_device *nss_dev)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_ctx_instance *nss_ctx = &nss_top->nss[nss_dev->id];

	/*
	 * Clean-up debugfs
	 */
	nss_stats_clean();

	/*
	 * Disable interrupts and bottom halves in HLOS
	 * Disable interrupts from NSS to HLOS
	 */
	nss_hal_disable_interrupt(nss_ctx->nmap, nss_ctx->int_ctx[0].irq,
					nss_ctx->int_ctx[0].shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);

	free_irq(nss_ctx->int_ctx[0].irq, &nss_ctx->int_ctx[0]);
	unregister_netdev(nss_ctx->int_ctx[0].ndev);
	free_netdev(nss_ctx->int_ctx[0].ndev);

	/*
	 * Check if second interrupt is supported
	 * If so then clear resources for second interrupt as well
	 */
	if (nss_ctx->int_ctx[1].irq) {
		nss_hal_disable_interrupt(nss_ctx->nmap, nss_ctx->int_ctx[1].irq,
					nss_ctx->int_ctx[1].shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);
		free_irq(nss_ctx->int_ctx[1].irq, &nss_ctx->int_ctx[1]);
		unregister_netdev(nss_ctx->int_ctx[1].ndev);
		free_netdev(nss_ctx->int_ctx[1].ndev);
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
 * nss_current_freq_handler()
 *	Handle Userspace Frequency Change Requests
 */
static int nss_current_freq_handler (ctl_table *ctl, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	void *ubicom_na_nss_context = NULL;
	int ret;
	int vret;

	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);

	if (write) {

		ubicom_na_nss_context = nss_register_ipv4_mgr(NULL);

		nss_info("Frequency Set to %d\n", nss_cmd_buf.current_freq);

		/* If support NSS freq is in the table send the new frequency request to NSS */

		if (nss_cmd_buf.current_freq == 110000000) {

			nss_freq_change(ubicom_na_nss_context, 533000000, 0);
			nss_hal_pvt_divide_pll(0, 11, 1);
			nss_hal_pvt_enable_pll18(1100);
			nss_freq_change(ubicom_na_nss_context, nss_cmd_buf.current_freq, 0);
			nss_hal_pvt_divide_pll(0, 18, 5);

			vret = regulator_set_voltage(nss0_vreg, NSS_NOM_VCC, NSS_NOM_VCC);
			if (vret) {
				nss_info("Regulator set voltage failed, err=%d\n", vret);
				return ret;
			}

		} else if (nss_cmd_buf.current_freq == 225000000) {

			nss_freq_change(ubicom_na_nss_context, 533000000, 0);
			nss_hal_pvt_divide_pll(0, 11, 1);
			nss_hal_pvt_enable_pll18(1100);
			nss_freq_change(ubicom_na_nss_context, nss_cmd_buf.current_freq, 0);
			nss_hal_pvt_divide_pll(0, 18, 2);

			vret = regulator_set_voltage(nss0_vreg, NSS_NOM_VCC, NSS_NOM_VCC);
			if (vret) {
				nss_info("Regulator set voltage failed, err=%d\n", vret);
				return ret;
			}

		} else if (nss_cmd_buf.current_freq == 550000000) {

			nss_freq_change(ubicom_na_nss_context, 533000000, 0);
			nss_hal_pvt_divide_pll(0, 11, 1);
			nss_hal_pvt_enable_pll18(1100);
			nss_freq_change(ubicom_na_nss_context, nss_cmd_buf.current_freq, 0);
			nss_hal_pvt_divide_pll(0, 18, 1);

			vret = regulator_set_voltage(nss0_vreg, NSS_NOM_VCC, NSS_NOM_VCC);
			if (vret) {
				nss_info("Regulator set voltage failed, err=%d\n", vret);
				return ret;
			}

		} else if (nss_cmd_buf.current_freq == 733000000) {
			vret = regulator_set_voltage(nss0_vreg, NSS_TURB_VCC, NSS_TURB_VCC);
			if (vret) {
				nss_info("Regulator set voltage failed, err=%d\n", vret);
				return ret;
			}

			nss_freq_change(ubicom_na_nss_context, 533000000, 0);
			nss_hal_pvt_divide_pll(0, 11, 1);
			nss_hal_pvt_enable_pll18(1466);
			nss_freq_change(ubicom_na_nss_context, nss_cmd_buf.current_freq, 0);
			nss_hal_pvt_divide_pll(0, 18, 1);

		} else {
			nss_info("Frequency not found. Please check Frequency Table\n");
		}
	}
	return ret;
}

/*
 * nss_auto_scale_handler()
 *	Enables or Disable Auto Scaling
 */
static int nss_auto_scale_handler (ctl_table *ctl, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);

	printk("Not Supported\n");

	return ret;
}

/*
 * nss_get_freq_table_handler()
 *	Display Support Freq and Ex how to Change.
 */
static int nss_get_freq_table_handler (ctl_table *ctl, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);

	printk("Frequency Supported - 110Mhz 225Mhz 550Mhz 733Mhz \n");
	printk("Ex. To Change Frequency - echo 110000000 > current_freq \n");

	return ret;
}

/*
 * sysctl-tuning infrastructure.
 */
static ctl_table nss_freq_table[] = {
	{
		.procname		= "current_freq",
		.data			= &nss_cmd_buf.current_freq,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &nss_current_freq_handler,
	},
	{
		.procname		= "freq_table",
		.data			= &nss_cmd_buf.max_freq,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &nss_get_freq_table_handler,
	},
	{
		.procname		= "auto_scale",
		.data			= &nss_cmd_buf.auto_scale,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &nss_auto_scale_handler,
	},
	{ }
};

static ctl_table nss_clock_dir[] = {
	{
		.procname		= "clock",
		.mode			= 0555,
		.child			= nss_freq_table,
	},
	{ }
};

static ctl_table nss_root_dir[] = {
	{
		.procname		= "nss",
		.mode			= 0555,
		.child			= nss_clock_dir,
	},
	{ }
};

static ctl_table nss_root[] = {
	{
		.procname		= "dev",
		.mode			= 0555,
		.child			= nss_root_dir,
	},
	{ }
};

static struct ctl_table_header *nss_dev_header;

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
	nss_hal_common_reset(&(nss_top_main.clk_src));

	/*
	 * Enable spin locks
	 */
	spin_lock_init(&(nss_top_main.lock));
	spin_lock_init(&(nss_top_main.stats_lock));

	/*
	 * Enable NSS statistics
	 */
	nss_stats_init();

	/*
	 * Store load addresses
	 */
	nss_top_main.nss[0].load = (uint32_t)load0;
	nss_top_main.nss[1].load = (uint32_t)load1;

	/*
	 * Register sysctl table.
	 */
	nss_dev_header = register_sysctl_table(nss_root);

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

	if (nss_dev_header)
		unregister_sysctl_table(nss_dev_header);

	platform_driver_unregister(&nss_driver);
}

module_init(nss_init);
module_exit(nss_cleanup);

MODULE_DESCRIPTION("QCA NSS Driver");
MODULE_AUTHOR("Qualcomm Atheros Inc");
MODULE_LICENSE("Dual BSD/GPL");
