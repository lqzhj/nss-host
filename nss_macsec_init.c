/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
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
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include <asm/io.h>
#include <mach/msm_iomap.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/types.h>
#include <linux/errno.h>

#include "nss_macsec_emac.h"
#include "nss_macsec_sdk_api.h"
#include "nss_macsec_fal_api.h"
#include "nss_macsec_utility.h"
#include "nss_macsec_os.h"

/* NSS MACSEC Base Addresses */
#define NSS_MACSEC_BASE			0x37800000
#define NSS_MACSEC_REG_LEN		0x00600000
#define MACSEC_DEVICE_NUM 3

static struct sock *sdk_nl_sk = NULL;

/**
 * @brief MACSEC driver context
 */
struct nss_macsec_ctx {
	char __iomem *macsec_base[MACSEC_DEVICE_NUM];
};
static struct nss_macsec_ctx macsec_ctx;

int nss_macsec_reg_read(unsigned int dev_id, unsigned int reg_addr,
			unsigned int *pvalue)
{
	*pvalue =
	    readl((unsigned char *)((uint32_t) macsec_ctx.macsec_base[dev_id] +
				    (reg_addr)));
	return 0;
}

int nss_macsec_reg_write(unsigned int dev_id, unsigned int reg_addr,
			 unsigned int pvalue)
{
	writel(pvalue,
	       (unsigned char *)((uint32_t) macsec_ctx.macsec_base[dev_id] +
				 (reg_addr)));
	return 0;
}

static unsigned int nss_macsec_msg_handle(void *msg_data, unsigned int *sync)
{
	struct sdk_msg_header *header = (struct sdk_msg_header *)msg_data;
	unsigned short cmd_type = header->cmd_type;
	unsigned int ret = 0;

	*sync = 1;
	switch (cmd_type) {
	case SDK_FAL_CMD:{
			ret = nss_macsec_fal_msg_handle(header);
		}
		break;

	default:
		break;
	}

	return ret;
}

static void nss_macsec_netlink_recv(struct sk_buff *__skb)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	void *msg_data;
	u32 pid = 0, msg_type = 0, sync = 0, ret = 0;

	if ((skb = skb_get(__skb)) != NULL) {
		nlh = nlmsg_hdr(skb);
		pid = nlh->nlmsg_pid;
		msg_data = NLMSG_DATA(nlh);
		msg_type = nlh->nlmsg_type;

		if (msg_type == SDK_CALL_MSG) {
			ret = nss_macsec_msg_handle(msg_data, &sync);
		} else {
			printk("Unexpected msg:0x%x received!\n", msg_type);
		}

		NETLINK_CB(skb).pid = 0;	/* from kernel */
		NETLINK_CB(skb).dst_group = 0;	/* unicast */
		netlink_unicast(sdk_nl_sk, skb, pid, MSG_DONTWAIT);

	}

	return;
}

static int nss_macsec_netlink_init(void)
{
	sdk_nl_sk = netlink_kernel_create(&init_net,
					  NETLINK_SDK,
					  0,
					  nss_macsec_netlink_recv,
					  NULL, THIS_MODULE);

	if (sdk_nl_sk == NULL) {
		printk("Create netlink socket fail\n");
		return -ENODEV;
	}

	return 0;
}

static void nss_macsec_netlink_fini(void)
{
	if (sdk_nl_sk) {
		sock_release(sdk_nl_sk->sk_socket);
		sdk_nl_sk = NULL;
	}
}

static int nss_macsec_probe(struct platform_device *pdev)
{
	int rc, ret = 0;
	unsigned int mem_start, mem_len;
	void __iomem *mmap_io_addr = NULL;
	mem_start = pdev->resource[0].start;
	mem_len = pdev->resource[0].end - mem_start + 1;
	if (!request_mem_region(mem_start, mem_len, pdev->name)) {
		macsec_warning("%s Unable to request resource.", __func__);
		return -EIO;
	}

	mmap_io_addr = ioremap_nocache(mem_start, mem_len);
	if (!mmap_io_addr) {
		macsec_warning("%s ioremap fail.", __func__);
		return -EIO;
	}
	macsec_trace("macsec.%d phy_addr:0x%x len:0x%x mem_start:%p\n",
		     pdev->id, mem_start, mem_len, mmap_io_addr);

	macsec_ctx.macsec_base[pdev->id] = mmap_io_addr;

	/* Invoke Macsec Initialization API */
	nss_macsec_secy_init(pdev->id);

	rc = nss_macsec_speed_cb_register(pdev->id + 1,
					  (void *)nss_macsec_speed);

	macsec_trace("macsec.%d probe done\n", pdev->id);
	return ret;
}

static int nss_macsec_remove(struct platform_device *pdev)
{
	unsigned int mem_start, mem_len;

	macsec_trace("%s for dev_id:%d\n", __func__, pdev->id);
	mem_start = pdev->resource[0].start;
	mem_len = pdev->resource[0].end - mem_start + 1;
	nss_macsec_speed_cb_register(pdev->id + 1, NULL);
	iounmap(macsec_ctx.macsec_base[pdev->id]);
	release_mem_region(mem_start, mem_len);
	return 0;
}

/**
 * @brief Linux Platform driver for MACSEC
 */
static struct platform_driver nss_macsec_drv = {
	.probe = nss_macsec_probe,
	.remove = nss_macsec_remove,
	.driver = {
		   .name = "nss-macsec",
		   .owner = THIS_MODULE,
		   },
};

static int __init nss_macsec_init_module(void)
{
	nss_macsec_pre_init();
	if (platform_driver_register(&nss_macsec_drv) != 0) {
		macsec_warning("platform drv reg failure\n");
		return -EIO;
	}
	//proc_debug_macsec();
	macsec_trace("%s done!\n", __func__);

	return 0;
}

static int __init nss_macsec_init(void)
{
	nss_macsec_netlink_init();

	nss_macsec_mutex_init();

	nss_macsec_init_module();

	macsec_trace("nss_macsec init success\n");

	return 0;
}

static void __exit nss_macsec_fini(void)
{
	nss_macsec_netlink_fini();

	nss_macsec_mutex_destroy();
	platform_driver_unregister(&nss_macsec_drv);
	nss_macsec_pre_exit();

	macsec_trace("nss_macsec exit success\n");
}

module_init(nss_macsec_init);
module_exit(nss_macsec_fini);
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif
