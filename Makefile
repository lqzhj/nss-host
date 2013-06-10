#
# Copyright (c) 2013 Qualcomm Atheros, Inc..
# All Rights Reserved.
#
# -----------------------------REVISION HISTORY---------------------------------
# Qualcomm Atheros                01/Feb/2013                  Created
#

# ###################################################
# # Makefile for the NSS driver
# ###################################################

obj-m += qca-nss-drv.o
qca-nss-drv-objs := nss_init.o nss_core.o nss_tx_rx.o nss_stats.o

obj-m += qca-nss-connmgr-ipv4.o
obj-m += qca-nss-connmgr-ipv6.o

qca-nss-connmgr-ipv4-objs := nss_connmgr_ipv4.o
qca-nss-connmgr-ipv6-objs := nss_connmgr_ipv6.o

ccflags-y += -I$(obj)/nss_hal/include -DNSS_DEBUG_LEVEL=0 -DNSS_EMPTY_BUFFER_SIZE=1792 -DNSS_PKT_STATS_ENABLED=0
ccflags-y += -DNSS_CONNMGR_DEBUG_LEVEL=0

obj ?= .

ifeq "$(CONFIG_ARCH_IPQ806X)" "y"
qca-nss-drv-objs += nss_hal/ipq806x/nss_hal_pvt.o
ccflags-y += -I$(obj)/nss_hal/ipq806x
endif
