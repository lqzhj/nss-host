##########################################################################
# Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
##########################################################################

# ###################################################
# # Makefile for the NSS driver
# ###################################################

obj-m += qca-nss-drv.o

#
# List the files that belong to the driver in alphabetical order.
#
qca-nss-drv-objs := \
			nss_cmn.o \
			nss_core.o \
			nss_crypto.o \
			nss_dynamic_interface.o \
			nss_gre_redir.o \
			nss_if.o \
			nss_init.o \
			nss_ipsec.o \
			nss_ipv4.o \
			nss_ipv4_reasm.o \
			nss_ipv6.o \
			nss_lag.o \
			nss_lso_rx.o \
			nss_phys_if.o \
			nss_pm.o \
			nss_sjack.o \
			nss_stats.o \
			nss_tun6rd.o \
			nss_tunipip6.o \
			nss_virt_if.o \
			nss_shaper.o \
			nss_pppoe.o \
			nss_capwap.o \
			nss_eth_rx.o \
			nss_n2h.o \
			nss_data_plane.o \
			nss_freq.o

#
# TODO: Deprecated files should be removed before merge
#
qca-nss-drv-objs += \
			nss_tx_rx_virt_if.o

obj-m += qca-nss-tunipip6.o
obj-m += qca-nss-ipsecmgr.o

ifeq "$(CONFIG_IPV6_SIT_6RD)" "y"
obj-m += qca-nss-tun6rd.o
qca-nss-tun6rd-objs := nss_connmgr_tun6rd.o
ccflags-y += -DNSS_TUN6RD_DEBUG_LEVEL=0
endif

qca-nss-tunipip6-objs := nss_connmgr_tunipip6.o
qca-nss-ipsecmgr-objs := nss_ipsecmgr.o

ccflags-y += -I$(obj)/nss_hal/include -I$(obj)/exports -DNSS_DEBUG_LEVEL=0 -DNSS_EMPTY_BUFFER_SIZE=1792 -DNSS_PKT_STATS_ENABLED=0
ccflags-y += -DNSS_TUNIPIP6_DEBUG_LEVEL=0
ccflags-y += -DNSS_PM_DEBUG_LEVEL=0
ccflags-y += -DNSS_IPSECMGR_DEBUG_LEVEL=3

qca-nss-drv-objs += nss_profiler.o
obj-y+= profiler/
obj-y+= nss_qdisc/
obj-y+= capwapmgr/

obj ?= .

ifeq "$(CONFIG_ARCH_IPQ806X)" "y"
qca-nss-drv-objs += nss_hal/ipq806x/nss_hal_pvt.o
ccflags-y += -I$(obj)/nss_hal/ipq806x
endif
