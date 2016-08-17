# ###################################################
# # Makefile for the NSS driver
# ###################################################

obj-m += qca-nss-drv.o

#
# List the files that belong to the driver in alphabetical order.
#
qca-nss-drv-objs := \
			nss_capwap.o \
			nss_cmn.o \
			nss_core.o \
			nss_coredump.o \
			nss_crypto.o \
			nss_dtls.o \
			nss_dynamic_interface.o \
			nss_eth_rx.o \
			nss_gre_redir.o \
			nss_if.o \
			nss_init.o \
			nss_ipsec.o \
			nss_ipv4.o \
			nss_ipv4_log.o \
			nss_ipv4_reasm.o \
			nss_ipv6.o \
			nss_ipv6_log.o \
			nss_ipv6_reasm.o \
			nss_l2tpv2.o \
			nss_lag.o \
			nss_log.o \
			nss_lso_rx.o \
			nss_map_t.o \
			nss_n2h.o \
			nss_oam.o \
			nss_phys_if.o \
			nss_profiler.o \
			nss_portid.o \
			nss_pppoe.o \
			nss_pptp.o \
			nss_shaper.o \
			nss_sjack.o \
			nss_stats.o \
			nss_tstamp.o \
			nss_tun6rd.o \
			nss_tunipip6.o \
			nss_virt_if.o \
			nss_wifi.o \
			nss_wifi_if.o \
			nss_wifi_vdev.o

#
# TODO: Deprecated files should be removed before merge
#
qca-nss-drv-objs += nss_tx_rx_virt_if.o

# Base NSS data plane/HAL support
qca-nss-drv-objs += nss_data_plane/nss_data_plane.o
qca-nss-drv-objs += nss_hal/nss_hal.o

# All active qsdk branches (banana/coconut/trunk) supports ipq806x
qca-nss-drv-objs += nss_data_plane/nss_data_plane_gmac.o \
		    nss_hal/ipq806x/nss_hal_pvt.o
ccflags-y += -I$(obj)/nss_hal/ipq806x -DNSS_HAL_IPQ806X_SUPPORT

# Only 4.4 Kernel (qsdk trunk) supports ipq807x
ifneq ($(findstring 4.4., $(KERNELVERSION)),)
qca-nss-drv-objs += nss_hal/ipq807x/nss_hal_pvt.o
ccflags-y += -I$(obj)/nss_hal/ipq807x -DNSS_HAL_IPQ807x_SUPPORT
endif

ccflags-y += -I$(obj)/nss_hal/include -I$(obj)/nss_data_plane/include -I$(obj)/exports -DNSS_DEBUG_LEVEL=0 -DNSS_PKT_STATS_ENABLED=1

ccflags-y += -DNSS_PM_DEBUG_LEVEL=0

ifneq ($(findstring 3.4, $(KERNELVERSION)),)
NSS_CCFLAGS = -DNSS_DT_SUPPORT=0 -DNSS_FW_DBG_SUPPORT=1 -DNSS_PM_SUPPORT=1 -DNSS_EMPTY_BUFFER_SIZE=1984
qca-nss-drv-objs += nss_pm.o
else
NSS_CCFLAGS = -DNSS_DT_SUPPORT=1 -DNSS_FW_DBG_SUPPORT=0 -DNSS_PM_SUPPORT=0 -DNSS_EMPTY_BUFFER_SIZE=1984

ccflags-y += -I$(obj)
endif

# Only the 3.14 Kernel implements fabric scaling framework and map-t
ifneq ($(findstring 3.14, $(KERNELVERSION)),)
NSS_CCFLAGS += -DNSS_FABRIC_SCALING_SUPPORT=1
else
NSS_CCFLAGS += -DNSS_FABRIC_SCALING_SUPPORT=0
endif

# Disable Frequency scaling
ifeq "$(NSS_FREQ_SCALE_DISABLE)" "y"
ccflags-y += -DNSS_FREQ_SCALE_SUPPORT=0
else
qca-nss-drv-objs += nss_freq.o
ccflags-y += -DNSS_FREQ_SCALE_SUPPORT=1
endif

ccflags-y += $(NSS_CCFLAGS)

export NSS_CCFLAGS

obj ?= .

