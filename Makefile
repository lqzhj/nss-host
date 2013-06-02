obj-m += qca-nss-drv.o
qca-nss-drv-objs := nss_init.o nss_core.o nss_tx_rx.o nss_stats.o

obj ?= .

ccflags-y += -I$(obj)/nss_hal/include -DNSS_DEBUG_LEVEL=0 -DNSS_EMPTY_BUFFER_SIZE=1792 -DNSS_PKT_STATS_ENABLED=0

ifeq "$(CONFIG_ARCH_IPQ806X)" "y"
qca-nss-drv-objs += nss_hal/ipq806x/nss_hal_pvt.o
ccflags-y += -I$(obj)/nss_hal/ipq806x
endif
