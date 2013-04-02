obj-m += qca-nss-drv.o
qca-nss-drv-objs := nss_init.o nss_core.o nss_tx_rx.o

obj ?= .

EXTRA_CFLAGS += -I$(obj)/nss_hal/include

ifeq "$(CONFIG_ARCH_IPQ806X)" "y"
qca-nss-drv-objs += nss_hal/ipq806x/nss_hal_pvt.o
EXTRA_CFLAGS += -I$(obj)/nss_hal/ipq806x
endif
