obj-$(CONFIG_IPQ_NSS)	+= ipq_nss.o
ipq_nss-objs		:= nss_init.o nss_core.o nss_tx_rx.o

obj ?= .

EXTRA_CFLAGS += -I$(obj)/nss_hal/include

ifeq "$(CONFIG_ARCH_IPQ806X)" "y"
ipq_nss-objs += nss_hal/ipq806x/nss_hal_pvt.o
EXTRA_CFLAGS += -I$(obj)/nss_hal/ipq806x
endif
