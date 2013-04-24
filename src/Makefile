#
# Copyright © 2013 - Qualcomm Atheros
#

NSS_CRYPTO_MOD_NAME=qca-nss-crypto

#ccflags-y += -DCONFIG_NSS_CRYPTO_ALIGN
ccflags-y += -DCONFIG_NSS_CRYPTO_CACHED_KEYS
ccflags-y += -DCONFIG_NSS_CRYPTO_AUTH -DCONFIG_NSS_CRYPTO_IDXWAR
ccflags-y += -DCONFIG_NSS_CRYPTO_OFFLOAD
#ccflags-y += -DCONFIG_NSS_CRYPTO_DBG

obj-m += $(NSS_CRYPTO_MOD_NAME).o
$(NSS_CRYPTO_MOD_NAME)-objs = nss_crypto_ipq806x.o
$(NSS_CRYPTO_MOD_NAME)-objs += nss_crypto_if.o
#$(NSS_CRYPTO_MOD_NAME)-objs += nss_crypto_data.o
$(NSS_CRYPTO_MOD_NAME)-objs += nss_crypto_ctrl.o

obj ?= .
ccflags-y += -I$(obj)/include -I$(obj)/
