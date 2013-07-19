#
# Copyright (c) 2013 Qualcomm Atheros, Inc.
#

# OCF specifc NSS cfi Makefile

NSS_IPSEC_MOD_NAME=qca-nss-ipsec

obj-m += $(NSS_IPSEC_MOD_NAME).o
$(NSS_IPSEC_MOD_NAME)-objs = nss_ipsec.o

obj ?= .
ccflags-y += -I$(obj)/../include
ccflags-y += -I$(obj)/
#ccflags-y += -DCONFIG_NSS_IPSEC_DEBUG
