#
# Copyright (c) 2013 Qualcomm Atheros, Inc..
#
# -----------------------------REVISION HISTORY---------------------------------
# Qualcomm Atheros                01/Feb/2013                  Created
#

###################################################
# Makefile for the NSS GMAC driver
###################################################

obj ?= .

obj-m += qca-nss-gmac.o

qca-nss-gmac-objs +=	nss_gmac_dev.o \
			nss_gmac_ctrl.o \
			nss_gmac_init.o \
			nss_gmac_ethtool.o \
			nss_gmac_tx_rx_offload.o \
			nss_gmac_mdiobus.o

GMAC_INCLUDE = -I$(obj)/include

# NSS_GMAC_DEBUG_LEVEL - 0: none, 1: warning, 2: info, 3: trace

ccflags-y += $(GMAC_INCLUDE) -DNSS_GMAC_DEBUG_LEVEL=0 -UNSS_GMAC_JUMBO

