#
# Copyright (c) 2013 Qualcomm Atheros, Inc..
# All Rights Reserved.
#
# -----------------------------REVISION HISTORY---------------------------------
# Qualcomm Atheros                01/Feb/2013                  Created
#

###################################################
# Makefile for the NSS GMAC driver
###################################################

PWD=$(shell pwd)

ifdef CONFIG_ARCH_IPQ806X
obj-m += ipq806x/
endif


