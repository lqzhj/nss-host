###################################################
# Makefile for the NSS GMAC driver
###################################################

PWD=$(shell pwd)

ifdef CONFIG_ARCH_IPQ806X
obj-m += ipq806x/
endif


