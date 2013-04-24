TOOL_MOD_NAME=qca-nss-crypto-tool

obj-m	+= $(TOOL_MOD_NAME).o
$(TOOL_MOD_NAME)-objs = nss_crypto_bench.o

obj ?= .
ccflags-y += -I$(obj)/../include -I$(obj)/../src -I$(obj)/
