ccflags-y := -I$(obj)/../exports -I$(obj)/..  -I$(obj)/nss_hal/include
ccflags-y += -DNSS_CLIENT_BUILD_ID="$(BUILD_ID)"

obj-m += qca-nss-bridge-mgr.o
qca-nss-bridge-mgr-objs := nss_bridge_mgr.o

ccflags-y += -DNSS_BRIDGE_MGR_DEBUG_LEVEL=0
