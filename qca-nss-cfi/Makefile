include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-nss-cfi
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DEPENDS:=ocf-crypto-headers

ifeq ($(CONFIG_TARGET_ipq),y)
subtarget:=$(SUBTARGET)
else
subtarget:=ipq806x
endif

ifeq ($(findstring 4.4, $(LINUX_VERSION)),)
#3.14 Kernel + ipq806x
  CFI_CRYPTOAPI_DIR:=cryptoapi/v1.0
  CFI_OCF_DIR:=ocf/v1.0
else
#4.4 Kernel
ifneq (, $(findstring ipq807x, $(subtarget)))
#4.4 Kernel + ipq807x
  CFI_OCF_DIR:=ocf/v2.0
  CFI_CRYPTOAPI_DIR:=cryptoapi/v2.0
else
#4.4 Kernel + ipq806x
  CFI_CRYPTOAPI_DIR:=cryptoapi/v1.1
  CFI_OCF_DIR:=ocf/v1.0
endif
endif

define KernelPackage/qca-nss-cfi
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=@TARGET_ipq806x||TARGET_ipq807x||TARGET_ipq_ipq807x||TARGET_ipq_ipq807x_64 +kmod-qca-nss-crypto +kmod-crypto-ocf +kmod-crypto-authenc
  TITLE:=Kernel driver for NSS cfi
  FILES:=$(PKG_BUILD_DIR)/$(CFI_OCF_DIR)/qca-nss-cfi-ocf.ko \
	 $(PKG_BUILD_DIR)/ipsec/qca-nss-ipsec.ko \
	 $(PKG_BUILD_DIR)/$(CFI_CRYPTOAPI_DIR)/qca-nss-cfi-cryptoapi.ko
  AUTOLOAD:=$(call AutoLoad,59,qca-nss-cfi-ocf qca-nss-cfi-cryptoapi qca-nss-ipsec)
endef

define KernelPackage/qca-nss-cfi/Description
This package contains a NSS cfi driver for QCA chipset
endef

EXTRA_CFLAGS+= \
	-DCONFIG_NSS_DEBUG_LEVEL=4 \
	-I$(STAGING_DIR)/usr/include/qca-nss-crypto \
	-I$(STAGING_DIR)/usr/include/crypto \
	-I$(STAGING_DIR)/usr/include/qca-nss-drv \

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CC="$(TARGET_CC)" \
		CFI_CRYPTOAPI_DIR=$(CFI_CRYPTOAPI_DIR) \
		CFI_OCF_DIR=$(CFI_OCF_DIR) \
		SoC=$(subtarget) \
		modules
endef

$(eval $(call KernelPackage,qca-nss-cfi))
