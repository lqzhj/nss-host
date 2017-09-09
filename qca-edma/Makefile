include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-edma
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/qca-edma
     SUBMENU:=Network Devices
     TITLE:=QCA IPQ40xx ethernet driver
     FILES:=$(PKG_BUILD_DIR)/essedma.ko
     AUTOLOAD:=$(call AutoLoad,45,essedma)
endef

define KernelPackage/qca-edma/description
     Kernel modules for IPQ40xx integrated ethernet adapater.
endef

EXTRA_CFLAGS+= \
        -I$(PKG_BUILD_DIR)


define Build/Compile
        $(MAKE) -C "$(LINUX_DIR)" \
                CROSS_COMPILE="$(TARGET_CROSS)" \
                ARCH="$(LINUX_KARCH)" \
                SUBDIRS="$(PKG_BUILD_DIR)" \
                EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
                modules
endef

define KernelPackage/qca-edma/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/qca-edma $(1)/etc/init.d/qca-edma
endef

$(eval $(call KernelPackage,qca-edma))
