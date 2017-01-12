#
# @brief NSS CFI Makefile
#

export BUILD_ID = \"Build Id: $(shell date +'%m/%d/%y, %H:%M:%S')\"

obj-m += ocf/
obj-m += ipsec/
obj-m += $(CFI_CRYPTOAPI_DIR)/
