#
# Copyright (C) 2006-2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=molmc-smartconfig
PKG_VERSION:=0.1
PKG_RELEASE:=1
PKG_LICENSE:=GPLv2

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/molmc-smartconfig
  SECTION:=net
  CATEGORY:=Intorobot
  DEPENDS:=+libpcap +libpthread +libopenssl +libnl +wireless-tools +ethtool
  TITLE:=Smartconfig tools for quick wifi-connection
  URL:=http://www.intorobot.com/
  MAINTAINER:=CH <support@molmc.com>
endef

define Package/molmc-smartconfig/description
  Smartconfig tools for quick wifi-connection
endef

MAKE_FLAGS += prefix=/usr \
	libnl=true \
	sqlite=false \
	unstable=false \
	OSNAME=Linux

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./files/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(MAKE_FLAGS)
endef

define Package/molmc-smartconfig/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/smartconfig-dump $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/smartconfig-response $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/smartconfig_get_ap_info $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/airmon-ng $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,molmc-smartconfig))
