include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-purewrt
PKG_VERSION:=$(strip $(shell cat $(CURDIR)/VERSION 2>/dev/null || cat $(CURDIR)/../../VERSION 2>/dev/null || echo 0.2.0))
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=PureWRT Developers
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

# LuCI assets (no compile — static views/rpcd/acl/menu). Source location:
#   - feed package (gh-action-sdk): this Makefile is at openwrt/luci-app-purewrt/,
#     the assets are the sibling openwrt/luci/ (= $(CURDIR)/../luci).
#   - local Taskfile build: package:sync copies openwrt/luci into the package dir.
ifeq ($(wildcard $(CURDIR)/luci),)
LUCI_SRC:=$(CURDIR)/../luci
else
LUCI_SRC:=$(CURDIR)/luci
endif

define Package/luci-app-purewrt
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for PureWRT
  DEPENDS:=+purewrt +luci-base +rpcd
  PKGARCH:=all
endef

define Package/luci-app-purewrt/description
 LuCI web interface for PureWRT.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(LUCI_SRC) $(PKG_BUILD_DIR)/luci
endef

define Build/Compile
endef

define Package/luci-app-purewrt/install
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/luci/root/usr/libexec/rpcd/purewrt $(1)/usr/libexec/rpcd/purewrt
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/luci/root/usr/share/rpcd/acl.d/luci-app-purewrt.json $(1)/usr/share/rpcd/acl.d/luci-app-purewrt.json
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/luci/root/usr/share/luci/menu.d/purewrt.json $(1)/usr/share/luci/menu.d/purewrt.json
	$(INSTALL_DIR) $(1)/www/luci-static/resources/purewrt
	$(CP) $(PKG_BUILD_DIR)/luci/htdocs/luci-static/resources/purewrt/* $(1)/www/luci-static/resources/purewrt/
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/purewrt
	$(CP) $(PKG_BUILD_DIR)/luci/htdocs/luci-static/resources/view/purewrt/* $(1)/www/luci-static/resources/view/purewrt/
endef

define Package/luci-app-purewrt/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/rpcd restart >/dev/null 2>&1 || true
	rm -rf /tmp/luci-indexcache /tmp/luci-modulecache >/dev/null 2>&1 || true
}
exit 0
endef

define Package/luci-app-purewrt/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/rpcd restart >/dev/null 2>&1 || true
	rm -rf /tmp/luci-indexcache /tmp/luci-modulecache >/dev/null 2>&1 || true
}
exit 0
endef

$(eval $(call BuildPackage,luci-app-purewrt))
