include $(TOPDIR)/rules.mk

PKG_NAME:=purewrt
# Version: from the VERSION file when present (local Taskfile builds rsync the
# whole repo into the package dir; CI seds PKG_VERSION from the release tag),
# else a hardcoded baseline.
PKG_VERSION:=$(strip $(shell cat $(CURDIR)/VERSION 2>/dev/null || cat $(CURDIR)/../../VERSION 2>/dev/null || echo 0.2.0))
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1

# Dual-mode source resolution:
#   - As a feed package (openwrt/gh-action-sdk): the package dir holds only this
#     Makefile, so fetch the Go sources from git. CI seds PKG_SOURCE_VERSION to
#     the tag/commit being built.
#   - Local Taskfile build: package:sync rsyncs the whole repo into the package
#     dir, so `cmd/` is present and we build straight from the working tree —
#     no fetch, so uncommitted changes build.
ifeq ($(wildcard $(CURDIR)/cmd),)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/mglants/purewrt.git
PKG_SOURCE_VERSION:=main
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_MIRROR_HASH:=skip
endif

PKG_MAINTAINER:=PureWRT Developers
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

GO_PKG:=github.com/purewrt/purewrt
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/purewrt $(GO_PKG)/cmd/purewrt-check $(GO_PKG)/cmd/purewrt-api

define Package/purewrt
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OpenWrt-native routing manager for mihomo
  # Zapret is intentionally NOT a hard dependency. PureWRT routes through
  # mihomo via nftables — the apply pipeline works without Zapret; only
  # the per-section DPI-bypass strategies + autotune/check tooling need
  # it. Users who want those install `zapret` separately; the LuCI side
  # detects nfqws/tpws presence at runtime and surfaces a "not installed"
  # notice on the Zapret tab when absent.
  DEPENDS:=$(GO_ARCH_DEPENDS) +kmod-nft-tproxy +kmod-nft-socket +kmod-nft-queue +kmod-nft-nat +ca-bundle +rpcd +dnsmasq-full +mihomo-alpha
endef

define Package/purewrt/description
 PureWRT: OpenWrt decides the route. Mihomo handles the proxy.
endef

# Without this, apk/opkg treat /etc/config/purewrt as a regular package
# file and replace it on every upgrade, wiping the user's sections,
# subscriptions and settings.
define Package/purewrt/conffiles
/etc/config/purewrt
endef

define Package/luci-app-purewrt
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for PureWRT
  DEPENDS:=+purewrt +luci-base +rpcd
endef

define Package/luci-app-purewrt/description
 LuCI web interface for PureWRT.
endef

Build/Configure=$(call GoPackage/Build/Configure)
Build/Compile=$(call GoPackage/Build/Compile)
Build/InstallDev=$(call GoPackage/Build/InstallDev,$(1))

# Normalise both source modes to a common layout under $(PKG_BUILD_DIR):
# the Go module at the root, plus files/ and luci/ for the install recipes.
ifeq ($(wildcard $(CURDIR)/cmd),)
# Feed/git mode: sources already unpacked to $(PKG_BUILD_DIR) with the repo's
# openwrt/ subdir — hoist files/ and luci/ to the root.
define Build/Prepare
	$(Build/Prepare/Default)
	$(CP) $(PKG_BUILD_DIR)/openwrt/files $(PKG_BUILD_DIR)/files
	$(CP) $(PKG_BUILD_DIR)/openwrt/luci $(PKG_BUILD_DIR)/luci
endef
else
# Local Taskfile mode: copy the working tree into the build dir.
define Build/Prepare
	$(Build/Prepare/Default)
	$(CP) $(CURDIR)/cmd $(CURDIR)/internal $(CURDIR)/go.mod $(CURDIR)/go.sum $(PKG_BUILD_DIR)/
	$(CP) $(CURDIR)/openwrt/files $(PKG_BUILD_DIR)/files
	$(CP) $(CURDIR)/openwrt/luci $(PKG_BUILD_DIR)/luci
endef
endif

define Package/purewrt/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/purewrt $(1)/usr/bin/purewrt
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/purewrt-check $(1)/usr/bin/purewrt-check
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/purewrt-api $(1)/usr/bin/purewrt-api
	$(CP) $(PKG_BUILD_DIR)/files/* $(1)/
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/usr/libexec/purewrt-peerdns $(1)/usr/libexec/purewrt-peerdns
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/purewrt $(1)/etc/init.d/purewrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/purewrt-zapret $(1)/etc/init.d/purewrt-zapret
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/purewrt-api $(1)/etc/init.d/purewrt-api
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/mihomo $(1)/etc/init.d/mihomo
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

$(eval $(call BuildPackage,purewrt))
$(eval $(call BuildPackage,luci-app-purewrt))
