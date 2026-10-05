include $(TOPDIR)/rules.mk

PKG_NAME:=mihomo-alpha
PKG_VERSION:=2026.10.05
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/MetaCubeX/mihomo.git
PKG_SOURCE_VERSION:=9f053c49075de076d83d3e5918241e410f7e9adf
PKG_MIRROR_HASH:=70539474ffe1dd58f33f22354ed16b9d52e0f4b0c73404913be0273d486083f4

PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=PureWRT Developers

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

PKG_BUILD_VERSION:=alpha-9f053c49
PKG_BUILD_TIME:=$(shell date -u -Iseconds)

GO_PKG:=github.com/metacubex/mihomo
GO_PKG_LDFLAGS_X:=$(GO_PKG)/constant.Version=$(PKG_BUILD_VERSION) $(GO_PKG)/constant.BuildTime=$(PKG_BUILD_TIME)
# No with_gvisor: PureWRT routes via TPROXY/nftables, never mihomo TUN (the only
# thing gvisor provides). Dropping it cuts the heaviest part of the build and
# shrinks the binary (helps low-RAM routers). The system gvisor stack is still
# available if a user manually enables TUN with a mixin.
GO_PKG_INSTALL_BIN_PATH:=/usr/libexec

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/mihomo-alpha
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Mihomo alpha proxy core
  URL:=https://wiki.metacubex.one
  # No kmod-tun (TUN mode unused — gvisor dropped) or kmod-inet-diag
  # (process-matching unused — PureWRT runs find-process-mode off). Avoids
  # pulling kernel-version-locked kmods that PureWRT never needs.
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
  PROVIDES:=mihomo
  CONFLICTS:=mihomo-meta
  VARIANT:=alpha
  ALTERNATIVES:=\
    300:/usr/bin/mihomo:/usr/libexec/mihomo
endef

define Package/mihomo-alpha/description
  Mihomo alpha is a rule based proxy core in Go, packaged for PureWRT.
endef

define Package/mihomo-alpha/install
	$(call GoPackage/Package/Install/Bin,$(1))
	$(INSTALL_DIR) $(1)/usr/bin
	ln -sf /usr/libexec/mihomo $(1)/usr/bin/mihomo
endef

# Restart a RUNNING mihomo after the binary is replaced. Without this the
# old process keeps serving from a deleted inode: procd sees an unchanged
# instance definition, so the generic `start` on upgrade is a no-op and
# the new version silently never loads. `running` (procd state) rather
# than `enabled` — a stopped or disabled service must stay stopped.
define Package/mihomo-alpha/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
if [ -x /etc/init.d/mihomo ] && /etc/init.d/mihomo running 2>/dev/null; then
	/etc/init.d/mihomo restart
fi
exit 0
endef

define Build/Prepare
	$(Build/Prepare/Default)
	$(RM) -r $(PKG_BUILD_DIR)/rules/logic_test
endef

$(eval $(call GoBinPackage,mihomo-alpha))
$(eval $(call BuildPackage,mihomo-alpha))
