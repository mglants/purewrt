include $(TOPDIR)/rules.mk

PKG_NAME:=mihomo-alpha
PKG_VERSION:=2026.07.20
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/MetaCubeX/mihomo.git
PKG_SOURCE_VERSION:=e40b5962e47aa683bb41b708efc52c7d228f5bf4
PKG_MIRROR_HASH:=c42bcfdf90ac6452563b7b715ab7a568aee9301138f031c8fbb5502847032133

PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=PureWRT Developers

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

PKG_BUILD_VERSION:=alpha-e40b5962
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

define Build/Prepare
	$(Build/Prepare/Default)
	$(RM) -r $(PKG_BUILD_DIR)/rules/logic_test
endef

$(eval $(call GoBinPackage,mihomo-alpha))
$(eval $(call BuildPackage,mihomo-alpha))
