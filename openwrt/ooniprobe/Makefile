include $(TOPDIR)/rules.mk

PKG_NAME:=ooniprobe
PKG_VERSION:=3.30.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/ooni/probe-cli.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
# Recompute on version bump with: .github/scripts/pin-mirror-hash.sh ooniprobe
PKG_MIRROR_HASH:=4932b528d196dbd0efc37d3b3602768188b7c9b17712931e88b483df658aee9a

PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE.md
PKG_MAINTAINER:=PureWRT Developers

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1

GO_PKG:=github.com/ooni/probe-cli/v3
GO_PKG_TAGS:=nouserauth
# Build only the ooniprobe CLI main; the module also contains miniooni and
# other commands we don't ship.
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/ooniprobe
GO_PKG_INSTALL_BIN_PATH:=/usr/bin

# probe-cli 3.30 requires Go 1.26 and builds on the 25.12 SDK. Version 3.31
# requires Go 1.27, which that SDK does not provide; keep the version pinned
# until the SDK toolchain is upgraded and the package build is verified.

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/ooniprobe
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OONI Probe censorship-measurement CLI
  URL:=https://ooni.org
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/ooniprobe/description
  OONI Probe (ooniprobe) measures internet censorship. Packaged for PureWRT as
  an optional companion: its backend/API traffic rides mihomo's mixed-port (via
  the --proxy flag) while measurements go direct. Runs via cron as a dedicated
  non-root user. Requires OpenWrt 25.12+ (Go 1.26).
endef

define Package/ooniprobe/install
	$(call GoPackage/Package/Install/Bin,$(1))
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-ooniprobe $(1)/etc/uci-defaults/99-ooniprobe
endef

$(eval $(call GoBinPackage,ooniprobe))
$(eval $(call BuildPackage,ooniprobe))
