include $(TOPDIR)/rules.mk

PKG_NAME:=ooniprobe
PKG_VERSION:=3.29.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/ooni/probe-cli.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
# Recompute on version bump with: .github/scripts/pin-mirror-hash.sh ooniprobe
PKG_MIRROR_HASH:=17954ff52fd6bdbb3dd6ac6c574f8953da9fda2c0e7da4e2d32a759aad06f9d2

PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE.md
PKG_MAINTAINER:=PureWRT Developers

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1

GO_PKG:=github.com/ooni/probe-cli/v3
# Build only the ooniprobe CLI main; the module also contains miniooni and
# other commands we don't ship.
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/ooniprobe
GO_PKG_INSTALL_BIN_PATH:=/usr/bin

# probe-cli requires Go 1.24 — it cannot build on the OpenWrt 24.10 SDK
# (Go 1.23). The CI matrix only adds this package to the 25.12 leg; this
# constraint is documented in docs and the build wiring.

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
  non-root user. Requires OpenWrt 25.12+ (Go 1.24).
endef

define Package/ooniprobe/install
	$(call GoPackage/Package/Install/Bin,$(1))
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-ooniprobe $(1)/etc/uci-defaults/99-ooniprobe
endef

$(eval $(call GoBinPackage,ooniprobe))
$(eval $(call BuildPackage,ooniprobe))
