include $(TOPDIR)/rules.mk

PKG_NAME:=purewrt
# Version: from the VERSION file when present (local Taskfile builds rsync the
# whole repo into the package dir; CI seds PKG_VERSION from the release tag),
# else a hardcoded baseline.
PKG_VERSION:=$(strip $(shell cat $(CURDIR)/VERSION 2>/dev/null || cat $(CURDIR)/../../VERSION 2>/dev/null || echo 0.2.0))
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1
# Go's runtime/cgo asm (gcc_mipsx.S) is incompatible with MIPS16, so the cgo
# build fails on mips/mipsel targets that default to -mips16. Build without it.
PKG_BUILD_FLAGS:=no-mips16

# Source location (purewrt builds from the checked-out repo — NO PKG_SOURCE, so
# no download/mirror-hash for our own fast-moving source):
#   - feed package (gh-action-sdk): this Makefile is at openwrt/purewrt/, the
#     repo root (with cmd/, internal/, go.mod) is two levels up (the feed is
#     src-linked at /feed → CURDIR=/feed/openwrt/purewrt).
#   - local Taskfile build: package:sync rsyncs the whole repo into the package
#     dir, so the sources sit right alongside this Makefile.
ifeq ($(wildcard $(CURDIR)/cmd),)
PUREWRT_SRC:=$(CURDIR)/../..
else
PUREWRT_SRC:=$(CURDIR)
endif

PKG_MAINTAINER:=PureWRT Developers
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

GO_PKG:=github.com/purewrt/purewrt
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/purewrt

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
  # kmod-nft-queue is NFQUEUE for zapret's nfqws — pulled in by the (optional)
  # zapret package, not needed for the core TPROXY path, so not a hard dep here.
  DEPENDS:=$(GO_ARCH_DEPENDS) +kmod-nft-tproxy +kmod-nft-socket +kmod-nft-nat +ca-bundle +rpcd +dnsmasq-full +mihomo-alpha
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

Build/Configure=$(call GoPackage/Build/Configure)
Build/Compile=$(call GoPackage/Build/Compile)
Build/InstallDev=$(call GoPackage/Build/InstallDev,$(1))

# Copy the checked-out sources into the build dir: the Go module at the root
# plus files/ and luci/ for the install recipes.
define Build/Prepare
	$(Build/Prepare/Default)
	$(CP) $(PUREWRT_SRC)/cmd $(PUREWRT_SRC)/internal $(PUREWRT_SRC)/go.mod $(PUREWRT_SRC)/go.sum $(PKG_BUILD_DIR)/
	$(CP) $(PUREWRT_SRC)/openwrt/files $(PKG_BUILD_DIR)/files
endef

define Package/purewrt/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/purewrt $(1)/usr/bin/purewrt
	$(LN) purewrt $(1)/usr/bin/purewrt-check
	$(LN) purewrt $(1)/usr/bin/purewrt-api
	$(CP) $(PKG_BUILD_DIR)/files/* $(1)/
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/usr/libexec/purewrt-peerdns $(1)/usr/libexec/purewrt-peerdns
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/purewrt $(1)/etc/init.d/purewrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/purewrt-zapret $(1)/etc/init.d/purewrt-zapret
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/purewrt-api $(1)/etc/init.d/purewrt-api
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/mihomo $(1)/etc/init.d/mihomo
endef

$(eval $(call BuildPackage,purewrt))
