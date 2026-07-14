include $(TOPDIR)/rules.mk

# easytier — prebuilt upstream musl binaries (Q2 decision: the upstream
# luci-app-easytier feed packages the same zips, but unpinned; we pin the
# release + SHA256 per arch so the signed purewrt feed stays reproducible).
# Rust source builds in the SDK need the full rust host toolchain (~1h per
# arch) for zero benefit — upstream ships static musl binaries for every
# target we build.

PKG_NAME:=easytier
PKG_VERSION:=2.6.4
PKG_RELEASE:=1

# OpenWrt $(ARCH) → upstream release asset arch. Mirrors upstream
# easytier-noweb: all 32-bit arm subtargets use the lowest-common 'arm'
# build; per-CPU tuning isn't worth per-subtarget hash bookkeeping.
#
# One ET_HASH_<arch> line per asset, selected via ET_HASH_$(ET_ARCH):
# the update-deps easytier job rewrites these lines with sed when bumping
# PKG_VERSION — keep the `ET_HASH_<arch>:=<sha256>` shape machine-editable.
ET_HASH_x86_64:=61b659eaedba658fa66fe47d17e1426cdd77e5d02fa15fed447bb4357c09dfd6
ET_HASH_aarch64:=f533ec25a7ea714e09f645615012200278058525795cc3bb690ff011aec1a70f
ET_HASH_arm:=6d2bd44507d7183a4fa9857ced8f89cb4eddc99cdfc8f8ddef5cc78f52caf2fd
ET_HASH_mips:=3b4d084aa922a4b23f5d0167b9bb4966c1593f5184061f7ff075132a2207a260
ET_HASH_mipsel:=7c93bcc9e9276f102b5299b0773941db7fd1d99ad04bac42b479a0d979ef5220

ET_ARCH:=$(ARCH)
ET_HASH:=$(ET_HASH_$(ET_ARCH))

PKG_SOURCE:=easytier-linux-$(ET_ARCH)-v$(PKG_VERSION).zip
PKG_SOURCE_URL:=https://github.com/EasyTier/EasyTier/releases/download/v$(PKG_VERSION)/
PKG_HASH:=$(ET_HASH)

PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=PureWRT Developers

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

# Prebuilt static musl binaries: SDK strip tooling doesn't always agree with
# foreign rustc output, and upstream already release-strips.
RSTRIP:=:
STRIP:=:

define Package/easytier
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Decentralized mesh VPN (PureWRT friend-mesh transport)
  URL:=https://github.com/EasyTier/EasyTier
  DEPENDS:=@(x86_64||aarch64||arm||mips||mipsel) +kmod-tun
endef

define Package/easytier/description
  EasyTier is a decentralized P2P mesh VPN. PureWRT uses it as the overlay
  transport for the friend-mesh feature; the purewrt-easytier init script
  runs it from the purewrt-generated TOML. Optional companion package —
  purewrt detects it at runtime and degrades gracefully when absent.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	unzip -o -j $(DL_DIR)/$(PKG_SOURCE) -d $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/easytier/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/easytier-core $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/easytier-cli $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/purewrt-easytier.init $(1)/etc/init.d/purewrt-easytier
endef

$(eval $(call BuildPackage,easytier))
