include $(TOPDIR)/rules.mk

PKG_NAME:=zapret
PKG_VERSION:=1.0.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/bol-van/zapret2.git
PKG_SOURCE_VERSION:=v1.0.1
# Real tarball hash (the SDK's strict check rejects `skip`). Pinned to the
# v1.0.1 git tag, so this is stable; if the SDK ever recomputes a different
# value it prints "PKG_MIRROR_HASH ... set to <hash>" — copy it here.
PKG_MIRROR_HASH:=c6c0ab421232f4f56c6e20568e7d4e2b6a7df5a4932748a4a2a1a5b87f20a03a

PKG_LICENSE:=MIT
PKG_MAINTAINER:=PureWRT Developers
PKG_BUILD_PARALLEL:=1
PKG_BUILD_DEPENDS:=lua/host zlib libcap

LUA_VER?=5.4

LIBMNL_VERSION:=1.0.5
LIBMNL_HASH:=274b9b919ef3152bfb3da3a13c950dd60d6e2bcd54230ffeca298d03b40d0525
LIBNFNETLINK_VERSION:=1.0.2
LIBNFNETLINK_HASH:=b064c7c3d426efb4786e60a8e6859b82ee2f2c5e49ffeea640cfe4fe33cbc376
LIBNETFILTER_QUEUE_VERSION:=1.0.5
LIBNETFILTER_QUEUE_HASH:=f9ff3c11305d6e03d81405957bdc11aea18e0d315c3e3f48da53a24ba251b9f5

include $(INCLUDE_DIR)/package.mk

# Pin the netfilter userspace libraries: cache via $(DL_DIR), verify SHA-256
# at fetch time, and fall through to OpenWrt's mirror if netfilter.org is
# blocked. Previously the build wget'd these tarballs at compile time with
# no checksum — a clear supply-chain hole that this Download/<name> block
# closes. Hashes pinned to the same versions OpenWrt's base feed ships.
define Download/libmnl
  URL:=https://www.netfilter.org/pub/libmnl/ \
       https://sources.openwrt.org/
  URL_FILE:=libmnl-$(LIBMNL_VERSION).tar.bz2
  FILE:=libmnl-$(LIBMNL_VERSION).tar.bz2
  HASH:=$(LIBMNL_HASH)
endef
$(eval $(call Download,libmnl))

define Download/libnfnetlink
  URL:=https://www.netfilter.org/pub/libnfnetlink/ \
       https://sources.openwrt.org/
  URL_FILE:=libnfnetlink-$(LIBNFNETLINK_VERSION).tar.bz2
  FILE:=libnfnetlink-$(LIBNFNETLINK_VERSION).tar.bz2
  HASH:=$(LIBNFNETLINK_HASH)
endef
$(eval $(call Download,libnfnetlink))

define Download/libnetfilter_queue
  URL:=https://www.netfilter.org/projects/libnetfilter_queue/files/ \
       https://sources.openwrt.org/
  URL_FILE:=libnetfilter_queue-$(LIBNETFILTER_QUEUE_VERSION).tar.bz2
  FILE:=libnetfilter_queue-$(LIBNETFILTER_QUEUE_VERSION).tar.bz2
  HASH:=$(LIBNETFILTER_QUEUE_HASH)
endef
$(eval $(call Download,libnetfilter_queue))

define Package/zapret
  SECTION:=net
  CATEGORY:=Network
  TITLE:=zapret2 DPI bypass tools for PureWRT
  URL:=https://github.com/bol-van/zapret2
  DEPENDS:=+zlib +libcap +kmod-nft-queue +lua$(LUA_VER) +curl +bind-host
endef

define Package/zapret/description
 zapret2 nfqws packaged for PureWRT zapret action support.
 Netfilter userspace libraries are linked statically into nfqws2.
endef

define Build/Compile
	rm -rf $(PKG_BUILD_DIR)/deps $(PKG_BUILD_DIR)/static-deps
	mkdir -p $(PKG_BUILD_DIR)/static-deps

	# Use the hash-pinned tarballs cached by Download/<name> in $(DL_DIR)
	# instead of fetching at compile time. This survives netfilter.org
	# outages or blocks (OpenWrt's mirror is the fallback URL) and refuses
	# to build on hash mismatch.
	tar -xjf $(DL_DIR)/libmnl-$(LIBMNL_VERSION).tar.bz2 -C $(PKG_BUILD_DIR)/static-deps
	tar -xjf $(DL_DIR)/libnfnetlink-$(LIBNFNETLINK_VERSION).tar.bz2 -C $(PKG_BUILD_DIR)/static-deps
	tar -xjf $(DL_DIR)/libnetfilter_queue-$(LIBNETFILTER_QUEUE_VERSION).tar.bz2 -C $(PKG_BUILD_DIR)/static-deps

	cd $(PKG_BUILD_DIR)/static-deps/libmnl-$(LIBMNL_VERSION) && \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		./configure \
			--prefix= \
			--host=$(GNU_TARGET_NAME) \
			--enable-static \
			--disable-shared \
			--disable-dependency-tracking && \
		$(MAKE) $(PKG_JOBS) && \
		$(MAKE) install DESTDIR=$(PKG_BUILD_DIR)/deps

	sed -i 's|^prefix=.*|prefix=$(PKG_BUILD_DIR)/deps|g' \
		$(PKG_BUILD_DIR)/deps/lib/pkgconfig/libmnl.pc

	cd $(PKG_BUILD_DIR)/static-deps/libnfnetlink-$(LIBNFNETLINK_VERSION) && \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		./configure \
			--prefix= \
			--host=$(GNU_TARGET_NAME) \
			--enable-static \
			--disable-shared \
			--disable-dependency-tracking && \
		$(MAKE) $(PKG_JOBS) && \
		$(MAKE) install DESTDIR=$(PKG_BUILD_DIR)/deps

	sed -i 's|^prefix=.*|prefix=$(PKG_BUILD_DIR)/deps|g' \
		$(PKG_BUILD_DIR)/deps/lib/pkgconfig/libnfnetlink.pc

	cd $(PKG_BUILD_DIR)/static-deps/libnetfilter_queue-$(LIBNETFILTER_QUEUE_VERSION) && \
		$(TARGET_CONFIGURE_OPTS) \
		CPPFLAGS="-I$(PKG_BUILD_DIR)/deps/include" \
		CFLAGS="$(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/deps/include" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(PKG_BUILD_DIR)/deps/lib" \
		PKG_CONFIG="$(STAGING_DIR_HOST)/bin/pkg-config" \
		PKG_CONFIG_PATH="$(PKG_BUILD_DIR)/deps/lib/pkgconfig" \
		./configure \
			--prefix= \
			--host=$(GNU_TARGET_NAME) \
			--enable-static \
			--disable-shared \
			--disable-dependency-tracking && \
		$(MAKE) $(PKG_JOBS) V=1 && \
		$(MAKE) install DESTDIR=$(PKG_BUILD_DIR)/deps

	sed -i 's|^prefix=.*|prefix=$(PKG_BUILD_DIR)/deps|g' \
		$(PKG_BUILD_DIR)/deps/lib/pkgconfig/libnetfilter_queue.pc

	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/nfq2 \
		$(TARGET_CONFIGURE_OPTS) \
		PKG_CONFIG="$(STAGING_DIR_HOST)/bin/pkg-config" \
		PKG_CONFIG_PATH="$(PKG_BUILD_DIR)/deps/lib/pkgconfig" \
		LUA_JIT=0 \
		LUA_VER="$(LUA_VER)" \
		LUA_CFLAGS="-I$(STAGING_DIR)/usr/include/lua$(LUA_VER)" \
		LUA_LIB="-L$(STAGING_DIR)/usr/lib -llua$(LUA_VER)" \
		CFLAGS_PIC= \
		LDFLAGS_PIE="-static" \
		CFLAGS="$(TARGET_CFLAGS) -std=gnu99 -Os -I$(PKG_BUILD_DIR)/deps/include -I$(STAGING_DIR)/usr/include" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(PKG_BUILD_DIR)/deps/lib -L$(STAGING_DIR)/usr/lib" \
		LIBS_LINUX="-Wl,-Bstatic -lnetfilter_queue -lnfnetlink -lmnl -Wl,-Bdynamic -lz -lcap -lm"
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/mdig \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -std=gnu99 -Os" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/zapret/install
	$(INSTALL_DIR) $(1)/usr/libexec/zapret $(1)/usr/libexec/zapret/nfq2 $(1)/usr/libexec/zapret/mdig $(1)/usr/libexec/zapret/lua $(1)/usr/libexec/zapret/files/fake $(1)/usr/bin $(1)/usr/lib/zapret $(1)/usr/share/zapret
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nfq2/nfqws2 $(1)/usr/libexec/zapret/nfqws2
	$(LN) ../nfqws2 $(1)/usr/libexec/zapret/nfq2/nfqws2
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mdig/mdig $(1)/usr/libexec/zapret/mdig/mdig
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/blockcheck2.sh $(1)/usr/libexec/zapret/blockcheck2.sh
	$(CP) $(PKG_BUILD_DIR)/blockcheck2.d $(1)/usr/libexec/zapret/
	$(CP) $(PKG_BUILD_DIR)/common $(1)/usr/libexec/zapret/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/config.default $(1)/usr/libexec/zapret/config.default
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lua/zapret-lib.lua $(1)/usr/lib/zapret/zapret-lib.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lua/zapret-antidpi.lua $(1)/usr/lib/zapret/zapret-antidpi.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lua/zapret-auto.lua $(1)/usr/lib/zapret/zapret-auto.lua
	$(LN) ../../../lib/zapret/zapret-lib.lua $(1)/usr/libexec/zapret/lua/zapret-lib.lua
	$(LN) ../../../lib/zapret/zapret-antidpi.lua $(1)/usr/libexec/zapret/lua/zapret-antidpi.lua
	$(LN) ../../../lib/zapret/zapret-auto.lua $(1)/usr/libexec/zapret/lua/zapret-auto.lua
	# Install the fake-payload library that named blobs (fake_default_tls,
	# fake_default_http, fake_default_quic, …) read at runtime. Without this
	# the upstream-style strategies parse but fail when nfqws2 tries to
	# load the blob file. zapret2 ships these under files/fake/.
	$(CP) $(PKG_BUILD_DIR)/files/fake/. $(1)/usr/libexec/zapret/files/fake/
	$(LN) ../libexec/zapret/nfqws2 $(1)/usr/bin/nfqws
endef

$(eval $(call BuildPackage,zapret))
