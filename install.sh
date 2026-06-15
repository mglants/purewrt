#!/bin/sh
# PureWRT one-shot installer for OpenWrt.
#   wget -O - https://mglants.github.io/purewrt/install.sh | sh
# Adds the signed package feed, then installs purewrt + luci-app-purewrt
# (mihomo-alpha is pulled in as a dependency). Works on opkg (24.10) and apk
# (25.12+). Set WITH_ZAPRET=1 to also install the optional zapret DPI-bypass.
set -e

REPO="https://mglants.github.io/purewrt"
WITH_ZAPRET="${WITH_ZAPRET:-0}"

if [ ! -x /bin/opkg ] && [ ! -x /usr/bin/apk ]; then
    echo "error: neither opkg nor apk found — is this OpenWrt?" >&2
    exit 1
fi
[ -x /sbin/fw4 ] || echo "warning: firewall4 (fw4) not found — PureWRT expects nftables/fw4" >&2

[ -r /etc/openwrt_release ] || { echo "error: /etc/openwrt_release missing" >&2; exit 1; }
. /etc/openwrt_release

arch="$DISTRIB_ARCH"
case "$DISTRIB_RELEASE" in
    *24.10*) branch="24.10" ;;
    *25.12*) branch="25.12" ;;
    SNAPSHOT|*snapshot*) echo "error: SNAPSHOT is not published; build from source" >&2; exit 1 ;;
    *) echo "error: unsupported OpenWrt release: $DISTRIB_RELEASE" >&2; exit 1 ;;
esac

feed="$REPO/$branch/$arch"
echo "PureWRT $branch / $arch"
echo "feed: $feed"

zapret_pkg=""
[ "$WITH_ZAPRET" = "1" ] && zapret_pkg="zapret"

if [ -x /bin/opkg ]; then
    echo "==> adding usign trust key"
    if wget -qO /tmp/purewrt-usign.pub "$REPO/purewrt-usign.pub"; then
        opkg-key add /tmp/purewrt-usign.pub || echo "   (opkg-key add failed — continuing)"
        rm -f /tmp/purewrt-usign.pub
    else
        echo "   (trust key not published yet — continuing without it)"
    fi

    echo "==> adding feed"
    sed -i '/purewrt/d' /etc/opkg/customfeeds.conf 2>/dev/null || true
    echo "src/gz purewrt $feed" >> /etc/opkg/customfeeds.conf
    opkg update

    # PureWRT needs the full dnsmasq (nftset support); it conflicts with the
    # stock dnsmasq, so swap it first.
    if opkg list-installed | grep -q '^dnsmasq '; then
        echo "==> replacing dnsmasq with dnsmasq-full"
        opkg install dnsmasq-full --download-only
        opkg remove dnsmasq
    fi
    opkg install dnsmasq-full
    echo "==> installing PureWRT"
    opkg install purewrt luci-app-purewrt $zapret_pkg
else
    echo "==> adding RSA trust key"
    wget -qO /etc/apk/keys/purewrt-apk.rsa.pub "$REPO/purewrt-apk.rsa.pub" \
        || { echo "   (trust key not published yet — will use --allow-untrusted)"; rm -f /etc/apk/keys/purewrt-apk.rsa.pub; }

    echo "==> adding feed"
    mkdir -p /etc/apk/repositories.d
    list=/etc/apk/repositories.d/customfeeds.list
    sed -i '/purewrt/d' "$list" 2>/dev/null || true
    echo "$feed/packages.adb" >> "$list"

    echo "==> replacing dnsmasq with dnsmasq-full"
    apk add dnsmasq-full 2>/dev/null || true

    echo "==> installing PureWRT"
    # Prefer the trusted feed; fall back to pinning the index untrusted if the
    # index signature can't be verified (apk v3 key-name nuances).
    if apk update >/dev/null 2>&1 && apk add purewrt luci-app-purewrt $zapret_pkg 2>/dev/null; then
        :
    else
        echo "   (verified feed unavailable — using --allow-untrusted -X)"
        apk add --allow-untrusted -X "$feed/packages.adb" purewrt luci-app-purewrt $zapret_pkg
    fi
fi

echo
echo "PureWRT installed. Next steps:"
echo "  - LuCI → Services → PureWRT → Run Setup Wizard"
echo "  - or: purewrt status"
