#!/bin/sh
# PureWRT package feed setup — adds the feed + trust key to an OpenWrt router.
#   wget -O - https://mglants.github.io/purewrt/feed.sh | sh
# Supports both opkg (OpenWrt 24.10) and apk (OpenWrt 25.12+).
set -e

REPO="https://mglants.github.io/purewrt"

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
echo "PureWRT feed: $feed"

if [ -x /bin/opkg ]; then
    echo "adding usign trust key"
    if wget -qO /tmp/purewrt-usign.pub "$REPO/purewrt-usign.pub"; then
        opkg-key add /tmp/purewrt-usign.pub || echo "  (opkg-key add failed — continuing)"
        rm -f /tmp/purewrt-usign.pub
    else
        echo "  (trust key not published yet — continuing without it)"
    fi

    echo "adding feed"
    sed -i '/purewrt/d' /etc/opkg/customfeeds.conf 2>/dev/null || true
    echo "src/gz purewrt $feed" >> /etc/opkg/customfeeds.conf
    opkg update
else
    echo "adding RSA trust key"
    wget -qO /etc/apk/keys/purewrt-apk.rsa.pub "$REPO/purewrt-apk.rsa.pub" \
        || { echo "  (trust key not published yet)"; rm -f /etc/apk/keys/purewrt-apk.rsa.pub; }

    echo "adding feed"
    mkdir -p /etc/apk/repositories.d
    list=/etc/apk/repositories.d/customfeeds.list
    sed -i '/purewrt/d' "$list" 2>/dev/null || true
    echo "$feed/packages.adb" >> "$list"
    apk update || echo "note: if apk update fails on signature, install.sh uses --allow-untrusted -X"
fi

echo "feed added. Install with: sh install.sh   (or opkg/apk install purewrt luci-app-purewrt)"
