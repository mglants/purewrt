#!/bin/sh
# Recompute PKG_MIRROR_HASH for a bundled OpenWrt package by downloading its
# source in an OpenWrt SDK and running `check FIXUP=1`, which rewrites the hash
# in the Makefile. The feed is bind-mounted, and `feeds install` symlinks the
# package dir back to it, so FIXUP edits our real Makefile in place.
#
# Best-effort: exits non-zero if the hash is still `skip` afterwards, so the
# calling step (continue-on-error) leaves the `skip` fallback in the PR.
set -eu

pkg="${1:?usage: pin-mirror-hash.sh <package>}"
img="${SDK_IMAGE:-ghcr.io/openwrt/sdk:x86-64-24.10.4}"
mk="openwrt/${pkg}/Makefile"

echo "Computing PKG_MIRROR_HASH for ${pkg} via ${img}"
docker run --rm -v "${PWD}:/feed" "${img}" sh -ceu '
  pkg="$1"
  cd "${HOME:-/home/build}/openwrt" 2>/dev/null || cd /home/build/openwrt
  grep -q "^src-link purewrt " feeds.conf.default \
    || echo "src-link purewrt /feed/openwrt" >> feeds.conf.default
  ./scripts/feeds update purewrt
  ./scripts/feeds install -p purewrt "$pkg"
  make defconfig
  make "package/feeds/purewrt/${pkg}/check" FIXUP=1 V=s
' _ "${pkg}"

echo "--- ${mk} after FIXUP ---"
grep -E "^PKG_(MIRROR_)?HASH" "${mk}" || true

# Treat a remaining `skip` as failure so the PR keeps the safe fallback.
if grep -q "^PKG_MIRROR_HASH:=skip" "${mk}"; then
  echo "FIXUP did not pin a hash; leaving skip" >&2
  exit 1
fi
echo "PKG_MIRROR_HASH pinned."
