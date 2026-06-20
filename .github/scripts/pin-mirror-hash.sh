#!/bin/sh
# Recompute PKG_MIRROR_HASH for a bundled OpenWrt package by downloading its
# source in an OpenWrt SDK and hashing the repacked tarball.
#
# PKG_MIRROR_HASH is exactly `sha256sum` of the tarball OpenWrt produces in
# `dl/` (verified). So we don't need `check FIXUP=1` to rewrite the Makefile
# from inside the container — which is fragile anyway: the container user
# (buildbot) often can't write the bind-mounted checkout (uid mismatch under
# rootless/userns docker). Instead we compute the hash in the container (it
# only writes its own `dl/`) and `sed` it into the Makefile out here on the
# host, where the workflow owns the checkout.
#
# Best-effort: exits non-zero if it can't compute a hash, so the calling step
# (continue-on-error) leaves the `skip` fallback in the PR — the git
# SHA/tag in PKG_SOURCE_VERSION is the real integrity anchor and the build CI
# re-fetches the exact source regardless.
set -eu

pkg="${1:?usage: pin-mirror-hash.sh <package>}"
img="${SDK_IMAGE:-ghcr.io/openwrt/sdk:x86-64-24.10.4}"
mk="openwrt/${pkg}/Makefile"

echo "Computing PKG_MIRROR_HASH for ${pkg} via ${img}"
hash=$(docker run --rm -v "${PWD}:/feed" "${img}" sh -ceu '
  pkg="$1"
  # SDK root moved between image generations (/home/build/openwrt → /builder);
  # locate it by the file that only the SDK tree has rather than hardcoding.
  root=""
  for d in /builder "${HOME:-}/openwrt" /home/build/openwrt "$PWD"; do
    [ -n "$d" ] && [ -f "$d/feeds.conf.default" ] && { root="$d"; break; }
  done
  [ -z "$root" ] && root=$(dirname "$(find / -maxdepth 4 -name feeds.conf.default -print -quit 2>/dev/null)")
  [ -n "$root" ] && [ -d "$root" ] || { echo "could not locate SDK root" >&2; exit 2; }
  cd "$root"
  grep -q "^src-link purewrt " feeds.conf.default \
    || echo "src-link purewrt /feed/openwrt" >> feeds.conf.default
  ./scripts/feeds update purewrt   >/dev/null 2>&1
  ./scripts/feeds install -p purewrt "$pkg" >/dev/null 2>&1
  make defconfig >/dev/null 2>&1
  # -k so a flaky bundled-dep mirror (e.g. netfilter.org) does not stop the
  # package`s own source from downloading; only that tarball matters here.
  make -k "package/feeds/purewrt/${pkg}/download" V=s >/dev/null 2>&1 || true
  # The package`s own tarball is the only dl/ file prefixed with its name
  # (bundled deps have their own distinct names).
  f=$(ls -t dl/"${pkg}"-*.tar* 2>/dev/null | head -1)
  [ -n "$f" ] && [ -f "$f" ] || { echo "no source tarball downloaded for $pkg" >&2; exit 3; }
  sha256sum "$f" | cut -d" " -f1
' _ "${pkg}")

# Validate: must be a 64-char hex sha256.
case "${hash}" in
  *[!0-9a-f]* | "") echo "did not get a valid hash (got: '${hash}'); leaving Makefile unchanged" >&2; exit 1 ;;
esac
[ "${#hash}" -eq 64 ] || { echo "hash wrong length: '${hash}'" >&2; exit 1; }

sed -i -E "s|^PKG_MIRROR_HASH:=.*|PKG_MIRROR_HASH:=${hash}|" "${mk}"
echo "--- ${mk} after pin ---"
grep -E "^PKG_(MIRROR_)?HASH" "${mk}" || true
echo "PKG_MIRROR_HASH pinned: ${hash}"
