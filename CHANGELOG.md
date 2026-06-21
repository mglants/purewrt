# Changelog

All notable changes to PureWRT are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are the `purewrt`
package version.

## [0.1.0] - 2026-06-22

### Added
- **OONI Probe integration** (optional package, OpenWrt 25.12+). Runs OONI
  censorship measurements on a schedule (cron, every 6 hours by default) as a
  dedicated non-root user.
  - Routing split: the OONI **backend/API** (check-in + upload) is routed
    through mihomo's mixed-port via `--proxy`, while **measurements go direct**
    (enforced by an nftables `skuid` exemption) so results reflect the real
    local network.
  - LuCI **OONI Probe** page: enable / upload / schedule / proxy settings, an
    on-demand **Run now** action (also reflects scheduled/external runs), and a
    live **logs** panel.
  - Upload to OONI's public archive is consent-gated.
- **VPN routing reworked onto mihomo.** VPNs are now mihomo `direct` outbounds
  pooled per-section and for DNS (with url-test failover and health-checks),
  replacing the previous kernel routing.
- Multiple LAN firewall source zones.
- `tcpdump` as an optional dependency (Client Traffic live capture); LuCI
  detects its presence and degrades gracefully.
- Client nftset ordered ahead of the other sets so client-identity rules take
  precedence.
- Clear log message when geoip data isn't ready yet.
- CI builds the full architecture matrix on **both** OpenWrt 24.10 and 25.12.

- **VPN manager in LuCI** (add / edit / **remove** VPN definitions), reachable
  from the "Manage VPNs" button on both the **Sections** and **DNS** pages. The
  DNS "upstream via VPN" picker now populates correctly and lets you select an
  existing VPN.

### Fixed
- **"What's Blocked Now" / site-check probe:**
  - Dials the dnsmasq-resolved IP instead of re-resolving the hostname,
    eliminating false `tcp_timeout` results under concurrent probes.
  - Removed DNS-poisoning detection — CDN/GeoDNS legitimately return different
    addresses per resolver/country, so the DoH-vs-system comparison produced
    false positives. Resolution now uses the client path (dnsmasq → mihomo)
    only.
  - Retries the system DNS lookup so a resolver burst no longer yields bogus
    `dns` (no-resolution) verdicts.
- Fixed a long dnsmasq apply loop.
- Dashboard rendering, DNS-options rendering, firewall-rule generation, and
  assorted LuCI JavaScript warnings.

- **site-check nftset membership now honors CIDR intervals.** A resolved IP
  covered by an IP-CIDR rule is correctly reported as in-set (membership is the
  `nft get element` exit status, which is interval-aware — it was previously a
  substring match that only caught exact elements).

### Dependencies
- Bumped mihomo-alpha and zapret (v1.0.2).
- Pinned `klauspost/compress` to 1.17.11 — its 1.18 raises the Go floor to 1.24,
  which the OpenWrt 24.10 SDK (Go 1.23) cannot build.
- Dependabot for Go modules + GitHub Actions, plus an auto-bump workflow for the
  git-pinned bundled packages (mihomo-alpha / zapret / ooniprobe).

### CI / release
- **Rolling package feed**: bundled-dependency bumps publish to the feed on
  merge to `main`; purewrt tarball releases are cut on `v*` tags. Feed rebuilds
  are gated to actual bundled-dep changes, and on a dep-bump publish purewrt is
  **pinned to its last release tag** — so unreleased purewrt work never ships
  alongside a dependency bump.
- ooniprobe is skipped on 32-bit MIPS (`mips_24kc`/`mipsel_24kc`): it needs CGO,
  whose `runtime/cgo` assembly doesn't build on that toolchain. The rest of the
  feed still builds and publishes for those arches.

## [0.0.1] - 2026-06-16

- Initial release.

[0.1.0]: https://github.com/mglants/purewrt/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/mglants/purewrt/releases/tag/v0.0.1
