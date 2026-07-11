# Changelog

All notable changes to PureWRT are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are the `purewrt`
package version.

## [0.3.1] - 2026-07-11

### Added
- **Global `suppress_hwid` privacy switch** — one setting to stop sending the
  HWID identity headers on provider/subscription fetches.
- **Version-stamped User-Agent** on provider downloads: default UA is now
  `mihomo/<mihomo version> (purewrt/<version>)`, with split
  `x-device-os` / `x-ver-os` headers.

### Changed
- **HWID identity sent only for subscriptions and proxy providers** (not
  plain rule-list fetches) — narrows what leaks to third-party list hosts.
- **Port-scoped zapret claims** — a zapret section only claims the ports its
  enabled strategies actually cover, so it doesn't shadow other traffic.
- **CLI GC target pinned**; `purewrt-check` / `purewrt-api` install as
  multi-call symlinks of the single binary (CI builds one multi-call binary).

### Fixed
- **Site check reports the real IP/CIDR route.** `purewrt-check` only tested
  the matched-domain-section's nftset, so a domain with no matching rule whose
  resolved IP sits in another section's IP/CIDR set was reported as *direct*
  while traffic is actually proxied by destination-IP match. It now scans the
  resolved IP across all routing sets in prerouting precedence and reports the
  ground-truth route, flagging domain-vs-IP divergence.
- **Stale artifacts pruned / leaked stage dirs swept** on update; the
  `.last_applied` marker is refreshed on every successful apply.

## [0.3.0] - 2026-07-09

### Added
- **Zapret strategy tester & candidate sweep.** Load a candidate desync
  strategy through real nfqws2 behind a throwaway nft queue and rank it by how
  many target sites it unblocks (baseline vs with-strategy), streamed live in
  LuCI. Candidates come from a shared list (embedded baseline + `/etc` override
  + `purewrt-lists` fetch), each with SHA256-verified fake-blob resolution.
  - **Service tags** (youtube / discord / games / generic) alongside ISP, with
    a service-scoped sweep; generic candidates are wildcards tried in every
    scope. Combined TCP+UDP strategies (one nfqws instance via `--new`).
  - **"Update strategies"** button fetches the latest candidate list from
    purewrt-lists and rebuilds the tester dropdowns in place.
- **Live Zapret status block.** Running/stopped pill, per-instance
  queue→nfqws PID, per-section queued-packet counters (from nftables), uptime,
  and recent-error surfacing — `zapret-status` CLI + `zapret_status` rpcd.
- **Parallel health-check panel** on Diagnostics: one "Run all" fans out
  service / mihomo / DNS-resolvers / bypass-warnings / IPv6 checks concurrently,
  each a spinner→green/yellow/red verdict chip with an aggregate banner.
- **Enable/disable toggle column** on the Sections / Routing table (mirrors
  rule providers).
- **Grouped CLI help.** `purewrt help` lists commands by area with
  descriptions; `purewrt help <cmd>` gives a per-command synopsis (dispatch is
  now a table-driven registry).
- **Client-side form validation** (cron / URL / CIDR) across settings,
  subscriptions, providers, and the IP/CIDR modal — errors caught at input
  instead of at apply time.
- **Loading spinners** on slow/no-feedback async actions (connectivity test,
  site check, blockcheck, DPI probe, lookups, install).

### Changed
- **Fake blobs auto-declared from strategy params.** `blob=NAME` /
  `seqovl_pattern=NAME` in a strategy's params are resolved to `--blob=` decls
  via the candidate catalog at generation time — works regardless of how the
  strategy was created; the profile Custom-blobs picker now also offers
  candidate aliases.
- **Full error output in LuCI** — failure notifications show the complete
  backend output behind a collapsible details element instead of a 400-char
  truncation; previously-silent failures (UCI parse, mixin merge, config
  backup, metrics dump) now warn.
- **Live progress on background jobs** (elapsed + last log line); the
  rule-provider update fan-out gains a context deadline.
- **Zapret upstream-config path is auto-derived, not a user setting** — the
  dead `/opt/zapret2` write path was removed (PureWRT runs its own per-instance
  nfqws from the env file).
- `client_traffic.go` split into pcap-decode / flow-state / enrichment files.

### Fixed
- **"Test selected" no longer times out the XHR** — a single strategy test now
  runs through the sweep background job instead of a synchronous rpc.
- Blob-using strategies no longer fail at runtime with
  `LUA ERROR: blob unavailable` (the active launch path never emitted `--blob`).

## [0.2.0] - 2026-07-02

### Added
- **`net-check` connectivity diagnostic.** Layered, topology-aware probe that
  drives *real* download/upload through the proxy mixed-port and isolates the
  failing stage — mihomo vs node vs routing vs WAN — so it catches nodes that
  pass mihomo's url-test but can't actually carry data.
  - Per-node throughput sweep (worst-first), domestic-direct WAN baseline,
    DNS + nftset routing checks, and a config/service preamble.
  - Adapts to topology: proxy / VPN-only probe the data path; zapret-only /
    direct boxes surface DPI-bypass efficacy instead; unconfigured paths are
    marked N/A rather than failed.
  - Surfaced on the **Diagnostics** page (Run test / Per-node test), schedulable
    via cron (`net_check_enabled` / `net_check_cron` / `net_check_bytes`), and
    exported as Prometheus metrics (throughput, verdict, per-layer, per-node).
- **Opt-in per-device and IP/CIDR routing** on the Sections page.
  - Devices is now a managed opt-in list: **add** a device (from DHCP leases /
    static hosts or a typed MAC) to assign it to a section **or exclude it from
    purewrt entirely** — no more dumping every LAN device. Live hostname
    resolution + inline editable target.
  - Source CIDRs moved into a dedicated **IP/CIDR routing** table (assign to a
    section or exclude), one target per CIDR, inline editable.
  - Device **exclusion** is a new MAC bypass; CIDR exclusion reuses the existing
    source-CIDR bypass. Edits stage into LuCI's normal change diff and commit via
    the standard Save & Apply (purewrt reloads via its procd trigger).
- **Zero-disruption apply.** mihomo hot-reloads in place on apply/update instead
  of restarting, so established proxy connections survive; full restart only when
  the controller moved or is gone.
- **DNS routing-set preservation.** Apply snapshots + restores the dynamically
  resolved `dns_*` nftset members so routing isn't blanked until clients
  re-query; adds a **Flush DNS lists** diagnostics action + `flush-dns-sets` CLI.
- **Background ASN database load** for the Client Traffic page (a slow/large DB
  no longer stalls live capture), VLAN/bridge-aware LAN-interface detection, and
  tighter live-capture `--max-seconds` teardown.
- Design/investigation docs: `docs/resilient-dns.md`, `docs/multi-wan-proxy-egress.md`.

### Changed
- **Deterministic client-routing precedence:** excluded devices/CIDRs (bypass) →
  device MAC assignments → source-CIDR assignments → destination rules. A client
  matched by MAC now always wins over one matched by IP/CIDR, independent of
  section priority.
- Log panels filter out crond's crontab-line echoes (busybox crond logs every
  loaded line at err level, which spammed the purewrt/update/OONI panels).

### Fixed
- **Catch-all resilience:** deleting or disabling the `common` section no longer
  dangles the `MATCH,Common` rule — the catch-all falls back to **DIRECT** so
  unmatched traffic degrades to direct internet instead of being black-holed
  (with a soft warning in LuCI before you delete it).
- **Per-node probe accuracy:** a fresh HTTP client per node prevents a reused
  HTTPS CONNECT tunnel from routing one node's probe through the previously
  selected node — dead nodes now correctly report `fail` instead of a false `ok`.
- **Device-section dedup:** device assignments are written as named `dev_<mac>`
  sections and deduped by MAC, fixing stale/anonymous sections that couldn't be
  unassigned.

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

[0.3.1]: https://github.com/mglants/purewrt/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mglants/purewrt/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mglants/purewrt/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mglants/purewrt/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/mglants/purewrt/releases/tag/v0.0.1
