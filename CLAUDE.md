# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What PureWRT is

An OpenWrt-native routing manager for the mihomo proxy. The guiding principle:
**OpenWrt decides the route, mihomo handles the proxy.** dnsmasq forwards DNS to
mihomo's resolver (`127.0.0.1:7874`), gets real-IP answers, and populates
nftables sets; nftables matches destination IPs and TPROXYs *only selected*
traffic into per-section mihomo listeners. Unmatched traffic stays direct (or
under mwan3). Routing decisions live in the firewall, not in mihomo's rule
engine — this is why rule providers expand into nftset/nftables rather than
mihomo `rules:`.

**Read `AGENTS.md` before touching anything that lands on the router.** It
documents the non-obvious gotchas (LuCI cache-busting, dnsmasq restart-not-
reload, boot `--force`, UA defaults, self-heal probes) that are easy to
regress and have dedicated tests guarding them.

## Commands

```sh
task test:go          # go test ./... && go vet ./...  — the canonical check
go test ./internal/manager/... -run TestApply   # single package / single test
task build:25.12      # full OpenWrt SDK build, produces .apk artifacts
task build:zapret     # build just the bundled zapret package
task doctor           # verify the NixOS dev-shell toolchain is present
```

Go toolchain is pinned via `mise.toml` (go 1.25.3); `go.mod` declares 1.22 as
the language floor. External dependencies are `gopkg.in/yaml.v3` and
`github.com/klauspost/compress` (zstd — binary MRS rule-set decoding only).

### Cross-compile + deploy a CLI binary to the test router

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /tmp/purewrt ./cmd/purewrt
scp -O /tmp/purewrt root@192.168.1.1:/root/purewrt-new   # -O = legacy SCP; Dropbear has no sftp-server
ssh root@192.168.1.1 'mv /root/purewrt-new /usr/bin/purewrt && chmod +x /usr/bin/purewrt'
```

192.168.1.1 is a **real production router** — don't reboot it to test; wipe
state (`nft delete table inet purewrt`, `ip rule del …`) and re-`apply` to
exercise self-heal. It runs OpenWrt 25.12 (apk, not opkg; busybox without
`stat`, fractional `sleep`, or `ip rule … mark`).

## Architecture

One multi-call binary in `cmd/purewrt`: `purewrt` (the CLI manager — ~47
subcommands, dispatched by a big switch in `cmd/purewrt/main.go`). It also
serves as `purewrt-check` (domain checker, `check.go`) and `purewrt-api`
(optional local API daemon, `api.go`) — those install as symlinks and
`main()` dispatches on the argv[0] basename, busybox-style.

The data flow is a pipeline, each stage in its own package:

```
UCI (/etc/config/purewrt)
  └─ internal/config       parse (uci.go) → Config struct (model.go) → serialize (write.go)
                           DefaultConfig() in model.go is the source of truth for every default
internal/provider          fetch + classify subscriptions / rule providers / proxy providers
internal/rules             parse rule lists (text, mrs, v2ray-profile) into rules.Provider
internal/geodb             parse v2ray geosite.dat/geoip.dat (hand-rolled protobuf, no deps)
internal/generator         render artifacts → /etc/purewrt/generated/*
                           mihomo.go (+mixin), dnsmasq.go, nftables.go, firewall.go,
                           mwan3*.go, zapret.go, stream.go (rule→nftset/nft expansion),
                           fingerprint.go (input hash that gates apply short-circuit)
internal/manager           orchestration: Import / Update / Generate / Apply / Reload / Disable
                           (manager.go is the hub; one file per feature area otherwise)
```

`internal/manager` is where almost all behaviour lives. `Apply` and the update
loop have self-heal logic (live-state probes before honouring the fingerprint
cache) and soft-continue semantics (one broken subscription doesn't abort the
whole update, but produces a non-zero exit to trigger the init-script retry) —
both documented in AGENTS.md with the reasoning, both regression-tested.

Supporting packages: `internal/mihomoapi` (external-controller HTTP client +
GitHub release updater), `internal/ipdb` (ip2asn DB for the Client Traffic
page — unrelated to mihomo geo), `internal/checker`, `internal/logging`,
`internal/metrics`, `internal/system` (atomic file writes — always
temp-then-rename so it survives ETXTBSY on a running binary).

### LuCI ↔ Go bridge

The LuCI app is **not** Go. It's three layers under `openwrt/luci/`:

1. **Views** (`htdocs/luci-static/resources/view/purewrt/*.js`) — ucode/JS
   client-side pages.
2. **rpcd dispatcher** (`root/usr/libexec/rpcd/purewrt`) — a shell script that
   shells out to the `purewrt` CLI and re-emits JSON. ubus rejects top-level
   JSON arrays, so array-returning methods wrap their output in an object
   (`{"items":[...]}`, `{"updates":[...]}`) and the view's `rpc.declare` uses
   `expect: { items: [] }` to unwrap.
3. **ACL** (`root/usr/share/rpcd/acl.d/luci-app-purewrt.json`) — every rpcd
   method must be listed under `read.ubus` or `write.ubus` or it returns
   "Access denied". **ACL grants are bound to a ubus session at login time** —
   after editing the ACL you must log out and back in (not just restart rpcd)
   for an existing browser session to see the new grant.

Adding a CLI-backed LuCI feature touches all four: a `cmd/purewrt/main.go`
case, an rpcd dispatcher arm, an ACL entry, and the view. Menu entries live in
`root/usr/share/luci/menu.d/purewrt.json`.

## Non-obvious behaviors

- **Rule dedup is three-mode** (`off`/`section`/`full`, `internal/generator/stream.go`).
  Section mode dedups within a `(section, rule type)` only — the same rule may
  appear in multiple sections. Full mode is global via the `claimed` map
  (`type:value` keys), and **provider iteration order decides the winner**:
  earlier providers claim duplicate values. The MRS streaming fast path honours
  all three modes through `streamDedup` — don't re-add an `off`-only gate.
- **MRS streaming is allocation-free by contract**: `MRSStreamHandlers.Domain`
  (`internal/rules/parse_mrs.go`) passes a `[]byte` into a buffer reused across
  calls — copy if you retain it. The dnsmasq emission path depends on this;
  materialising rules instead turns ~50 ms generations into tens of seconds on
  large providers.
- **Provider downloads degrade silently**: the bootstrap client
  (`internal/provider/httpclient.go`) tries the TOFU IP cache first, then DoH,
  and on DoH failure falls back to the plain system resolver so a misconfigured
  resolver pool can't brick downloads — but in censored environments that
  fallback is unencrypted and produces no error.
- **`IPv6Mode` semantics** (`Config.IPv6Routed()` in `internal/config/model.go`):
  `on`/`off` are absolute overrides; only the default/`auto` case delegates to
  the legacy `ipv6 && !LowResource()` behaviour. Setting `off` bypasses
  resource-profile checks entirely.
- **rpcd background jobs are flock-guarded**: long-running dispatcher methods
  (`update`, `dpi-check`, `zapret-check`, …) take `flock -nx` on dedicated
  lockfiles so check-and-launch can't race. New long-running rpcd methods must
  follow the same pattern.

## OpenWrt packaging

`openwrt/purewrt/Makefile` is the `purewrt` package. It builds from the
checked-out repo (no `PKG_SOURCE`/download): `PUREWRT_SRC` resolves to
`$(CURDIR)` under the local `Taskfile` rsync, or to `$(CURDIR)/../..` (the repo
root) when built as a feed package by `openwrt/gh-action-sdk` in CI (the feed is
src-linked at `/feed`, so the Makefile sits at `/feed/openwrt/purewrt`), gated on
whether `$(CURDIR)/cmd` exists. `openwrt/mihomo-alpha/Makefile` and
`openwrt/zapret/Makefile` are bundled dependency packages built from upstream
git tags. `openwrt/files/etc/init.d/purewrt` is the service init script — boot
runs `purewrt apply --force` in the foreground (the `--force` is mandatory; see
AGENTS.md). `Taskfile.yml` drives local SDK builds (NixOS dev shell); CI
(`.github/workflows/`) builds + signs + publishes the package feed via
`openwrt/gh-action-sdk` across a curated arch × {24.10, 25.12} matrix.

Zapret is intentionally **not** a hard dependency of the purewrt package — LuCI
detects its presence at runtime via the `zapret_installed` rpcd method and
degrades gracefully.
