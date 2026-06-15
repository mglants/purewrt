# PureWRT

**English** · [Русский](README.ru.md)

An OpenWrt-native routing manager for the [mihomo](https://github.com/MetaCubeX/mihomo) proxy.

> **OpenWrt decides the route. Mihomo handles the proxy.**

PureWRT keeps routing decisions in the firewall where they belong: dnsmasq forwards DNS to mihomo's
resolver, gets real-IP answers, and populates nftables sets; nftables matches destination IPs and
TPROXYs **only selected traffic** into per-section mihomo listeners. Everything else stays direct (or
under mwan3). Rule providers expand into nftset/nftables rather than mihomo's `rules:` engine — so the
hot path is the kernel, not the proxy.

---

## How it works

```
LAN client
   │  DNS query
   ▼
dnsmasq ──forwards──► mihomo resolver (127.0.0.1:7874) ──► real IP answer
   │                                                          │
   │  populates nftables sets (per section)  ◄────────────────┘
   ▼
nftables: destination IP in a section's set?
   ├─ yes → TPROXY into that section's mihomo listener → proxy / VPN / zapret
   └─ no  → direct (or mwan3 / default route)
```

The default mode is **real-IP nftset routing**. fake-ip and full-core modes are intentionally not the
default. Unmatched traffic is never forced through the proxy.

### Routing targets — not just mihomo

A routing section isn't tied to a mihomo proxy. Each section sends its matched traffic through whichever
backend you pick:

- **mihomo proxy group** — the usual proxied path (selector / url-test / load-balance / …).
- **VPN** — route the section straight out a WireGuard/VPN interface configured on the router, with no
  proxy involved.
- **zapret** — apply DPI circumvention to the section's traffic without any proxy or VPN at all.
- **direct** / **reject** — bypass everything, or drop it.

So you can mix freely: e.g. streaming via a proxy group, a work subnet out a WireGuard tunnel, censored
sites through zapret, and everything else direct. (VPN and Zapret configurations are even preserved
across a wizard reset, since they're yours, not imported.)

---

## Quick start — the setup wizard

After installing the `purewrt` package and the `luci-app-purewrt` LuCI app:

1. Open LuCI → **Services → PureWRT** (the **General** page).
2. Click **Run Setup Wizard**.
   > ⚠️ Applying the wizard **resets all PureWRT configuration to defaults** (subscriptions, providers,
   > routing sections, device assignments, DNS, settings). Only your **VPN** and **Zapret** configs, the
   > mihomo binary, and the controller credentials are preserved.
3. **Step 1 — choose a source:**
   - **Use a subscription URL** — paste a Clash/Mihomo subscription URL, a proxy list, or a rule list
     (recommended if your vendor gave you a URL).
   - **Default lists** — pull curated rule lists straight from the published catalog; optionally add a
     proxy-nodes URL.
   - **Manual setup** — skip import and configure nodes/providers from the regular tabs later.
4. **Preview** what will be imported, then map rule sets to **routing sections** and set each section's
   protocol (proxy group / VPN / zapret / direct) on the drag-flow board.
5. Set global options (IPv6, updates, DNS), then **finish** — the wizard imports, generates, and applies
   in one go.

## Adding a subscription

Three ways, pick whichever fits:

- **Wizard** — Step 1 → *Use a subscription URL* (see above). Best for first-time setup.
- **LuCI → Proxy Subscriptions tab** — add a subscription, paste the URL (and any panel type / headers),
  **Save & Apply**. Use this to add a subscription without resetting anything.
- **CLI:**
  ```sh
  purewrt analyze 'https://panel.example/sub/secret?format=clash'   # preview only (optional)
  purewrt import  'https://panel.example/sub/secret?format=clash'   # persist it
  purewrt update                                                    # fetch nodes + rules
  purewrt apply                                                     # generate + apply
  ```

---

## Features

- **Setup wizard** — flush-and-start or import; choose a subscription URL or the curated default lists,
  map rule sets to routing sections, and configure per-section proxy/VPN/zapret in one drag-flow board.
- **Proxy subscriptions** — Mihomo/Clash YAML, proxy-URI lists, base64 subscriptions, with
  panel-aware downloads (Remnawave & compatible) and stable router-derived HWID.
- **Rule providers** — text, MRS (binary, allocation-free streaming decode), and GeoSite/GeoIP from
  local v2ray dat files. Import curated lists straight from the published catalog with multi-select.
- **Sections / routing** — group rules into sections, each routed via a proxy group, a VPN, zapret, or
  direct/reject; per-section proxy strategy, filters, and group type.
- **Per-device routing** — assign LAN devices to sections by MAC (survives DHCP churn, covers IPv6).
- **Mihomo management** — browse proxy groups, switch nodes with latency test + connection draining,
  track upstream alpha releases.
- **Zapret integration** — bundled, optional, detected at runtime and degraded gracefully when absent.
- **mwan3 coexistence** — detect-and-coexist multi-WAN; masked fwmark preserves mwan3 bits.
- **Diagnostics** — domain checker, "What's Blocked Now", and a **Client Traffic** page that captures
  live flows + DNS + rejection signals and flags blocked/DPI-stalled/frozen connections with ASN/country
  enrichment.
- **Operations** — config export/import (secrets redacted), push notifications (ntfy/webhook) for update
  failures and subscription expiry, and Prometheus metrics with example Grafana dashboards/alerts.

---

## Components

| Binary / app    | Role                                                          |
|-----------------|---------------------------------------------------------------|
| `purewrt`       | The CLI manager — import, update, generate, apply, diagnose.  |
| `purewrt-check` | Domain classifier (which section/route a hostname resolves to). |
| `purewrt-api`   | Optional local API daemon.                                    |
| LuCI app        | `luci-app-purewrt` — the web UI (tabs above are LuCI views).  |

Configuration lives in UCI at `/etc/config/purewrt`; generated artifacts in `/etc/purewrt/generated/*`.

---

## Install (package feed)

On a router running OpenWrt **24.10** (opkg) or **25.12+** (apk), one line:

```sh
wget -O - https://mglants.github.io/purewrt/install.sh | sh
```

It auto-detects your release + architecture, adds the signed PureWRT feed and its trust key, swaps in
`dnsmasq-full`, and installs `purewrt` + `luci-app-purewrt` (add `WITH_ZAPRET=1` for the optional
zapret DPI-bypass). Then open **LuCI → Services → PureWRT → Run Setup Wizard**.

Prefer to add the feed and install manually? `wget -O - https://mglants.github.io/purewrt/feed.sh | sh`
then `opkg install purewrt luci-app-purewrt` (or `apk add …`). Feed layout + public keys live at
`https://mglants.github.io/purewrt/`. Builds are produced by GitHub Actions for a curated set of
arches (x86_64, aarch64 cortex-a53/a72/a76, mipsel_24kc); for other targets, build from source below.

---

## Install & build

PureWRT is built with the OpenWrt SDK. The bundled `Taskfile.yml` orchestrates SDK downloads and builds
in a NixOS dev shell for OpenWrt 24.10 and 25.12 and the two reference devices.

```sh
# NixOS dev shell
nix-shell
task doctor            # verify the toolchain
task build:25.12       # full SDK build → .apk artifacts
task build:cudy-wr3000h
task build:bananapi-bpi-r3-mini
```

Or build the package in an existing SDK checkout:

```sh
./scripts/feeds update -a && ./scripts/feeds install -a
make package/mihomo-alpha/compile V=s
make package/purewrt/compile V=s
```

Runtime dependencies: `dnsmasq-full`, `nftables`, `kmod-nft-tproxy`, `ip-full`, `ca-bundle`,
`luci-base`, and a mihomo binary (the bundled `mihomo-alpha` package provides `/usr/bin/mihomo`).

> OpenWrt 25.12 uses APK packages, so artifacts are `.apk` (not `.ipk`). See the build notes near the end
> of this file for SDK target overrides and NixOS troubleshooting.

---

## Configuration

Everything is UCI-driven. A subscription, for example:

```uci
config subscription
    option url 'https://panel.example/sub/secret?format=clash'
    option panel_type 'remnawave'
    option user_agent 'PureWRT/0.2'
    list header 'X-Custom-Header: value'
```

PureWRT derives a stable HWID from router identity and appends `hwid`/`device_name` when missing; it
sends `x-hwid`, `x-ver-os`, `x-device-model` (plus compatibility aliases) on every download. Manual HWID
overrides are intentionally ignored to keep identity router-derived.

---

## Small / low-RAM routers

PureWRT ships a `resource_profile` setting (`standard` (default) / `low` / `high`). Set it in
**Settings**, or `uci set purewrt.settings.resource_profile='low'`. **`low`** automatically:

- moves the rule cache to **tmpfs** (`/tmp/purewrt/cache`) instead of flash;
- **disables the artifact cache** (providers re-parse on each update — saves flash + RAM);
- **turns off rule dedup** (less RAM/CPU; duplicate set entries are harmless);
- **disables IPv6 routing** when `ipv6_mode=auto` (override with `ipv6_mode=on` if you really need it);
- **forces mihomo geodata off**, and tunes the mihomo core (no process matching, shorter keep-alives,
  proxy health-checks off);
- shrinks the apply config-backup cap to 128 KB.

Knobs `low` does **not** set, worth disabling on tight hardware:

```uci
config main 'settings'
    option resource_profile 'low'
    option ipv6_mode 'off'
    option dashboard_enabled '0'          # the metacubexd dashboard costs ~5 MB
    option mihomo_geodata_enabled '0'
    option background_updates '0'
    option update_concurrency '1'
```

Also: **prefer the native lists from the catalog** (`parse_mode=native_import`, the wizard's
"Default lists — lightest" path) and small text lists over large **MRS** or **GeoSite/GeoIP** providers —
MRS decoding and per-section dnsmasq buffers (capped at 32 MB) are the main RAM spikes. Subscriptions
already import only proxy nodes (not their large rule lists) under `low` unless you opt in per
subscription.

**What fits:**

| RAM | What to run |
|-----|-------------|
| **~32 MB** | The mihomo proxy core (a Go binary needing tens of MB) generally **won't fit** alongside OpenWrt. Use **zapret-only routing** — route sections through zapret for DPI bypass with **no proxy** (see [Routing targets](#routing-targets--not-just-mihomo)); PureWRT's routing/DNS layer itself is light. Or run the proxy on bigger hardware. |
| **~64 MB** | A minimal mihomo proxy is possible with `resource_profile=low`: a few nodes, small native lists, dashboard off, no geodata, IPv6 off. |
| **≥128 MB** | Comfortable — `standard` profile, MRS providers, IPv6, and the dashboard are all fine. |

---

## Commands

```sh
purewrt analyze <url>        # inspect a subscription without importing
purewrt import <url>         # import a subscription / provider
purewrt add-native-list <url> <section> [--priority=N]
purewrt update               # fetch subscriptions + rule providers
purewrt generate             # render artifacts to /etc/purewrt/generated
purewrt apply                # generate + install + reload services (self-healing)
purewrt reload               # alias of apply
purewrt status               # current state
purewrt validate             # validate config
purewrt client-traffic <IP>  # live flow / DNS / rejection capture for a client
purewrt doctor               # check the dev/runtime toolchain
purewrt disable              # remove PureWRT routing + DNS changes
purewrt-check chatgpt.com    # classify a domain
```

---

## Safety model

- The mihomo external controller listens on `127.0.0.1` by default.
- PureWRT owns only `/etc/purewrt/generated/*`, its dnsmasq fragments, and `table inet purewrt`.
- Policy routing uses a **masked** fwmark `0x1/0xff`; nftables sets the mark with
  `meta mark set meta mark | 0x1`, preserving mwan3's bits.
- `apply` is self-healing: it probes live state (nft table, ip rules, dnsmasq fragments) before honoring
  the fingerprint cache, and one broken subscription doesn't abort the whole update.
- `disable` removes only PureWRT-generated routing and DNS changes.

---

## Development

```sh
task test:go     # go test ./... && go vet ./...  — the canonical check
go test ./internal/manager/... -run TestApply
```

The Go toolchain is pinned via `mise.toml`; `go.mod` declares the language floor. External dependencies
are kept minimal: `gopkg.in/yaml.v3` and `github.com/klauspost/compress` (zstd, for binary MRS decoding).

See `CLAUDE.md` and `AGENTS.md` for the architecture map and the non-obvious gotchas (LuCI cache-busting,
dnsmasq restart-not-reload, boot `apply --force`, self-heal probes) that have dedicated regression tests.

---

## Building: detailed notes

<details>
<summary>OpenWrt SDK targets and NixOS troubleshooting</summary>

### SDK targets

Defaults target `x86/64`. Override target variables when needed:

```sh
OPENWRT_VERSION=24.10.0 OPENWRT_TARGET=x86 OPENWRT_SUBTARGET=64 OPENWRT_ARCH=x86_64 task build
```

The SDK is downloaded into `.build/openwrt/`; packages are synced into the SDK under
`package/network/services/`; resulting `.apk`/`.ipk` files are printed from `bin/packages` / `bin/targets`.

### Cudy WR3000H (mediatek/filogic, 25.12)

```sh
OPENWRT_VERSION=25.12.0 OPENWRT_GCC_VERSION=14.3.0 OPENWRT_TARGET=mediatek \
  OPENWRT_SUBTARGET=filogic OPENWRT_ARCH=x86_64 task build
```

### Feed selection

The Taskfile intentionally does **not** run `./scripts/feeds install -a` — on `mediatek/filogic` that
pulls unrelated bootloader variants. It installs only what `purewrt` and `mihomo-alpha` need. If an SDK
was polluted with `install -a`, run `task sdk:reset` with the matching target vars and rebuild.

### NixOS nix-ld

`shell.nix` exports `NIX_LD`/`NIX_LD_LIBRARY_PATH` for stub-ld compatibility. If a build failed in
`golang-bootstrap`, clean host Go artifacts with `task sdk:clean-go-host` (with target vars) and rebuild.

### mihomo updates

Runtime overwrite of `/usr/bin/mihomo` is disabled by design — PureWRT ships package-managed
`mihomo-alpha`. Update it by rebuilding the package (`openwrt/mihomo-alpha/Makefile`) or installing a
newer package from your repository.

</details>
