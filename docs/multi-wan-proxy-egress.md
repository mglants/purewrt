<!-- Network identifiers and addresses in this document are anonymized examples. -->

# Multi-WAN proxy egress via mihomo — post-mortem + reimplementation notes

## Retest: both WANs work (2026-10-23)

Isolated tests on `192.0.2.1`, with Mihomo `alpha-dc4d4fcb` (2026-07-17),
confirmed working proxy egress through both WAN A (`eth1`, mark `256`)
and WAN B (`eth2`, mark `512`). LTE was online but not tested.
The older conclusions below are historical, not current implementation constraints.
The difference from the June failures has not been isolated to a specific fix.

The test core listened only on localhost ports 17899/19099 and ran in
`/services/mihomo/wan-test`, covered by PureWRT's existing cgroup bypass.
Read-only provider data stayed on the router. Non-blocking nft counters scoped
to that test cgroup and each output device independently verified the WAN path.

| Test | Result |
|---|---|
| Direct outbound, mark only / device only / both | All six returned the expected WAN public IP |
| One subscription VLESS/gRPC node, mark / chained marked direct / device | All six HTTPS requests succeeded over the intended WAN, about 0.25–0.28 s |
| One sampled Hysteria2 node with the same variants | Failed on both WANs; counters confirmed packets on the intended device |
| One VLESS/TCP provider node, `override.dialer-proxy: WAN`, round-robin WAN group | Four 1 MiB downloads succeeded and alternated WANs, 0.38–0.61 s |
| One VLESS/gRPC node through that shared WAN group | Successful transfers reused the initially selected WAN, including with optional smux disabled |
| Two VLESS/gRPC instances, each with its own WAN mark, in a round-robin group | Six 1 MiB downloads alternated WANs, all succeeded, 0.17–0.35 s |
| Same two instances, two simultaneous 4 MiB downloads | Both succeeded, 0.46/0.48 s; counters increased on both WANs |

These are bounded functional transfer tests, not sustained throughput benchmarks
or LAN-client TPROXY tests. WAN outage, health-check recovery, IPv6 and prolonged
stability were not tested. No production WAN was disconnected.

Implementation implication: a shared marked-direct WAN group works for fresh
TCP dials, but gRPC connection reuse pins subsequent streams to the original
WAN. To offer both paths consistently for such transports, create independent
WAN-specific proxy instances (or provider instances with distinct names and
WAN overrides), then select/balance those with existing Mihomo groups. Discover
marks from mwan3 rather than hardcoding this router's values. Check health over
the actual proxy path; a direct WAN health check alone cannot detect node/DPI
failures. Existing streams cannot be assumed to migrate between WANs.

All temporary test configuration, credentials, counters and the test core were
removed. Production Mihomo remained PID 4395, DNS still resolved, and the WANs
remained online. No permanent multi-WAN feature was enabled.

## Historical attempt (2026-06)

**Status at the time: attempted, dropped.** The code was fully written, tested, and live-tested on a real
mwan3 router (192.0.2.1: wan1 `eth2` + wan2 `eth1`), then **removed** because it does not
route reliably. This documents what was tried, exactly why it failed, the facts established, and how to
reimplement.

## Goal

Let each subscription proxy node reach its server over **either WAN** and **switch WAN at the mihomo layer**
(health-checked, fast for new dials) instead of mwan3's failover flushing conntrack and dropping
connections. I.e. proxy *egress* survives a WAN going down.

## What was tried (the dropped design)

Same mechanism as the VPN outbounds:
- Per-WAN `type: direct` outbound (`wan_<l3dev>`), one per enabled mwan3 interface (resolved netifd
  `l3_device`).
- A `WANs` proxy-group (fallback / url-test / load-balance) over them, 60s health-check.
- Every proxy-provider got `override.dialer-proxy: WANs` so all nodes dial their server **through** the WANs
  group.

Two ways to pin each WAN outbound to its link were tried:
1. `interface-name: <l3dev>` (SO_BINDTODEVICE).
2. `routing-mark: <mwan3 fwmark>` (the mwan3 per-WAN mark, discovered from `ip rule fwmark … lookup <table>`
   joined with `ip route show table <t>` → `default dev`).

## Why it failed (live evidence)

- **`interface-name`** → every proxy dial: `connect: no route to host`. On an mwan3 box WAN selection is
  **fwmark-based** (`ip rule fwmark 0x200/0x3f00 lookup 2` → table 2 → eth2), so binding to the device
  (SO_BINDTODEVICE) bypasses mwan3's tables and the lookup fails. **This is the same root cause as the
  `curl --interface <dev>` failure below — confirmed on the wire.**
- **`routing-mark`** → mihomo `WANs` group: **"all proxies timeout"**; the healthy WAN (wan1) reported
  `alive:false` and `fallback` stuck on the dead wan2 WAN as `now`.

Crucially, the kernel *can* route both ways — these all succeeded:
- `ip route get <ip> mark 0x200` → `table 2 … dev eth2` (mark routing resolves).
- `curl --interface eth2 http://api.browser.yandex.ru/generate_204` → **204** (WAN reachable direct).

### ⚠️ CORRECTION — `curl --interface <dev>` is NOT a valid WAN-liveness test on mwan3

An earlier draft recorded `curl --interface eth1` → `000` as proof that **wan2 (wan_a) was dead**. **That
was wrong.** Re-verified on 192.0.2.1 with wan_a up and stable:

| test | result |
|---|---|
| `curl --interface eth1` (SO_BINDTODEVICE, **device name**) | `000`, **zero SYN on any interface** (tcpdump empty) |
| `curl --interface 192.0.2.10` (bind wan_a **source IP**) | **204** ✅ |
| `ping` via the wan_a fwmark `0x100` → table 1 (`8.8.8.8`, tracker `77.88.8.3`) | **0% loss** ✅ |

`--interface <devname>` issues `SO_BINDTODEVICE`, which carries **no fwmark**. mwan3 reaches a WAN's table
only via `ip rule fwmark 0x100/0x3f00 lookup 1`; rule `99: suppress_prefixlength 0` strips the default from
`main` for unmarked traffic, so a device-bound, unmarked socket lands in no per-WAN table — the kernel can't
reconcile `oif=eth1` with the surviving routes and **drops `connect()` before any packet leaves**. The
WAN itself is fine. **To probe a WAN on an mwan3 box, bind its source IP (`--interface <wan-ip>`) or set its
fwmark — never the device name.** `ip route get <ip> oif <dev>` resolving is also *not* proof a
device-bound socket will work (it does not replicate SO_BINDTODEVICE source validation + the rule chain).

So the WANs are reachable and the kernel honors `mark` (but **not** unmarked `oif` for locally-bound
sockets). **mihomo just doesn't apply the
per-WAN mark/bind to the socket it actually dials through the `dialer-proxy` chain** on this setup — the
probe (and likely the relayed dial) egress via the default route, not the intended WAN. Suspected
contributing factors: mihomo's own outbound is cgroup-exempt in PureWRT's nft output chain; there are **two**
default routes (one per WAN); and mihomo may only attach `routing-mark`/`interface-name` to a proxy's *own*
dial, not to a dial it makes *as a dialer-proxy target* for another proxy.

## Facts established (don't re-discover)

- mihomo `alpha-c59c99a0` **parses** `proxy-provider override.dialer-proxy`, `direct` + `interface-name`,
  `direct` + `routing-mark`, and `fallback`/`url-test`/`load-balance` groups (`mihomo -t` → "test is
  successful"). **The failure is runtime routing, not syntax.**
- mwan3 marks: parse `ip rule show` for `fwmark 0xMARK/0x3f00 lookup <numeric table>`, then
  `ip route show table <table>` → `default … dev <l3dev>` gives device→mark.
- `interface-name` must be the **kernel device** (`eth2`), not the netifd name (`wwan1`).
- WAN health-check URL must be reachable **direct** on each WAN; in RU, `http://api.browser.yandex.ru/generate_204`
  works, cloudflare's may not. (This was *not* the blocker, but is needed for correct failover selection.)

## ✅ Isolation test run (2026-06, 192.0.2.1) — resolves plan step 1

Ran the plan's step-1 experiment in full on the live router (separate test mihomo instance, ports 17899 /
ctrl 19099, never touching the production service). **Verdict: mihomo `routing-mark` does NOT take effect on
this box — not via dialer-proxy, not even on a `direct` outbound's own dial.** The whole `direct`+mark
approach is a dead end here.

### What was proven, in order

1. **Kernel honors a pre-set mark (control).** An isolated nft rule stamping `meta mark set 0x100` (priority
   −160, before mwan3's mangle at −150) on ICMP to `8.8.8.8` → **0% loss, ~21 ms via wan_a**. So `SO_MARK
   0x100` → `ip rule 2001 fwmark 0x100/0x3f00 → table 1 → eth1` works. The kernel half is fine.
2. **mwan3 does NOT clobber a pre-set mark.** Every mwan3 OUTPUT-hook mark rule is gated on
   `-m mark --mark 0x0/0x3f00` (acts only when the `0x3f00` bits are zero); a packet entering with `0x100`
   already set sails through untouched, and `CONNMARK --save-mark` even persists it for replies. So if mihomo
   set the mark, mwan3 would respect it.
3. **mihomo never sets the mark.** Config: `direct` outbounds `wan_a`(`routing-mark: 256`/0x100) and
   `wan_b`(`routing-mark: 512`/0x200), plus `node`(`direct, dialer-proxy: wan_a`); a `select` group over
   them; dial a dest **not in any nftset** (`8.8.8.8:80`, verified 0 set hits, so no TPROXY capture of the
   non-cgroup-exempt test instance). For **all three** selections the dial's conntrack showed
   **`mark=16128` (0x3f00) and `src=198.51.100.10` (WAN B)** — i.e. it went out *unmarked*, picked up
   mwan3's default `0x3f00`, and took the lowest-metric default route. Never `0x100`/`0x200`, never wan_a.
   `mihomo -t` parses `routing-mark` fine; it's simply not applied to the socket at runtime.

### Gotchas that wasted time (note for the re-runner)

- **`tcpdump -i any` on this busybox prints `UNSUPPORTED` + hex** (can't decode the SLL2 cooked header) —
  text/BPF host filters silently match nothing. Decode the hex IP header by hand, or read conntrack
  (`/proc/net/nf_conntrack`, more reliable than `conntrack -L` here).
- **`pkill` does not exist** (busybox); kill by PID. And `pgrep -f /tmp/iso` **matches your own ssh shell**
  (its cmdline contains the string) — it'll kill your session. Match `mihomo` specifically or find the pid
  by its listening port.
- A shared/popular dest IP (e.g. a yandex front) is polluted by LAN/prod traffic to the same IP — use a dest
  only the test instance contacts, and verify it's in **no** nftset (else the live mihomo TPROXYs your test
  dial and you measure the *production* egress, which is what made an early read look like success).
- `routing-mark` is dest-independent; if it ever looks like it works for one dest and not another, you're
  measuring contamination, not mihomo.

### Conclusion → the only viable path is kernel-side (plan step 2, branch B)

Both mihomo levers are out on an mwan3 box: `interface-name` (SO_BINDTODEVICE, no mark) can't reach mwan3's
fwmark tables, and `routing-mark` (SO_MARK) isn't emitted at all. So per-WAN egress **cannot** be selected
inside mihomo here. If revisited, solve it in the kernel: have nft/ip-rule stamp the mwan3 per-WAN fwmark on
**mihomo's own egress** keyed by chosen WAN (e.g. a cgroup/owner match on the mihomo service that sets
`0x100`/`0x200`), rather than asking mihomo to mark its sockets. Before building that, re-verify whether a
newer mihomo build emits `routing-mark` (one quick rerun of the step-3 test above settles it). Until then,
multi-WAN proxy egress stays dropped.

## Reimplementation plan

1. **Isolate the mihomo behavior first** (no PureWRT code): hand-write a config with ONE `direct` +
   `routing-mark` outbound and point a section's group directly at it (NOT via dialer-proxy). Reload, force
   `/group/<g>/delay`. If it goes `alive` and egresses the right WAN → the bug is the `dialer-proxy` chain
   not propagating the mark; if still timeout → mihomo isn't applying `routing-mark` at all here (kernel/nft
   interaction). This single experiment decides the whole approach.
2. Depending on (1):
   - If `dialer-proxy` is the problem: **materialize per-WAN node variants** instead — duplicate each
     subscription node with `interface-name`/`routing-mark` per WAN into a per-section group (heavier:
     re-materialize on provider update; breaks clean provider auto-update). Each node's *own* dial then
     carries the mark.
   - If `routing-mark` never applies: solve it at the **kernel** — have nft/ip-rule mark mihomo's
     per-destination egress, or relax the cgroup exemption for WAN-routed dials. More invasive.
3. Keep a WAN-reachable `health-check` URL configurable (was `Settings.WANHealthURL`).
4. **Test protocol (avoid the prod break that happened):** always `mihomo -t` first; enable on the router
   only with a revert one-liner ready (`uci set purewrt.settings.wan_failover=0; purewrt apply --force`);
   verify subscription nodes stay `alive:true` and `logread` shows no new `no route to host`/timeouts BEFORE
   declaring success; then down a WAN (`ip link set <l3dev> down`) and confirm failover.

## Where the code lived (for restoring)

Removed in the drop; re-add in these spots:
- `internal/config/model.go`: `Settings.WAN{Failover,Mode,LoadBalanceStrategy,HealthURL,Interfaces}` +
  `WANInterfacesResolved []WANRoute` + `type WANRoute{Device string; Mark int}` + Default literal.
- `internal/config/uci.go` / `write.go`: parse/emit `wan_failover`, `wan_mode`, `wan_lb_strategy`,
  `wan_health_url`, `wan_interface`.
- `internal/manager/wan_resolver.go`: `ResolveWANInterfaces` + `resolveWANMarks` + `enabledMwan3Networks`
  (device→mwan3-mark discovery). Call it next to `ResolveZapretProfileInterfaces` in Generate /
  GenerateCacheStatus / applyPrepare.
- `internal/generator/mihomo.go`: per-WAN `direct` outbounds, `WANs` group, proxy-provider
  `override.dialer-proxy`, and `fallback` in `normalizedProxyGroupType` + the url/interval emit.
- `openwrt/luci/.../settings.js`: the "Multi-WAN failover" section.
- Tests: `internal/generator/wan_failover_test.go`, `internal/manager/wan_resolver_test.go`.

## Opt-in provider generation

The native implementation uses the existing `config mwan3 'mwan3'` section:

```uci
    option proxy_wan_enabled '1'
    list proxy_wan 'wan_a'
    list proxy_wan 'wan_b'
```

LuCI → Settings → Proxy WANs exposes the enable switch and WAN selection
when enabled mwan3 interfaces exist. The default is disabled: no provider copies,
WAN overrides or discovery commands are added to ordinary generation.

At apply time PureWRT joins selected mwan3 interface names with netifd devices,
then joins mwan3's per-device `iif` policy rules with its marked table rules.
The discovered mark and device pin each independent provider instance. Missing,
ambiguous or overlapping marks abort generation before changing live state.
WAN routing is re-discovered on each apply/generate, including guard reloads and
config previews. Changes to discovered devices/marks invalidate the fingerprint.
If netifd or mwan3 loses a selected device/rule during an outage, apply fails and
preserves the existing configuration; it does not silently use unmarked egress.

PureWRT downloads each configured provider once as before. Generated variants
use `type: file`, the shared downloaded file, and provider overrides for
`routing-mark`, `interface-name`, `ip-version: ipv4`, and a unique node suffix.
A provider's inherited `dialer-proxy` is cleared so its own WAN binding applies.
DNSProxy, section groups, NetCheckProbe and adaptive-guard candidate groups use
the same WAN variants. Explicit VPN/friend outbounds are unchanged. Original
provider definitions in UCI are retained, so disabling restores ordinary
provider generation. Group filters are not rewritten; expressions anchored to
the end of a node name may need adjustment for the added ` · WAN [provider]`
suffix. Quarantines identify each suffixed node/WAN pair independently.

This initial implementation pins IPv4 proxy-server connections. IPv6 WAN
routing and automatic WAN bonding are outside its scope. Connection selection
still follows each existing group's type and strategy, not an unconditional
round-robin policy. Existing streams cannot migrate between failed WANs.

### Implementation validation (2026-10-23)

The resolver discovered marks 256/512 for WAN A/WAN B without manual mark
input. The full generated production-shaped config passed `mihomo -t` without
being installed. Two provider instances reading the same file exposed distinct
suffixed names. Using the exact generated overrides with an isolated VLESS/gRPC
sample, four 1 MiB transfers succeeded and alternated WANs (0.15–0.31 s).

An isolated nft drop affected only the test core's WAN A traffic. With test-only
2-second health intervals and a 1.5-second timeout, after six seconds all three
256 KiB requests succeeded through the surviving path. After removing the drop
and waiting six seconds, requests used both paths again. These accelerated
health settings were not installed as production defaults. All temporary test
state was removed; production Mihomo remained running as PID 4395.

The unused `mmx_mask_auto`, `purewrt_mark`, `rule_priority`, and duplicated
`purewrt_mask`/`mwan3_mask` controls have been removed. Diagnostics use the active
PureWRT mark mask and read mwan3's configured mask directly. Older UCI values
for those options are ignored and omitted on the next PureWRT config save.

The legacy integrated-rules feature has also been removed: no `mode`, `detect`,
`integrated_rules`, or per-provider/section `mwan3_policy` options, generated
mwan3 rule files, or mwan3 reloads remain. PureWRT never edits mwan3 policies.
Zapret retains its per-profile interface selection; automatic profiles discover
mwan3 members without a second global detection switch. Existing manually
installed mwan3 rules are not deleted by this change.

### Production deployment validation (2026-10-23)

Installed the binary, Settings/Providers LuCI views and updated read ACL on
`192.0.2.1`, then enabled WAN A and WAN B with an on-router rollback backup.
Apply hot-reloaded Mihomo; its PID remained 4395. Each WAN exposed 29 independent
nodes (25 reported healthy at verification), and DNSProxy contained 58 members.
Two 1 MiB gRPC sample transfers per WAN all succeeded: WAN A 273/131 ms, WAN B
291/128 ms. Domestic and international lookups through dnsmasq succeeded.

The live check uncovered that this Mihomo build omits provider nodes from
`/proxies` while returning their names in group membership. The API client now
fills missing members from `/providers/proxies`, retaining each node's provider,
health and delay history. A regression test covers two independent WAN members.
The deployed guard dry-run successfully tracked 29 nodes for each WAN without
writing state or changing quarantines. LuCI file checksums matched the build;
its cache stamp was bumped. Existing LuCI sessions need a fresh login for the
new mwan3 read permission.

### Live wire verification

A further production check selected the same VLESS/gRPC sample through
NetCheckProbe, once per WAN, while holding the shared probe lock. Headers-only
tcpdump captures on both WAN devices matched the proxy server's IPv4 endpoint
and TCP port 443; conntrack records independently supplied source IPs, marks
and byte deltas. Each requested payload was exactly 4 MiB:

- WAN A: HTTP 200, 289 ms; 1,615 captured packets on `eth1` versus 3 on
  `eth2`. The corresponding WAN A-source connection had conntrack mark
  256 and received 4,521,864 bytes including protocol overhead.
- WAN B: HTTP 200, 305 ms; 1,482 captured packets on `eth2` versus 50
  on `eth1`. The corresponding WAN B-source connection had mark 512 and
  received 4,282,334 bytes including overhead.

Background traffic/health checks remained active, so the other interface was
not expected to have zero packets. The bulk transfers matched the intended
WAN in both captures and kernel connection state. The probe selection was
restored, captures stopped, and the temporary helper removed. This verifies
actual egress for the sampled node, not every protocol in the subscription.
