# Multi-WAN proxy egress via mihomo — post-mortem + reimplementation notes

**Status: attempted, dropped (2026-06).** The code was fully written, tested, and live-tested on a real
mwan3 router (192.168.214.1: wan1 `br-lan.3000` + wan2 `br-lan.3`), then **removed** because it does not
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
  **fwmark-based** (`ip rule fwmark 0x200/0x3f00 lookup 2` → table 2 → br-lan.3000), so binding to the device
  (SO_BINDTODEVICE) bypasses mwan3's tables and the lookup fails. **This is the same root cause as the
  `curl --interface <dev>` failure below — confirmed on the wire.**
- **`routing-mark`** → mihomo `WANs` group: **"all proxies timeout"**; the healthy WAN (wan1) reported
  `alive:false` and `fallback` stuck on the dead wan2 WAN as `now`.

Crucially, the kernel *can* route both ways — these all succeeded:
- `ip route get <ip> mark 0x200` → `table 2 … dev br-lan.3000` (mark routing resolves).
- `curl --interface br-lan.3000 http://api.browser.yandex.ru/generate_204` → **204** (WAN reachable direct).

### ⚠️ CORRECTION — `curl --interface <dev>` is NOT a valid WAN-liveness test on mwan3

An earlier draft recorded `curl --interface br-lan.3` → `000` as proof that **wan2 (mgts) was dead**. **That
was wrong.** Re-verified on 192.168.214.1 with mgts up and stable:

| test | result |
|---|---|
| `curl --interface br-lan.3` (SO_BINDTODEVICE, **device name**) | `000`, **zero SYN on any interface** (tcpdump empty) |
| `curl --interface 46.138.252.189` (bind mgts **source IP**) | **204** ✅ |
| `ping` via the mgts fwmark `0x100` → table 1 (`8.8.8.8`, tracker `77.88.8.3`) | **0% loss** ✅ |

`--interface <devname>` issues `SO_BINDTODEVICE`, which carries **no fwmark**. mwan3 reaches a WAN's table
only via `ip rule fwmark 0x100/0x3f00 lookup 1`; rule `99: suppress_prefixlength 0` strips the default from
`main` for unmarked traffic, so a device-bound, unmarked socket lands in no per-WAN table — the kernel can't
reconcile `oif=br-lan.3` with the surviving routes and **drops `connect()` before any packet leaves**. The
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
- `interface-name` must be the **kernel device** (`br-lan.3000`), not the netifd name (`wwan1`).
- WAN health-check URL must be reachable **direct** on each WAN; in RU, `http://api.browser.yandex.ru/generate_204`
  works, cloudflare's may not. (This was *not* the blocker, but is needed for correct failover selection.)

## ✅ Isolation test run (2026-06, 192.168.214.1) — resolves plan step 1

Ran the plan's step-1 experiment in full on the live router (separate test mihomo instance, ports 17899 /
ctrl 19099, never touching the production service). **Verdict: mihomo `routing-mark` does NOT take effect on
this box — not via dialer-proxy, not even on a `direct` outbound's own dial.** The whole `direct`+mark
approach is a dead end here.

### What was proven, in order

1. **Kernel honors a pre-set mark (control).** An isolated nft rule stamping `meta mark set 0x100` (priority
   −160, before mwan3's mangle at −150) on ICMP to `8.8.8.8` → **0% loss, ~21 ms via mgts**. So `SO_MARK
   0x100` → `ip rule 2001 fwmark 0x100/0x3f00 → table 1 → br-lan.3` works. The kernel half is fine.
2. **mwan3 does NOT clobber a pre-set mark.** Every mwan3 OUTPUT-hook mark rule is gated on
   `-m mark --mark 0x0/0x3f00` (acts only when the `0x3f00` bits are zero); a packet entering with `0x100`
   already set sails through untouched, and `CONNMARK --save-mark` even persists it for replies. So if mihomo
   set the mark, mwan3 would respect it.
3. **mihomo never sets the mark.** Config: `direct` outbounds `mgts`(`routing-mark: 256`/0x100) and
   `starlink`(`routing-mark: 512`/0x200), plus `node`(`direct, dialer-proxy: mgts`); a `select` group over
   them; dial a dest **not in any nftset** (`8.8.8.8:80`, verified 0 set hits, so no TPROXY capture of the
   non-cgroup-exempt test instance). For **all three** selections the dial's conntrack showed
   **`mark=16128` (0x3f00) and `src=77.50.206.79` (Starlink)** — i.e. it went out *unmarked*, picked up
   mwan3's default `0x3f00`, and took the lowest-metric default route. Never `0x100`/`0x200`, never mgts.
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
