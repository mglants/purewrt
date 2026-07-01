# VPN routing in PureWRT — design, trade-offs, and the kernel fast-path escape hatch

This document records **why VPN routing goes through mihomo**, how it works, and an executable recipe to
**reintroduce an optional kernel fast-path** later if a real need appears. Hand this file back to the agent
("implement the kernel fast-path from docs/vpn-routing.md") and it has everything required.

## Current model: VPN = a mihomo proxy backend

A VPN is just `{Name, Enabled, Interface}` (`internal/config/model.go`). It is exposed to mihomo as a
`type: direct` outbound bound to the tunnel interface:

```yaml
proxies:
  - name: vpn_<name>
    type: direct
    interface-name: <iface>     # SO_BINDTODEVICE → egress that tunnel
```

A proxy section (`Section.VPNs []string`) and/or DNS (`DNS.VPNs []string`) select VPNs by name. Those
join the section's / DNSProxy's mihomo proxy group **pooled with subscription nodes**
(`writeProxyGroup` emits `use: <providers>` + `proxies: [vpn_*]`), so the whole section runs through
mihomo with its url-test/select/load-balance + filter + strategy + health-check.

Data path:

```
client pkt → nft TPROXY → mihomo listener → mihomo relays into socket bound to tunnel iface
           → kernel tunnel crypto (e.g. WireGuard) → wire
```

There is **no** kernel VPN marking, no per-VPN `ip rule`/route table, no masquerade. mihomo is cgroup-exempt
in the nft output chain, so its own egress is not re-captured (no loop), and router-originated traffic
sources from the tunnel IP (no masquerade needed). See `AGENTS.md` → "VPN routing is a mihomo proxy
backend".

## Why mihomo, not kernel routing (the decision)

| | Kernel native (old `action=vpn`) | mihomo proxy backend (current) |
|---|---|---|
| Throughput | Multi-Gbps, crypto-bound, low CPU | Userspace relay, ~hundreds Mbps–~1.5 Gbps/flow, CPU-bound |
| Latency | Minimal (in-kernel) | +sub-ms userspace hop |
| Failover | **None** — dead tunnel = dead routing | url-test auto-failover across VPNs + nodes |
| Health-check | None | Per-group, mihomo-native |
| Per-section / per-domain selection | Coarse | Full (sections, DNS, mixed pools) |
| Mix VPN + subscription nodes | No | Yes, one pool |

**Decision: mihomo is the default.** Rationale for this product (censorship-bypass router, wan1/LTE
uplinks ~50–300 Mbps):

- The userspace overhead is **moot** — mihomo's relay ceiling sits above the real WAN speed, so the link is
  the bottleneck, not mihomo.
- The actual failure mode is **tunnels dying/being blocked**, which kernel routing could not survive;
  mihomo's failover does. Reliability > raw throughput here.
- Per-section/DNS selection + mixing VPNs with subscription nodes is core to a resilient bypass setup.

Cheap ways to narrow the throughput gap without architecture change: ensure mihomo uses all cores
(GOMAXPROCS), TCP Fast Open, sniffer off where unused. The shipped FD-limit fix (mihomo init raises nofile
to 1,000,000 via a `ulimit` exec wrapper — `procd_set_param limits` is clamped by pid-1's hard limit)
removed the real-world failure mode (connection exhaustion), which hurt far more than relay overhead.

## When to reintroduce a kernel fast-path

Only if a **measured** need appears that mihomo can't meet:

- A single high-throughput VPN must saturate a **gigabit+** LAN→VPN path, and the router CPU (not the WAN)
  is the proven bottleneck, **and**
- That section can accept **no failover/health-check** (kernel routing is dumb: one tunnel, no probing).

If you just want "more speed" on a sub-gigabit WAN, this won't help — don't build it. Measure first
(`iperf3` through the section; check mihomo CPU at the target rate).

## Recipe: add an opt-in kernel fast-path section (coexists with the mihomo pool)

Design: a per-section opt-in that routes a **single-VPN** section in the **kernel** (mark → ip rule →
table → iface) instead of TPROXY→mihomo. mihomo is bypassed for that section; it gets max speed and loses
failover/health. All other sections keep the mihomo pool. This is **additive** — do not remove the mihomo
path.

Most of the old kernel-VPN code was deleted in the "unify VPN into mihomo" change; recover exact snippets
from git history (`git log -p -- internal/generator/mwan3.go internal/generator/nftables.go` around that
commit) rather than rewriting from scratch.

### 1. Config (`internal/config/model.go`, `uci.go`, `write.go`)
- Add `Section.KernelFastPath bool` (uci `kernel_fastpath`). Meaningful only when the section is
  `action=proxy`, has **exactly one** VPN in `Section.VPNs`, and **no** subscription providers in its pool
  (kernel can't pool/failover). Validate that in `manager.go` (reject fast-path with >1 VPN or with nodes).
- Re-add the per-VPN kernel fields, but **derived, not user-set**: a helper `kernelVPNParams(c, name)` that
  returns `{FwMark, FwMarkMask, RouteTable, IPRulePriority}` derived by VPN index (old `NormalizeVPN`:
  `FwMark=0x2<<i`, `RouteTable=200+i`, `IPRulePriority=110+i`, mask from `Settings.FwMarkMask`/`0xff`). Keep
  the `VPN` struct otherwise minimal. **Guard the fwmark against the zapret/PureWRT mark overlap** (restore
  the check removed from `validateZapretProfileMarks`).

### 2. nftables (`internal/generator/nftables.go`)
- For a fast-path section, in **prerouting** (and the device/source rules), instead of the proxy TPROXY
  arm, emit the old vpn mark rule:
  `ip daddr @<set> meta mark set meta mark | <fwmark> accept` (+ ip6). This is the exact code removed in the
  unify change — restore it gated on `s.KernelFastPath`.
- In **output_mangle**, same: mark the section's dest set with the VPN fwmark (router-originated).
- Optional masquerade: re-add `oifname "<iface>" masquerade` only if a new `VPN.Masquerade` (or section)
  flag is set; default off (tunnel-IP-sourced router traffic returns fine; LAN clients need it only when the
  peer doesn't route LAN back).
- Do **not** emit a mihomo TPROXY arm or listener for a fast-path section (skip it in the proxy loop and in
  `mihomo.go`).

### 3. ip rule / route (`internal/generator/mwan3.go` `PolicyCommandArgs`)
- For each VPN referenced by a fast-path section, re-add:
  ```
  ip rule add priority <prio> fwmark <fwmark>/<mask> table <table>
  ip route replace default dev <iface> table <table>
  ```
  (+ `ip -6` variants). Restore the loop removed in the unify change, but iterate **only fast-path VPNs**.
- Apply already runs `PolicyCommandArgs` via `applyPolicyRules`; the existing `ip rule del`/drift-check
  pattern cleans up. **Add cleanup of stale rules** when a section leaves fast-path (the unify change had a
  one-time orphan-rule gap — delete old fast-path `ip rule`/table on apply).

### 4. mihomo (`internal/generator/mihomo.go`)
- Skip listener + proxy-group + `IN-NAME` rule for a fast-path section (it never enters mihomo). Still emit
  `vpn_<name>` proxies / groups for the non-fast-path sections.

### 5. Fingerprint (`internal/generator/fingerprint.go`)
- `KernelFastPath` rides in via `sections` (already hashed by `mihomo`, `openwrt_bundle`, `policy` groups).
  The derived fwmark/table affect nft + policy → ensure those groups see them (they hash `sections`; add the
  derived params to the hashed section entry if the bool alone isn't enough).

### 6. LuCI (`openwrt/luci/.../sections.js`)
- Add a `form.Flag` `kernel_fastpath` on a proxy section, `depends('action','proxy')`, with a description:
  "Route this section in the kernel for max throughput — requires exactly one VPN member and no subscription
  nodes; loses health-check/failover." Show it only meaningfully when the section has one VPN.

### 7. Tests
- `nftables_test`: fast-path section ⇒ `@<set> … mark | <fwmark> accept`, **no** TPROXY arm/listener for it;
  non-fast-path sections still TPROXY + appear in mihomo groups.
- `mwan3` test: fast-path VPN ⇒ `ip rule add … fwmark <fwmark>/<mask> table <table>` + `ip route … dev
  <iface>`; non-fast-path VPNs produce none.
- validation: fast-path with >1 VPN or with providers ⇒ error; fwmark overlap with zapret ⇒ error.
- fingerprint: toggling `kernel_fastpath` flips the relevant group hashes.

### 8. Verify on the router
- `iperf3` through the section before/after; confirm the kernel path beats the mihomo path at the target
  rate and CPU drops.
- `nft list table inet purewrt` → fast-path section marks (no TPROXY); other sections unchanged.
- `ip rule show` → the fast-path VPN rule present; `ip route show table <table>` → default dev `<iface>`.
- Kill the tunnel → confirm the fast-path section has **no** failover (expected; that's the trade), while
  mihomo-pool sections still fail over.

### Guardrails
- Fast-path is **opt-in and additive** — never the default, never removes the mihomo path.
- Keep the fwmark scheme disjoint from PureWRT's `0x1` TPROXY mark and zapret's `0x40000000` (the old
  `0x2<<i` scheme is fine; restore the overlap validation).
- Document the loss of failover/health prominently in the LuCI description and `AGENTS.md`.
