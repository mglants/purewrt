# Zapret2 (nfqws2) documentation review vs. PureWRT

Source: `sources/todo/Zapret2/` (upstream Zapret2 / nfqws2 docs). This is a
research pass comparing our zapret implementation against the current nfqws2
model, with the concrete changes we adopted. Cross-checked against the actual
code (`internal/generator/zapret.go`, `internal/config/model.go`,
`openwrt/luci/.../view/purewrt/zapret.js`), not just the docs.

## How our pipeline actually feeds nfqws2

- Each enabled `zapret_strategy` on a section with `Action=zapret` becomes one
  `--new`-separated profile in the compiled `NFQWS2_OPT`
  (`ZapretUpstreamConfig`, `zapret.go:92`), prefixed by the three mandatory
  `--lua-init=@<lua>/zapret-{lib,antidpi,auto}.lua` scripts (`zapretLuaInit`).
- **Key mechanic** (`zapretProfileClause`, `zapret.go:146`): if a strategy's
  `Params` already contains `--filter-tcp`/`--filter-udp`, the whole clause is
  `Params` **verbatim** — the `--name=` / port-filter / field-derived flags are
  skipped. All six shipped presets embed `--filter-tcp/udp` in `Params`, so the
  preset `Params` string is exactly what nfqws2 receives. That's why a wrong
  flag in a preset is a real runtime break, not cosmetic.
- Field-driven strategies (Params without a `--filter-*`) get the clause built
  from struct fields — this is the path the new `L7Filter`/`Payload`/out-range
  emission uses.

## Syntax: `--lua-desync`, not `--dpi-desync`

nfqws2's model is `packet → profile filters → --lua-desync=<func>:<args> → Lua
function` (`desync.md`). The legacy nfqws1 flags (`--dpi-desync=`,
`--dpi-desync-repeats=`, `--dpi-desync-fooling=md5sig`, `--dpi-desync-split-pos=`)
are **not** the nfqws2 interface. (`multidisorder_legacy` is itself a
`--lua-desync` variant, not the old flag — the "legacy" refers to segment
ordering behaviour.)

Translation:

| nfqws1 (legacy) | nfqws2 (`--lua-desync`) |
| --- | --- |
| `--dpi-desync=fake` | `--lua-desync=fake:blob=<blob>` |
| `--dpi-desync-repeats=N` | `:repeats=N` |
| `--dpi-desync-fooling=md5sig` | `:tcp_md5` |
| `--dpi-desync-split-pos=` | `:pos=` |

## Desync methods (nfqws2)

`fake`, `multisplit`, `multidisorder`, `fakedsplit`, `fakeddisorder`,
`hostfakesplit`, `syndata`, `oob`, `tcpseg`. All `--lua-desync=<method>:<k=v>:…`
(colon-separated, no spaces). `fake` needs a `blob` **and** fooling — `fake.md:82`:
"минимальный TLS-фейк (обязателен `blob` + fooling)"; minimal form is
`fake:blob=fake_default_tls:tcp_md5`.

Standard blobs (`blob.md:19-63`): `fake_default_tls` (TLS, `--payload=tls_client_hello`),
`fake_default_http` (HTTP, `--payload=http_req`), `fake_default_quic`
(QUIC/UDP, `--payload=quic_initial`).

## Payload / filter flags

- `--payload=<type>` — restrict a desync to a packet type. **Must precede** its
  `--lua-desync` (`последовательность аргументов.md`): `--payload` before
  `--lua-desync`, else the payload filter doesn't apply.
- `--filter-l7=<proto>` — L7 protocol match: `tls,http,quic,wireguard,dht,discord,
  stun,xmpp,dns,mtproto,known,unknown` (needs conntrack).
- `--out-range=-dN` / `--in-range=-sN` — limit desync to the first N data packets
  (CPU + robustness).
- `--filter-tcp=`/`--filter-udp=`, `--hostlist=`, `--ipset=` — profile filters.

## Findings and what we changed

### P0 — broken presets (nfqws2 rejects them) — FIXED

The three UDP presets shipped nfqws1 legacy syntax. Rewritten to nfqws2:

| Preset | Before | After |
| --- | --- | --- |
| `youtube_quic` | `--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6` | `--filter-udp=443 --payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6` |
| `discord_voice_udp` | `--filter-udp=443,50000-65535 --dpi-desync=fake --dpi-desync-repeats=6` | `--filter-udp=443,50000-65535 --payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6` |
| `udp_games` | `--filter-udp=1024-65535 --dpi-desync=fake --dpi-desync-repeats=3` | `--filter-udp=1024-65535 --payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=3` |

### P1 — correctness + capability — DONE

- **TCP fake fooling.** `youtube_tcp`, `googlevideo_tcp`, `rkn_https`: added
  `:tcp_md5` to `fake:blob=fake_default_tls` (fake.md: fooling mandatory).
- **`L7Filter` + `Payload` strategy fields.** New `ZapretStrategy.L7Filter`
  and `.Payload`; emitted as `--filter-l7=` / `--payload=` (payload placed
  before Params so it precedes any `--lua-desync`) in the field-driven clause.
  Exposed in the LuCI strategy editor. Lets a custom strategy target a protocol
  without hand-writing `Params`.
- **Out-range from packet limits.** The `TCPPktOut`/`UDPPktOut` fields were
  stored but never emitted; now rendered as `--out-range=-d<N>` on the
  field-driven path (they remain no-ops for verbatim-Params presets).
- **MTProto preset.** `telegram_mtproto` — `--filter-tcp=443 --filter-l7=mtproto
  --payload=mtproto_initial --lua-desync=fake:blob=0x00000000:repeats=2:tcp_md5
  --lua-desync=multisplit:pos=16`. nfqws2-native; needs conntrack; no hostlist
  (MTProto exposes no SNI — use `--ipset` to scope).
- **Arg-order guard.** Client-side lint warns when a strategy's `Params` puts
  `--lua-desync` before `--payload` (silent-failure trap).

### P2 — deferred (documented, not implemented)

- **Circular orchestration** (`circular.md`): `--lua-desync=circular:fails=…:time=…`
  + `strategy=N[:final]` tags auto-rotate strategies on RST/retransmit. Real
  nfqws2 feature; a sizeable model + generator + UI change. Deferred.
- **Blob management** (`preset.md`): declare `--blob=name:@file` once in the
  header, reference by name. Needs a blob UI. Deferred.
- **Terminology.** Zapret2 "profile" = a `--new` content block; "preset" = a
  full multi-profile file. Our `ZapretProfile` (interface/fwmark/queue binding)
  + `ZapretStrategy` (per-target args) invert that naming. Functional, so left
  as-is (rename = high churn, no behaviour gain).

### Not applicable — WinDivert (Windows only)

`wf.md` and `windivert.md` document the WinDivert filter DSL / `winws2`
(`--wf-*`, `--wf-raw`, kernel-level byte filters). PureWRT runs nfqws2 on Linux
NFQUEUE — none of it applies. Ignored.

### Follow-up (correctness + UX) — DONE

After a second, exhaustive doc pass (all Zapret2 docs + the legacy nfqws v72.2 set), three more
verified items were adopted; the rest confirmed either redundant with our architecture or superseded
by Blockcheck:

- **conntrack always on.** The compiled `NFQWS2_OPT` head now emits `--ctrack-disable=0` alongside
  `--lua-init` (`generator/zapret.go`, `ZapretUpstreamConfig`). `--filter-l7`/MTProto detection
  no-ops without nfqws2's ctrack (`распознавание mtproto.md:49,349`); the `telegram_mtproto` preset
  needed this. Harmless for non-L7 strategies.
- **L7-filter / payload fields — considered, then dropped.** Briefly added as multi-select fields,
  then removed: redundant with the free-form `params` field (which already accepts `--filter-l7=` /
  `--payload=` verbatim), and — because `zapretProfileClause` passes Params verbatim whenever it
  carries its own `--filter-tcp/udp` — they'd have been ignored for every preset-based strategy
  anyway. For an advanced-only feature, one clear way (params) beats two. The arg-order `validate`
  guard on the params field stays. The `telegram_mtproto` preset carries `--filter-l7=mtproto`
  directly in its params.
- **autottl in the fake presets.** Every `fake:` clause now carries
  `:ip_autottl=-2,3-20:ip6_autottl=-2,3-20` (used in 12 real preset profiles); without it the fake's
  TTL can reach the origin and break the connection.

Confirmed out of scope after the legacy review: `--wsize`/`--synack-split`/`--dup*`/HTTP-header
tricks/`tamper`/`udplen` (deprecated or superseded by nfqws2 Lua); `--hostlist`/`--ipset` (redundant
with per-section nftset); `--filter-ssid`, WinDivert (Windows/wifi).

## Notes

- Preset `Params` are only **starting hints**; the merged Blockcheck tool finds
  empirically-working strategies per network. Correct preset defaults still
  matter (they ship enabled-by-name in the dropdown and as config defaults).
- L7 detection (`--filter-l7`, MTProto) depends on conntrack being available.


## LAN-client strategy tester

The Zapret page offers a manual client test alongside router-generated probes.
Choose a DHCP client, a WAN device with a main-table IPv4 default route, and a
catalog candidate. A TCP-only candidate can be paired with a UDP-only candidate;
combined candidates run alone. The direct baseline passes packets unchanged.

A five-minute worker bypasses PureWRT proxy and production Zapret processing for
that client's IPv4 traffic, pins internet egress to the selected WAN, and queues
the first 20 original / 10 reply TCP or UDP packets per connection to a dedicated
nfqws2 instance. Candidate payload and port filters still control modification.
LAN destinations and router DNS retain their ordinary paths. IPv6 internet
forwarding is rejected for the selected client's MAC during this IPv4-only test.
The client must be directly attached and present in the neighbor table.

Restart Discord (or the tested application) after starting each candidate. Check
login/chat and voice independently; queue counters alone do not establish success.
**Add to routing strategies** stages the active or last tested candidate as an
application assignment for the tested WAN. Assign the application to a routing
section before Save & Apply. Testing itself never writes UCI.

Stop, timeout, or nfqws exit removes temporary rules and the private routing table.
Kernel timeout sets also expire the client bypass/mark/IPv6 guard after five
minutes if the worker dies abruptly. A small independent shell timer also terminates the nfqws child if the
Go worker is killed; normal cleanup terminates the private process group. Stop can remove stale owned objects after an interruption. No mwan3
installation is required; the test does not change mwan3 policies. A failed
selected WAN does not silently move the measurement to another WAN.

Reserved runtime resources: queue/table 9908, routing priority 101, route mark
0x08000000, disjoint generated-packet mark 0x10000000 (both routed to the selected
WAN), and the `purewrt_client_test`
nftables table/set/comment. Occupied routing resources fail setup. Blockcheck,
router strategy probes and client sessions share a test lock. Configuration
reloads that remove the client bypass cause the worker to stop. Avoid changing
routing configuration while evaluating a candidate.

The client runner temporarily wraps fw4's flow-add rule with a timed exclusion
for the selected client's conntrack original source. Without it, flow offload
can skip the strategy queue after the TCP handshake. The flowtable is recreated with its original definition in the same nft
transaction at test start (not conntrack/NAT state); unrelated clients
remain eligible for offload. Stop restores the original flow-add expression,
and a fw4 reload terminates the client test. No UCI offload setting is changed.

The client route mark must never overlap nfqws's generated-packet mark: nfqws
skips packets when **any** generated-mark bit is present, not only when the
whole mark matches. A combined fake mark containing the client's route bit
silently passes every client packet unchanged. Separate policy rules at the
reserved priority route each disjoint mark through the same temporary table;
fake packets retain notrack and production-Zapret/proxy exemptions. The
regression test models nfqws's any-bit check with an additional WAN mark.

Live Android validation (2026-10-24): after separating the marks, the user
confirmed browser access, Discord login/chat, and voice with TCP candidate
`online_combo_google` plus UDP candidate `online_voice_zero` from the router's
local candidate catalog. The WAN capture showed generated fake/split TCP
packets followed by server data; voice success was user-confirmed. This is a
single-client/WAN result, not a universal preset guarantee. The temporary
session was stopped afterward; both priority-101 routing rules and the test
nftables table were removed, leaving the production queue running. No
production strategy was saved. Earlier failed rotations with overlapping
marks are not valid evidence against those strategies.

During an active session, **Switch strategy** (CLI: `purewrt zapret-client-switch
<candidate> [extra-candidate]`) changes candidates without stopping client
routing. The worker starts a replacement nfqws on the spare queue (9908/9910),
waits for attachment, then replaces the three queue destinations in one nft
transaction before stopping the previous process. Client/WAN selection,
policy rules, bypass sets, offload exclusion, counters and the original
five-minute deadline remain unchanged. Preparation or transaction failure
leaves the previous candidate active and reports the error. Stop remains
available; switching does not prolong the session. There is a brief overlap
of two nfqws instances during preparation, not a permanent extra daemon.
Reconnect the application to evaluate a fresh handshake: switching strategies
does not recreate existing connections or transfer nfqws's connection state.

### Local strategy library

The Zapret page's **Strategy library** can create, duplicate, edit, delete,
import and export individual JSON candidates. Catalog entries are read-only sources: duplicate them to create a `user_`
entry. Configured routing strategies stay in their own table and are not
duplicated in the library or tester candidate lists.
Both client and router testers see these entries immediately. Saving a library
entry does not apply routing. The client tester's **Add to routing strategies** stages the
candidate as an application assignment for the tested WAN. It never creates a profile. Assign the strategy to a routing
section, then Save & Apply when ready.

User entries live in `/etc/purewrt/zapret_user_candidates.json`, separately from
catalog downloads. The library is limited to 128 entries and 1 MiB. Parameters
must include their TCP/UDP filters; process options and script imports are not
accepted. Saves check protocols, ports and blob aliases, resolve referenced
files, and run the installed nfqws2 in dry-run mode before an atomic write.

Choose packaged `.bin` files or upload a custom blob (nonempty, at most 64 KiB).
Uploads are stored under `/etc/purewrt/blobs/` with content-derived filenames;
the returned reference includes its SHA256. Missing custom files are reported
locally rather than downloaded from the catalog. JSON export includes blob
references, not binary contents; upload custom files separately on another
router. Deleting a library entry keeps uploaded files and saved routing
strategies intact, since either may still reference them.

Dry-run validates engine options, not whether a strategy bypasses DPI. Some Lua
function errors appear only when matching packets are processed; a successful
save still needs a live test.

Applications store library references rather than copies of parameters, ports
or blob declarations. Config loading resolves references in memory, so library
edits affect the next apply and participate in generation fingerprints. Missing
references fail explicitly. Deleting or renaming a referenced user entry is
rejected. For a combined TCP/UDP test, the tester reuses an existing combined
entry or creates one user library entry and references it.

### Application WAN assignments (current configuration)

Zapret configuration now consists of applications, each with a library strategy
reference per WAN device. The old user-configured profiles, custom inline
routing strategies and per-entry queue settings are removed; there is no
compatibility loader or automatic migration. Routers not using Zapret need no
entries. The existing test router was migrated explicitly.

```uci
config zapret_strategy 'zs_discord'
    option enabled '1'
    list assignment 'wan_a=user_discord_a'
    list assignment 'wan_b=user_discord_b'

config section 'sec_discord'
    option action 'zapret'
    list zapret_strategy 'discord'
```

The Zapret application editor assigns library strategies to selected WAN devices.
An unassigned interface is not processed. A section selects the application once.
The client tester's **Add to routing strategies** updates only the tested WAN
assignment in the named application; it preserves assignments for other WANs.
Blockcheck winners save to the library before application assignment.

The loader expands applications to internal runtime profiles in one shared
daemon and queue. Multiple devices using the same library entry within an
application share a selector. Generated packet marks and binary/Lua locations use the standard runtime
defaults. Runtime instances are never serialized back to UCI. Assignment
validation rejects duplicate devices, invalid names and missing candidates.
Library deletion/rename checks include disabled applications. Uncovered WANs
have no Zapret processing; there is no automatic proxy fallback.

### Shared-process investigation (2026-10-24; historical experiments)

The installed nfqws2 build supports `--filter-mark=mark/mask`. Upstream
`nfq2/desync.c::dp_match` compares `(packet_mark & filter_mask) == filter_mark`
before protocol/host filters. This permits nftables to retain application
classification while several application strategies share one process.

An isolated loopback experiment used temporary queue 9909 and a temporary
OUTPUT table matching only 127.0.0.1 TCP ports 49091–49093. Two nfqws profiles
had identical port filters, with selectors 0x10000/0xff0000 and
0x20000/0xff0000. Debug output selected profile A, profile B, and default
no-action respectively for marks 0x10000, 0x20000 and 0x30000. The table and
process were removed afterward; production queue 200 stayed running.
This confirms mark-based selection, not full production shared-process
correctness. The current production process showed about 1992 KiB RSS;
that is not a measured saving from consolidation.

A reasonable next design is one queue/process per used WAN, with application
selectors set immediately before NFQUEUE in both directions. Every `--new`
clause must receive its selector. Reserve and validate a disjoint selector
mask (the experiment's mask is not a committed allocation); preserve mwan3,
TPROXY, client-test and fake-packet mark bits. Account for nfqws's cached
per-flow profile, replayed packets, fake-packet mark propagation and cleanup
of selector bits. Keep bind-fix and existing offload exclusions. Validate
TCP, UDP, IPv6, overlapping section rules and WAN failure/recovery before
switching production. No new dependency on mwan3 is necessary: existing
incoming/outgoing device matches supply the WAN selection.

Sources: upstream docs/manual.en.md (`--filter-mark`), and nfq2/desync.c
(`dp_match`, `play_prolog`, `dp_rediscovery`) in bol-van/zapret2.

An additional isolated router-originated IPv4 HTTPS test fetched
`https://discord.com/login` through two WANs. Each temporary process contained
a no-action baseline profile and the saved Discord TCP/UDP candidate, selected
by separate mark values. On both WANs the baseline timed out after five seconds;
the Discord TCP strategy returned HTTP 200 twice per WAN (about 75 KB per
response). TLS completion took 79–95 ms. Debug logs confirmed selection of
`discord_working` and execution of `hostfakesplit`; interface captures and
bidirectional queue counters confirmed traffic on both WANs. Each temporary
process used approximately 2 MiB RSS after the probes.

The first port-scoped attempts were invalid: curl did not use the requested
local ports, leaving queue counters zero. The successful run classified only
router-originated HTTPS to the test address, set its WAN mark after mwan3,
and restored the selector on replies using conntrack. Temporary rules and
processes were removed; production queue 200 stayed running. This validates
the TCP strategy in a shared process, not client forwarding, Discord voice,
IPv6, memory savings at scale, or live WAN failover.

A subsequent authorized failover test used the existing primary/secondary
mwan3 policy for the isolated router-originated Discord HTTPS probes, without
binding curl to a device or hardcoding its WAN mark. Both requests returned
HTTP 200 on the primary. After `mwan3 ifdown` disabled the primary, both new
requests returned HTTP 200 on the secondary; primary queue counters stayed
unchanged while secondary counters increased. After `mwan3 ifup`, both new
requests returned HTTP 200 on the primary again. Debug logs selected the
Discord profile in the respective per-WAN process. The primary was restored
and temporary rules/processes removed. This exercises policy failover for new
IPv4 HTTPS connections, not tracker detection time, physical link failure,
established-session migration, forwarded clients, or voice continuity.

The same test was then repeated with one process and one queue (9920) for
both WANs. Separate selectors 0x20000 and 0x30000 chose distinct profile
blocks containing the same known-working Discord TCP/UDP parameters. All
six HTTPS requests across primary, disabled-primary fallback, and restored
primary phases returned HTTP 200. Two concurrent request loops then completed
ten requests per WAN, all HTTP 200. Logs selected the primary profile 14 times
and secondary profile 12 times; both devices' bidirectional rules fed the same
queue. Queue and userspace drop counters were zero. Final RSS was 2144 KiB,
versus roughly 4 MiB summed RSS for the earlier two-process experiment (RSS
double-counts shared pages, so this is not a precise physical-memory saving).
This supports a single-process implementation for functionality at light
load; it is not a throughput/CPU saturation benchmark or a UDP voice test.
WAN state and production routing were restored and test resources removed.

### Shared production daemon

Generation now emits one `shared` nfqws2 instance on queue 200. Application
WAN assignments remain unchanged in UCI. Each distinct application/strategy
combination receives a runtime selector in reserved bits `0x00ff0000` (up to
255 combinations); assignments using the same library entry within an
application share a selector. Every `--new` clause, including combined TCP/UDP
strategies, receives the selector filter. Blob aliases are namespaced per
selector so two library entries cannot overwrite one another's fake data.

Outgoing rules select by destination, ports and actual egress device, in
section priority order. They preserve other packet/connection mark bits and
store the selector in conntrack. Once classified, a flow cannot fall into a
later strategy after its initial packet budget is exhausted. A dedicated reply
chain restores that selector before queueing replies on the assigned ingress
WAN. Later base chains clear the packet selector bits; connection selector bits
remain for the lifetime of the flow. Routing remains the responsibility of
OpenWrt/mwan3. Fake-packet bypass and `--bind-fix4/6` remain enabled.

Apply rejects conflicts with active IPv4/IPv6 policy-routing masks, even with
proxy WAN generation disabled. Routers without Zapret assignments do not run
these probes or launch the daemon. Runtime status reports a single process;
per-section outgoing queue counters remain available. Fingerprints include
resolved strategies so library edits regenerate both nftables and daemon
parameters. This replaces multiple production processes; the temporary client
tester continues using its own isolated queue/process.

Deployment and verification of this implementation are recorded below.

### Shared-daemon deployment verification (2026-10-24)

The implementation was subsequently deployed and tested. Full Go tests passed;
additional regressions cover compound TCP/UDP selectors, conflicting blob
aliases, routing-mask conflicts, and daemon restart behavior. Live testing found
and fixed two apply/routing gaps: changed Zapret env now restarts its service
(and rollback restarts the restored env), and router OUTPUT follows section
priority rather than configuration order.

A temporary Discord routing section exercised generated production rules and
queue 200 alongside the existing YouTube application. Six Discord HTTPS
requests passed across primary, secondary failover and primary restoration,
with the same shared PID throughout. Ten additional requests passed in two
concurrent WAN loops. Queue and userspace drop counts remained zero; shared
RSS after these requests was 2316 KiB. The temporary section and policy rules
were removed and the primary WAN restored. This validates router-originated
IPv4 HTTPS and the deployed apply path; Android voice, forwarded-client
traffic, IPv6 traffic and sustained throughput are not covered by this test.
