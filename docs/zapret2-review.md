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
