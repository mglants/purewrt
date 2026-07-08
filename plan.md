# PureWRT Improvement Plan

Derived from full-codebase review (2026-07-09): tech quality, UX, ease of use.
Re-verified against current working tree on 2026-07-09.
Status legend: `[ ]` open · `[x]` fixed · `[~]` partially fixed

## Findings

### Tech (Go backend)

| # | Status | Finding | Where | Severity |
|---|--------|---------|-------|----------|
| T1 | [ ] | Monolithic ~825-line switch dispatch; ad-hoc flag parsing (`stripFlag` main.go:86, `stripJSONFlag` main.go:33) per subcommand; no table-driven registry | `cmd/purewrt/main.go:148-972` | Med |
| T2 | [~] | `client_traffic.go` still 1,824 LOC monolith. **Race concern resolved**: goroutines guard shared maps with `sync.Mutex` (d.mu.Lock at :464, :531, :545, :572, :712, :822, :1773). Remaining issue is modularity only → severity downgraded to Med | `internal/manager/client_traffic.go` | Med (was High) |
| T3 | [ ] | Silent UCI parse failures — `if len(fields) < 2 { continue }` (uci.go:34-35); unrecognized directives silently ignored | `internal/config/uci.go:28-55` | Med |
| T4 | [ ] | No `Config.Validate()`; validation only in `manager.Validate()` (manager.go:958), surfaces at apply time | `internal/config/model.go`, `manager.go:958` | Med |
| T5 | [ ] | `updateRuleProvidersAsync` has **no ctx parameter at all** (manager.go:624); goroutine at :691 runs to completion regardless | `internal/manager/manager.go:624-750` | Med |
| T6 | [ ] | Best-effort errors discarded: `_, _ = config.Backup(m.ConfigPath)` (manager.go:518); `dumpMetrics` swallows via `_ = system.AtomicWrite` in notify.go. Intentional best-effort, but unlogged | `manager.go:518, 593`, `notify.go` | Low-Med |
| T7 | [~] | Provider order for full-dedup **is explicit**: `orderedRuleProviders` sorts by priority-then-name (stream.go:161, :366-373). Missing: comment documenting winner semantics | `internal/generator/stream.go:161,366-373` | Low (was Med) |
| T8 | [ ] | Mixin merge failure silently falls back to base config (`if err == nil { return merged } return base`, mihomo.go:18-20); no logging | `internal/generator/mihomo.go:13-21` | Med |
| T9 | [~] | `cmd/purewrt/main_test.go` exists — one test, `TestExitCodeFor` (exit 3 partial vs 1 hard failure). No dispatch/flag-parsing tests | `cmd/purewrt/main_test.go` | Med |
| T10 | [ ] | Only sentinel errors exist (`ErrPartialUpdate` in manager.go, `ErrLockBusy` in system/lock.go); no user-mistake vs I/O vs corrupt-state distinction | cross-cutting | Low |

### User experience & ease of use

| # | Status | Finding | Where | Severity |
|---|--------|---------|-------|----------|
| U1 | [ ] | CLI help unusable — `usage()` is a single comma-separated line, no descriptions/grouping; no `case "help"` (falls to "unknown command" at main.go:970); no per-command `--help` | `cmd/purewrt/main.go:1050-1052` | Critical |
| U2 | [ ] | No progress/phase on long jobs — `start_bg_job`/`poll_bg_job` return only `{running, rc, output}`; static `_('Downloading…')` (subscriptions.js:392) | dispatcher, `subscriptions.js` | High |
| U3 | [~] | Partial validation: `datatype: 'uinteger'/'integer'` on numeric fields (settings.js, ruleproviders.js:468,471). Missing: cron (settings.js:159), URL (settings.js:176,290-292), CIDR, regex | `settings.js`, `sections.js`, `ruleproviders.js` | High |
| U4 | [ ] | Errors still truncated: `.slice(-400)` / `.slice(0,400)` (subscriptions.js:124,129); dispatcher `tail -n 500` (rpcd:127); no collapsible full-error display | dispatcher, `subscriptions.js:124-129` | High |
| U5 | [ ] | Wizard re-run still wipes all config — `m.WizardReset()` (wizard.js:238) unconditional; warning banner exists (wizard.js:332) but no partial-reconfigure path | `wizard.js:238,332` | Med |
| U6 | [~] | Cache mode + rule dedup mode now described (settings.js:222-239); resource profile described in wizard.js:821-824. Remaining: label consistency ("Mihomo binary", DNS "upstreams" terminology) | `settings.js`, `dns.js:83-85` | Low (was Med) |
| U7 | [ ] | Polling hardcoded: `POLL_MS = 3000` (logs.js:56), `setTimeout(..., 2000)` (client_traffic.js:671,790; mihomo.js:270) | LuCI views | Low |
| U8 | [x] | **Review finding was wrong**: `MihomoAutoUpdateEnabled: false` — auto-update is opt-in (model.go:539 area). Channel default is `alpha` but nothing auto-installs without consent. No action needed | `internal/config/model.go:539` | — |
| U9 | [ ] | `wizard.js` 1,546 lines; `zapret.js` 1,091 lines | LuCI views | Low |

### In-flight zapret strategy-tester WIP

| # | Status | Finding | Where | Severity |
|---|--------|---------|-------|----------|
| Z1 | [x] | **Done 2026-07-09**: seams added (`zapretResolveHostFn`, `zapretProbeSitesFn`, `zapretStartCmd`, `zapretFindNFQWS`, `zapretNewRunner`, `zapretResolveBlobFn`, `zapretBindDelay`); new tests cover NFT setup-fail cleanup, blob-resolve failure cleanup, orphan nfqws2 kill-on-return, timeout mid-probe, unresolved-site skip, end-to-end verdict aggregation | `internal/manager/zapret_strategy_tester(_test).go` | — |
| Z2 | [x] | `blockcheckVerdict()` (zapret.js:316-331) emits explicit "output format may have changed" error when markers present but zero strategies parse | `zapret.js:271-331` | — |
| Z3 | [x] | `zapret_blobs` loops all 4 fake dirs, dedups by name (earlier dir wins), no early break | dispatcher :388-409 | — |
| Z4 | [x] | **Done 2026-07-09**: `EnsureZapretBlobs` now resolves all blobs and reports every failure at once (no first-fail abort); `ResolveBlob` rejects zero-byte fetches before caching. Magic-byte check intentionally skipped — fakes are arbitrary binary (TLS/QUIC payloads), no universal magic exists | `zapret_candidates.go` | — |
| Z5 | [x] | No collision: test mark `0x10000000` (tester:28), production zapret `0x40000000` (model.go:612, nftables.go:313), purewrt routing `0x1`/mask `0xff` — disjoint bits. rpcd kills orphans by fwmark filter (:307-308) | verified | — |
| Z6 | [x] | Probes within a candidate run parallel (semaphore 8 = upstream Zapret-Manager PARALLEL=8, intentional per comment :338); candidates sequential by design. 1s bind sleep remains but acceptable | tester:201,338-367 | — |

## Phased plan (updated after verification)

### Phase 1 — Land the WIP safely (uncommitted work first)

1. ~~**Z1** error-path tests + seams~~ — done 2026-07-09.
2. ~~**Z3** fix dir scan~~ — done.
3. ~~**Z2** harden blockcheck parse~~ — done.
4. ~~**Z5** verify fwmark~~ — verified, no collision.
5. ~~**Z4** aggregate blob errors + reject empty fetches~~ — done 2026-07-09.
6. Commit the WIP.

### Phase 2 — CLI help & error surfacing (biggest UX win per effort)

7. **U1 + T1**: structured CLI help — grouped, described command table; `purewrt help [cmd]`. Convert dispatch to table-driven registry (name → {args, desc, handler}). Also makes T9 fully testable.
8. **U4**: stop truncating errors in LuCI — dispatcher returns full output; views render collapsible details.
9. **T6 + T8 + T3**: log best-effort failures and mixin merge failures at WARN; warn on skipped UCI lines.

### Phase 3 — Form validation & progress feedback

10. **U3** (remaining): validate cron/URL/CIDR/regex in LuCI forms (numerics already done).
11. **U2**: background jobs write progress/phase line to status file; views poll and show phase + elapsed. Sweep already streams incrementally — extend to blockcheck/ipdb.
12. **U6** (remaining): label consistency pass only (descriptions largely done).

### Phase 4 — Structural debt (opportunistic)

13. **T2**: split `client_traffic.go` into pcap-decode / flow-state / enrichment files (races already mutex-guarded — modularity only).
14. **T5**: thread context through `updateRuleProvidersAsync`; check ctx.Done() in workers.
15. **T7** (remaining): one comment on `orderedRuleProviders` documenting dedup-winner semantics (sort already explicit).
16. ~~**U8** channel/auto-update defaults~~ — non-issue: auto-update already off by default.
