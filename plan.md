# PureWRT Improvement Plan

Derived from full-codebase review (2026-07-09): tech quality, UX, ease of use.
Re-verified against current working tree on 2026-07-09.
Status legend: `[ ]` open · `[x]` fixed · `[~]` partially fixed

## Findings

### Tech (Go backend)

| # | Status | Finding | Where | Severity |
|---|--------|---------|-------|----------|
| T1 | [x] | **Done 2026-07-09**: switch replaced by table-driven `commands` registry (name/aliases/group/args/desc/handler) + `lookupCommand`; registry test guards uniqueness and help coverage | `cmd/purewrt/main.go` | — |
| T2 | [x] | **Done 2026-07-09**: split into client_traffic.go (597 — types, entry points, emit), _pcap.go (562 — packet/DNS/TLS/QUIC decoding), _flow.go (338 — conntrack/flow state), _enrich.go (377 — ASN/hostname/nftset enrichment). Pure code movement; races were already mutex-guarded | `internal/manager/client_traffic*.go` | — |
| T3 | [x] | **Done 2026-07-09**: parser warns on stderr with file:line for malformed lines, valueless options, options outside sections, unknown directives (`parseWarn`, uci.go) | `internal/config/uci.go` | — |
| T4 | [ ] | No `Config.Validate()`; validation only in `manager.Validate()` (manager.go:958), surfaces at apply time | `internal/config/model.go`, `manager.go:958` | Med |
| T5 | [x] | **Done 2026-07-09**: fan-out takes a context with 10-min `ruleProviderUpdateBudget`; queued workers stop on cancellation instead of firing new downloads. (In-flight downloads still not ctx-aware — would need provider.DownloadWithOptions API change) | `internal/manager/manager.go` | — |
| T6 | [x] | **Done 2026-07-09**: `config.Backup` warns centrally on stderr (covers all 8 best-effort call sites); `dumpMetrics` logs WARN on write failure | `internal/config/write.go`, `notify.go` | — |
| T7 | [x] | **Done 2026-07-09**: `orderedRuleProviders` doc comment states the sort is load-bearing for full-dedup winner selection | `internal/generator/stream.go` | — |
| T8 | [x] | **Done 2026-07-09**: mixin merge failure warns on stderr that the generated config lacks the user's overrides | `internal/generator/mihomo.go` | — |
| T9 | [~] | **Improved 2026-07-09**: registry tests added (`TestCommandRegistry` — name/alias uniqueness, help metadata, group coverage; `TestLookupCommand` — alias resolution) alongside `TestExitCodeFor`. Handler bodies still untested (they shell out to Manager) | `cmd/purewrt/main_test.go` | Low |
| T10 | [ ] | Only sentinel errors exist (`ErrPartialUpdate` in manager.go, `ErrLockBusy` in system/lock.go); no user-mistake vs I/O vs corrupt-state distinction | cross-cutting | Low |

### User experience & ease of use

| # | Status | Finding | Where | Severity |
|---|--------|---------|-------|----------|
| U1 | [x] | **Done 2026-07-09**: `purewrt help` prints commands grouped by area with descriptions; `purewrt help <cmd>` gives per-command synopsis + aliases; `-h`/`--help` work; unknown command prints a hint to stderr | `cmd/purewrt/main.go` | — |
| U2 | [x] | **Done 2026-07-09**: `bg_job.run()` takes an `onProgress` callback ({elapsedMs, output} per poll); provider-update UI shows elapsed + last log line live, ipdb download shows elapsed seconds; zapret blockcheck/sweep already streamed | `bg_job.js`, `update_async.js`, views | — |
| U3 | [x] | **Done 2026-07-09**: shared `validateCron`/`validateHTTPURL`/`validateCIDR` in purewrt.format; wired into settings (crons, URLs), subscriptions (cron, URL), rule/proxy provider URLs, IP/CIDR add-modal | `format.js` + 5 views | — |
| U4 | [x] | **Done 2026-07-09**: `fmt.errorDetails` renders summary + full output in collapsible details; all `.slice(400)` sites replaced (subscriptions, diagnostics, save_chain); `poll_bg_job` tail 500→1000 lines | `format.js`, views, dispatcher | — |
| U5 | [ ] | Wizard re-run still wipes all config — `m.WizardReset()` (wizard.js:238) unconditional; warning banner exists (wizard.js:332) but no partial-reconfigure path | `wizard.js:238,332` | Med |
| U6 | [x] | **Done 2026-07-09**: "Mihomo binary path"/"Mihomo config path" labels + descriptions, update-channel description (alpha=prerelease, auto-update opt-in), DoH upstreams description added | `settings.js`, `dns.js` | — |
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

### Phase 2 — CLI help & error surfacing — DONE 2026-07-09 (commit 0629a70)

7. ~~**U1 + T1** registry + grouped help~~ — done.
8. ~~**U4** full errors, collapsible details~~ — done.
9. ~~**T6 + T8 + T3** loud fallbacks~~ — done.

### Phase 3 — Form validation & progress feedback — DONE 2026-07-09

10. ~~**U3** cron/URL/CIDR validation~~ — done.
11. ~~**U2** live progress on background jobs~~ — done.
12. ~~**U6** label/description pass~~ — done.

### Phase 4 — Structural debt

13. ~~**T2** split `client_traffic.go`~~ — done (4 files, no behavior change).
14. ~~**T5** context in update fan-out~~ — done (10-min budget; in-flight downloads still not ctx-aware).
15. ~~**T7** dedup-winner comment~~ — done.
16. ~~**U8** channel/auto-update defaults~~ — non-issue: auto-update already off by default.

### Remaining open (not scheduled)

- **T4** — no `Config.Validate()`; validation stays in `manager.Validate()` (works, surfaces at apply time; a config-side validator is a larger refactor).
- **T10** — structured error taxonomy (only `ErrPartialUpdate`/`ErrLockBusy` sentinels exist).
- **U5** — wizard still resets everything on re-run (warning banner exists; partial-reconfigure is a feature design question).
- **U7** — polling intervals hardcoded (3s logs / 2s traffic) — cosmetic, low value.
- **U9** — wizard.js/zapret.js single-file size — cosmetic.
- **Z6 residue** — 1s nfqws bind sleep (now a `zapretBindDelay` var, tunable).
