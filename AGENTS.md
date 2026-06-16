# AGENTS.md — gotchas for agents working on PureWRT

This file collects non-obvious things an agent needs to know to make changes
land correctly on the router. Pure mechanical "go read the code" notes don't
belong here.

## LuCI static-asset cache busting

LuCI mints the `?v=` query string on every `<script src=…>` / dynamic
`L.require(…)` URL as `<revision>-<mtime(/lib/apk/db/installed)>` (see
`/usr/share/ucode/luci/runtime.uc::pkgs_update_time`). The browser uses that
URL as its HTTP cache key. Consequence: **if you `scp` an updated
`/www/luci-static/resources/…` file onto a running router, the browser will
keep serving the cached old version through reloads, Ctrl+Shift+R, `rpcd`
restart, `uhttpd` restart, and even explicit `fetch(url, {cache:'reload'})`** —
because the URL hasn't changed.

Symptoms when you hit this:

- File on disk has the new content (`grep` confirms).
- `fetch(url, {cache: 'no-store'})` returns the new content.
- But the page still renders / behaves as if the old file is loaded.
- `Network` panel would show the old file served from cache (304 or "from
  disk cache"), but its body never updates.

Fix after any `scp` to `/www/luci-static/…`:

```sh
ssh root@<router> '
  touch /lib/apk/db/installed   # bump LuCI version stamp
  rm -rf /tmp/luci-*            # clear LuCI menu/index caches
  /etc/init.d/rpcd restart      # rebuild module dispatch
'
```

Then reload the page (a normal reload is enough — the URL now has a new
`?v=<new-stamp>` suffix). The `apk add purewrt` install flow already
modifies `/lib/apk/db/installed`, so this only bites during `scp`-style
incremental deploys.

A `Taskfile.yml` target wrapping this would be reasonable; we haven't
added one yet. If you're doing rapid LuCI iteration, do it manually.

## SSH access to the test router (192.168.1.1)

- This is a real production router. Reboots interrupt the user's network.
  Don't reboot to test things; use targeted state wipes
  (`nft delete table inet purewrt; ip rule del …`) plus an `apply` to
  verify the self-heal paths.
- Default OpenWrt 25.12 ships busybox `sleep` without fractional-second
  support and busybox `ip rule` without `mark` argument support. Stick
  to integer sleeps; probe routing via `ip route get <ip>` (no `mark`).
- `opkg` is gone in 25.12 — use `apk` (`apk list -I`, `apk add`,
  `apk info -L purewrt`).
- `stat` is not on busybox. Use `ls -la --time-style=…` or read
  `/proc/<pid>/…` directly.

## Deploying `purewrt` Go binaries to the router

Cross-compile + scp pattern (matches the verified Banana Pi BPi-R3 Mini):

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath -ldflags='-s -w' \
  -o /tmp/purewrt ./cmd/purewrt

scp -O /tmp/purewrt root@192.168.1.1:/root/purewrt-new
ssh root@192.168.1.1 'mv /root/purewrt-new /usr/bin/purewrt && chmod +x /usr/bin/purewrt'
```

`-O` forces the legacy SCP protocol because the router runs Dropbear with
no `sftp-server` binary. Don't use the new SFTP protocol (default in OpenSSH
9+) for this host.

Filename collision: if you `scp` two files into the same directory without
distinct destination names, only one keeps the basename. Always rename on
the source side when shipping multiple files (`scp foo root@…:/root/foo-bin`).

## Apply-path drift checks (recently shipped)

`applyNFT` and `applyPolicyRules` in `internal/manager/manager.go` now run a
cheap probe (`nft list table inet purewrt` / `ip rule show | grep fwmark
$FwMark`) before honouring the fingerprint-cache short-circuit. If the live
state has been wiped (by `nft delete`, a buggy `fw4 reload`, a reboot before
the boot apply ran, etc.), apply forces a reload instead of trusting the
fingerprint. Don't undo that — it's the self-heal layer for the
"`apply` succeeded but lists are empty" class of bugs.

## Boot apply must be `--force`

`/etc/init.d/purewrt::start_service` runs `purewrt apply --force` in the
foreground at boot. Without `--force`, `prepare_runtime` writes the
generation fingerprint, the subsequent `apply` sees the fingerprint matches
its inputs, short-circuits all writes including `nft -f`, reports
"applied PureWRT safely", and leaves the live kernel state empty. The
`--force` flag bypasses that and is mandatory at boot.

## Background `update-if-needed` retry loop

`run_bg_with_retries` in the init script wraps the boot's
`update-if-needed` invocation with 3 attempts at 30/60/120 s backoff. The
retry triggers when the Go binary exits non-zero — which it now does on any
per-subscription / per-provider download failure (see `UpdateDetailedWithOptions`
in `internal/manager/manager.go`). The soft-continue behaviour means a single
broken subscription URL doesn't kill the entire update, but the aggregated
error at the end is what fires the retry. Don't merge the two: soft-continue
is for "do as much as we can"; non-zero exit is for "tell the operator + the
retry layer we still have unfinished business".

## Subscription import: User-Agent must default to `mihomo-purewrt`

Some proxy panels (sub-store, v2bx, xboard, etc.) **gate the response
format on the User-Agent**: default UAs get a base64-encoded URI list,
"mihomo*" / "clash*" UAs get a Clash YAML profile. PureWRT's import flow
calls Analyze **twice** — once during `Import()` (no subscription persisted
yet) and again during `UpdateDetailedWithOptions` (using the persisted
subscription's UA, defaulted to `mihomo-purewrt`).

If those two passes see different content types, the import creates **two
proxy providers**: a `main` (type=http, URL=raw, content is base64 garbage
mihomo can't parse) and a `<sub_name>_nodes` (type=file with the YAML
decoded by `DecomposeYAMLProfile`). Only the YAML one is actually usable;
the http one fails silently in mihomo logs.

`downloadOptionsForURL` in `internal/manager/manager.go` therefore defaults
the UA to `mihomo-purewrt` when no subscription/provider matches the URL
yet. **Don't change that fallback to `PureWRT/0.1` or empty** — the wizard's
first-pass analyze will start returning base64 again and the redundant
`main` provider will come back.

## Dnsmasq must be restarted, never reloaded

`/etc/init.d/dnsmasq reload` on OpenWrt is just `procd_send_signal dnsmasq HUP`,
plus a `rc_procd start_service` that no-ops when the procd command/args haven't
changed. SIGHUP makes dnsmasq re-read `/etc/hosts`, `/etc/ethers`, and the
DHCP leases file — **but not the conf-dir**, which is where PureWRT writes
its `nftset=` fragments (`/tmp/dnsmasq.cfg<id>.d/purewrt-*.dnsmasq`).

Consequence: if you call `/etc/init.d/dnsmasq reload` after writing a fragment,
dnsmasq keeps running with whatever nftset directives it had at startup —
which on a fresh boot is **none**, because procd brings dnsmasq up before
PureWRT's boot apply runs. The `dns_*` nftables sets stay permanently empty
and routing-by-domain silently fails.

`applyServiceRestarts` and `restoreAndReload` in
`internal/manager/manager.go` therefore use `/etc/init.d/dnsmasq restart`,
not `reload`. The fingerprint gate (`groups.OpenWrtBundle`) already ensures
this only fires when a conf-dir fragment actually changed, so DNS doesn't
blip on every apply. **Don't change it back to `reload`** — apply tests in
`apply_test.go` assert on the `restart` invocation specifically to catch a
future regression.

## TPROXY'd packets must be accepted at `input` — per LAN source zone

A TPROXY'd connection is delivered to mihomo's **local** listener, so the
packet traverses fw4's `input` chain and must be ACCEPTed there. On a single
`lan` zone with `input ACCEPT` this is free; on multi-VLAN setups where client
zones are `input REJECT` (e.g. `iot`/`guest`/`servers`), the locally-delivered
packet is dropped and **proxied traffic silently fails while direct traffic
works**. The accept must match the **exact** fwmark PureWRT sets in the
prerouting TPROXY rule (`c.Settings.FwMark`/`FwMarkMask`, default `0x1/0xff`) —
a hand-written rule matching a different mask (a real outage was caused by an
`0x8/0xe` rule vs PureWRT's `0x1/0xff`) drops everything.

PureWRT therefore generates, for each zone in `Settings.LANSourceZones`
(`lan_source_zone` UCI list, default `["lan"]`, picked in LuCI → Settings),
into `/etc/config/purewrt-firewall.generated`: a `purewrt_tproxy_accept_<zone>`
rule keyed on `FwMark` (always), plus the DNS-hijack redirect +
`purewrt_dns_accept_<zone>` (when `DNS.HijackLANDNS`). `FirewallRules`
(`internal/generator/firewall.go`) emits them from `c.Settings.FwMark` so the
mark can never drift; `applyUCIDNSFirewall` reconciles by deleting **all**
`purewrt_*` firewall sections (`deletePurewrtFirewallSections`) before
re-importing, so de-selecting a zone removes its rules. Don't hardcode the
mask — always derive it from `c.Settings.FwMark`/`FwMarkMask`.

## Plan files

`~/.claude/plans/*.md` are scratch files for the in-flight task. They get
overwritten between unrelated tasks (the plan-mode workflow does that
automatically). Don't treat them as durable documentation — if something is
worth keeping past the next plan cycle, it goes here (or in the relevant
code comment).
