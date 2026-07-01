# Resilient DNS — keep the router resolving when every proxy node dies

**Status: investigated + live-tested on 192.168.214.1 (2026-06). Design proven, not yet
implemented in the generator.** This documents the problem, the experiments run against the
production router, what they proved (incl. dead ends), the proven design, and the one open
design decision before coding.

## Problem

If every proxy node dies / gets censored, the router currently **loses DNS for all LAN
clients** — total outage, recoverable only by manual `purewrt disable`. A proxy outage must
degrade to "router still resolves, direct/domestic sites work", not "dead router".

Why it breaks today (confirmed):
- `dns:` uses `respect-rules: true` (`internal/generator/mihomo.go`), so every DNS-upstream
  connection follows the routing `rules`. `nameserver` (foreign DoH) connections hit
  `DOMAIN-SUFFIX,dns.google,DNSProxy` etc. → proxy groups; the catch-all `MATCH,Common`
  pushes the rest through proxy too. All nodes dead → no alive node → DNS-upstream fails.
- dnsmasq is locked to mihomo: `noresolv=1`, sole `server=127.0.0.1#7874`
  (`internal/generator/dns_uci.go`), `peerdns=0` on WANs → no independent fallback resolver.

## Experiments run on 192.168.214.1 (production)

Method: block mihomo's egress to the 9 proxy node IPs with a top-inserted
`nft ... tcp dport 443 drop` in `inet fw4 output` (the rule must be **inserted/prepended** —
appended, an earlier accept rule matches first and the block is a no-op), force-reload a
candidate `/etc/purewrt/generated/mihomo.yaml` via the controller
(`PUT /configs?force=true {"path":...}`, which also clears the DNS cache), then `nslookup`
**never-before-queried** foreign domains (gnu.org, freebsd.org, openbsd.org, wireguard.com)
so cache can't mask the result. Every run was wrapped in a `trap cleanup EXIT` that removes
the nft rule, restores the original config, and reloads — prod always returned to normal.

### Findings (in order)

1. **`direct-nameserver` does not help foreign domains.** mihomo **resolves before it routes**.
   `direct-nameserver` (Yandex) is consulted only for domains matched DIRECT by a *domain* rule —
   not for the post-resolution catch-all. So foreign-domain resolution always rides the proxied
   `nameserver`/`DNSProxy` path. Dead proxy → dead.

2. **Forcing the catch-all to DIRECT does not help foreign DNS.** Set `MATCH,DIRECT` + block:
   fresh foreign domains still failed (drop counter climbing — mihomo still hammering the dead
   proxy *for DNS*). Routing changes fix *where traffic goes*, not *how DNS resolves*. The
   resolver path stays proxied. The 300s natural health-flip has the same limitation — it only
   flips routing, never the resolver — so it was not worth a 5-minute prod proxy outage to watch.

3. **mihomo `fallback` fails *closed*.** Candidate: `nameserver` = domestic Yandex DoH,
   `fallback` = foreign DoH, `fallback-filter {geoip: true, geoip-code: RU}`. With the fallback
   servers dead, a foreign (non-RU) domain that `fallback-filter` routes to the fallback list
   **does not** degrade to the `nameserver` answer — it just fails. So mihomo `fallback` is a
   strict anti-poison mechanism, **not** a resilience mechanism. **Drop `fallback` entirely.**
   (Independently, configuring `fallback` auto-enables `fallback-filter` with `geoip-code: CN`,
   wrong for RU — already a reason it was removed earlier.)

4. **Proven working design.** `nameserver` = **domestic Yandex DoH**, **direct-routed**
   (`DOMAIN-SUFFIX,yandex.net,DIRECT` + `IP-CIDR,77.88.8.8/32,DIRECT,no-resolve` /
   `77.88.8.1/32` so the resolver bypasses the dead proxy), **no DNS `fallback`/`fallback-filter`.**
   With all 9 proxies blocked, all four fresh foreign domains resolved to real IPs:

   ```
   gnu.org:       209.51.188.116
   freebsd.org:   96.47.72.84
   openbsd.org:   199.185.178.80
   wireguard.com: 192.248.189.215
   ```

   drop counter only 256 (DNS no longer chasing the dead proxy). Router keeps resolving
   everything when proxies are 100% dead.

## The trade-off this exposes

Yandex resolving *everything* means truly **DNS-censored domains get poisoned answers while
proxies are alive** → the proxy dials the poison IP → censored sites **break**. That is a
regression vs. today's foreign-DoH-for-all behaviour.

So a domestic-first `nameserver` is **only correct together with** a `nameserver-policy` that
sends the **censored / proxied domain sets → foreign DoH (via proxy)** for unpoisoned IPs,
leaving everything else on domestic Yandex.

Net behaviour:
- **proxies alive:** censored/proxied domains → foreign DoH (real IPs, sites work); everything
  else → Yandex (fine, real IPs for uncensored).
- **proxies dead:** censored-domain DNS fails (those sites are unreachable anyway); **everything
  else resolves via Yandex → router works.**

`nameserver-policy` is therefore **mandatory**, not optional.

## Proven candidate `dns:` + `rules:` shape

```yaml
dns:
  enable: true
  listen: 127.0.0.1:7874
  ipv6: false
  enhanced-mode: normal
  use-hosts: true
  respect-rules: true
  proxy-server-nameserver:   # domestic — resolve proxy node addresses, reachable in-country
    - 77.88.8.8
    - 77.88.8.1
  default-nameserver:        # domestic — bootstrap the DoH hostnames
    - 77.88.8.8
    - 77.88.8.1
  direct-nameserver:         # domestic — direct-routed domains
    - https://common.dot.dns.yandex.net/dns-query
  nameserver:                # domestic default — RESILIENT (direct-routed, see rules below)
    - https://common.dot.dns.yandex.net/dns-query
  nameserver-policy:         # TODO: censored/proxied domain sets → foreign DoH (unpoisoned)
    # "<proxied domain sets>":
    #   - https://dns.google/dns-query
    #   - https://cloudflare-dns.com/dns-query
    #   - https://dns.quad9.net/dns-query
  # NO fallback / fallback-filter

rules:
  # domestic resolver must bypass the (possibly dead) proxy:
  - DOMAIN-SUFFIX,yandex.net,DIRECT
  - IP-CIDR,77.88.8.8/32,DIRECT,no-resolve
  - IP-CIDR,77.88.8.1/32,DIRECT,no-resolve
  # foreign DoH still proxied (for the nameserver-policy'd censored domains):
  - DOMAIN-SUFFIX,dns.google,DNSProxy
  - DOMAIN-SUFFIX,cloudflare-dns.com,DNSProxy
  - DOMAIN-SUFFIX,dns.quad9.net,DNSProxy
  - IP-CIDR,1.1.1.1/32,DNSProxy,no-resolve
  - IP-CIDR,8.8.8.8/32,DNSProxy,no-resolve
  - IP-CIDR,9.9.9.9/32,DNSProxy,no-resolve
  - IN-NAME,tproxy-VPN,VPN
  - IN-NAME,tproxy-media,Media
  - IN-NAME,tproxy-ai,AI
  - IN-NAME,tproxy-common,Common
  - MATCH,CatchAll
```

(`CatchAll` = `type: fallback` over `[Common, DIRECT]` — already shipped; the proxy-group
`fallback` type is unrelated to the DNS `fallback:` key that we drop.)

## Open design decision (before coding)

**Which domains feed `nameserver-policy` → foreign DoH?** These are the domains that need
*unpoisoned* (foreign) DNS, i.e. the DNS-censored ones. Recommendation: reuse the **section
domain rule-providers** (the domains already TPROXY'd) — if you proxy a domain you generally
want its real IP. Sub-question: express them as **`rule-set:` refs** in `nameserver-policy`
(mihomo supports rule-set/geosite keys) vs. **inlining** the domain list. Decide before coding.

Risk to weigh: this widens the poison surface for any proxied domain *not* in the policy
(resolved domestically). Conversely, putting too much in the policy shrinks resilience (those
fail when proxies die). The section-provider set is the natural middle.

## Current shipped state (already on 192.168.214.1)

The earlier, *partial* resilience work is live and is the baseline this plan builds on:
- `DNS.DomesticDoH` / `DNS.DomesticPlainDNS` / `DNS.Resilient` config fields
  (`internal/config/model.go`, `uci.go`, `write.go`) + LuCI fields (`dns.js`).
- domestic `proxy-server-nameserver` / `default-nameserver`, Yandex `direct-nameserver`,
  **no `fallback:`**, `CatchAll` fallback group + `MATCH,CatchAll` (`internal/generator/mihomo.go`).
- Tests: `TestMihomoResilientDNSByDefault`, `TestMihomoDNSNonResilientKeepsLegacyShape`.

This is verified to keep **local/domestic + cached** DNS alive on outage, but **fresh foreign
lookups still fail** — exactly the gap this plan closes (domestic `nameserver` + `nameserver-policy`,
drop the foreign-DoH-as-`nameserver`).

## Implementation checklist (when approved)

- `internal/generator/mihomo.go`: emit domestic Yandex as `nameserver`; emit `nameserver-policy`
  from the proxied domain sets → foreign DoH; emit the `DOMAIN-SUFFIX,yandex.net,DIRECT` +
  domestic-IP `DIRECT` rules **before** the DNSProxy/MATCH rules; keep the foreign-DoH→DNSProxy
  rules (now only for the policy'd domains); keep `CatchAll`. Gate on `DNS.Resilient`.
- Config struct: a knob for the foreign-DoH list used by `nameserver-policy` (likely the existing
  `DoHUpstreams`), and whatever selects the policy domain set.
- `internal/generator/fingerprint.go`: confirm the new fields feed the mihomo group hash.
- Tests: assert domestic `nameserver`, `nameserver-policy` → foreign DoH, the DIRECT resolver
  rules, **no `fallback:`/`fallback-filter`**; legacy shape when `dns_resilient=0`.
- LuCI `dns.js`: surface the foreign-DoH-for-censored vs domestic-default split if user-tunable.

## Verification (repeat the proven method)

`task test:go`, cross-compile arm64, deploy to 192.168.214.1. Then:
- **proxies alive:** a censored/proxied domain resolves *unpoisoned* (foreign DoH) and loads via
  proxy; a normal domain resolves via Yandex; no leak of censored domains to domestic.
- **all proxies dead** (block the 9 node IPs `:443` via top-inserted `nft ... drop` in
  `inet fw4 output`, force-reload to clear cache): fresh foreign domains resolve to real IPs
  via Yandex; censored domains fail (expected). Always wrap in `trap cleanup EXIT`.
- `dns_resilient=0` regenerates the legacy shape.
