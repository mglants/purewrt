# Zapret port-scoped claims — design

Date: 2026-07-10. Status: approved.

## Problem

A zapret-action section claims its hosts on **all** ports even though its
strategies only mangle specific (protocol, port) pairs. Traffic to those
hosts on non-strategy ports goes direct instead of falling to a proxy
section. Example: an Amazon host under a `udp 443` (QUIC) strategy — QUIC
gets nfqws treatment, but TCP 443 should be proxied via `common`; today it
goes direct because:

- Under full dedup (`resource_profile high`) the zapret provider claims the
  host, so it never lands in a proxy section's nft set at all.
- The OUTPUT chain emits a blanket `ip daddr @zapret_set return` covering
  every port.
- Conversely, under section dedup a host present in *both* sets has its
  strategy-covered ports tproxy'd by the proxy section's rule (zapret
  sections emit no terminal rule in PREROUTING), silently bypassing zapret.

## Decision

A zapret section only claims the (protocol, port) pairs covered by its
enabled strategies — the union across the section's strategies; an empty
port list on an enabled protocol covers the whole protocol. Everything else
to those hosts falls through the chain and is proxied iff the host also
appears in a later section's set. Section order in UCI is the priority: a
zapret section above `common` wins its covered ports; below it, the proxy
rule wins everything (user's choice, no reordering by the generator).

Rejected alternatives: a per-section `fallback_section` tproxy target (extra
config surface, hosts kept out of proxy sets), and a zapret-owned mihomo
listener (most invasive).

## Changes

### nftables generator (`internal/generator/nftables.go`)

1. **PREROUTING**: zapret sections additionally emit port-scoped returns at
   their own position in the section loop:
   `ip daddr @<set> udp dport { 443 } return` (per family, per enabled
   protocol, ports = union across the section's strategies; no port expr
   when a strategy covers the whole protocol). This keeps covered traffic
   direct so nfqws sees it, even when the host is also in a later proxy
   set — fixing the section-dedup silent-bypass bug. Existing saddr NFQUEUE
   rules stay as they are (already port-scoped).
2. **OUTPUT** (`writeOutputChain`): the zapret arm's blanket `return`
   becomes the same port-scoped return. Router-originated non-covered
   traffic falls through to the proxy mark rules.
3. POSTROUTING NFQUEUE rules unchanged (already port-scoped).

### Dedup exemption (`internal/generator/stream.go`)

Full-dedup's `claimed` map gives a host to exactly one set, which breaks
both directions here (zapret wins → proxy never sees the host; proxy wins →
zapret set is empty). Providers feeding zapret-action sections skip the
claimed map entirely — they neither claim nor honor claims — in both the
materialized path and the MRS streaming path (`streamDedup`). Cost: zapret
hosts are duplicated into proxy sets, slightly larger sets.

## Compatibility

No new UCI options. Behaviour shifts:

- Full-dedup configs: non-covered ports to zapret hosts move direct → proxy
  (the requested change) when the host is also in a proxy provider's list.
- Section-dedup configs with overlapping lists: covered ports move
  mihomo → zapret+direct (bug fix).
- Hosts only in a zapret set: unchanged (direct on non-covered ports).

## Testing

TDD generator tests: port-scoped return emission in both chains; port union
across multiple strategies; empty-ports ⇒ whole-protocol return; protocol
disabled ⇒ no return for it; section-order preservation; dedup exemption in
both the materialized and MRS streaming paths.
