# Section protocol and destination-port filters

Proxy and Zapret sections can optionally restrict their matches with:

- `option match_protocol 'udp'`: `tcp`, `udp`, `tcp_udp`, or empty/`any`.
- `option destination_ports '443,10000-11000'`: comma-separated ports and
  inclusive ranges from 1 to 65535. Empty means no additional restriction.

These predicates narrow the section's existing destination or supported client
assignment matches. They do not create a catch-all by themselves. A packet that
fails a predicate continues to subsequent rules. Client assignments retain their
existing precedence over destination-based routing; priorities order rules within
each pass. Forwarded IPv4/IPv6 and router-originated destination routing use the
same filters.

For example, a proxy section at priority 10 can handle UDP ports 10000-11000 to
an EC2 range, while another proxy section at priority 20 handles other traffic to
the same range. The latter needs a matching list or applicable client assignment;
fallthrough does not automatically choose a proxy. Neither rule identifies an
application: any traffic matching the destination and ports receives its action.

## Direct and reject remain global exclusions

Direct/reject destination lists still populate the shared global exclusion sets.
They do not gain protocol or port filters. The new settings are hidden for these
actions and ignored by generation, including values left over after changing a
section's action. Global exclusions and client-identity precedence are unchanged.
There is no new port-scoped direct action.

## Zapret

With empty section filters, a Zapret section uses its strategies' supported
protocols and ports. Explicit filters narrow that scope by intersection. Both the
terminal claim and postrouting NFQUEUE rules use the same intersection. An empty
intersection emits neither a claim nor a queue rule. The shared nfqws process,
per-WAN strategy selection, reply selectors, and bind-fix flags are unchanged.
This does not add new Zapret client-assignment support.

## Provider overlap and upgrades

Cross-section ownership/deduplication is removed. Each section retains its own
copy of overlapping destinations so later sections can match other ports.
Duplicates are removed within each section for materialized, MRS, and native
imports. Static nft interval sets retain their existing auto-merge behavior.
Provider artifact caching is unchanged.

The old `rule_dedup_mode` option is ignored and no longer written or exposed in
LuCI. Resource profiles no longer change deduplication semantics. Existing
sections without filters keep unrestricted matching; configurations that used
full cross-section dedup now resolve overlap using runtime routing precedence,
rather than provider ownership. Overlapping lists can use more memory. The
generation fingerprint version is bumped so an upgrade rebuilds generated rules.

## Verification

Unit/regression tests cover configuration persistence, validation, intersection,
IPv4/IPv6 and OUTPUT rule generation, client filters, exclusion precedence,
provider overlap across import paths, and fingerprint invalidation.

Optional kernel syntax tests run in a private network namespace:

```sh
NFT_TEST_BINARY=/usr/sbin/nft go test ./internal/generator -run TestSectionFiltersKernelSyntax -v
```

They use `nft --check` and do not change the host or router firewall.

Rule providers have no priority. Generation uses provider names for stable ordering;
routing precedence belongs to sections. Old provider priority options are ignored
and omitted when configuration is saved. Native-list imports preserve existing
section priorities and give newly created sections the default priority 100.
