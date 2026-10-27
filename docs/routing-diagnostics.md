# Destination routing diagnostics

LuCI's Site Checker and `purewrt-check` accept a domain or IP, optional
protocol (`tcp` or `udp`), destination port, and outgoing WAN device:

```sh
purewrt-check discord.com tcp 443 br-lan.3
purewrt-check 216.244.8.84 udp 10600 br-lan.3000
```

The list trace evaluates global Reject/Direct exclusions first, then enabled
sections by ascending section priority. Provider names only order provenance.
Steps identify matching scopes, skips that fall through, conditional decisions,
and scopes shadowed by an earlier terminal match. Missing providers or unsupported
native expressions make the result conditional. Missing protocol/port inputs
also remain conditional when necessary.

Zapret's claim is the union of enabled strategies' protocol/ports intersected
with section filters. Covered flows leave proxy dispatch before WAN-specific
NFQUEUE handling. On a WAN without a compatible strategy they stay direct;
they do not fall through to a lower proxy section. Ports outside the claim
can fall through. Specifying a WAN device explains this distinction.

Resolved addresses are checked against live nft destination sets with the same
flow constraints. This is a destination-only diagnostic, not a packet trace:
client identity rules, local/DNS exemptions, native expressions, existing marks,
connection state and real WAN selection are not simulated. List matches alone
do not establish live DNS-set population.

# Mihomo release checks

`mihomo-check-update [alpha|stable]` is read-only. An omitted channel uses the
configured channel. Current version comes from the configured executable's
`-v` output; stale release metadata in UCI is not trusted. If the executable's
version cannot be determined, the response leaves it unknown.

Legacy `mihomo-download` / `mihomo-update` aliases perform the same read-only
check and return release information. They neither install a release nor
overwrite installed-version metadata. Use `mihomo-install-release` for
installation. Actual installation continues recording provenance in UCI.

# UDP connectivity in What's blocked

Probe now also checks `stun.cloudflare.com:3478` and `stun.nextcloud.com:443`
with IPv4 UDP STUN Binding requests. The report validates response type, magic
cookie, transaction ID and mapped address, and shows the public endpoint.
Each endpoint gets up to three attempts within a five-second budget.

These checks follow current router routing, including proxy rules; they are not
a direct-per-WAN comparison. Timeouts and network errors carry low confidence
and do not affect the website blocking verdict. A successful reply establishes
reachability of that endpoint only, not arbitrary UDP or game servers.
