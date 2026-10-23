# DNS address fallback during proxy outages

PureWRT's DNS configuration supports a separate concurrent fallback pool and
domains that should use it immediately. Configure these in LuCI → DNS, or in the
existing `config dns 'dns'` UCI section. No mixin or additional daemon is needed.

The default configuration targets a Russian WAN and uses the generated `DNSProxy` group:

```uci
    option enhanced_mode 'redir-host'
    list udp_upstream '77.88.8.8#DIRECT'
    list udp_upstream '77.88.8.1#DIRECT'
    list doh_upstream 'https://dns.google/dns-query#DNSProxy'
    list doh_upstream 'https://cloudflare-dns.com/dns-query#DNSProxy'
    list doh_upstream 'https://dns.quad9.net/dns-query#DNSProxy'
    list fallback_upstream 'https://common.dot.dns.yandex.net/dns-query#DIRECT'
    list fallback_domain '+.ru'
    list fallback_domain '+.su'
    list fallback_domain '+.xn--p1ai'
```

Replace the existing upstream lists rather than appending these to them.
`udp_upstream` supplies bootstrap and proxy-hostname resolution. A nonempty
`fallback_upstream` replaces its legacy use as the fallback pool. Empty
`fallback_upstream` retains that existing behavior. Primary upstreams can use
`#DNSProxy`; fallback/bootstrap can use `#DIRECT` to bypass proxy routing.

For address queries, `.ru`, `.su`, and `.рф` go straight to domestic fallback.
Other domains use an acceptable overseas answer when available. The domestic
query runs concurrently, so it can supply an answer if the overseas path fails.
The generator explicitly sets `fallback-lazy-query: false`. A custom fallback
pool or domain list disables implicit GeoIP filtering, even if other rules use
Mihomo geodata. A separate mixin `nameserver-policy` can override this behavior.

The Go defaults and packaged OpenWrt configuration both enable this setup.
Resolver addresses and suffixes remain configurable; explicitly configured
upstream lists are preserved when loading an existing configuration.
Missing fallback options inherit these defaults. Set `option fallback_upstream ''`
or `option fallback_domain ''` to explicitly clear the corresponding list.
The example requires direct reachability to Yandex DNS and uses real-IP
resolution for PureWRT's dnsmasq nftsets.

## Trade-offs and router validation

Tested on 2026-10-23, on the router at 192.0.2.1, using isolated Mihomo instances:
installed `alpha-dc4d4fcb` and official `v1.19.33`. Production traffic was not
blocked. An unavailable SOCKS endpoint simulated immediate refusal and a TCP
endpoint accepting connections without responding simulated a silent outage.

- Immediate refusal: address fallback succeeded quickly.
- Silent outage with `fallback-lazy-query: true`: address queries returned
  SERVFAIL after about five seconds on both builds.
- Silent outage with `fallback-lazy-query: false`: tested address queries
  succeeded after about five seconds.
- RU address queries sent directly to fallback succeeded in roughly 40–70 ms.
- TXT and HTTPS (type 65) queries failed during the outage with either setting.

Domestic DNS receives queries even when overseas DNS works, including queries
for blocked domains. Its answers may be censored. Every uncached non-RU address
query can still wait for the overseas timeout during a silent outage. This is
address fallback, not complete DNS outage recovery; it also requires Mihomo to
remain running. RU suffix matching does not identify all Russian services and
also includes blocked sites under those suffixes.

The lazy-fallback failure is consistent with main and fallback sharing a
query deadline. Concurrent fallback avoids starting the domestic lookup only
after that deadline has expired. Upgrading to v1.19.33 did not fix this behavior.

## Deployment

Save the DNS options and run `purewrt apply`. The apply pipeline validates the
generated configuration and hot-reloads Mihomo when its controller is available.
These fields are included in UCI load/save and the DNS generation fingerprint,
so later apply/update operations retain the settings.

If migrating from a DNS mixin, remove those DNS overrides; otherwise the mixin
still takes precedence over the native fields. Preserve unrelated mixin content.

After applying, verify fresh queries through both Mihomo's DNS listener and
LAN-facing dnsmasq, plus production routing and the Mihomo PID. Test failure
scenarios in an isolated instance rather than blocking production proxy nodes.

References: [Mihomo DNS settings](https://wiki.metacubex.one/en/config/dns/),
[resolver implementation](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/dns/resolver.go).
