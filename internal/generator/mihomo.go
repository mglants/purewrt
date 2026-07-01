package generator

import (
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

func Mihomo(c config.Config) []byte {
	base := renderMihomoBase(c)
	// Optional mixin: deep-merges user overrides from <Workdir>/mihomo-mixin.yaml
	// into the generated base. No-op when Settings.MihomoMixinEnabled is
	// false or the file doesn't exist. On merge error (malformed mixin),
	// falls back to the base so a bad mixin doesn't take down the router —
	// the user-facing mixin Save endpoint validates before writing, so this
	// is purely a defensive fallback for tampering or partial writes.
	merged, err := applyMihomoMixin(base, c)
	if err == nil {
		return merged
	}
	return base
}

// renderMihomoBase is the original Mihomo() body, kept verbatim. Pulled
// out so applyMihomoMixin can post-process its output without recursion.
func renderMihomoBase(c config.Config) []byte {
	var b strings.Builder
	s := c.Settings
	enabledProviders := make([]config.ProxyProvider, 0, len(c.ProxyProviders))
	for _, p := range c.ProxyProviders {
		if p.Enabled {
			enabledProviders = append(enabledProviders, p)
		}
	}
	// allow-lan false (default) binds the mixed-port HTTP/SOCKS proxy to
	// 127.0.0.1 only — a LAN scan can't detect/use the router as an open
	// proxy, and the download-via-proxy fallback still reaches the
	// loopback listener.
	allowLAN := "false"
	if s.MihomoAllowLAN {
		allowLAN = "true"
	}
	b.WriteString("mixed-port: " + itoa(config.DefaultMihomoMixedPort) + "\nallow-lan: " + allowLAN + "\nmode: rule\nlog-level: " + mihomoLogLevel(s.LogLevel) + "\n")
	if mihomoGeodataEnabled(c) {
		b.WriteString("geodata-mode: true\n")
	} else {
		b.WriteString("geodata-mode: false\ngeo-auto-update: false\n")
	}
	// Perf, always on: PureWRT routes by dest-IP nftset (TPROXY), never by
	// process, so find-process-mode just burns CPU reading /proc per
	// connection — keep it off. tcp-concurrent dials a domain's resolved IPs
	// in parallel and uses the fastest, cutting connect latency. (The sniffer
	// — TLS/HTTP host sniffing — is likewise unused for routing and stays
	// off; it's opt-in via Settings.Sniffer, default false.)
	b.WriteString("find-process-mode: off\ntcp-concurrent: true\n")
	if c.LowResource() {
		b.WriteString("unified-delay: true\nkeep-alive-idle: 15\nkeep-alive-interval: 15\n")
		for i := range enabledProviders {
			enabledProviders[i].HealthCheck = false
		}
	}
	if s.Sniffer {
		b.WriteString("sniffer:\n  enable: true\n  sniff:\n    HTTP:\n      ports: [80, 8080-8880]\n    TLS:\n      ports: [443, 8443]\n")
	}
	externalController := s.ExternalController
	if s.DashboardEnabled && s.DashboardListen != "" {
		externalController = s.DashboardListen
	}
	b.WriteString("external-controller: " + externalController + "\nsecret: \"" + s.Secret + "\"\n")
	// Dashboard external-ui is honored whenever DashboardEnabled is true,
	// including on the low resource profile. The wizard / Settings page
	// surface this as an explicit user opt-in (the checkbox stays
	// settable on low) so the user can choose to spend the ~5 MB of
	// dashboard bundle on a memory-constrained router if they really
	// want the metacubexd UI. The auto-off used to live here but it was
	// indistinguishable from a bug: the user checks the box, the box
	// stays checked, but nothing happens.
	if s.DashboardEnabled {
		b.WriteString("external-ui: " + s.DashboardPath + "\n")
		b.WriteString("external-ui-url: \"" + s.DashboardURL + "\"\n")
		b.WriteString("external-ui-name: " + s.DashboardName + "\n")
	}
	b.WriteString("\n")
	b.WriteString("dns:\n  enable: true\n  listen: " + c.DNS.Listen + "\n  ipv6: ")
	if c.IPv6Routed() {
		b.WriteString("true\n")
	} else {
		b.WriteString("false\n")
	}
	mode := c.DNS.EnhancedMode
	if c.Settings.FakeIP || c.DNS.FakeIP {
		mode = "fake-ip"
	}
	b.WriteString("  enhanced-mode: " + mode + "\n  use-hosts: true\n  respect-rules: true\n")
	if mode == "fake-ip" {
		b.WriteString("  fake-ip-range: 198.18.0.1/16\n")
	}
	b.WriteString("  proxy-server-nameserver:\n")
	for _, u := range c.DNS.UDPUpstreams {
		b.WriteString("    - " + u + "\n")
	}
	b.WriteString("  default-nameserver:\n")
	for _, u := range c.DNS.UDPUpstreams {
		b.WriteString("    - " + u + "\n")
	}
	b.WriteString("  fallback:\n")
	for _, u := range c.DNS.UDPUpstreams {
		b.WriteString("    - " + u + "\n")
	}
	b.WriteString("  nameserver:\n")
	for _, u := range c.DNS.DoHUpstreams {
		b.WriteString("    - " + u + "\n")
	}
	for _, u := range c.DNS.DoQUpstreams {
		b.WriteString("    - " + u + "\n")
	}
	hasProxySection := anyEnabledProxySection(c)
	b.WriteString("\nlisteners:\n")
	for _, sec := range c.Sections {
		if sec.Enabled && sec.Action == "proxy" {
			b.WriteString("  - name: " + sec.ListenerName() + "\n    type: tproxy\n    port: ")
			b.WriteString(itoa(sec.TPROXYPort))
			b.WriteString("\n    listen: 0.0.0.0\n")
		}
	}
	// net-check probe listener: a loopback `mixed` proxy whose traffic is
	// routed via the NetCheckProbe select group (rule below). Lets
	// `purewrt net-check --per-node` pin one node/group/VPN and measure real
	// throughput in isolation from live routing. Loopback-only — no LAN
	// exposure, carries no traffic unless net-check drives it.
	if hasProxySection {
		b.WriteString("  - name: netcheck-probe\n    type: mixed\n    port: " + itoa(config.DefaultNetCheckProbePort) + "\n    listen: 127.0.0.1\n")
	}
	// VPN interfaces as `direct` outbounds (interface-name binds the socket to
	// the tunnel). Emitted for every VPN referenced by a section or DNS, so
	// sections/DNS can pool them with subscription nodes under a proxy group.
	if vpns := referencedVPNs(c); len(vpns) > 0 {
		b.WriteString("\nproxies:\n")
		for _, v := range vpns {
			// tfo: TCP Fast Open — saves a round trip where the destination
			// supports it; mihomo falls back to plain TCP otherwise.
			b.WriteString("  - name: " + vpnProxyName(v.Name) + "\n    type: direct\n    interface-name: " + v.Interface + "\n    tfo: true\n")
		}
	}
	b.WriteString("\nproxy-providers:\n")
	if len(enabledProviders) == 0 {
		b.WriteString("  main:\n    type: file\n    path: /etc/purewrt/providers/main.yaml\n")
	} else {
		for _, p := range enabledProviders {
			providerType := p.Type
			if providerType == "" {
				providerType = "http"
			}
			b.WriteString("  " + p.Name + ":\n    type: " + providerType + "\n")
			if providerType != "file" && p.URL != "" {
				b.WriteString("    url: \"" + p.URL + "\"\n")
			}
			b.WriteString("    path: " + p.Path + "\n")
			if providerType != "file" && p.Interval > 0 {
				b.WriteString("    interval: " + itoa(p.Interval) + "\n")
			}
			b.WriteString("    health-check:\n      enable: ")
			if p.HealthCheck {
				b.WriteString("true\n")
			} else {
				b.WriteString("false\n")
			}
			b.WriteString("      url: " + p.HealthCheckURL + "\n      interval: " + itoa(p.HealthCheckInterval) + "\n      timeout: 3000\n")
		}
	}
	b.WriteString("\nproxy-groups:\n")
	writeProxyGroup(&b, "DNSProxy", c.DNS.ProxyGroupType, c.DNS.ProxyFilter, c.DNS.ProxyExcludeFilter, c.DNS.ProxyStrategy, "", 0, enabledProviders, resolveVPNMembers(c, c.DNS.VPNs))
	for _, sec := range c.Sections {
		if sec.Enabled && sec.Action == "proxy" {
			writeProxyGroup(&b, sec.ProxyGroup, sec.ProxyGroupType, sec.ProxyFilter, sec.ProxyExcludeFilter, sec.ProxyStrategy, sec.ProxyHealthCheckURL, sec.ProxyHealthCheckInterval, enabledProviders, resolveVPNMembers(c, sec.VPNs))
		}
	}
	if hasProxySection {
		writeNetCheckProbeGroup(&b, c, enabledProviders)
	}
	b.WriteString("\nrules:\n  - DOMAIN-SUFFIX,dns.google,DNSProxy\n  - DOMAIN-SUFFIX,cloudflare-dns.com,DNSProxy\n  - DOMAIN-SUFFIX,dns.quad9.net,DNSProxy\n  - IP-CIDR,1.1.1.1/32,DNSProxy,no-resolve\n  - IP-CIDR,8.8.8.8/32,DNSProxy,no-resolve\n  - IP-CIDR,9.9.9.9/32,DNSProxy,no-resolve\n")
	for _, sec := range c.Sections {
		if sec.Enabled && sec.Action == "proxy" {
			b.WriteString("  - IN-NAME," + sec.ListenerName() + "," + sec.ProxyGroup + "\n")
		}
	}
	if hasProxySection {
		b.WriteString("  - IN-NAME,netcheck-probe,NetCheckProbe\n")
	}
	catchAll := "DIRECT"
	if hasCommonGroup(c) {
		catchAll = "Common"
	}
	b.WriteString("  - MATCH," + catchAll + "\n")
	return []byte(b.String())
}

func mihomoGeodataEnabled(c config.Config) bool {
	return c.Settings.MihomoGeodataEnabled && !c.LowResource()
}

func mihomoLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error", "err":
		return "error"
	case "info", "notice":
		return "info"
	case "debug":
		return "debug"
	default:
		return "warning"
	}
}

func vpnProxyName(n string) string { return "vpn_" + n }

// anyEnabledProxySection reports whether at least one enabled section egresses
// via a proxy group — the gate for emitting the net-check probe path.
func anyEnabledProxySection(c config.Config) bool {
	for _, s := range c.Sections {
		if s.Enabled && s.Action == "proxy" {
			return true
		}
	}
	return false
}

// hasCommonGroup reports whether an enabled proxy section emits the "Common"
// group that the catch-all MATCH targets. When absent (common section deleted/
// disabled), the catch-all falls to DIRECT so unmatched traffic degrades to
// direct internet instead of dangling on a non-existent group.
func hasCommonGroup(c config.Config) bool {
	for _, s := range c.Sections {
		if s.Enabled && s.Action == "proxy" && s.ProxyGroup == "Common" {
			return true
		}
	}
	return false
}

// writeNetCheckProbeGroup emits the NetCheckProbe `select` group whose members
// are every section proxy group + each vpn_* outbound + DIRECT, plus the
// provider nodes via `use:` (a select group can hold both groups and nodes).
// net-check --per-node SelectProxy's each member to probe it in isolation.
func writeNetCheckProbeGroup(b *strings.Builder, c config.Config, providers []config.ProxyProvider) {
	b.WriteString("  - name: NetCheckProbe\n    type: select\n    proxies:\n      - DIRECT\n")
	seen := map[string]bool{}
	for _, sec := range c.Sections {
		if sec.Enabled && sec.Action == "proxy" && sec.ProxyGroup != "" && !seen[sec.ProxyGroup] {
			seen[sec.ProxyGroup] = true
			b.WriteString("      - " + sec.ProxyGroup + "\n")
		}
	}
	for _, v := range referencedVPNs(c) {
		b.WriteString("      - " + vpnProxyName(v.Name) + "\n")
	}
	if len(providers) > 0 {
		b.WriteString("    use:\n")
		for _, p := range providers {
			b.WriteString("      - " + p.Name + "\n")
		}
	}
}

// resolveVPNMembers maps a section/DNS VPN-name list to mihomo proxy names,
// keeping only enabled VPNs that have an interface.
func resolveVPNMembers(c config.Config, names []string) []string {
	out := []string{}
	for _, n := range names {
		if _, ok := c.VPNForName(n); ok {
			out = append(out, vpnProxyName(n))
		}
	}
	return out
}

// referencedVPNs returns the unique enabled VPNs referenced by DNS or any
// enabled section, so a `direct` outbound is emitted for each.
func referencedVPNs(c config.Config) []config.VPN {
	seen := map[string]bool{}
	var out []config.VPN
	add := func(names []string) {
		for _, n := range names {
			if seen[n] {
				continue
			}
			if v, ok := c.VPNForName(n); ok {
				seen[n] = true
				out = append(out, v)
			}
		}
	}
	add(c.DNS.VPNs)
	for _, s := range c.Sections {
		if s.Enabled {
			add(s.VPNs)
		}
	}
	return out
}

func writeProxyGroup(b *strings.Builder, name, typ, filter, excludeFilter, strategy, healthURL string, healthInterval int, providers []config.ProxyProvider, vpnMembers []string) {
	typ = normalizedProxyGroupType(typ)
	b.WriteString("  - name: " + name + "\n    type: " + typ + "\n")
	// Pool = subscription providers (via `use:`) + selected VPN interfaces (via
	// `proxies:`). filter/exclude-filter apply to the provider proxies only;
	// the explicit VPN `proxies:` entries are always kept. With neither,
	// fall back to the empty `main` provider so the group is still valid.
	if len(providers) == 0 && len(vpnMembers) == 0 {
		b.WriteString("    use:\n      - main\n")
	} else {
		if len(providers) > 0 {
			b.WriteString("    use:\n")
			for _, p := range providers {
				b.WriteString("      - " + p.Name + "\n")
			}
		}
		if len(vpnMembers) > 0 {
			b.WriteString("    proxies:\n")
			for _, m := range vpnMembers {
				b.WriteString("      - " + m + "\n")
			}
		}
	}
	if filter != "" {
		b.WriteString("    filter: \"" + escapeYAMLDoubleQuoted(filter) + "\"\n")
	}
	if excludeFilter != "" {
		b.WriteString("    exclude-filter: \"" + escapeYAMLDoubleQuoted(excludeFilter) + "\"\n")
	}
	if typ == "url-test" || typ == "load-balance" {
		if healthURL == "" {
			healthURL = "https://cp.cloudflare.com/generate_204"
		}
		if healthInterval <= 0 {
			healthInterval = 300
		}
		b.WriteString("    url: " + healthURL + "\n    interval: " + itoa(healthInterval) + "\n")
	}
	if typ == "load-balance" {
		b.WriteString("    strategy: " + normalizedLoadBalanceStrategy(strategy) + "\n")
	}
}

func normalizedProxyGroupType(v string) string {
	switch v {
	case "select", "url-test", "load-balance":
		return v
	default:
		return "url-test"
	}
}

func normalizedLoadBalanceStrategy(v string) string {
	switch v {
	case "consistent-hashing", "round-robin", "sticky-sessions":
		return v
	default:
		return "sticky-sessions"
	}
}

func escapeYAMLDoubleQuoted(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	return strings.ReplaceAll(v, "\"", "\\\"")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		digits = string(byte('0'+i%10)) + digits
		i /= 10
	}
	return digits
}
