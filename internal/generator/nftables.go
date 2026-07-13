package generator

import (
	"io"
	"net/netip"
	"sort"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

// sectionsByPriority returns the enabled sections ordered by ascending Priority
// (lowest number = highest precedence). Prerouting evaluates sections in this
// order so the priority field actually controls routing precedence: a section
// with a lower priority number wins an overlap (e.g. a VPN section at 10 beats
// a proxy section at 40 for a domain listed in both). Stable so equal
// priorities keep config order.
func sectionsByPriority(sections []config.Section) []config.Section {
	out := make([]config.Section, 0, len(sections))
	for _, s := range sections {
		if s.Enabled {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// cgroupExemptionRule returns the nft snippet that exempts mihomo's own
// outbound from re-marking. OpenWrt 24.10+ ships cgroupv2-only, so we
// always emit `socket cgroupv2 level N "path"` — the v1 `meta cgroup
// <classid>` fallback was removed along with the runtime probe. Boards
// without cgroupv2 would need the package's `kmod-nft-socket` dep plus
// a custom procd cgroup placement, which is well outside what this
// codebase supports.
func cgroupExemptionRule(c config.Config) string {
	path := strings.TrimPrefix(strings.TrimSpace(c.Settings.CgroupV2Path), "/")
	if path == "" {
		path = "services/mihomo"
	}
	level := strings.Count(path, "/") + 1
	return "    socket cgroupv2 level " + itoa(level) + " \"" + path + "\" return\n"
}

// EasytierCgroupPath is the procd-assigned cgroup of the overlay daemon
// (service purewrt-easytier). Shared with the manager, which pre-creates the
// directory before loading rules: nft refuses to load a `socket cgroupv2`
// match whose path doesn't exist (verified live), and on the first apply
// after mesh-join the rules load before procd has started the service.
const EasytierCgroupPath = "services/purewrt-easytier"

// easytierExemptionRule keeps the overlay daemon's own WAN transport
// (rendezvous dials, hole-punch packets, relayed tunnels) out of the
// router-output proxy — the mihomo cgroup exemption's twin. Without it a
// proxied destination that happens to cover a rendezvous host or a friend's
// WAN IP would TPROXY the mesh transport into mihomo, coupling the overlay's
// liveness to the proxy's.
func easytierExemptionRule(c config.Config) string {
	if !c.MeshActive() {
		return ""
	}
	level := strings.Count(EasytierCgroupPath, "/") + 1
	return "    socket cgroupv2 level " + itoa(level) + " \"" + EasytierCgroupPath + "\" return\n"
}

// ooniExemptionRule keeps the OONI probe's traffic out of the proxy. The probe
// runs as a dedicated non-root user; matching its socket owner uid and
// returning early means its direct measurement sockets are never transparently
// TPROXY'd into mihomo — even when a measurement target sits in a proxy nftset.
// (OONI's backend/API still rides mihomo via the probe's `--proxy` flag, which
// is an explicit app-level proxy connection, not transparent capture.) Emitted
// only when OONI is enabled AND the uid resolved, so a stale enable flag with
// no user present can't break ruleset load.
func ooniExemptionRule(c config.Config) string {
	if !c.OONI.Enabled || c.OONI.UID <= 0 {
		return ""
	}
	return "    meta skuid " + itoa(c.OONI.UID) + " return\n"
}

func NFTables(c config.Config) []byte {
	return NFTablesWithNative(c, nil)
}

func NFTablesWithNative(c config.Config, native map[string][]string) []byte {
	var b strings.Builder
	var nat strings.Builder
	includeIPv6 := c.IPv6Routed()
	// Atomic-replace prologue: `add table` ensures the table exists in the
	// transaction's view (no-op if already present), `delete table` then
	// removes it, and the `table { ... }` block below re-adds it fresh.
	// All three execute in a single `nft -f` transaction, so userspace
	// observes one atomic ruleset swap (no rule gap). Without this, an
	// existing table's chain bodies are not replaced by subsequent loads —
	// rule-shape changes (e.g., tightening prerouting loop-breakers or
	// adding output_mangle) silently no-op until the table is explicitly
	// deleted.
	b.WriteString("add table inet purewrt\n")
	b.WriteString("delete table inet purewrt\n")
	b.WriteString("table inet purewrt {\n")
	sets := []string{"bypass4", "proxy_server_bypass4", "direct4", "reject4"}
	if includeIPv6 {
		sets = append(sets, "bypass6", "proxy_server_bypass6", "direct6", "reject6")
	}
	for _, s := range c.Sections {
		if s.Action == "proxy" || s.Action == "zapret" {
			sets = append(sets, s.NFTSet4())
			if includeIPv6 {
				sets = append(sets, s.NFTSet6())
			}
		}
	}
	for _, set := range sets {
		b.WriteString(nftSetDefinition(set, false))
		b.WriteString(nftSetDefinition(dnsSetName(set), true))
		// One named counter per set, mirroring nftSetRefs(). Lets the
		// Statistics page report packets+bytes that matched each set,
		// aggregated across every rule referencing it.
		b.WriteString(nftCounterDecl(set))
		b.WriteString(nftCounterDecl(dnsSetName(set)))
	}
	// Loop-breakers tightened to allow OUTPUT-marked re-injected packets through.
	// Re-injected packets arrive with iifname=lo and our mark already set; they
	// must fall through to the per-section TPROXY dispatch below. The plain
	// `iifname lo return` (catching all loopback) would block them, so we
	// restrict the bypass to genuine router-to-self loopback (`fib daddr type
	// local`), and the mark-already-set bypass to externally-marked traffic
	// not coming from lo.
	b.WriteString("  chain prerouting {\n    type filter hook prerouting priority mangle; policy accept;\n    iifname \"lo\" fib daddr type local return\n    iifname != \"lo\" meta mark & " + c.Settings.FwMarkMask + " == " + c.Settings.FwMark + " return\n    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
	if includeIPv6 {
		b.WriteString("    ip6 daddr { ::1, fc00::/7, fe80::/10, ff00::/8 } return\n")
	}
	b.WriteString("    ip daddr @bypass4" + counterTag("bypass4") + " return\n")
	if includeIPv6 {
		b.WriteString("    ip6 daddr @bypass6" + counterTag("bypass6") + " return\n")
	}
	b.WriteString("    ip daddr @" + dnsSetName("bypass4") + counterTag(dnsSetName("bypass4")) + " return\n")
	if includeIPv6 {
		b.WriteString("    ip6 daddr @" + dnsSetName("bypass6") + counterTag(dnsSetName("bypass6")) + " return\n")
	}
	b.WriteString("    ip daddr @proxy_server_bypass4" + counterTag("proxy_server_bypass4") + " return\n")
	if includeIPv6 {
		b.WriteString("    ip6 daddr @proxy_server_bypass6" + counterTag("proxy_server_bypass6") + " return\n")
	}
	writeSourceBypassRules(&b, c, includeIPv6)
	// Devices excluded from purewrt: an early MAC `return` so the device routes
	// direct as if purewrt weren't there — outranks every section assignment
	// and the catch-all. Placed alongside the source-CIDR bypass returns.
	writeExcludedDeviceRules(&b, c)
	ordered := sectionsByPriority(c.Sections)
	// Client-identity pass: device (MAC) + source (CIDR) assignments take
	// precedence over destination-based routing, so a client explicitly
	// assigned to a section routes ALL its traffic there — a VPN client
	// tunnels everything even with no domain rules. Emitted after the
	// loop-breakers/LAN/bypass returns (so proxy clients can't loop back into
	// TPROXY for the proxy-server IP) but before the destination sets.
	//
	// Two passes so precedence is DETERMINISTIC and independent of section
	// priority: ALL MAC (device) rules first, then ALL source-CIDR rules — so a
	// client matched by MAC always wins over one matched by IP/CIDR, whichever
	// sections they belong to. Section priority only orders rules within a pass.
	for _, s := range ordered {
		writeSectionDeviceRules(&b, c, s, includeIPv6)
	}
	for _, s := range ordered {
		writeSectionSourceRules(&b, c, s, includeIPv6)
	}
	for _, set := range nftSetRefs("reject4") {
		b.WriteString("    ip daddr @" + set + counterTag(set) + " reject\n")
	}
	if includeIPv6 {
		for _, set := range nftSetRefs("reject6") {
			b.WriteString("    ip6 daddr @" + set + counterTag(set) + " reject\n")
		}
	}
	for _, set := range nftSetRefs("direct4") {
		b.WriteString("    ip daddr @" + set + counterTag(set) + " return\n")
	}
	if includeIPv6 {
		for _, set := range nftSetRefs("direct6") {
			b.WriteString("    ip6 daddr @" + set + counterTag(set) + " return\n")
		}
	}
	// Destination pass: nftset (domain/IP) rules in priority order, so a
	// higher-priority section wins a destination listed in more than one.
	// Device/source rules were already emitted above (client-identity pass).
	for _, s := range ordered {
		if s.Action == "reject" {
			for _, set := range nftSetRefs(s.NFTSet4()) {
				b.WriteString("    ip daddr @" + set + counterTag(set) + " reject\n")
			}
			if includeIPv6 {
				for _, set := range nftSetRefs(s.NFTSet6()) {
					b.WriteString("    ip6 daddr @" + set + counterTag(set) + " reject\n")
				}
			}
			continue
		}
		if s.Action == "direct" {
			for _, set := range nftSetRefs(s.NFTSet4()) {
				b.WriteString("    ip daddr @" + set + counterTag(set) + " return\n")
			}
			if includeIPv6 {
				for _, set := range nftSetRefs(s.NFTSet6()) {
					b.WriteString("    ip6 daddr @" + set + counterTag(set) + " return\n")
				}
			}
			continue
		}
		if s.Action == "zapret" {
			writeZapretPreroutingRules(&b, c, s, includeIPv6)
			writeZapretClaimReturns(&b, c, s, includeIPv6)
			continue
		}
		if s.Action != "proxy" {
			continue
		}
		for _, expr := range native[s.Name] {
			for _, line := range nativeNFTLines(expr, s, c.Settings.FwMark) {
				b.WriteString(line)
			}
		}
		if s.UDPMode == "block_quic" {
			for _, set := range nftSetRefs(s.NFTSet4()) {
				b.WriteString("    ip daddr @" + set + counterTag(set) + " udp dport 443 reject\n")
			}
			if includeIPv6 {
				for _, set := range nftSetRefs(s.NFTSet6()) {
					b.WriteString("    ip6 daddr @" + set + counterTag(set) + " udp dport 443 reject\n")
				}
			}
		}
		for _, set := range nftSetRefs(s.NFTSet4()) {
			b.WriteString("    ip daddr @" + set + " meta l4proto tcp meta mark set meta mark | " + c.Settings.FwMark + counterTag(set) + " tproxy ip to :" + itoa(s.TPROXYPort) + " accept\n")
			if s.UDPMode != "tcp_only" {
				b.WriteString("    ip daddr @" + set + " meta l4proto udp meta mark set meta mark | " + c.Settings.FwMark + counterTag(set) + " tproxy ip to :" + itoa(s.TPROXYPort) + " accept\n")
			}
		}
		if includeIPv6 {
			for _, set := range nftSetRefs(s.NFTSet6()) {
				b.WriteString("    ip6 daddr @" + set + " meta l4proto tcp meta mark set meta mark | " + c.Settings.FwMark + counterTag(set) + " tproxy ip6 to :" + itoa(s.TPROXYPort) + " accept\n")
				if s.UDPMode != "tcp_only" {
					b.WriteString("    ip6 daddr @" + set + " meta l4proto udp meta mark set meta mark | " + c.Settings.FwMark + counterTag(set) + " tproxy ip6 to :" + itoa(s.TPROXYPort) + " accept\n")
				}
			}
		}
	}
	if c.DNS.BlockDoT {
		b.WriteString("    tcp dport 853 reject\n")
	}
	// When the user explicitly disables IPv6 routing AND opts into the
	// safety reject, refuse all outbound v6 on the LAN-facing prerouting
	// hook so v6-only paths to upstream services fail fast instead of
	// quietly bypassing the proxy. Cheap insurance against IPv6 leaks.
	if !c.IPv6Routed() && c.Settings.IPv6RejectWhenOff {
		b.WriteString("    ip6 daddr ::/0 reject\n")
	}
	if c.DNS.BlockDoQ {
		// DoQ (DNS-over-QUIC, RFC 9250) lives on UDP/853. Same posture as
		// BlockDoT: refuse so clients fall back to the LAN-hijacked path.
		b.WriteString("    udp dport 853 reject\n")
	}
	if c.DNS.BlockDoH3 {
		// DoH3 is HTTPS-over-QUIC on UDP/443. Blanket-blocking UDP/443
		// would break all QUIC, so we restrict to known DoH3 server IPs.
		if expr := nftCIDRSetExpr(normalizeCIDRs(c.DNS.DoH3BlockIPs4, false)); expr != "" {
			b.WriteString("    ip daddr " + expr + " udp dport 443 reject\n")
		}
		if includeIPv6 {
			if expr := nftCIDRSetExpr(normalizeCIDRs(c.DNS.DoH3BlockIPs6, true)); expr != "" {
				b.WriteString("    ip6 daddr " + expr + " udp dport 443 reject\n")
			}
		}
	}
	if nat.Len() > 0 {
		b.WriteString("  }\n\n  chain dstnat {\n    type nat hook prerouting priority dstnat; policy accept;\n")
		b.WriteString(nat.String())
	}
	if len(c.EnabledZapretProfiles()) > 0 && hasEnabledZapretStrategies(c) {
		b.WriteString("  }\n\n  chain postrouting {\n    type filter hook postrouting priority srcnat + 1; policy accept;\n")
		for _, s := range c.Sections {
			if !s.Enabled || s.Action != "zapret" {
				continue
			}
			writeZapretPostroutingRules(&b, c, s, includeIPv6)
		}
		// Notrack any packet already carrying the zapret profile's fwmark
		// in OUTPUT so its own re-injected packets (and any traffic that
		// was already classified upstream) bypass conntrack. Applied
		// unconditionally for enabled profiles — tpws-only profiles don't
		// stamp the mark, so the rule is a cheap no-op for them; nfqws
		// profiles need it to avoid re-queueing their own output.
		b.WriteString("  }\n\n  chain predefrag {\n    type filter hook output priority -401; policy accept;\n")
		for _, p := range c.EnabledZapretProfiles() {
			b.WriteString("    meta mark & " + p.FwMark + " != 0 notrack\n")
		}
	}
	b.WriteString("  }\n")
	if c.Settings.RouterOutputProxy {
		writeOutputChain(&b, c, includeIPv6)
	}
	writeMeshLimiterChains(&b, c)
	b.WriteString("}\n")
	return []byte(b.String())
}

// writeMeshLimiterChains polices friend exit traffic when exit_max_mbit is
// set: two filter-hook chains cap the mesh listener's throughput on the
// overlay TUN, one per direction. tcp AND udp are matched — the ss listener
// is udp-enabled, so a tcp-only cap would be trivially bypassed. Deliberately
// NOT gated on meshExitViable (that needs the enabled-provider list): if the
// mihomo listener isn't emitted the rules are inert, and nftables stays
// decoupled from provider state. fw4's zone stays the reachability gate —
// this table only rate-limits; a drop in any hooked chain wins. The re-add-
// table prologue resets the limiter's token bucket on every apply, which
// just grants a momentary burst allowance.
//
// A burstless byte policer makes TCP goodput settle ~10-20% under the
// nominal cap; `burst` is the tuning knob if that ever matters.
func writeMeshLimiterChains(b *strings.Builder, c config.Config) {
	if !c.MeshActive() || !c.Mesh.ExitEnabled || c.Mesh.ListenPort <= 0 || c.Mesh.ExitMaxMbit <= 0 {
		return
	}
	// 1 Mbit/s = 125000 bytes/s — exact, avoids nft's 1024-based units.
	rate := itoa(c.Mesh.ExitMaxMbit * 125000)
	port := itoa(c.Mesh.ListenPort)
	dev := c.Mesh.DeviceName
	b.WriteString("\n  chain mesh_limit_in {\n    type filter hook input priority filter; policy accept;\n")
	b.WriteString("    iifname \"" + dev + "\" meta l4proto { tcp, udp } th dport " + port + " limit rate over " + rate + " bytes/second counter drop\n  }\n")
	b.WriteString("\n  chain mesh_limit_out {\n    type filter hook output priority filter; policy accept;\n")
	b.WriteString("    oifname \"" + dev + "\" meta l4proto { tcp, udp } th sport " + port + " limit rate over " + rate + " bytes/second counter drop\n  }\n")
}

// writeOutputChain emits the OUTPUT-side chain that proxies router-originated
// traffic. Same destination-set-driven shape as PREROUTING — only daddrs in an
// enabled section's @set get marked. The mark triggers `type route` reroute →
// `ip rule fwmark` → table `local default dev lo` → kernel re-injects via lo →
// existing PREROUTING TPROXY's the packet to the right per-section listener.
//
// Loop safety:
//   - First rule exempts mihomo's own outbound by cgroup (init script places
//     mihomo's PID in this cgroup at start). Without it, mihomo's connection
//     to the remote proxy server would itself get re-marked.
//   - `@proxy_server_bypass4/6` provides destination-based defense in depth
//     if the cgroup wiring fails.
//   - Zapret's re-injected output already carries `0x40000000`; we skip it.
//   - `fib daddr type local` skips router-to-self; `ct direction reply`
//     skips return packets of established connections.
//
// Per-section dispatch:
//   - reject sections: `reject` (same as PREROUTING).
//   - direct sections: `return`.
//   - zapret sections: port-scoped `return` for strategy-covered
//     (protocol, port) pairs only — those stay out of mihomo so nfqws can
//     mangle them via POSTROUTING; other ports to the same hosts fall
//     through to the proxy mark rules below.
//   - vpn sections: mark with the VPN's fwmark; the VPN's own ip rule
//     handles the route.
//   - proxy sections: mark with `Settings.FwMark`. No `tproxy` action here
//     (PREROUTING-only); the existing PREROUTING TPROXY rule fires on the
//     re-injected packet and dispatches to the right per-section port.
func writeOutputChain(b *strings.Builder, c config.Config, includeIPv6 bool) {
	b.WriteString("\n  chain output_mangle {\n    type route hook output priority mangle; policy accept;\n")
	b.WriteString(cgroupExemptionRule(c))
	b.WriteString(easytierExemptionRule(c))
	b.WriteString(ooniExemptionRule(c))
	b.WriteString("    meta mark & 0x40000000 != 0 return\n")
	b.WriteString("    fib daddr type { local, broadcast, anycast, multicast } return\n")
	b.WriteString("    ct direction reply return\n")
	b.WriteString("    meta l4proto != { tcp, udp } return\n")
	b.WriteString("    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
	if includeIPv6 {
		b.WriteString("    ip6 daddr { ::1, fc00::/7, fe80::/10, ff00::/8 } return\n")
	}
	b.WriteString("    ip daddr @bypass4" + counterTag("bypass4") + " return\n")
	if includeIPv6 {
		b.WriteString("    ip6 daddr @bypass6" + counterTag("bypass6") + " return\n")
	}
	b.WriteString("    ip daddr @" + dnsSetName("bypass4") + counterTag(dnsSetName("bypass4")) + " return\n")
	if includeIPv6 {
		b.WriteString("    ip6 daddr @" + dnsSetName("bypass6") + counterTag(dnsSetName("bypass6")) + " return\n")
	}
	b.WriteString("    ip daddr @proxy_server_bypass4" + counterTag("proxy_server_bypass4") + " return\n")
	if includeIPv6 {
		b.WriteString("    ip6 daddr @proxy_server_bypass6" + counterTag("proxy_server_bypass6") + " return\n")
	}
	for _, s := range c.Sections {
		if !s.Enabled {
			continue
		}
		switch s.Action {
		case "reject":
			for _, set := range nftSetRefs(s.NFTSet4()) {
				b.WriteString("    ip daddr @" + set + counterTag(set) + " reject\n")
			}
			if includeIPv6 {
				for _, set := range nftSetRefs(s.NFTSet6()) {
					b.WriteString("    ip6 daddr @" + set + counterTag(set) + " reject\n")
				}
			}
		case "direct":
			for _, set := range nftSetRefs(s.NFTSet4()) {
				b.WriteString("    ip daddr @" + set + counterTag(set) + " return\n")
			}
			if includeIPv6 {
				for _, set := range nftSetRefs(s.NFTSet6()) {
					b.WriteString("    ip6 daddr @" + set + counterTag(set) + " return\n")
				}
			}
		case "zapret":
			writeZapretClaimReturns(b, c, s, includeIPv6)
		case "proxy", "":
			for _, set := range nftSetRefs(s.NFTSet4()) {
				b.WriteString("    ip daddr @" + set + " meta l4proto tcp meta mark set meta mark | " + c.Settings.FwMark + counterTag(set) + " accept\n")
				if s.UDPMode != "tcp_only" {
					b.WriteString("    ip daddr @" + set + " meta l4proto udp meta mark set meta mark | " + c.Settings.FwMark + counterTag(set) + " accept\n")
				}
			}
			if includeIPv6 {
				for _, set := range nftSetRefs(s.NFTSet6()) {
					b.WriteString("    ip6 daddr @" + set + " meta l4proto tcp meta mark set meta mark | " + c.Settings.FwMark + counterTag(set) + " accept\n")
					if s.UDPMode != "tcp_only" {
						b.WriteString("    ip6 daddr @" + set + " meta l4proto udp meta mark set meta mark | " + c.Settings.FwMark + counterTag(set) + " accept\n")
					}
				}
			}
		}
	}
	b.WriteString("  }\n")
}

func writeSourceBypassRules(b *strings.Builder, c config.Config, includeIPv6 bool) {
	if expr := nftCIDRSetExpr(normalizeCIDRs(c.Bypass.SourceCIDR4, false)); expr != "" {
		b.WriteString("    ip saddr " + expr + " return\n")
	}
	if includeIPv6 {
		if expr := nftCIDRSetExpr(normalizeCIDRs(c.Bypass.SourceCIDR6, true)); expr != "" {
			b.WriteString("    ip6 saddr " + expr + " return\n")
		}
	}
}

// writeExcludedDeviceRules emits a single early `ether saddr { <macs> } return`
// for every enabled device flagged Exclude — dropping that device's traffic
// out of purewrt before any section or catch-all rule. `ether saddr` covers
// both IP families in one match; same directly-attached-L2 limitation as the
// other device rules.
func writeExcludedDeviceRules(b *strings.Builder, c config.Config) {
	var macs []string
	for _, d := range c.Devices {
		if d.Enabled && d.Exclude && d.MAC != "" {
			macs = append(macs, d.MAC)
		}
	}
	if len(macs) == 0 {
		return
	}
	b.WriteString("    ether saddr { " + strings.Join(macs, ", ") + " } return\n")
}

// writeSectionDeviceRules emits per-device (MAC-based) routing for the
// LuCI Devices page. `ether saddr` covers both IP families in one match
// and is immune to DHCP churn / IPv6 privacy addresses; it only sees
// devices on the directly attached L2 segment (traffic relayed through a
// downstream router carries that router's MAC) — same limitation fw4 MAC
// rules have. Mirrors writeSectionSourceRules' action arms with
// `meta nfproto` family selectors instead of saddr CIDR matches. The
// zapret action is intentionally unsupported for devices in v1 — its
// source-rule path is queue-number plumbing that has no MAC variant yet.
func writeSectionDeviceRules(b *strings.Builder, c config.Config, s config.Section, includeIPv6 bool) {
	var macs []string
	for _, d := range c.Devices {
		if d.Enabled && d.Section == s.Name && d.MAC != "" {
			macs = append(macs, d.MAC)
		}
	}
	if len(macs) == 0 {
		return
	}
	set := "{ " + strings.Join(macs, ", ") + " }"
	switch s.Action {
	case "reject":
		b.WriteString("    ether saddr " + set + " reject\n")
	case "direct":
		b.WriteString("    ether saddr " + set + " return\n")
	case "proxy", "":
		b.WriteString("    meta nfproto ipv4 ether saddr " + set + " meta l4proto tcp meta mark set meta mark | " + c.Settings.FwMark + " tproxy ip to :" + itoa(s.TPROXYPort) + " accept\n")
		if s.UDPMode != "tcp_only" {
			b.WriteString("    meta nfproto ipv4 ether saddr " + set + " meta l4proto udp meta mark set meta mark | " + c.Settings.FwMark + " tproxy ip to :" + itoa(s.TPROXYPort) + " accept\n")
		}
		if includeIPv6 {
			b.WriteString("    meta nfproto ipv6 ether saddr " + set + " meta l4proto tcp meta mark set meta mark | " + c.Settings.FwMark + " tproxy ip6 to :" + itoa(s.TPROXYPort) + " accept\n")
			if s.UDPMode != "tcp_only" {
				b.WriteString("    meta nfproto ipv6 ether saddr " + set + " meta l4proto udp meta mark set meta mark | " + c.Settings.FwMark + " tproxy ip6 to :" + itoa(s.TPROXYPort) + " accept\n")
			}
		}
	}
}

func writeSectionSourceRules(b *strings.Builder, c config.Config, s config.Section, includeIPv6 bool) {
	v4 := nftCIDRSetExpr(normalizeCIDRs(s.SourceCIDR4, false))
	v6 := ""
	if includeIPv6 {
		v6 = nftCIDRSetExpr(normalizeCIDRs(s.SourceCIDR6, true))
	}
	if v4 == "" && v6 == "" {
		return
	}
	switch s.Action {
	case "reject":
		if v4 != "" {
			b.WriteString("    ip saddr " + v4 + " reject\n")
		}
		if v6 != "" {
			b.WriteString("    ip6 saddr " + v6 + " reject\n")
		}
	case "direct":
		if v4 != "" {
			b.WriteString("    ip saddr " + v4 + " return\n")
		}
		if v6 != "" {
			b.WriteString("    ip6 saddr " + v6 + " return\n")
		}
	case "zapret":
		writeZapretSourcePreroutingRules(b, c, s, v4, v6)
	case "proxy", "":
		if v4 != "" {
			b.WriteString("    ip saddr " + v4 + " meta l4proto tcp meta mark set meta mark | " + c.Settings.FwMark + " tproxy ip to :" + itoa(s.TPROXYPort) + " accept\n")
			if s.UDPMode != "tcp_only" {
				b.WriteString("    ip saddr " + v4 + " meta l4proto udp meta mark set meta mark | " + c.Settings.FwMark + " tproxy ip to :" + itoa(s.TPROXYPort) + " accept\n")
			}
		}
		if v6 != "" {
			b.WriteString("    ip6 saddr " + v6 + " meta l4proto tcp meta mark set meta mark | " + c.Settings.FwMark + " tproxy ip6 to :" + itoa(s.TPROXYPort) + " accept\n")
			if s.UDPMode != "tcp_only" {
				b.WriteString("    ip6 saddr " + v6 + " meta l4proto udp meta mark set meta mark | " + c.Settings.FwMark + " tproxy ip6 to :" + itoa(s.TPROXYPort) + " accept\n")
			}
		}
	}
}

func hasEnabledZapretStrategies(c config.Config) bool {
	for _, s := range c.Sections {
		if !s.Enabled || s.Action != "zapret" || len(s.ZapretStrategies) == 0 {
			continue
		}
		for _, name := range s.ZapretStrategies {
			if _, ok := c.ZapretStrategyByName(name); ok {
				return true
			}
		}
	}
	return false
}

func writeZapretPreroutingRules(b *strings.Builder, c config.Config, s config.Section, includeIPv6 bool) {
	for _, name := range s.ZapretStrategies {
		zs, ok := c.ZapretStrategyByName(name)
		if !ok {
			continue
		}
		p, ok := c.ZapretProfileByName(zs.Profile)
		if !ok {
			continue
		}
		for _, set := range nftSetRefs(s.NFTSet4()) {
			writeZapretPreroutingSetRules(b, "ip", "@"+set, set, p, zs)
		}
		if includeIPv6 {
			for _, set := range nftSetRefs(s.NFTSet6()) {
				writeZapretPreroutingSetRules(b, "ip6", "@"+set, set, p, zs)
			}
		}
	}
}

func writeZapretSourcePreroutingRules(b *strings.Builder, c config.Config, s config.Section, v4, v6 string) {
	for _, name := range s.ZapretStrategies {
		zs, ok := c.ZapretStrategyByName(name)
		if !ok {
			continue
		}
		p, ok := c.ZapretProfileByName(zs.Profile)
		if !ok {
			continue
		}
		if v4 != "" {
			// No set name when matching on a CIDR-literal saddr; skip the counter.
			writeZapretPreroutingSetRules(b, "ip", v4, "", p, zs)
		}
		if v6 != "" {
			writeZapretPreroutingSetRules(b, "ip6", v6, "", p, zs)
		}
	}
}

func writeZapretPreroutingSetRules(b *strings.Builder, family, src, counterSet string, p config.ZapretProfile, zs config.ZapretStrategy) {
	iif := nftIfaceExpr("iifname", p.Interfaces)
	cnt := ""
	if counterSet != "" {
		cnt = counterTag(counterSet)
	}
	if protocolEnabled(zs, "tcp") && zs.TCPPktIn > 0 {
		b.WriteString("    " + family + " saddr " + src + iif + " meta l4proto tcp" + nftPortExpr("tcp", "sport", zs.TCPPorts) + " ct reply packets >= 1 ct reply packets <= " + itoa(zs.TCPPktIn) + cnt + " queue num " + itoa(zs.QueueNum) + " bypass\n")
	}
	if protocolEnabled(zs, "udp") && zs.UDPPktIn > 0 {
		b.WriteString("    " + family + " saddr " + src + iif + " meta l4proto udp" + nftPortExpr("udp", "sport", zs.UDPPorts) + " ct reply packets >= 1 ct reply packets <= " + itoa(zs.UDPPktIn) + cnt + " queue num " + itoa(zs.QueueNum) + " bypass\n")
	}
}

func writeZapretPostroutingRules(b *strings.Builder, c config.Config, s config.Section, includeIPv6 bool) {
	for _, name := range s.ZapretStrategies {
		zs, ok := c.ZapretStrategyByName(name)
		if !ok {
			continue
		}
		p, ok := c.ZapretProfileByName(zs.Profile)
		if !ok {
			continue
		}
		for _, set := range nftSetRefs(s.NFTSet4()) {
			writeZapretPostroutingSetRules(b, "ip", "@"+set, set, p, zs)
		}
		if includeIPv6 {
			for _, set := range nftSetRefs(s.NFTSet6()) {
				writeZapretPostroutingSetRules(b, "ip6", "@"+set, set, p, zs)
			}
		}
	}
}

func writeZapretPostroutingSetRules(b *strings.Builder, family, dst, counterSet string, p config.ZapretProfile, zs config.ZapretStrategy) {
	oif := nftIfaceExpr("oifname", p.Interfaces)
	cnt := ""
	if counterSet != "" {
		cnt = counterTag(counterSet)
	}
	if protocolEnabled(zs, "tcp") {
		b.WriteString("    " + family + " daddr " + dst + oif + " meta mark & " + p.FwMark + " == 0 meta l4proto tcp" + nftPortExpr("tcp", "dport", zs.TCPPorts) + " ct original packets >= 1 ct original packets <= " + itoa(zs.TCPPktOut) + cnt + " queue num " + itoa(zs.QueueNum) + " bypass\n")
		b.WriteString("    " + family + " daddr " + dst + oif + " meta mark & " + p.FwMark + " == 0 meta l4proto tcp" + nftPortExpr("tcp", "dport", zs.TCPPorts) + " tcp flags & (fin | rst) != 0" + cnt + " queue num " + itoa(zs.QueueNum) + " bypass\n")
	}
	if protocolEnabled(zs, "udp") {
		b.WriteString("    " + family + " daddr " + dst + oif + " meta mark & " + p.FwMark + " == 0 meta l4proto udp" + nftPortExpr("udp", "dport", zs.UDPPorts) + " ct original packets >= 1 ct original packets <= " + itoa(zs.UDPPktOut) + cnt + " queue num " + itoa(zs.QueueNum) + " bypass\n")
	}
}

func nftIfaceExpr(keyword string, ifaces []string) string {
	vals := make([]string, 0, len(ifaces))
	seen := map[string]bool{}
	for _, v := range ifaces {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		vals = append(vals, "\""+v+"\"")
	}
	if len(vals) == 1 {
		return " " + keyword + " " + vals[0]
	}
	if len(vals) == 0 {
		return ""
	}
	return " " + keyword + " { " + strings.Join(vals, ", ") + " }"
}

func protocolEnabled(zs config.ZapretStrategy, proto string) bool {
	for _, p := range zs.Protocols {
		if strings.EqualFold(strings.TrimSpace(p), proto) {
			return true
		}
	}
	return false
}

// writeZapretClaimReturns emits the section's port-scoped claim: covered
// (protocol, port) traffic to the section's sets returns from the chain so
// it stays direct for nfqws; everything else falls through to later
// sections' rules. Shared by PREROUTING and OUTPUT — both need the exact
// same claim shape (docs/zapret-port-scoped-claims.md). Precedence against
// proxy sections comes purely from section order.
func writeZapretClaimReturns(b *strings.Builder, c config.Config, s config.Section, includeIPv6 bool) {
	claims := zapretSectionPortClaims(c, s)
	if len(claims) == 0 {
		return
	}
	emit := func(family string, sets []string) {
		for _, set := range sets {
			for _, proto := range []string{"tcp", "udp"} {
				cl, ok := claims[proto]
				if !ok {
					continue
				}
				b.WriteString("    " + family + " daddr @" + set + " meta l4proto " + proto + nftPortExpr(proto, "dport", cl.ports) + counterTag(set) + " return\n")
			}
		}
	}
	emit("ip", nftSetRefs(s.NFTSet4()))
	if includeIPv6 {
		emit("ip6", nftSetRefs(s.NFTSet6()))
	}
}

// zapretPortClaim is one protocol's share of a zapret section's claim.
// all=true means every port of the protocol (a strategy with an empty
// port list); otherwise ports is a comma-joined, order-preserving union
// across the section's enabled strategies, ready for nftPortExpr.
type zapretPortClaim struct {
	ports string
	all   bool
}

// zapretSectionPortClaims computes which (protocol, ports) a zapret section
// claims: the union over its enabled strategies. Ports outside the claim
// fall through the chain to later sections (docs/zapret-port-scoped-claims.md).
func zapretSectionPortClaims(c config.Config, s config.Section) map[string]zapretPortClaim {
	claims := map[string]zapretPortClaim{}
	seen := map[string]map[string]bool{}
	add := func(proto, ports string) {
		cl := claims[proto]
		if cl.all {
			return
		}
		if strings.TrimSpace(ports) == "" {
			claims[proto] = zapretPortClaim{all: true}
			return
		}
		if seen[proto] == nil {
			seen[proto] = map[string]bool{}
		}
		parts := []string{}
		if cl.ports != "" {
			parts = append(parts, cl.ports)
		}
		for _, p := range strings.Split(ports, ",") {
			p = strings.TrimSpace(p)
			if p == "" || seen[proto][p] {
				continue
			}
			seen[proto][p] = true
			parts = append(parts, p)
		}
		claims[proto] = zapretPortClaim{ports: strings.Join(parts, ", ")}
	}
	for _, name := range s.ZapretStrategies {
		zs, ok := c.ZapretStrategyByName(name)
		if !ok {
			continue
		}
		if protocolEnabled(zs, "tcp") {
			add("tcp", zs.TCPPorts)
		}
		if protocolEnabled(zs, "udp") {
			add("udp", zs.UDPPorts)
		}
	}
	return claims
}

func nftPortExpr(proto, dir, ports string) string {
	ports = strings.TrimSpace(ports)
	if ports == "" {
		return ""
	}
	return " " + proto + " " + dir + " { " + ports + " }"
}

func normalizeCIDRs(in []string, ipv6 bool) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		var normalized string
		if p, err := netip.ParsePrefix(v); err == nil {
			if p.Addr().Is6() != ipv6 {
				continue
			}
			normalized = p.Masked().String()
		} else if a, err := netip.ParseAddr(v); err == nil {
			if a.Is6() != ipv6 {
				continue
			}
			if ipv6 {
				normalized = a.String() + "/128"
			} else {
				normalized = a.String() + "/32"
			}
		}
		if normalized != "" && !seen[normalized] {
			seen[normalized] = true
			out = append(out, normalized)
		}
	}
	return out
}

func nftCIDRSetExpr(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	if len(vals) == 1 {
		return vals[0]
	}
	return "{ " + strings.Join(vals, ", ") + " }"
}

func WriteNFTSetPayloadHeader(w io.Writer, c config.Config) error {
	if _, err := io.WriteString(w, "#!/usr/sbin/nft -f\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "# PureWRT generated set payload; do not edit.\n"); err != nil {
		return err
	}
	for _, set := range nftPayloadSets(c) {
		if _, err := io.WriteString(w, "flush set inet purewrt "+set+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func WriteNFTSetElement(w io.Writer, set string, value string) error {
	_, err := io.WriteString(w, "add element inet purewrt "+set+" { "+value+" }\n")
	return err
}

func nftPayloadSets(c config.Config) []string {
	includeIPv6 := c.IPv6Routed()
	sets := []string{"bypass4", "proxy_server_bypass4", "direct4", "reject4"}
	if includeIPv6 {
		sets = append(sets, "bypass6", "proxy_server_bypass6", "direct6", "reject6")
	}
	for _, s := range c.Sections {
		if s.Action == "proxy" || s.Action == "zapret" {
			sets = append(sets, s.NFTSet4())
			if includeIPv6 {
				sets = append(sets, s.NFTSet6())
			}
		}
	}
	return sets
}

func nftSetDefinition(set string, dynamicDNS bool) string {
	typ := "ipv4_addr"
	if isIPv6Set(set) {
		typ = "ipv6_addr"
	}
	var b strings.Builder
	b.WriteString("  set " + set + " {\n    type " + typ + "\n")
	if dynamicDNS {
		b.WriteString("    flags dynamic,timeout\n    timeout 150m\n    size 65535\n")
		b.WriteString("  }\n\n")
		return b.String()
	}
	b.WriteString("    flags interval\n    auto-merge\n")
	b.WriteString("  }\n\n")
	return b.String()
}

func dnsSetName(set string) string { return "dns_" + set }

// DynamicDNSSetNames returns the runtime-populated dns_* set names for the
// config — the sets dnsmasq fills from resolved domains (wiped by the atomic
// table replace on apply and not re-seeded from the static sets file). Keyed on
// the *current* config so callers (apply snapshot/restore, the flush-dns-sets
// diagnostic) never touch a removed section's set.
func DynamicDNSSetNames(c config.Config) []string {
	base := nftPayloadSets(c)
	out := make([]string, 0, len(base))
	for _, s := range base {
		out = append(out, dnsSetName(s))
	}
	return out
}

func nftSetRefs(set string) []string { return []string{set, dnsSetName(set)} }

// nftCounterDecl emits a named counter declaration for `set`. Counters are
// declared alongside the set they observe (same lifetime) and referenced from
// any chain rule that matches @set. nftables aggregates increments across
// every rule sharing the same counter name, so one counter per set captures
// total traffic across PREROUTING/OUTPUT and v4/v6 variants of that set.
func nftCounterDecl(set string) string {
	return "  counter " + set + " {\n  }\n\n"
}

// counterTag is the inline rule fragment that increments the named counter
// for `set`. Insert immediately before the rule's verdict so packets that are
// dropped/returned/tproxy'd still get counted. Includes a leading space so
// it appends cleanly onto any existing rule expression.
func counterTag(set string) string {
	return " counter name \"" + set + "\""
}

func isIPv6Set(set string) bool {
	return strings.HasSuffix(set, "6")
}

func nativeNFTLines(expr string, s config.Section, fwmark string) []string {
	base := " meta mark set meta mark | " + fwmark
	port := itoa(s.TPROXYPort)
	if strings.Contains(expr, "ip6 ") {
		return []string{"    " + expr + base + " tproxy ip6 to :" + port + " accept\n"}
	}
	if strings.Contains(expr, "ip ") {
		return []string{"    " + expr + base + " tproxy ip to :" + port + " accept\n"}
	}
	return []string{
		"    ip version 4 " + expr + base + " tproxy ip to :" + port + " accept\n",
		"    ip6 version 6 " + expr + base + " tproxy ip6 to :" + port + " accept\n",
	}
}
