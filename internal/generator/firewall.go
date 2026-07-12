package generator

import (
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

// FirewallRules emits the fw4 (uci firewall) rules PureWRT needs for each
// configured LAN source zone, written to /etc/config/purewrt-firewall.generated
// and `uci import`ed by applyUCIDNSFirewall. Per zone:
//
//   - a TPROXY input-accept keyed on PureWRT's FwMark — ALWAYS, so the
//     TPROXY'd packets mihomo delivers locally are accepted even on zones with
//     `input REJECT` (multi-VLAN setups). The mark is taken from
//     c.Settings.FwMark/FwMarkMask so it can never drift from the nftables
//     TPROXY rule (a mismatch silently drops all proxied traffic).
//   - a DNS-hijack redirect (udp+tcp/53 -> DNAT) and a DNS input-accept,
//     only when DNS.HijackLANDNS — so clients are forced onto, and can reach,
//     the router's dnsmasq (which populates the routing nftsets).
//
// All section names are prefixed `purewrt_` so applyUCIDNSFirewall can delete
// the previous generation wholesale and reconcile against the current zone set.
func FirewallRules(c config.Config) []byte {
	// The ["lan"] default lives in config.Default() (the single source of truth
	// for defaults, seeded by config.Load); an explicitly-empty list means the
	// operator opted out of PureWRT-managed zone firewall rules, so emit none.
	zones := c.Settings.LANSourceZones
	mark := c.Settings.FwMark
	if mark == "" {
		mark = "0x1"
	}
	mask := c.Settings.FwMarkMask
	if mask == "" {
		mask = "0xff"
	}

	var b strings.Builder
	for _, z := range zones {
		z = strings.TrimSpace(z)
		if z == "" {
			continue
		}
		// TPROXY input-accept (always). meta mark on the locally-delivered
		// packet == FwMark; without this, an input-REJECT zone drops it.
		b.WriteString("config rule 'purewrt_tproxy_accept_" + z + "'\n")
		b.WriteString("    option name 'PureWRT TPROXY accept (" + z + ")'\n")
		b.WriteString("    option src '" + z + "'\n")
		b.WriteString("    option proto 'all'\n")
		b.WriteString("    option mark '" + mark + "/" + mask + "'\n")
		b.WriteString("    option target 'ACCEPT'\n\n")

		if !c.DNS.HijackLANDNS {
			continue
		}
		// DNS input-accept so input-REJECT zones can reach the router resolver.
		b.WriteString("config rule 'purewrt_dns_accept_" + z + "'\n")
		b.WriteString("    option name 'PureWRT DNS accept (" + z + ")'\n")
		b.WriteString("    option src '" + z + "'\n")
		b.WriteString("    option proto 'tcp udp'\n")
		b.WriteString("    option dest_port '53'\n")
		b.WriteString("    option target 'ACCEPT'\n\n")
		// DNS hijack: force port-53 to the router's dnsmasq. fw4 accepts both
		// protocols on one redirect (`proto 'tcp udp'`), so emit a single rule
		// rather than duplicating it per protocol.
		b.WriteString("config redirect 'purewrt_dns_hijack_" + z + "'\n")
		b.WriteString("    option name 'PureWRT DNS hijack (" + z + ")'\n")
		b.WriteString("    option src '" + z + "'\n")
		b.WriteString("    option proto 'tcp udp'\n")
		b.WriteString("    option src_dport '53'\n")
		b.WriteString("    option dest_port '53'\n")
		b.WriteString("    option target 'DNAT'\n\n")
	}
	writeMeshFirewall(&b, c)
	if b.Len() == 0 {
		return nil
	}
	return []byte(b.String())
}

// writeMeshFirewall emits the fw4 zone + rules for the easytier overlay
// device. Default posture REJECT: forward REJECT means the kernel can never
// transit packets between the overlay and LAN/WAN (friend traffic terminates
// at local listeners only — structural loop/abuse prevention), input REJECT
// means only the explicitly-accepted mesh ports are reachable from friends.
// Self-cleaning: purewrt_* sections are wholesale-reconciled on apply.
func writeMeshFirewall(b *strings.Builder, c config.Config) {
	if !c.MeshActive() {
		return
	}
	m := c.Mesh
	b.WriteString("config zone 'purewrt_mesh'\n")
	b.WriteString("    option name 'pwmesh'\n")
	b.WriteString("    list device '" + m.DeviceName + "'\n")
	b.WriteString("    option input 'REJECT'\n")
	b.WriteString("    option forward 'REJECT'\n")
	b.WriteString("    option output 'ACCEPT'\n\n")
	if m.ExitEnabled && m.ListenPort > 0 {
		b.WriteString("config rule 'purewrt_mesh_ss'\n")
		b.WriteString("    option name 'PureWRT mesh exit (ss)'\n")
		b.WriteString("    option src 'pwmesh'\n")
		b.WriteString("    option proto 'tcp udp'\n")
		b.WriteString("    option dest_port '" + itoa(m.ListenPort) + "'\n")
		b.WriteString("    option target 'ACCEPT'\n\n")
	}
	if m.APIMeshPort > 0 {
		b.WriteString("config rule 'purewrt_mesh_api'\n")
		b.WriteString("    option name 'PureWRT mesh api'\n")
		b.WriteString("    option src 'pwmesh'\n")
		b.WriteString("    option proto 'tcp'\n")
		b.WriteString("    option dest_port '" + itoa(m.APIMeshPort) + "'\n")
		b.WriteString("    option target 'ACCEPT'\n\n")
	}
}
