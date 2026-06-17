package generator

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// vpnOrderConfig builds a config with a VPN section at priority 10 (highest
// precedence) plus the default proxy sections (media=20, ai=30, common=40),
// a VPN definition, and a device assigned to the VPN section.
func vpnOrderConfig() config.Config {
	c := config.Default()
	c.VPNs = []config.VPN{{Name: "vpn", Enabled: true, Interface: "tun0", RouteTable: "201", FwMark: "0x2", FwMarkMask: "0xff", IPRulePriority: "101"}}
	c.Sections = append(c.Sections, config.Section{
		Name: "VPN", Enabled: true, Action: "vpn", VPN: "vpn",
		Priority: 10, IPv4Enabled: true, IPv6Enabled: true,
	})
	c.Devices = []config.Device{{Name: "client", MAC: "aa:bb:cc:00:00:01", Section: "VPN", Enabled: true}}
	return c
}

// TestPreroutingVPNDestBeatsProxyByPriority: a destination listed in both the
// VPN section (priority 10) and a proxy section must be evaluated under the
// VPN rule first, because prerouting now emits sections in priority order.
func TestPreroutingVPNDestBeatsProxyByPriority(t *testing.T) {
	c := vpnOrderConfig()
	out := string(NFTables(c))
	vpnIdx := strings.Index(out, "@vpn_VPN4")
	proxyIdx := strings.Index(out, "@proxy_common4")
	if vpnIdx < 0 || proxyIdx < 0 {
		t.Fatalf("expected both vpn_VPN4 and proxy_common4 rules, got vpn=%d proxy=%d:\n%s", vpnIdx, proxyIdx, out)
	}
	if vpnIdx > proxyIdx {
		t.Fatalf("vpn_VPN4 (priority 10) must precede proxy_common4 (priority 40) in prerouting; got vpn@%d proxy@%d", vpnIdx, proxyIdx)
	}
}

// TestPreroutingClientIdentityBeatsProxyDest: a client (device) assigned to the
// VPN section must have its source-match rule emitted before the proxy
// destination rules, so ALL its traffic is tunnelled even for destinations that
// are in a proxy set (the whole point of "VPN for a client").
func TestPreroutingClientIdentityBeatsProxyDest(t *testing.T) {
	c := vpnOrderConfig()
	out := string(NFTables(c))
	devIdx := strings.Index(out, "ether saddr { aa:bb:cc:00:00:01 }")
	proxyIdx := strings.Index(out, "@proxy_common4")
	if devIdx < 0 || proxyIdx < 0 {
		t.Fatalf("expected device rule and proxy_common4, got dev=%d proxy=%d:\n%s", devIdx, proxyIdx, out)
	}
	if devIdx > proxyIdx {
		t.Fatalf("device→VPN rule must precede proxy destination rules so the client tunnels everything; got dev@%d proxy@%d", devIdx, proxyIdx)
	}
}

// TestPreroutingLANGuardStillFirst: the client-identity pass must not jump ahead
// of the loop-breakers / LAN / bypass returns — RFC1918 still returns before any
// device rule, so a VPN client's LAN traffic is never tunnelled.
func TestPreroutingLANGuardStillFirst(t *testing.T) {
	c := vpnOrderConfig()
	out := string(NFTables(c))
	lanIdx := strings.Index(out, "192.168.0.0/16")
	devIdx := strings.Index(out, "ether saddr { aa:bb:cc:00:00:01 }")
	if lanIdx < 0 || devIdx < 0 {
		t.Fatalf("expected LAN guard and device rule, got lan=%d dev=%d", lanIdx, devIdx)
	}
	if lanIdx > devIdx {
		t.Fatalf("RFC1918 LAN return must precede the client-identity rule; got lan@%d dev@%d", lanIdx, devIdx)
	}
}
