package generator

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// orderConfig adds a high-priority (10) proxy section "hipri" alongside the
// default proxy sections (media=20, ai=30, common=40) plus a device assigned
// to it, to exercise prerouting precedence: sections emit in priority order and
// client-identity rules precede destination rules.
func orderConfig() config.Config {
	c := config.Default()
	c.Sections = append(c.Sections, config.Section{
		Name: "hipri", Enabled: true, Action: "proxy", TPROXYPort: 7896,
		ProxyGroup: "Hipri", ProxyGroupType: "url-test",
		Priority: 10, IPv4Enabled: true, IPv6Enabled: true,
	})
	c.Devices = []config.Device{{Name: "client", MAC: "aa:bb:cc:00:00:01", Section: "hipri", Enabled: true}}
	return c
}

// TestPreroutingHigherPriorityDestFirst: a higher-priority section's dest rule
// is emitted before a lower-priority one (sections in priority order).
func TestPreroutingHigherPriorityDestFirst(t *testing.T) {
	out := string(NFTables(orderConfig()))
	hi := strings.Index(out, "@proxy_hipri4")
	lo := strings.Index(out, "@proxy_common4")
	if hi < 0 || lo < 0 {
		t.Fatalf("expected both proxy_hipri4 and proxy_common4, got hi=%d lo=%d:\n%s", hi, lo, out)
	}
	if hi > lo {
		t.Fatalf("proxy_hipri4 (priority 10) must precede proxy_common4 (priority 40); got hi@%d lo@%d", hi, lo)
	}
}

// TestPreroutingClientIdentityBeatsProxyDest: a device assigned to a section
// has its source-match rule emitted before the destination rules, so all its
// traffic routes to that section regardless of destination.
func TestPreroutingClientIdentityBeatsProxyDest(t *testing.T) {
	out := string(NFTables(orderConfig()))
	devIdx := strings.Index(out, "ether saddr { aa:bb:cc:00:00:01 }")
	proxyIdx := strings.Index(out, "@proxy_common4")
	if devIdx < 0 || proxyIdx < 0 {
		t.Fatalf("expected device rule and proxy_common4, got dev=%d proxy=%d:\n%s", devIdx, proxyIdx, out)
	}
	if devIdx > proxyIdx {
		t.Fatalf("device rule must precede proxy destination rules; got dev@%d proxy@%d", devIdx, proxyIdx)
	}
}

// TestPreroutingLANGuardStillFirst: RFC1918 returns before any device rule, so
// LAN traffic is never proxied/tunnelled.
func TestPreroutingLANGuardStillFirst(t *testing.T) {
	out := string(NFTables(orderConfig()))
	lanIdx := strings.Index(out, "192.168.0.0/16")
	devIdx := strings.Index(out, "ether saddr { aa:bb:cc:00:00:01 }")
	if lanIdx < 0 || devIdx < 0 {
		t.Fatalf("expected LAN guard and device rule, got lan=%d dev=%d", lanIdx, devIdx)
	}
	if lanIdx > devIdx {
		t.Fatalf("RFC1918 LAN return must precede the client-identity rule; got lan@%d dev@%d", lanIdx, devIdx)
	}
}
