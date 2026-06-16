package generator

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestFirewallRules_MultiZoneWithHijack(t *testing.T) {
	c := config.Default()
	c.Settings.FwMark = "0x1"
	c.Settings.FwMarkMask = "0xff"
	c.Settings.LANSourceZones = []string{"iot", "guest"}
	c.DNS.HijackLANDNS = true

	got := string(FirewallRules(c))
	for _, want := range []string{
		"config rule 'purewrt_tproxy_accept_iot'",
		"config rule 'purewrt_tproxy_accept_guest'",
		"option mark '0x1/0xff'",
		"option src 'iot'",
		"option src 'guest'",
		"config rule 'purewrt_dns_accept_iot'",
		"config redirect 'purewrt_dns_hijack_iot_udp'",
		"config redirect 'purewrt_dns_hijack_guest_tcp'",
		"option dest_port '53'",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestFirewallRules_HijackOffOnlyTProxyAccept(t *testing.T) {
	c := config.Default()
	c.Settings.LANSourceZones = []string{"iot"}
	c.DNS.HijackLANDNS = false

	got := string(FirewallRules(c))
	if !strings.Contains(got, "purewrt_tproxy_accept_iot") {
		t.Fatalf("expected tproxy accept for iot, got:\n%s", got)
	}
	for _, unwanted := range []string{"purewrt_dns_hijack_", "purewrt_dns_accept_"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("hijack off: did not expect %q in:\n%s", unwanted, got)
		}
	}
}

func TestFirewallRules_DefaultsToLanAndCustomMark(t *testing.T) {
	c := config.Default() // config.Default() seeds LANSourceZones = ["lan"]
	c.Settings.FwMark = "0x8"
	c.Settings.FwMarkMask = "0xe"
	c.DNS.HijackLANDNS = true

	got := string(FirewallRules(c))
	if !strings.Contains(got, "purewrt_tproxy_accept_lan") {
		t.Errorf("default config must route the lan zone, got:\n%s", got)
	}
	if !strings.Contains(got, "option mark '0x8/0xe'") {
		t.Errorf("custom fwmark must be reflected, got:\n%s", got)
	}
}

func TestFirewallRules_EmptyZonesEmitsNothing(t *testing.T) {
	c := config.Default()
	c.Settings.LANSourceZones = nil // operator opted out
	c.DNS.HijackLANDNS = true

	if got := FirewallRules(c); got != nil {
		t.Errorf("empty zone list must emit no rules, got:\n%s", got)
	}
}
