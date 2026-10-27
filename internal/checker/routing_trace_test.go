package checker

import (
	"github.com/purewrt/purewrt/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func traceConfig(t *testing.T) config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("DOMAIN-SUFFIX,example.com\nIP-CIDR,203.0.113.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Sections = []config.Section{
		{Name: "early", Enabled: true, Action: "proxy", Priority: 10, MatchProtocol: "udp", DestinationPorts: "7770,10000-11000", IPv4Enabled: true, IPv6Enabled: true},
		{Name: "later", Enabled: true, Action: "proxy", Priority: 20, MatchProtocol: "tcp", DestinationPorts: "443", IPv4Enabled: true, IPv6Enabled: true},
	}
	c.RuleProviders = []config.RuleProvider{
		{Name: "a_later", Enabled: true, Section: "later", Path: path, Format: "text"},
		{Name: "z_early", Enabled: true, Section: "early", Path: path, Format: "text"},
	}
	return c
}
func TestDestinationTraceScopeFallthrough(t *testing.T) {
	for _, tc := range []struct {
		f               Flow
		section, action string
	}{
		{Flow{Protocol: "udp", Port: 10600}, "early", "proxy"},
		{Flow{Protocol: "tcp", Port: 443}, "later", "proxy"},
		{Flow{Protocol: "udp", Port: 443}, "", "direct"},
		{Flow{Protocol: "tcp", Port: 80}, "", "direct"},
		{Flow{}, "", "conditional"},
	} {
		c := traceConfig(t)
		got := TraceDestination(c, "example.com", tc.f)
		if got.Section != tc.section || got.Action != tc.action {
			t.Fatalf("%+v: %+v", tc.f, got)
		}
		if len(got.Steps) != 2 || got.Steps[0].Section != "early" {
			t.Fatalf("incorrect order: %+v", got)
		}
	}
}
func TestDestinationTraceExclusionsDisabledAndShadowed(t *testing.T) {
	c := traceConfig(t)
	c.Sections[0].MatchProtocol = "tcp"
	c.Sections[0].DestinationPorts = "443"
	got := TraceDestination(c, "example.com", Flow{Protocol: "tcp", Port: 443})
	if got.Steps[1].Status != "shadowed" {
		t.Fatal(got)
	}
	c.Sections[0].Enabled = false
	if got = TraceDestination(c, "example.com", Flow{Protocol: "tcp", Port: 443}); got.Section != "later" {
		t.Fatal(got)
	}
	c.Sections[0].Enabled = true
	c.Sections[0].Action = "direct"
	c.Sections[0].Priority = 1000
	if got = TraceDestination(c, "example.com", Flow{Protocol: "udp", Port: 80}); got.Action != "direct" || got.Section != "early" {
		t.Fatal(got)
	}
	c.Sections[1].Action = "reject"
	if got = TraceDestination(c, "example.com", Flow{}); got.Action != "reject" {
		t.Fatal(got)
	}
}
func TestDestinationTraceZapretIntersectionWAN(t *testing.T) {
	c := traceConfig(t)
	c.Sections[0].Action = "zapret"
	c.Sections[0].ZapretStrategies = []string{"game"}
	c.Sections[1].MatchProtocol = "udp"
	c.Sections[1].DestinationPorts = ""
	c.ZapretStrategies = []config.ZapretStrategy{{Name: "game", Enabled: true, Profile: "wan", Protocols: []string{"udp"}, UDPPorts: "10600"}}
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, Interfaces: []string{"eth1"}}}
	for _, tc := range []struct {
		flow            Flow
		section, action string
	}{
		{Flow{"udp", 10600, "eth1"}, "early", "zapret"},
		{Flow{"udp", 10600, "eth2"}, "early", "direct"},
		{Flow{"udp", 10500, "eth1"}, "later", "proxy"},
		{Flow{"udp", 10600, ""}, "", "conditional"},
	} {
		got := TraceDestination(c, "example.com", tc.flow)
		if got.Section != tc.section || got.Action != tc.action {
			t.Fatalf("%+v: %+v", tc.flow, got)
		}
	}
}
func TestLiveIPFlowFallthrough(t *testing.T) {
	c := traceConfig(t)
	stubIPSet(t, map[string]string{"proxy_early4": "203.0.113.1", "proxy_later4": "203.0.113.1"})
	for _, tc := range []struct {
		flow            Flow
		section, action string
	}{
		{Flow{"udp", 10600, ""}, "early", "proxy"},
		{Flow{"tcp", 443, ""}, "later", "proxy"},
		{Flow{"udp", 443, ""}, "", "default"},
	} {
		got := ClassifyIPFlow(c, "203.0.113.1", tc.flow)
		if got.Section != tc.section || got.Action != tc.action {
			t.Fatalf("%+v: %+v", tc.flow, got)
		}
	}
	c.Sections[0].Enabled = false
	if got := ClassifyIPFlow(c, "203.0.113.1", Flow{"udp", 10600, ""}); got.Action != "default" {
		t.Fatal(got)
	}
}
func TestDestinationUDPPolicy(t *testing.T) {
	c := traceConfig(t)
	s := c.Sections[1]
	s.MatchProtocol = ""
	s.DestinationPorts = ""
	s.UDPMode = "tcp_only"
	if state, _ := SectionFlowScope(c, s, Flow{"udp", 443, ""}); state != "skip" {
		t.Fatal(state)
	}
	s.UDPMode = "block_quic"
	if state, _ := SectionFlowScope(c, s, Flow{"udp", 443, ""}); state != "reject" {
		t.Fatal(state)
	}
}

func TestDestinationVirtualDirectAndUnavailableProvider(t *testing.T) {
	c := traceConfig(t)
	c.RuleProviders[0].Section = "direct"
	got := TraceDestination(c, "example.com", Flow{"udp", 10600, ""})
	if got.Action != "direct" || got.Section != "direct" {
		t.Fatal(got)
	}
	c.RuleProviders[0].Path = "/missing/provider"
	got = TraceDestination(c, "example.com", Flow{"udp", 10600, ""})
	if got.Action != "conditional" || len(got.Warnings) == 0 {
		t.Fatal(got)
	}
}
