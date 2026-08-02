package generator

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/proxyguard"
	"gopkg.in/yaml.v3"
)

func TestProxyGuardOverlayPreservesUserExcludeFilter(t *testing.T) {
	c := config.Default()
	c.Settings.ProxyGuardEnabled = true
	c.ProxyProviders = []config.ProxyProvider{{Name: "main", Enabled: true, Type: "file", Path: "/tmp/main.yaml"}}
	userFilter := `(?i)private|do-not-touch` + "`" + `^manual-exclude$`
	for i := range c.Sections {
		if c.Sections[i].ProxyGroup == "Common" {
			c.Sections[i].ProxyExcludeFilter = userFilter
		}
	}
	s := proxyguard.NewState()
	s.Nodes["bad[1]"] = &proxyguard.NodeState{Name: "bad[1]", State: proxyguard.Quarantined}
	s.Groups["Common"] = &proxyguard.GroupState{Name: "Common", Members: []string{"bad[1]", "good"}}

	out, err := MihomoWithProxyGuardState(c, &s)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "PureWRTGuardCandidate_") {
		t.Fatalf("candidate shadow missing:\n%s", text)
	}
	if !strings.Contains(text, userFilter+"`^(?:bad\\[1\\])$") {
		t.Fatalf("user expression was not preserved as the first clause:\n%s", text)
	}
	for _, section := range c.Sections {
		if section.ProxyGroup == "Common" && section.ProxyExcludeFilter != userFilter {
			t.Fatalf("stored user expression changed: got %q want %q", section.ProxyExcludeFilter, userFilter)
		}
	}

	empty := proxyguard.NewState()
	clean, err := MihomoWithProxyGuardState(c, &empty)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(clean), userFilter+"`") {
		t.Fatalf("empty guard must restore exact user filter:\n%s", clean)
	}
}

func TestProxyGuardOverlayKeepsThreeBestExplicitMembers(t *testing.T) {
	c := config.Default()
	c.Settings.ProxyGuardEnabled = true
	c.VPNs = []config.VPN{
		{Name: "a", Enabled: true, Interface: "wg0"},
		{Name: "b", Enabled: true, Interface: "wg1"},
		{Name: "c", Enabled: true, Interface: "wg2"},
		{Name: "d", Enabled: true, Interface: "wg3"},
	}
	for i := range c.Sections {
		if c.Sections[i].ProxyGroup == "Common" {
			c.Sections[i].VPNs = []string{"a", "b", "c", "d"}
		}
	}
	s := proxyguard.NewState()
	s.Nodes["vpn_a"] = &proxyguard.NodeState{Name: "vpn_a", State: proxyguard.Quarantined}
	s.Nodes["vpn_b"] = &proxyguard.NodeState{Name: "vpn_b", State: proxyguard.Quarantined}
	s.Nodes["vpn_c"] = &proxyguard.NodeState{Name: "vpn_c", State: proxyguard.Quarantined}
	s.Nodes["vpn_d"] = &proxyguard.NodeState{Name: "vpn_d", State: proxyguard.Quarantined}
	s.Groups["Common"] = &proxyguard.GroupState{
		Name:        "Common",
		Members:     []string{"vpn_a", "vpn_b", "vpn_c", "vpn_d"},
		LastResorts: []string{"vpn_b", "vpn_c", "vpn_d"},
	}

	out, err := MihomoWithProxyGuardState(c, &s)
	if err != nil {
		t.Fatal(err)
	}
	group := decodedProxyGroup(t, out, "Common")
	members := decodedStringSlice(t, group["proxies"])
	if containsGuardTestString(members, "vpn_a") {
		t.Fatalf("quarantined explicit member remained: %#v", members)
	}
	for _, retained := range []string{"vpn_b", "vpn_c", "vpn_d"} {
		if !containsGuardTestString(members, retained) {
			t.Fatalf("last-resort member %s removed: %#v", retained, members)
		}
	}
	if containsGuardTestString(members, "DIRECT") {
		t.Fatalf("guard must never add DIRECT: %#v", members)
	}
}

func decodedProxyGroup(t *testing.T, data []byte, name string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("decode mihomo config: %v", err)
	}
	groups, ok := root["proxy-groups"].([]any)
	if !ok {
		t.Fatalf("proxy-groups has unexpected type %T", root["proxy-groups"])
	}
	for _, raw := range groups {
		group, ok := raw.(map[string]any)
		if ok && group["name"] == name {
			return group
		}
	}
	t.Fatalf("group %q not found", name)
	return nil
}

func decodedStringSlice(t *testing.T, value any) []string {
	t.Helper()
	raw, ok := value.([]any)
	if !ok {
		t.Fatalf("string slice has unexpected type %T", value)
	}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("string slice member has unexpected type %T", value)
		}
		out = append(out, text)
	}
	return out
}

func containsGuardTestString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
