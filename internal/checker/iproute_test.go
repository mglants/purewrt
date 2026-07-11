package checker

import (
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func iprouteTestConfig() config.Config {
	return config.Config{Sections: []config.Section{
		{Name: "common", Enabled: true, Action: "proxy", Priority: 50},
		{Name: "ai", Enabled: true, Action: "proxy", Priority: 40},
		{Name: "block", Enabled: true, Action: "reject", Priority: 20},
		{Name: "home", Enabled: true, Action: "direct", Priority: 30},
	}}
}

// stubIPSet makes ipSetContains report membership from a fixed set→ip map.
func stubIPSet(t *testing.T, members map[string]string) {
	t.Helper()
	orig := ipSetContains
	t.Cleanup(func() { ipSetContains = orig })
	ipSetContains = func(set, ip string) bool { return members[set] == ip }
}

func TestClassifyIP(t *testing.T) {
	c := iprouteTestConfig()

	// The reported snuffpin.gs case: IP only in proxy_common4 → proxied via common.
	stubIPSet(t, map[string]string{"proxy_common4": "95.217.201.153"})
	if r := ClassifyIP(c, "95.217.201.153"); r.Action != "proxy" || r.Section != "common" || r.Set != "proxy_common4" {
		t.Fatalf("common IP: got %+v, want proxy/common/proxy_common4", r)
	}

	// Bypass wins over everything.
	stubIPSet(t, map[string]string{"bypass4": "1.1.1.1", "proxy_common4": "1.1.1.1"})
	if r := ClassifyIP(c, "1.1.1.1"); r.Action != "bypass" {
		t.Fatalf("bypass IP: got %+v, want bypass", r)
	}

	// Global reject aggregate.
	stubIPSet(t, map[string]string{"reject4": "2.2.2.2"})
	if r := ClassifyIP(c, "2.2.2.2"); r.Action != "reject" || r.Set != "reject4" {
		t.Fatalf("reject IP: got %+v, want reject/reject4", r)
	}

	// dns_ dynamic variant counts too.
	stubIPSet(t, map[string]string{"dns_proxy_ai4": "3.3.3.3"})
	if r := ClassifyIP(c, "3.3.3.3"); r.Action != "proxy" || r.Section != "ai" {
		t.Fatalf("dns_ variant: got %+v, want proxy/ai", r)
	}

	// In no set → default route.
	stubIPSet(t, map[string]string{})
	if r := ClassifyIP(c, "4.4.4.4"); r.Action != "default" {
		t.Fatalf("no set: got %+v, want default", r)
	}

	// v6 uses the 6-suffixed set.
	stubIPSet(t, map[string]string{"proxy_common6": "2001:db8::1"})
	if r := ClassifyIP(c, "2001:db8::1"); r.Action != "proxy" || r.Set != "proxy_common6" {
		t.Fatalf("v6: got %+v, want proxy/proxy_common6", r)
	}
}
