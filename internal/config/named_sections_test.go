package config

import (
	"strings"
	"testing"
)

// Providers/profiles serialize as named UCI sections (config <type> '<name>')
// with no redundant `option name` when the name is a valid UCI identifier —
// mirroring how routing sections (`config section 'ai'`) work.
func TestSerializeEmitsNamedProviderSections(t *testing.T) {
	c := Default()
	c.ProxyProviders = []ProxyProvider{{Name: "main", Enabled: true, URL: "https://example.com/sub", Path: "/etc/purewrt/providers/main.yaml"}}
	c.RuleProviders = []RuleProvider{{Name: "native_ai", Enabled: true, Path: "/etc/purewrt/rulesets/native_ai.txt", Section: "ai"}}
	c.ZapretProfiles = []ZapretProfile{{Name: "wan", Enabled: true, Interfaces: []string{"wan"}}}
	c.ZapretStrategies = []ZapretStrategy{{Name: "youtube_tcp", Enabled: true, Profile: "wan"}}
	out := string(Serialize(c))
	for _, want := range []string{
		"config proxy_provider 'main'",
		"config rule_provider 'native_ai'",
		"config zapret_profile 'wan'",
		"config zapret_strategy 'youtube_tcp'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing named section header %q", want)
		}
	}
	if strings.Contains(out, "option name") {
		t.Errorf("redundant `option name` emitted alongside named sections:\n%s", out)
	}
}

// Names that are not valid UCI identifiers (dots, dashes) cannot be section
// ids — those fall back to the legacy anonymous-section + `option name` form.
func TestSerializeFallsBackToAnonymousForUnsafeIDs(t *testing.T) {
	c := Default()
	c.ProxyProviders = []ProxyProvider{{Name: "my-sub.v2", Enabled: true, URL: "https://example.com/sub", Path: "/etc/purewrt/providers/a.yaml"}}
	c.ZapretProfiles = []ZapretProfile{{Name: "wan-dsl", Enabled: true, Interfaces: []string{"wan-dsl"}}}
	out := string(Serialize(c))
	if !strings.Contains(out, "config proxy_provider\n") {
		t.Errorf("expected anonymous section for unsafe id, got:\n%s", out)
	}
	if !strings.Contains(out, "option name 'my-sub.v2'") {
		t.Errorf("expected name option fallback, got:\n%s", out)
	}
	if !strings.Contains(out, "config zapret_profile\n") || !strings.Contains(out, "option name 'wan-dsl'") {
		t.Errorf("expected anonymous zapret profile for dash name, got:\n%s", out)
	}
}

// Round-trip: named-section serialization must load back with identical names.
func TestNamedSectionRoundTripPreservesNames(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/purewrt"
	c := Default()
	c.ProxyProviders = []ProxyProvider{{Name: "main", Enabled: true, URL: "https://example.com/sub", Path: "/etc/purewrt/providers/main.yaml"}}
	c.RuleProviders = []RuleProvider{{Name: "native_ai", Enabled: true, Path: "/etc/purewrt/rulesets/native_ai.txt", Section: "ai"}}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ProxyProviders) != 1 || got.ProxyProviders[0].Name != "main" {
		t.Fatalf("proxy provider name lost: %+v", got.ProxyProviders)
	}
	if len(got.RuleProviders) == 0 || got.RuleProviders[len(got.RuleProviders)-1].Name != "native_ai" {
		t.Fatalf("rule provider name lost: %+v", got.RuleProviders)
	}
}


// Duplicate names cannot both become named sections — libuci silently merges
// duplicate section ids (last wins), losing data. The second occurrence must
// fall back to the anonymous + `option name` form.
func TestSerializeDuplicateNamesFallBackToAnonymous(t *testing.T) {
	c := Default()
	c.ProxyProviders = []ProxyProvider{
		{Name: "dup", Enabled: true, URL: "https://example.com/a", Path: "/tmp/a.yaml"},
		{Name: "dup", Enabled: true, URL: "https://example.com/b", Path: "/tmp/b.yaml"},
	}
	c.RuleProviders = []RuleProvider{
		{Name: "rdup", Enabled: true, Path: "/tmp/r1.txt", Section: "common"},
		{Name: "rdup", Enabled: true, Path: "/tmp/r2.txt", Section: "media"},
	}
	out := string(Serialize(c))
	if strings.Count(out, "config proxy_provider 'dup'") != 1 {
		t.Errorf("expected exactly one named 'dup' proxy provider:\n%s", out)
	}
	if !strings.Contains(out, "config proxy_provider\n") || !strings.Contains(out, "option name 'dup'") {
		t.Errorf("second duplicate proxy provider must be anonymous with name option:\n%s", out)
	}
	if strings.Count(out, "config rule_provider 'rdup'") != 1 || !strings.Contains(out, "option name 'rdup'") {
		t.Errorf("duplicate rule provider not guarded:\n%s", out)
	}
	// Round-trip: both entries must survive a load.
	// (libuci would merge duplicate ids — our own parser must see two.)
	dir := t.TempDir()
	if err := Save(dir+"/purewrt", c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir + "/purewrt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ProxyProviders) != 2 || len(got.RuleProviders) != 2 {
		t.Fatalf("duplicates lost in round-trip: pp=%d rp=%d", len(got.ProxyProviders), len(got.RuleProviders))
	}
}
