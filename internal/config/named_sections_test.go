package config

import (
	"os"
	"strings"
	"testing"
)

// Providers/profiles serialize as named UCI sections with a type-scoped id
// prefix (`config rule_provider 'rp_youtube'`) and no redundant `option name`
// when the name is a valid UCI identifier — the parser strips the prefix
// back off. Devices pioneered this pattern with dev_<mac>.
func TestSerializeEmitsNamedProviderSections(t *testing.T) {
	c := Default()
	c.ProxyProviders = []ProxyProvider{{Name: "main", Enabled: true, URL: "https://example.com/sub", Path: "/etc/purewrt/providers/main.yaml"}}
	c.RuleProviders = []RuleProvider{{Name: "native_ai", Enabled: true, Path: "/etc/purewrt/rulesets/native_ai.txt", Section: "ai"}}
	c.ZapretProfiles = []ZapretProfile{{Name: "wan", Enabled: true, Interfaces: []string{"wan"}}}
	c.ZapretStrategies = []ZapretStrategy{{Name: "youtube_tcp", Enabled: true, Profile: "wan"}}
	out := string(Serialize(c))
	for _, want := range []string{
		"config proxy_provider 'pp_main'",
		"config rule_provider 'rp_native_ai'",
		"config zapret_profile 'zp_wan'",
		"config zapret_strategy 'zs_youtube_tcp'",
		"config section 'sec_common'",
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

// libuci section ids share ONE namespace per config file across ALL section
// types — a duplicate id under a different type is a hard parse error
// ("section of different type overwrites prior section with same name") that
// bricks every uci consumer of the file. Type-scoped prefixes let the same
// display name coexist on every type: section 'youtube' + rule_provider
// 'youtube' + zapret_strategy 'youtube' → sec_youtube / rp_youtube /
// zs_youtube. Names that would still collide (e.g. literally "bypass" is
// fine — it becomes pp_bypass) are guarded by the shared seen map.
func TestSerializeSectionIDsAreUniqueAcrossTypes(t *testing.T) {
	c := Default()
	c.ZapretStrategies = []ZapretStrategy{{Name: "youtube", Enabled: true, Profile: "wan"}}
	c.RuleProviders = []RuleProvider{{Name: "youtube", Enabled: true, Path: "/tmp/y.txt", Section: "media"}}
	c.ProxyProviders = []ProxyProvider{{Name: "bypass", Enabled: true, URL: "https://example.com/s", Path: "/tmp/b.yaml"}}
	c.Sections = append(c.Sections, Section{Name: "youtube", Enabled: true, Action: "proxy", TPROXYPort: 7899, ProxyGroup: "Youtube"})
	c.Subscriptions = []Subscription{{Name: "youtube", Enabled: true, URL: "https://example.com/sub"}}
	c.VPNs = []VPN{{Name: "youtube", Enabled: true, Interface: "wg0"}}

	out := string(Serialize(c))
	ids := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "config ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		id := strings.Trim(f[2], "'")
		if prev, ok := ids[id]; ok {
			t.Errorf("section id %q used by both %q and %q — libuci parse error", id, prev, f[1])
		}
		ids[id] = f[1]
	}
	for id, typ := range map[string]string{
		"zs_youtube": "zapret_strategy", "rp_youtube": "rule_provider",
		"sec_youtube": "section", "sub_youtube": "subscription",
		"vpn_youtube": "vpn", "pp_bypass": "proxy_provider", "bypass": "bypass",
	} {
		if ids[id] != typ {
			t.Errorf("id %q: want type %q, got %q", id, typ, ids[id])
		}
	}
	// Nothing lost: displaced entries fall back to option name.
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/purewrt", []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir + "/purewrt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RuleProviders) != 1 || got.RuleProviders[0].Name != "youtube" {
		t.Fatalf("rule provider name lost: %+v", got.RuleProviders)
	}
	if len(got.ProxyProviders) != 1 || got.ProxyProviders[0].Name != "bypass" {
		t.Fatalf("proxy provider name lost: %+v", got.ProxyProviders)
	}
	if len(got.ZapretStrategies) != 1 || got.ZapretStrategies[0].Name != "youtube" {
		t.Fatalf("zapret strategy name lost: %+v", got.ZapretStrategies)
	}
	if len(got.Subscriptions) != 1 || got.Subscriptions[0].Name != "youtube" {
		t.Fatalf("subscription name lost: %+v", got.Subscriptions)
	}
	if len(got.VPNs) != 1 || got.VPNs[0].Name != "youtube" {
		t.Fatalf("vpn name lost: %+v", got.VPNs)
	}
	found := false
	for _, sec := range got.Sections {
		if sec.Name == "youtube" {
			found = true
		}
	}
	if !found {
		t.Fatalf("routing section name lost: %+v", got.Sections)
	}
}

// Legacy configs — unprefixed named sections and anonymous + `option name`
// forms — must load with identical names and normalize to prefixed ids on
// the next save.
func TestLegacyUnprefixedConfigMigrates(t *testing.T) {
	legacy := `config section 'common'
	option enabled '1'
	option action 'proxy'
	option tproxy_port '7893'
	option proxy_group 'Common'

config zapret_strategy 'youtube'
	option enabled '1'
	option profile 'wan'

config rule_provider
	option name 'blocked-list.v2'
	option enabled '1'
	option path '/tmp/b.txt'
	option section 'common'

config proxy_provider 'main'
	option enabled '1'
	option url 'https://example.com/sub'
	option path '/etc/purewrt/providers/main.yaml'
`
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/purewrt", []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir + "/purewrt")
	if err != nil {
		t.Fatal(err)
	}
	if got.Sections[0].Name != "common" {
		t.Fatalf("legacy section name = %q", got.Sections[0].Name)
	}
	if len(got.ZapretStrategies) != 1 || got.ZapretStrategies[0].Name != "youtube" {
		t.Fatalf("legacy zapret strategy: %+v", got.ZapretStrategies)
	}
	if len(got.RuleProviders) != 1 || got.RuleProviders[0].Name != "blocked-list.v2" {
		t.Fatalf("legacy rule provider: %+v", got.RuleProviders)
	}
	if len(got.ProxyProviders) != 1 || got.ProxyProviders[0].Name != "main" {
		t.Fatalf("legacy proxy provider: %+v", got.ProxyProviders)
	}
	out := string(Serialize(got))
	for _, want := range []string{
		"config section 'sec_common'",
		"config zapret_strategy 'zs_youtube'",
		"config proxy_provider 'pp_main'",
		"option name 'blocked-list.v2'", // unsafe id keeps option-name form
	} {
		if !strings.Contains(out, want) {
			t.Errorf("normalized output missing %q:\n%s", want, out)
		}
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
	if strings.Count(out, "config proxy_provider 'pp_dup'") != 1 {
		t.Errorf("expected exactly one named 'dup' proxy provider:\n%s", out)
	}
	if !strings.Contains(out, "config proxy_provider\n") || !strings.Contains(out, "option name 'dup'") {
		t.Errorf("second duplicate proxy provider must be anonymous with name option:\n%s", out)
	}
	if strings.Count(out, "config rule_provider 'rp_rdup'") != 1 || !strings.Contains(out, "option name 'rdup'") {
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
