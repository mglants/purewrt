package manager

import (
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func ruleProviderByName(c config.Config, name string) (config.RuleProvider, bool) {
	for _, rp := range c.RuleProviders {
		if rp.Name == name {
			return rp, true
		}
	}
	return config.RuleProvider{}, false
}

// An explicit priority must reach the rule provider, and a list mapped to an
// existing section must not mutate that section's priority.
func TestAddNativeListExistingSectionExplicitPriority(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, config.Default()); err != nil {
		t.Fatal(err)
	}
	m := Manager{ConfigPath: cfgPath}

	name, err := m.AddNativeList("https://lists.example/media.native", "media", 25)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rp, ok := ruleProviderByName(got, name)
	if !ok || rp.Priority != 25 || rp.Section != "media" || rp.RouteAction != "proxy" {
		t.Fatalf("rule provider priority/section/action wrong: %+v", rp)
	}
	// media (a Default section) keeps its own priority — imports never
	// re-prioritize an existing section.
	sec, _ := got.SectionByName("media")
	if sec.Priority != 10 {
		t.Fatalf("existing media section priority mutated: %d", sec.Priority)
	}
}

// An omitted priority on an existing section inherits the section's priority.
func TestAddNativeListInheritsSectionPriority(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, config.Default()); err != nil {
		t.Fatal(err)
	}
	m := Manager{ConfigPath: cfgPath}

	name, err := m.AddNativeList("https://lists.example/common.native", "common", 0)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := config.Load(cfgPath)
	rp, _ := ruleProviderByName(got, name)
	if rp.Priority != 60 { // common's Default priority
		t.Fatalf("expected inherited priority 60, got %d", rp.Priority)
	}
}

// A list mapped to a section that doesn't exist must create a complete proxy
// section: enabled, action=proxy, the given priority, and a unique port.
func TestAddNativeListCreatesProxySection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, config.Default()); err != nil {
		t.Fatal(err)
	}
	m := Manager{ConfigPath: cfgPath}

	name, err := m.AddNativeList("https://lists.example/games.native", "games", 30)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := config.Load(cfgPath)
	sec, ok := got.SectionByName("games")
	if !ok {
		t.Fatalf("section 'games' was not created")
	}
	if !sec.Enabled || sec.Action != "proxy" || sec.Priority != 30 {
		t.Fatalf("created section wrong: %+v", sec)
	}
	if sec.TPROXYPort <= 7895 {
		t.Fatalf("created proxy section needs a freshly-allocated port, got %d", sec.TPROXYPort)
	}
	// No port collision with the defaults.
	for _, d := range []int{7893, 7894, 7895} {
		if sec.TPROXYPort == d {
			t.Fatalf("allocated port collides with a default: %d", sec.TPROXYPort)
		}
	}
	rp, _ := ruleProviderByName(got, name)
	if rp.Priority != 30 {
		t.Fatalf("rule provider priority wrong: %d", rp.Priority)
	}
}

// A list mapped to "reject" creates a reject section (no proxy port needed)
// and falls back to the default priority when none is given.
func TestAddNativeListCreatesRejectSection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, config.Default()); err != nil {
		t.Fatal(err)
	}
	m := Manager{ConfigPath: cfgPath}

	if _, err := m.AddNativeList("https://lists.example/ads.native", "reject", 0); err != nil {
		t.Fatal(err)
	}
	got, _ := config.Load(cfgPath)
	sec, ok := got.SectionByName("reject")
	if !ok {
		t.Fatalf("section 'reject' was not created")
	}
	if sec.Action != "reject" {
		t.Fatalf("expected action reject, got %q", sec.Action)
	}
	if sec.Priority != 100 { // default fallback
		t.Fatalf("expected default priority 100, got %d", sec.Priority)
	}
}
