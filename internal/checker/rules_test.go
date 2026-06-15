package checker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/rules"
)

// TestRuleProviderIndex_MRSDomainSet verifies that an MRS-format provider
// pointed at the YouTube fixture matches both an exact domain entry and a
// subdomain via the non-materialising DomainSet path. Guards against
// regressions in the wiring inside parseNext / lookup.
func TestRuleProviderIndex_MRSDomainSet(t *testing.T) {
	src, err := os.ReadFile("../../testdata/mrs/youtube.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "youtube.mrs")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}

	cfg := config.Config{
		Sections: []config.Section{
			{Name: "common", Enabled: true, Action: "proxy"},
		},
		RuleProviders: []config.RuleProvider{
			{Name: "youtube", Enabled: true, Format: "mrs", Path: path, Section: "common", Priority: 1},
		},
	}

	idx := NewRuleProviderIndex(cfg)
	m := idx.Match("www.youtube.com")
	if !m.Matched {
		t.Fatalf("expected match for www.youtube.com, got fallback %+v", m)
	}
	if m.Provider != "youtube" {
		t.Fatalf("Provider=%q, want %q", m.Provider, "youtube")
	}
	if m.Section != "common" || m.Action != "proxy" {
		t.Fatalf("Section/Action=%q/%q, want common/proxy", m.Section, m.Action)
	}
	if m.Rule.Type != rules.DomainSuffix {
		t.Fatalf("Rule.Type=%q, want DomainSuffix", m.Rule.Type)
	}
	if m.Rule.Value != "youtube.com" {
		t.Fatalf("Rule.Value=%q, want %q", m.Rule.Value, "youtube.com")
	}
	if m.Rule.SourceProvider != "youtube" {
		t.Fatalf("Rule.SourceProvider=%q, want %q", m.Rule.SourceProvider, "youtube")
	}

	// Negative path: a domain not in any YouTube provider should fall
	// through to the common+proxy fallback (Matched=false).
	miss := idx.Match("example.com")
	if miss.Matched {
		t.Fatalf("unexpected match for example.com: %+v", miss)
	}
}

// TestRuleProviderIndex_MRSPriorityOverText guarantees that a higher-priority
// (lower-priority-number) MRS provider claims the domain before a text
// provider at a later priority would have a chance to.
func TestRuleProviderIndex_MRSPriorityOverText(t *testing.T) {
	src, err := os.ReadFile("../../testdata/mrs/youtube.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	tmp := t.TempDir()
	mrsPath := filepath.Join(tmp, "youtube.mrs")
	if err := os.WriteFile(mrsPath, src, 0o644); err != nil {
		t.Fatalf("write mrs: %v", err)
	}
	textPath := filepath.Join(tmp, "extra.txt")
	if err := os.WriteFile(textPath, []byte("DOMAIN-SUFFIX,www.youtube.com\n"), 0o644); err != nil {
		t.Fatalf("write text: %v", err)
	}

	cfg := config.Config{
		Sections: []config.Section{
			{Name: "common", Enabled: true, Action: "proxy"},
			{Name: "direct", Enabled: true, Action: "direct"},
		},
		RuleProviders: []config.RuleProvider{
			{Name: "youtube", Enabled: true, Format: "mrs", Path: mrsPath, Section: "common", Priority: 1},
			{Name: "extra", Enabled: true, Format: "text", Path: textPath, Section: "direct", Priority: 5},
		},
	}

	m := NewRuleProviderIndex(cfg).Match("www.youtube.com")
	if !m.Matched || m.Provider != "youtube" || m.Section != "common" {
		t.Fatalf("priority-1 MRS should claim www.youtube.com, got %+v", m)
	}
}
