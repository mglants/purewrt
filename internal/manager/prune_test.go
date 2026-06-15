package manager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestPruneOrphanProviderFiles(t *testing.T) {
	workdir := t.TempDir()
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{workdir}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mkdir := func(parts ...string) string {
		p := filepath.Join(append([]string{workdir}, parts...)...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(p, "abc.rules"), []byte("x"), 0o644)
		return p
	}

	// rulesets: one kept provider + one orphan, each with a .meta.json sidecar.
	keepRule := mk("rulesets", "keep.txt")
	mk("rulesets", "keep.txt.meta.json")
	orphanRule := mk("rulesets", "orphan.txt")
	orphanRuleMeta := mk("rulesets", "orphan.txt.meta.json")

	// providers: a proxy provider + a subscription file (both kept) + an orphan.
	keepProxy := mk("providers", "prox.yaml")
	mk("providers", "prox.yaml.meta.json")
	keepSub := mk("providers", "sub.yaml")
	mk("providers", "sub.yaml.meta.json")
	orphanProxy := mk("providers", "orphan.yaml")

	// cache/rules: per-provider dirs — keep_name (for keep rule provider) + orphan_name.
	keepCacheDir := mkdir("cache", "rules", "keep")
	orphanCacheDir := mkdir("cache", "rules", "orphan_name")

	// A provider whose Path points OUTSIDE the owned dirs must never be touched.
	outside := filepath.Join(t.TempDir(), "external.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := config.Default()
	c.Settings.Workdir = workdir
	c.RuleProviders = []config.RuleProvider{
		{Name: "keep", Enabled: true, Path: keepRule},
		{Name: "external", Enabled: true, Path: outside},
	}
	c.ProxyProviders = []config.ProxyProvider{{Name: "prox", Enabled: true, Path: keepProxy}}
	c.Subscriptions = []config.Subscription{{Name: "sub", Enabled: true, URL: "https://x/y"}}

	m := Manager{}

	// Dry-run: reports orphans but removes nothing.
	would := m.PruneOrphanProviderFiles(c, true)
	if len(would) != 4 {
		t.Fatalf("dry-run expected 4 orphans, got %d: %v", len(would), would)
	}
	for _, p := range []string{orphanRule, orphanRuleMeta, orphanProxy, orphanCacheDir} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("dry-run must not remove %s: %v", p, err)
		}
	}

	// Real run: removes exactly the orphans.
	removed := m.PruneOrphanProviderFiles(c, false)
	if len(removed) != 4 {
		t.Fatalf("expected 4 removed, got %d: %v", len(removed), removed)
	}
	for _, p := range []string{orphanRule, orphanRuleMeta, orphanProxy, orphanCacheDir} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("orphan not removed: %s (err=%v)", p, err)
		}
	}
	// Kept files/dirs survive.
	for _, p := range []string{keepRule, keepProxy, keepSub, keepCacheDir, outside} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("kept path was removed: %s (err=%v)", p, err)
		}
	}
	if _, err := os.Stat(keepRule + ".meta.json"); err != nil {
		t.Errorf("kept sidecar removed: %v", err)
	}

	// Idempotent second run removes nothing.
	if again := m.PruneOrphanProviderFiles(c, false); len(again) != 0 {
		t.Fatalf("second run should be a no-op, removed %v", again)
	}
}

func TestPruneOrphanProviderFiles_MissingDirs(t *testing.T) {
	// No rulesets/providers/cache dirs at all → no error, no removals.
	c := config.Default()
	c.Settings.Workdir = t.TempDir()
	if removed := (Manager{}).PruneOrphanProviderFiles(c, false); len(removed) != 0 {
		t.Fatalf("expected no removals on empty workdir, got %v", removed)
	}
}
