package manager

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
)

func TestUpdateDetailedForceBypassesProviderIntervals(t *testing.T) {
	dir := t.TempDir()
	proxySrc := filepath.Join(dir, "proxy-src.yaml")
	ruleSrc := filepath.Join(dir, "rule-src.list")
	proxyPath := filepath.Join(dir, "providers", "main.yaml")
	rulePath := filepath.Join(dir, "rulesets", "main.list")
	if err := os.MkdirAll(filepath.Dir(proxyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(rulePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxySrc, []byte("proxies: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ruleSrc, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for _, path := range []string{proxyPath, rulePath} {
		if err := os.WriteFile(path, []byte("old\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	c := config.Default()
	c.Settings.Workdir = filepath.Join(dir, "workdir")
	c.Settings.GeneratedDir = filepath.Join(dir, "generated")
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.MihomoConfig = filepath.Join(dir, "generated", "mihomo.yaml")
	c.Settings.CacheMode = "off"
	c.Settings.ArtifactCacheMode = "off"
	c.Settings.CacheDir = filepath.Join(dir, "cache")
	c.DNS.HijackLANDNS = false
	c.Mwan3.IntegratedRules = false
	c.ProxyProviders = []config.ProxyProvider{{Name: "main", Enabled: true, URL: "file://" + proxySrc, Path: proxyPath, Interval: 86400}}
	c.RuleProviders = []config.RuleProvider{{Name: "main", Enabled: true, URL: "file://" + ruleSrc, Path: rulePath, Interval: 86400, Behavior: "domain", Format: "text", Section: "common", RouteAction: "proxy"}}
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	res, err := (Manager{ConfigPath: cfgPath}).UpdateDetailedWithOptions(true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("forced update should report changed when provider content differs despite interval cache")
	}
	proxyData, err := os.ReadFile(proxyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(proxyData) != "proxies: []\n" {
		t.Fatalf("proxy provider was not force refreshed, got %q", proxyData)
	}
	ruleData, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(ruleData) != "example.com\n" {
		t.Fatalf("rule provider was not force refreshed, got %q", ruleData)
	}
}

// TestUpdatePartialFailureWrapsErrPartialUpdate guards the soft-continue
// contract: when one provider fails but another succeeds, the error must
// wrap ErrPartialUpdate (so the CLI exits 3, not 1) and the successful
// provider's content must still land on disk.
func TestUpdatePartialFailureWrapsErrPartialUpdate(t *testing.T) {
	dir := t.TempDir()
	proxySrc := filepath.Join(dir, "proxy-src.yaml")
	proxyPath := filepath.Join(dir, "providers", "main.yaml")
	rulePath := filepath.Join(dir, "rulesets", "main.list")
	if err := os.MkdirAll(filepath.Dir(proxyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(rulePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxySrc, []byte("proxies: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Settings.Workdir = filepath.Join(dir, "workdir")
	c.Settings.GeneratedDir = filepath.Join(dir, "generated")
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.MihomoConfig = filepath.Join(dir, "generated", "mihomo.yaml")
	c.Settings.CacheMode = "off"
	c.Settings.ArtifactCacheMode = "off"
	c.Settings.CacheDir = filepath.Join(dir, "cache")
	c.DNS.HijackLANDNS = false
	c.Mwan3.IntegratedRules = false
	c.ProxyProviders = []config.ProxyProvider{{Name: "main", Enabled: true, URL: "file://" + proxySrc, Path: proxyPath, Interval: 86400}}
	// file:// source that doesn't exist → this provider's download fails.
	c.RuleProviders = []config.RuleProvider{{Name: "broken", Enabled: true, URL: "file://" + filepath.Join(dir, "missing.list"), Path: rulePath, Interval: 86400, Behavior: "domain", Format: "text", Section: "common", RouteAction: "proxy"}}
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	res, err := (Manager{ConfigPath: cfgPath}).UpdateDetailedWithOptions(true)
	if err == nil {
		t.Fatal("expected partial-failure error, got nil")
	}
	if !errors.Is(err, ErrPartialUpdate) {
		t.Fatalf("partial failure must wrap ErrPartialUpdate, got %v", err)
	}
	if !res.Changed {
		t.Fatal("successful proxy provider should still report changed")
	}
	proxyData, err := os.ReadFile(proxyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(proxyData) != "proxies: []\n" {
		t.Fatalf("successful provider content must land despite sibling failure, got %q", proxyData)
	}
}

func TestShouldWriteArtifactSkipsLowResourceAndOversized(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.ResourceProfile = "low"
	c.Settings.CacheDir = filepath.Join(dir, "cache")
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	m := Manager{ConfigPath: cfgPath}
	if m.shouldWriteArtifact(config.RuleProvider{Format: "text"}, 1) {
		t.Fatal("low-resource profile should skip artifact writes")
	}

	c.Settings.ResourceProfile = "standard"
	c.Settings.ArtifactCacheMaxBytes = 4
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	if m.shouldWriteArtifact(config.RuleProvider{Format: "text"}, len(strings.Repeat("x", 8))) {
		t.Fatal("oversized rule provider should skip artifact writes")
	}
	if !m.shouldWriteArtifact(config.RuleProvider{Format: "text"}, 4) {
		t.Fatal("small standard provider should write artifact")
	}
}
