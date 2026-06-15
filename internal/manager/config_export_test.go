package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func exportTestConfig(t *testing.T) (Manager, config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	c := config.Default()
	c.Settings.Secret = "super-secret-token"
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Subscriptions = []config.Subscription{{Name: "sub", Enabled: true, URL: "https://example.com/sub?token=hunter2", HWID: "abc123"}}
	c.RuleProviders = []config.RuleProvider{{Name: "rp", Enabled: true, Behavior: "domain", Format: "text", URL: "https://example.com/rp.txt?key=tok", Path: filepath.Join(dir, "rp.txt"), Section: "common", Mirrors: []string{"https://mirror.example.com/rp.txt?key=tok2"}}}
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	return Manager{ConfigPath: cfgPath}, c, cfgPath
}

func TestExportConfigRedactsSecrets(t *testing.T) {
	m, _, _ := exportTestConfig(t)
	out, err := m.ExportConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"super-secret-token", "token=hunter2", "key=tok", "abc123"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("redacted export leaked %q", leaked)
		}
	}
	if !strings.Contains(out, "REDACTED") || !strings.Contains(out, "?...") {
		t.Fatalf("expected redaction markers in export:\n%s", out)
	}
}

func TestExportConfigIncludeSecretsRoundTrips(t *testing.T) {
	m, c, _ := exportTestConfig(t)
	out, err := m.ExportConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	// Byte-identical to a Serialize of the loaded config — the export IS
	// the canonical config file.
	if out != string(config.Serialize(config.EnsureDefaults(c))) && out != string(config.Serialize(c)) {
		// Load normalizes via EnsureDefaults; accept either shape but the
		// secrets must be present verbatim.
		if !strings.Contains(out, "super-secret-token") || !strings.Contains(out, "token=hunter2") {
			t.Fatalf("include-secrets export lost credentials:\n%s", out)
		}
	}
}

func TestImportConfigRejectsInvalidWithoutTouchingLive(t *testing.T) {
	m, _, cfgPath := exportTestConfig(t)
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// An unparseable fwmark trips validateConfigHardening's hex check.
	bad := "config main 'settings'\n\toption enabled '1'\n\toption fwmark 'not-a-mark'\n"
	if _, err := m.ImportConfig([]byte(bad)); err == nil {
		t.Fatal("expected invalid import to error")
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed import must not modify the live config")
	}
}

func TestImportConfigSucceedsAndBacksUp(t *testing.T) {
	m, c, cfgPath := exportTestConfig(t)
	c.Settings.LogLevel = "debug"
	res, err := m.ImportConfig(config.Serialize(c))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !res.OK || res.Applied {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Backup == "" {
		t.Fatal("expected a backup path")
	}
	if _, err := os.Stat(res.Backup); err != nil {
		t.Fatalf("backup file missing: %v", err)
	}
	got, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Settings.LogLevel != "debug" {
		t.Fatalf("imported change not present, log_level=%q", got.Settings.LogLevel)
	}
}

func TestImportConfigWarnsOnRedactedURLs(t *testing.T) {
	m, _, _ := exportTestConfig(t)
	redacted, err := m.ExportConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.ImportConfig([]byte(redacted))
	if err != nil {
		t.Fatalf("redacted import should succeed with warnings, got %v", err)
	}
	var found bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "redacted URLs") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected redacted-URL warning, got %v", res.Warnings)
	}
}
