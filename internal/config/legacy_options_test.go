package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLegacyOptionsIgnoredAndDropped guards the removal of the dead
// dns_mode / quic_policy knobs: configs on existing routers may still
// carry them, so Load must ignore them silently and the next Save must
// not write them back.
func TestLegacyOptionsIgnoredAndDropped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "purewrt")
	raw := `config main 'settings'
	option enabled '1'
	option dns_mode 'fake-ip-filter'
	option quic_policy 'block'
	option log_level 'debug'
`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("legacy options must parse cleanly, got %v", err)
	}
	if c.Settings.LogLevel != "debug" {
		t.Fatalf("options after the legacy lines must still parse, got log_level=%q", c.Settings.LogLevel)
	}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, dead := range []string{"dns_mode", "quic_policy"} {
		if strings.Contains(string(out), dead) {
			t.Fatalf("serialized config must not contain removed option %q", dead)
		}
	}
}
