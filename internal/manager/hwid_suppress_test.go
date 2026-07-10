package manager

import (
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// Settings.SuppressHWID is the global privacy switch: with it set, no
// download carries router identity, regardless of per-subscription /
// per-provider flags. Per-entity suppress_hwid still works for opting out
// a single panel while others keep their identity.
func TestGlobalSuppressHWIDOverridesPerEntity(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.SuppressHWID = true
	c.Subscriptions = []config.Subscription{{Name: "sub", Enabled: true, URL: "https://panel.example/sub", HWID: "sub-hwid"}}
	c.ProxyProviders = []config.ProxyProvider{{Name: "pp", Enabled: true, URL: "https://panel.example/pp", HWID: "pp-hwid"}}
	cfgPath := filepath.Join(dir, "purewrt")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	m := Manager{ConfigPath: cfgPath}
	for _, url := range []string{"https://panel.example/sub", "https://panel.example/pp"} {
		opt := m.downloadOptionsForURL(url)
		if !opt.SuppressHWID {
			t.Fatalf("global suppress_hwid must reach the download options for %s: %+v", url, opt)
		}
	}
}

func TestGlobalSuppressHWIDRoundtripsThroughUCI(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.SuppressHWID = true
	cfgPath := filepath.Join(dir, "purewrt")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Settings.SuppressHWID {
		t.Fatal("Settings.SuppressHWID lost in UCI roundtrip")
	}
}
