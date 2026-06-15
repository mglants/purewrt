package manager

import (
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestWizardResetPreservesAndFlushes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "purewrt.conf")

	c := config.Default()
	// Stuff that must be flushed.
	c.Subscriptions = []config.Subscription{{Name: "sub", Enabled: true, URL: "https://x/y"}}
	c.RuleProviders = []config.RuleProvider{{Name: "rp", Enabled: true, Format: "text", Section: "common", Path: "/tmp/rp"}}
	c.ProxyProviders = []config.ProxyProvider{{Name: "pp", Enabled: true, URL: "https://x/pp"}}
	c.Devices = []config.Device{{Name: "phone", MAC: "aa:bb:cc:dd:ee:ff", Section: "common", Enabled: true}}
	c.Sections = append(c.Sections, config.Section{Name: "extra", Enabled: true, Action: "proxy", Priority: 99})
	c.Settings.LogLevel = "debug"
	c.Settings.AutoUpdateCron = "0 0 * * *"
	// Stuff that must be preserved.
	c.VPNs = []config.VPN{{Name: "wg0", Enabled: true, Interface: "wg0", FwMark: "0x40000002"}}
	c.ZapretProfiles = []config.ZapretProfile{{Name: "custom", Enabled: true, Interfaces: []string{"wan"}}}
	c.ZapretStrategies = []config.ZapretStrategy{{Name: "myst", Enabled: true, Profile: "custom", Params: "--foo"}}
	c.Settings.Secret = "my-real-secret-token"
	c.Settings.MihomoBin = "/etc/purewrt/mihomo-bin/mihomo-alpha-abc123"
	c.Settings.MihomoVersion = "alpha-abc123"
	c.Settings.DefaultListsBaseURL = "https://example.com/mylists/"
	c.Settings.DNSMasqIncludeDir = "/tmp/dnsmasq.cfg01411c.d"
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}

	if err := (Manager{ConfigPath: cfgPath}).WizardReset(); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Flushed.
	if len(got.Subscriptions) != 0 || len(got.RuleProviders) != 0 || len(got.ProxyProviders) != 0 || len(got.Devices) != 0 {
		t.Fatalf("providers/subscriptions/devices not flushed: %+v", got)
	}
	def := config.Default()
	if len(got.Sections) != len(def.Sections) {
		t.Fatalf("sections not reset to default: got %d want %d", len(got.Sections), len(def.Sections))
	}
	if got.Settings.LogLevel != def.Settings.LogLevel || got.Settings.AutoUpdateCron != def.Settings.AutoUpdateCron {
		t.Fatalf("settings not reset: log=%q cron=%q", got.Settings.LogLevel, got.Settings.AutoUpdateCron)
	}

	// Preserved.
	if len(got.VPNs) != 1 || got.VPNs[0].Name != "wg0" {
		t.Fatalf("VPNs not preserved: %+v", got.VPNs)
	}
	if len(got.ZapretProfiles) != 1 || got.ZapretProfiles[0].Name != "custom" {
		t.Fatalf("zapret profiles not preserved: %+v", got.ZapretProfiles)
	}
	if len(got.ZapretStrategies) != 1 || got.ZapretStrategies[0].Name != "myst" {
		t.Fatalf("zapret strategies not preserved: %+v", got.ZapretStrategies)
	}
	if got.Settings.Secret != "my-real-secret-token" {
		t.Fatalf("secret not preserved: %q", got.Settings.Secret)
	}
	if got.Settings.MihomoBin != "/etc/purewrt/mihomo-bin/mihomo-alpha-abc123" || got.Settings.MihomoVersion != "alpha-abc123" {
		t.Fatalf("mihomo binary selection not preserved: bin=%q ver=%q", got.Settings.MihomoBin, got.Settings.MihomoVersion)
	}
	if got.Settings.DefaultListsBaseURL != "https://example.com/mylists/" {
		t.Fatalf("default_lists_base_url not preserved: %q", got.Settings.DefaultListsBaseURL)
	}
	if got.Settings.DNSMasqIncludeDir != "/tmp/dnsmasq.cfg01411c.d" {
		t.Fatalf("dnsmasq_include_dir not preserved: %q", got.Settings.DNSMasqIncludeDir)
	}
}
