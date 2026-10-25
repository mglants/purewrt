package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateProxyURLLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "purewrt")
	data := "config main 'settings'\n    option update_via_proxy '1'\n    option update_proxy_url 'http://127.0.0.1:7890'\n    option dashboard_enabled '1'\n    option dashboard_listen '0.0.0.0:9090'\n    option dashboard_path '/etc/purewrt/dashboard'\n    option dashboard_url 'https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip'\n    option dashboard_name 'metacubexd'\n    option backup_retention '5'\n    option background_updates '1'\n    option boot_update_delay '120'\n    option update_nice '18'\n    option update_ionice_class '2'\n    option update_ionice_level '6'\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Settings.UpdateProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("unexpected update proxy url: %q", c.Settings.UpdateProxyURL)
	}
	if !c.Settings.UpdateViaProxy {
		t.Fatal("expected update_via_proxy to be enabled")
	}
	if !c.Settings.DashboardEnabled || c.Settings.DashboardListen != "0.0.0.0:9090" || c.Settings.DashboardPath != "/etc/purewrt/dashboard" || c.Settings.DashboardName != "metacubexd" {
		t.Fatalf("unexpected dashboard settings: %+v", c.Settings)
	}
	if !c.Settings.BackgroundUpdates || c.Settings.BootUpdateDelay != 120 || c.Settings.UpdateNice != 18 || c.Settings.UpdateIONiceClass != 2 || c.Settings.UpdateIONiceLevel != 6 {
		t.Fatalf("unexpected background update settings: %+v", c.Settings)
	}
	if c.Settings.BackupRetention != 5 {
		t.Fatalf("unexpected backup retention: %+v", c.Settings)
	}
	out := filepath.Join(dir, "purewrt.out")
	if err := Save(out, c); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "option update_proxy_url 'http://127.0.0.1:7890'") {
		t.Fatalf("saved config missing update_proxy_url:\n%s", string(written))
	}
	if !strings.Contains(string(written), "option update_via_proxy '1'") {
		t.Fatalf("saved config missing update_via_proxy:\n%s", string(written))
	}
	if !strings.Contains(string(written), "option dashboard_enabled '1'") || !strings.Contains(string(written), "option dashboard_name 'metacubexd'") {
		t.Fatalf("saved config missing dashboard settings:\n%s", string(written))
	}
	if !strings.Contains(string(written), "option background_updates '1'") || !strings.Contains(string(written), "option boot_update_delay '120'") || !strings.Contains(string(written), "option update_nice '18'") || !strings.Contains(string(written), "option update_ionice_class '2'") || !strings.Contains(string(written), "option update_ionice_level '6'") {
		t.Fatalf("saved config missing background update settings:\n%s", string(written))
	}
	if !strings.Contains(string(written), "option backup_retention '5'") {
		t.Fatalf("saved config missing backup retention:\n%s", string(written))
	}
}

func TestZapretApplicationsLoadAndSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purewrt")
	data := "config zapret_strategy 'zs_discord'\n option enabled '1'\n list assignment 'wan_a=youtube_combined'\n list assignment 'wan_b=discord_combined'\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ZapretApplications) != 1 || len(c.ZapretStrategies) != 2 {
		t.Fatal(c.ZapretApplications, c.ZapretStrategies)
	}
	out := string(Serialize(c))
	if strings.Contains(out, "zapret_profile") || strings.Contains(out, "option params") || !strings.Contains(out, "list assignment 'wan_b=discord_combined'") {
		t.Fatal(out)
	}
}
