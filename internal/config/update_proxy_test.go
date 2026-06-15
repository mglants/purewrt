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

func TestZapretProfilesLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "purewrt")
	data := "config zapret 'zapret'\n    option enabled '1'\n    option mode 'nfqws'\n    option queue_num '200'\n    option params '--legacy-ignored'\n\nconfig zapret_profile 'wan_a'\n    option enabled '1'\n    list interface 'wan_a'\n    option mode 'nfqws'\n    option queue_num '201'\n    option fwmark '0x40000001'\n    option params '--strategy-a'\n\nconfig zapret_profile 'wan_b'\n    option enabled '1'\n    list interface 'wan_b'\n    option mode 'tpws'\n    option tpws_port '989'\n    option params '--strategy-b'\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ZapretProfiles) != 2 {
		t.Fatalf("expected two zapret profiles, got %+v", c.ZapretProfiles)
	}
	if c.ZapretProfiles[0].Name != "wan_a" || len(c.ZapretProfiles[0].Interfaces) != 1 || c.ZapretProfiles[0].Interfaces[0] != "wan_a" || c.ZapretProfiles[0].QueueNum != 201 || c.ZapretProfiles[1].Name != "wan_b" || c.ZapretProfiles[1].TPWSPort != 989 {
		t.Fatalf("unexpected zapret profiles: %+v", c.ZapretProfiles)
	}
	out := filepath.Join(dir, "purewrt.out")
	if err := Save(out, c); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(written), "config zapret 'zapret'") || strings.Contains(string(written), "--legacy-ignored") {
		t.Fatalf("saved config must drop legacy single zapret config:\n%s", string(written))
	}
	if !strings.Contains(string(written), "config zapret_profile\n") || strings.Contains(string(written), "config zapret_profile '") || !strings.Contains(string(written), "list interface 'wan_b'") || strings.Contains(string(written), "option interface '") {
		t.Fatalf("saved config missing zapret profiles:\n%s", string(written))
	}
}
