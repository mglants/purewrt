package manager

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestMihomoCheckReadOnlyUsesInstalledVersionAndConfiguredChannel(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mihomo")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'Mihomo Meta v1.0.0 linux arm64'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stable" {
			t.Errorf("wrong configured channel: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v2.0.0","assets":[{"name":"mihomo-linux-arm64-v2.0.0.gz","browser_download_url":"https://example.com/mihomo.gz"}]}`))
	}))
	defer srv.Close()
	c := config.Default()
	c.Settings.MihomoBin = bin
	c.Settings.MihomoVersion = "v2.0.0"
	c.Settings.MihomoChannel = "stable"
	c.Settings.MihomoArch = "arm64"
	c.Settings.MihomoStableReleaseAPI = srv.URL + "/stable"
	c.Settings.MihomoReleaseAPI = srv.URL + "/alpha"
	c.Settings.BootstrapDoHEnabled = false
	c.Settings.BootstrapProxyFallback = false
	path := filepath.Join(dir, "purewrt")
	if err := config.Save(path, c); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	m := Manager{ConfigPath: path}
	info, err := m.MihomoCheckUpdateChannel("")
	if err != nil {
		t.Fatal(err)
	}
	if info.CurrentVersion != "v1.0.0" || info.Version != "v2.0.0" || !info.UpdateAvailable || info.Channel != "stable" {
		t.Fatalf("%+v", info)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("release check modified configuration")
	}
	backups, _ := filepath.Glob(path + ".*")
	if len(backups) != 0 {
		t.Fatalf("check created backup: %v", backups)
	}
}
func TestInstalledMihomoVersionDoesNotTrustStoredRelease(t *testing.T) {
	c := config.Default()
	c.Settings.MihomoBin = filepath.Join(t.TempDir(), "missing")
	c.Settings.MihomoVersion = "stale"
	if got := installedMihomoVersion(c); got != "" {
		t.Fatalf("trusted stale metadata: %s", got)
	}
}
