package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNoZapretUpgradeStaysInactive(t *testing.T) {
	for _, extra := range []string{"", "config zapret_profile 'wan'\n option enabled '0'\nconfig zapret_strategy 'youtube_tcp'\n option enabled '0'\n option profile 'wan'\n"} {
		path := filepath.Join(t.TempDir(), "purewrt")
		if err := os.WriteFile(path, []byte("config section 'sec_common'\n option action 'proxy'\n option enabled '1'\n"+extra), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.ZapretProfiles) != 0 || len(c.ZapretStrategies) != 0 || c.Sections[0].Action != "proxy" {
			t.Fatal("upgrade activated Zapret", c.ZapretProfiles, c.ZapretStrategies)
		}
	}
}
func TestOldActiveZapretRequiresExplicitConversion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purewrt")
	if err := os.WriteFile(path, []byte("config zapret_strategy 'zs_old'\n option enabled '1'\n option profile 'wan'\n option params '--filter-tcp=443'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("accepted old active strategy without WAN assignments")
	}
}
