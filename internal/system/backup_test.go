package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupFilesKeepsOnlyThreeTimestampedBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "purewrt.nft")
	if err := os.WriteFile(path, []byte("current"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, stamp := range []string{"20260101T000001Z", "20260101T000002Z", "20260101T000003Z", "20260101T000004Z"} {
		name := filepath.Join(dir, "purewrt.nft."+stamp+".bak")
		if err := os.WriteFile(name, []byte(stamp), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := BackupFiles(path); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "purewrt.nft.*.bak"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 3 {
		t.Fatalf("expected 3 retained backups, got %d: %#v", len(matches), matches)
	}
	if _, err := os.Stat(filepath.Join(dir, "purewrt.nft.20260101T000001Z.bak")); !os.IsNotExist(err) {
		t.Fatalf("oldest backup should be removed, stat err=%v", err)
	}
}

func TestBackupFilesWithRetentionUsesConfiguredLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mihomo.yaml")
	if err := os.WriteFile(path, []byte("current"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, stamp := range []string{"20260101T000001Z", "20260101T000002Z", "20260101T000003Z", "20260101T000004Z"} {
		name := filepath.Join(dir, "mihomo.yaml."+stamp+".bak")
		if err := os.WriteFile(name, []byte(stamp), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := BackupFilesWithRetention(2, path); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "mihomo.yaml.*.bak"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 retained backups, got %d: %#v", len(matches), matches)
	}
}

func TestBackupFilesTempWithLimitBacksUpSmallAndSkipsLarge(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "tmp")
	small := filepath.Join(dir, "small.conf")
	large := filepath.Join(dir, "large.conf")
	if err := os.WriteFile(small, []byte("small"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(large, []byte("large-data"), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := BackupFilesTempWithLimit(base, 5, small, large)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Cleanup()
	if _, ok := res.Set[small]; !ok {
		t.Fatalf("small file should be backed up: %+v", res.Set)
	}
	if _, ok := res.Set[large]; ok {
		t.Fatalf("large file should be skipped: %+v", res.Set)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != large {
		t.Fatalf("unexpected skipped files: %#v", res.Skipped)
	}
	if err := os.WriteFile(small, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := res.Set.Restore(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(small)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "small" {
		t.Fatalf("small file was not restored, got %q", data)
	}
	backupDir := filepath.Dir(res.Set[small])
	res.Cleanup()
	if _, err := os.Stat(backupDir); !os.IsNotExist(err) {
		t.Fatalf("temp backup dir should be removed, err=%v", err)
	}
}
