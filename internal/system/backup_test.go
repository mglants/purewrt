package system

import (
	"os"
	"path/filepath"
	"testing"
)

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
