package provider

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupArtifactsEnforcesEntryLimit(t *testing.T) {
	dir := t.TempDir()
	old := ArtifactPathInCache(dir, "p", "old")
	newer := ArtifactPathInCache(dir, "p", "new")
	if err := os.MkdirAll(filepath.Dir(old), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-time.Hour)
	_ = os.Chtimes(old, oldTime, oldTime)
	stats, err := CleanupArtifacts(dir, CacheLimits{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Entries != 1 || stats.Removed != 1 {
		t.Fatalf("stats=%#v", stats)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old artifact still exists or unexpected error: %v", err)
	}
	if _, err := os.Stat(newer); err != nil {
		t.Fatalf("new artifact missing: %v", err)
	}
}
