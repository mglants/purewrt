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

// The size/entry caps alone never fire on real routers (16MB default vs a
// few MB of artifacts), so superseded checksums pile up on flash — a router
// accumulated 15.6MB of stale artifacts whose rebuild-from-scratch was 59KB.
// Live pruning removes artifacts whose checksum no longer matches the
// provider's current source file, and whole dirs for providers that left
// the config. A nil Live map keeps the old measure/cap-only behaviour
// (statistics calls CleanupArtifacts with empty limits just to count).
func TestCleanupArtifactsPrunesNonLiveChecksums(t *testing.T) {
	dir := t.TempDir()
	stale := ArtifactPathInCache(dir, "p", "aaaa")
	live := ArtifactPathInCache(dir, "p", "bbbb")
	gone := ArtifactPathInCache(dir, "removed-provider", "cccc")
	for _, p := range []string{stale, live, gone} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p+".meta.json", []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := CleanupArtifacts(dir, CacheLimits{Live: map[string]string{"p": "bbbb"}})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Removed != 2 || stats.Entries != 1 {
		t.Fatalf("expected 2 pruned / 1 kept, stats=%#v", stats)
	}
	for _, p := range []string{stale, gone, stale + ".meta.json", gone + ".meta.json"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s must be pruned, err=%v", p, err)
		}
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("live artifact must survive: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(gone)); !os.IsNotExist(err) {
		t.Fatalf("emptied provider dir must be removed, err=%v", err)
	}
}

func TestCleanupArtifactsKeepsProviderWithUnknownChecksum(t *testing.T) {
	dir := t.TempDir()
	p := ArtifactPathInCache(dir, "p", "aaaa")
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// Live checksum "" means the provider's source file is currently
	// unreadable (not yet downloaded, transient error) — don't prune what
	// we can't compare.
	stats, err := CleanupArtifacts(dir, CacheLimits{Live: map[string]string{"p": ""}})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Removed != 0 {
		t.Fatalf("must not prune on unknown live checksum, stats=%#v", stats)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("artifact must survive: %v", err)
	}
}

func TestCleanupArtifactsNilLiveKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	p := ArtifactPathInCache(dir, "p", "aaaa")
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	stats, err := CleanupArtifacts(dir, CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Removed != 0 || stats.Entries != 1 {
		t.Fatalf("nil Live must be measure-only, stats=%#v", stats)
	}
}
