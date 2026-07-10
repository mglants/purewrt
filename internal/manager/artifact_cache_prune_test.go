package manager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/provider"
)

// cleanupArtifactCache must prune artifacts superseded by a newer source
// download (checksum changed) and artifacts of providers removed from the
// config — the byte/entry caps alone never fire on real routers, which is
// how one accumulated 15.6MB of dead artifacts on flash.
func TestCleanupArtifactCachePrunesStaleAndOrphanedArtifacts(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "rulesets", "p.txt")
	if err := os.MkdirAll(filepath.Dir(srcPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, []byte("DOMAIN,example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	liveSum := provider.ArtifactChecksum(srcPath)

	c := config.Default()
	c.Settings.Workdir = dir
	c.Settings.CacheDir = filepath.Join(dir, "cache")
	c.RuleProviders = []config.RuleProvider{{Name: "p", Enabled: true, Format: "text", Path: srcPath}}
	cfgPath := filepath.Join(dir, "uci-purewrt")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}

	cacheDir := c.CacheDir()
	live := provider.ArtifactPathInCache(cacheDir, "p", liveSum)
	stale := provider.ArtifactPathInCache(cacheDir, "p", "deadbeef")
	orphan := provider.ArtifactPathInCache(cacheDir, "removed", "cafe")
	for _, p := range []string{live, stale, orphan} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := (Manager{ConfigPath: cfgPath}).cleanupArtifactCache(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("live artifact must survive: %v", err)
	}
	for _, p := range []string{stale, orphan} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s must be pruned, err=%v", p, err)
		}
	}
}
