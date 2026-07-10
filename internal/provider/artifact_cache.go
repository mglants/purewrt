package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/rules"
	"github.com/purewrt/purewrt/internal/system"
)

type ArtifactMetadata struct {
	Version     int       `json:"version"`
	Provider    string    `json:"provider"`
	Checksum    string    `json:"checksum"`
	Format      string    `json:"format"`
	EntryCount  int       `json:"entry_count"`
	GeneratedAt time.Time `json:"generated_at"`
}

var safeArtifactNameRE = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

type CacheLimits struct {
	MaxBytes   int64
	MaxEntries int
	// Live maps provider name → checksum of its current source file. When
	// non-nil, artifacts under a provider dir not present in the map, or
	// with a checksum other than the live one, are pruned — the size caps
	// alone never fire in practice (16MB default vs a few MB of live
	// artifacts) so superseded checksums otherwise accumulate on flash
	// forever. An empty checksum value means "source currently unreadable";
	// that provider's artifacts are kept. Nil keeps the legacy
	// measure-and-cap-only behaviour (statistics uses it to count).
	Live map[string]string
}

type CacheStats struct {
	Dir     string
	Bytes   int64
	Entries int
	Removed int
}

func ArtifactPath(workdir, providerName, checksum string) string {
	return filepath.Join(artifactDir(workdir, providerName), checksum+".rules")
}

func ArtifactPathInCache(cacheDir, providerName, checksum string) string {
	return filepath.Join(artifactDirFromCache(cacheDir, providerName), checksum+".rules")
}

func EnsureArtifact(workdir string, rpName, format, checksum string, data []byte) (ArtifactMetadata, error) {
	path := ArtifactPath(workdir, rpName, checksum)
	if meta, err := ReadArtifactMetadata(path); err == nil && meta.Version == rules.ArtifactVersion && meta.Checksum == checksum {
		if _, err := ReadArtifact(path); err == nil {
			return meta, nil
		}
	}
	parsed, err := ParseRuleProviderForGeneration(rpName, format, data)
	if err != nil {
		return ArtifactMetadata{}, err
	}
	neutral := make([]rules.NeutralRule, 0, len(parsed.Rules))
	for _, r := range parsed.Rules {
		if !r.SupportedOpenWrt {
			continue
		}
		if nr, ok := rules.RuleToNeutral(r); ok {
			neutral = append(neutral, nr)
		}
	}
	if err := WriteArtifact(path, rpName, format, checksum, neutral); err != nil {
		return ArtifactMetadata{}, err
	}
	return ReadArtifactMetadata(path)
}

func WriteArtifact(path, providerName, format, checksum string, neutral []rules.NeutralRule) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	var b bytes.Buffer
	if err := rules.WriteArtifact(&b, neutral); err != nil {
		return err
	}
	if err := system.AtomicWrite(path, b.Bytes(), 0600); err != nil {
		return err
	}
	meta := ArtifactMetadata{Version: rules.ArtifactVersion, Provider: providerName, Checksum: checksum, Format: format, EntryCount: len(neutral), GeneratedAt: time.Now().UTC()}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return system.AtomicWrite(path+".meta.json", append(mb, '\n'), 0600)
}

func ReadArtifact(path string) ([]rules.NeutralRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return rules.ReadArtifact(f)
}

func ReadArtifactMetadata(path string) (ArtifactMetadata, error) {
	b, err := os.ReadFile(path + ".meta.json")
	if err != nil {
		return ArtifactMetadata{}, err
	}
	var meta ArtifactMetadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return ArtifactMetadata{}, err
	}
	return meta, nil
}

func CleanupArtifacts(cacheDir string, limits CacheLimits) (CacheStats, error) {
	stats := CacheStats{Dir: cacheDir}
	if cacheDir == "" {
		return stats, nil
	}
	type item struct {
		path string
		size int64
		mod  time.Time
	}
	var items []item
	err := filepath.WalkDir(cacheDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || strings.HasSuffix(path, ".meta.json") || !strings.HasSuffix(path, ".rules") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		items = append(items, item{path: path, size: info.Size(), mod: info.ModTime()})
		stats.Bytes += info.Size()
		stats.Entries++
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return stats, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mod.Before(items[j].mod) })
	var liveByDir map[string]string
	if limits.Live != nil {
		liveByDir = make(map[string]string, len(limits.Live))
		for name, sum := range limits.Live {
			liveByDir[safeArtifactName(name)] = sum
		}
	}
	remove := func(it item) {
		// Only credit the stats when the artifact actually went away —
		// otherwise a flaky filesystem makes Bytes/Entries drift below
		// reality and the limit checks stop firing while the disk is
		// still full. The meta.json removal stays best-effort: an
		// orphaned meta file costs bytes we no longer track but can't
		// resurrect the artifact.
		if err := os.Remove(it.path); err != nil && !os.IsNotExist(err) {
			return
		}
		_ = os.Remove(it.path + ".meta.json")
		stats.Bytes -= it.size
		stats.Entries--
		stats.Removed++
	}
	if liveByDir != nil {
		kept := items[:0]
		for _, it := range items {
			providerDir := filepath.Dir(it.path)
			liveSum, known := liveByDir[filepath.Base(providerDir)]
			if known && liveSum == "" {
				kept = append(kept, it) // source unreadable — can't compare, keep
				continue
			}
			if known && strings.TrimSuffix(filepath.Base(it.path), ".rules") == liveSum {
				kept = append(kept, it)
				continue
			}
			remove(it)
			_ = os.Remove(providerDir) // best-effort; fails while non-empty
		}
		items = kept
	}
	for _, it := range items {
		if limits.MaxEntries > 0 && stats.Entries > limits.MaxEntries {
			remove(it)
			continue
		}
		if limits.MaxBytes > 0 && stats.Bytes > limits.MaxBytes {
			remove(it)
		}
	}
	if stats.Bytes < 0 {
		stats.Bytes = 0
	}
	if stats.Entries < 0 {
		stats.Entries = 0
	}
	return stats, nil
}

func safeArtifactName(providerName string) string {
	name := strings.Trim(safeArtifactNameRE.ReplaceAllString(providerName, "_"), "_")
	if name == "" {
		name = "provider"
	}
	return name
}

func artifactDir(workdir, providerName string) string {
	if workdir == "" {
		workdir = "/etc/purewrt"
	}
	return filepath.Join(workdir, "cache", "rules", safeArtifactName(providerName))
}

func artifactDirFromCache(cacheDir, providerName string) string {
	if cacheDir == "" {
		cacheDir = filepath.Join("/etc/purewrt", "cache")
	}
	return filepath.Join(cacheDir, "rules", safeArtifactName(providerName))
}

func ArtifactChecksum(path string) string {
	return existingFileChecksum(path)
}

func existingFileChecksum(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}
