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

func artifactDir(workdir, providerName string) string {
	if workdir == "" {
		workdir = "/etc/purewrt"
	}
	name := strings.Trim(safeArtifactNameRE.ReplaceAllString(providerName, "_"), "_")
	if name == "" {
		name = "provider"
	}
	return filepath.Join(workdir, "cache", "rules", name)
}

func artifactDirFromCache(cacheDir, providerName string) string {
	if cacheDir == "" {
		cacheDir = filepath.Join("/etc/purewrt", "cache")
	}
	name := strings.Trim(safeArtifactNameRE.ReplaceAllString(providerName, "_"), "_")
	if name == "" {
		name = "provider"
	}
	return filepath.Join(cacheDir, "rules", name)
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
