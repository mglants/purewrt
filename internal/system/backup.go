package system

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type BackupSet map[string]string

type BackupTempResult struct {
	Set     BackupSet
	Skipped []string
	Cleanup func()
}

func BackupFiles(paths ...string) (BackupSet, error) {
	return BackupFilesWithRetention(3, paths...)
}

func BackupFilesWithRetention(retention int, paths ...string) (BackupSet, error) {
	set := BackupSet{}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return set, err
		}
		backup := filepath.Join(filepath.Dir(p), filepath.Base(p)+"."+stamp+".bak")
		if err := AtomicWrite(backup, data, 0600); err != nil {
			return set, err
		}
		_ = cleanupBackups(p, retention)
		set[p] = backup
	}
	return set, nil
}

func BackupFilesTempWithLimit(baseDir string, maxBytes int64, paths ...string) (BackupTempResult, error) {
	if baseDir == "" {
		baseDir = os.TempDir()
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return BackupTempResult{Set: BackupSet{}, Cleanup: func() {}}, err
	}
	backupDir, err := os.MkdirTemp(baseDir, "purewrt-apply-backup-*")
	if err != nil {
		return BackupTempResult{Set: BackupSet{}, Cleanup: func() {}}, err
	}
	res := BackupTempResult{
		Set:     BackupSet{},
		Cleanup: func() { _ = os.RemoveAll(backupDir) },
	}
	for i, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			res.Cleanup()
			return res, err
		}
		if info.IsDir() {
			continue
		}
		if maxBytes >= 0 && info.Size() > maxBytes {
			res.Skipped = append(res.Skipped, p)
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			res.Cleanup()
			return res, err
		}
		backup := filepath.Join(backupDir, strings.ReplaceAll(filepath.Clean(p), string(filepath.Separator), "_")+fmt.Sprintf(".%d.bak", i))
		if err := AtomicWrite(backup, data, info.Mode().Perm()); err != nil {
			res.Cleanup()
			return res, err
		}
		res.Set[p] = backup
	}
	return res, nil
}

func cleanupBackups(path string, keep int) error {
	if keep <= 0 {
		return nil
	}
	pattern := filepath.Join(filepath.Dir(path), filepath.Base(path)+".*.bak")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	prefix := filepath.Base(path) + "."
	filtered := matches[:0]
	for _, m := range matches {
		base := filepath.Base(m)
		stamp := strings.TrimSuffix(strings.TrimPrefix(base, prefix), ".bak")
		if len(stamp) == len("20060102T150405Z") {
			filtered = append(filtered, m)
		}
	}
	sort.Strings(filtered)
	for len(filtered) > keep {
		_ = os.Remove(filtered[0])
		filtered = filtered[1:]
	}
	return nil
}

func (b BackupSet) Restore() error {
	for original, backup := range b {
		data, err := os.ReadFile(backup)
		if err != nil {
			return err
		}
		if err := AtomicWrite(original, data, 0600); err != nil {
			return err
		}
	}
	return nil
}
