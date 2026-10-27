package system

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type BackupSet map[string]string

type BackupTempResult struct {
	Set     BackupSet
	Skipped []string
	Cleanup func()
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
