package system

import (
	"bytes"
	"os"
	"path/filepath"
)

// AtomicWrite writes data to path via a tmp-file-and-rename. Always
// takes the temp-then-rename path so the result is *truly* atomic for
// every caller — there used to be a >1MB shortcut to WriteFile, but
// that's a direct OpenFile(O_TRUNC) which fails with ETXTBSY when the
// target is a currently-executing binary. Rename(2) handles that case
// cleanly because it just relinks an inode.
func AtomicWrite(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func WriteIfChanged(path string, data []byte, perm os.FileMode) (bool, error) {
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm() != perm.Perm() {
			if err := os.Chmod(path, perm); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, nil
	}
	return true, AtomicWrite(path, data, perm)
}

func WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
