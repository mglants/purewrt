package system

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteIfChangedSkipsIdenticalContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "purewrt.conf")
	if err := os.WriteFile(path, []byte("same"), 0644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	changed, err := WriteIfChanged(path, []byte("same"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical content should not be rewritten")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(oldTime) {
		t.Fatalf("mtime changed despite identical content: got %s want %s", info.ModTime(), oldTime)
	}
}

func TestWriteIfChangedWritesDifferentContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "purewrt.conf")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := WriteIfChanged(path, []byte("new"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("different content should be rewritten")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("unexpected content: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected mode: %v", info.Mode().Perm())
	}
}
