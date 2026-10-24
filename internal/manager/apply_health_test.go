package manager

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
)

func TestEmptyNFTPayloadRejectedBeforeLiveChanges(t *testing.T) {
	c, staged, backup := applyTestConfig(t, t.TempDir())
	if e := os.Truncate(staged.NFTSetsFile, 0); e != nil {
		t.Fatal(e)
	}
	r := &fakeRunner{}
	err := (Manager{}).applyWithRunnerPaths(c, backup, staged, applyTestLivePaths(t.TempDir()), r)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty-file error, got %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("touched live system before rejecting empty file: %v", r.calls)
	}
	if _, e := os.Stat(filepath.Join(c.RuntimeDir(), ".last_applied")); !os.IsNotExist(e) {
		t.Fatal("marked bad apply successful")
	}
}

func TestApplyHealthRecordsDiskErrorAndChecksLiveFiles(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.RuntimeDir = filepath.Join(dir, "run")
	c.Settings.GeneratedDir = filepath.Join(dir, "generated")
	c.Settings.MihomoConfig = filepath.Join(dir, "mihomo.yaml")
	cfg := filepath.Join(dir, "config")
	if e := config.Save(cfg, c); e != nil {
		t.Fatal(e)
	}
	stamp := time.Now().UTC().Truncate(time.Second)
	failure := applyFailure("promotion", &os.PathError{Op: "write", Path: "output", Err: syscall.ENOSPC})
	if !errors.Is(failure, syscall.ENOSPC) {
		t.Fatal("lost underlying error")
	}
	if e := recordApplyAttempt(c, stamp, failure); e != nil {
		t.Fatal(e)
	}
	r := (Manager{ConfigPath: cfg}).ApplyHealth()
	if r.Last == nil || r.Last.Success || r.Last.Stage != "promotion" || !strings.Contains(r.Last.Error, "no space left") || !r.Last.Time.Equal(stamp) {
		t.Fatalf("bad status: %+v", r)
	}
	if len(r.Issues) != 3 {
		t.Fatalf("expected missing output issues: %+v", r)
	}
	p := generator.DefaultGeneratedPaths(c)
	for _, path := range []string{p.MihomoConfig, p.NFTFile, p.NFTSetsFile} {
		os.MkdirAll(filepath.Dir(path), 0755)
		if e := os.WriteFile(path, []byte("generated"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := recordApplyAttempt(c, stamp, nil); e != nil {
		t.Fatal(e)
	}
	r = (Manager{ConfigPath: cfg}).ApplyHealth()
	if r.Last == nil || !r.Last.Success || len(r.Issues) != 0 {
		t.Fatalf("bad recovered status: %+v", r)
	}
	if e := os.Truncate(p.NFTSetsFile, 0); e != nil {
		t.Fatal(e)
	}
	if r = (Manager{ConfigPath: cfg}).ApplyHealth(); len(r.Issues) != 1 || !strings.Contains(r.Issues[0], "empty") {
		t.Fatalf("empty output not detected: %+v", r)
	}
}

func TestApplyAttemptBoundedAndWriteFailure(t *testing.T) {
	c := config.Default()
	c.Settings.RuntimeDir = t.TempDir()
	if e := recordApplyAttempt(c, time.Now(), errors.New(strings.Repeat("x", 10000))); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(applyHealthPath(c))
	if e != nil || info.Size() > 4096 {
		t.Fatal("unbounded state", e)
	}
	// JSON escaping may expand the bounded error by up to six times.
	if e := recordApplyAttempt(c, time.Now(), errors.New(strings.Repeat("\x00", 10000))); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(applyHealthPath(c))
	var attempt ApplyAttempt
	if e != nil || len(data) > 16*1024 || json.Unmarshal(data, &attempt) != nil {
		t.Fatal("invalid bounded status", e)
	}
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, []byte("x"), 0600)
	c.Settings.RuntimeDir = blocker
	if e = recordApplyAttempt(c, time.Now(), syscall.ENOSPC); e == nil {
		t.Fatal("status write failure hidden")
	}
}
