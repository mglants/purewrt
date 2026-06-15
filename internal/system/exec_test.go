package system

import (
	"strings"
	"testing"
	"time"
)

func TestRunnerDryRun(t *testing.T) {
	t.Parallel()

	out, err := (Runner{DryRun: true}).Run("echo", "hello", "world")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out != "echo hello world" {
		t.Fatalf("out = %q", out)
	}
}

func TestRunnerRunSuccessAndFailure(t *testing.T) {
	t.Parallel()

	out, err := (Runner{Timeout: time.Second}).Run("/bin/sh", "-c", "printf ok")
	if err != nil || out != "ok" {
		t.Fatalf("success out=%q err=%v", out, err)
	}

	out, err = (Runner{Timeout: time.Second}).Run("/bin/sh", "-c", "printf bad; exit 7")
	if err == nil || out != "bad" {
		t.Fatalf("failure out=%q err=%v", out, err)
	}
}

func TestRunnerOutputLimit(t *testing.T) {
	t.Parallel()

	out, err := (Runner{Timeout: time.Second, MaxOut: 3}).Run("/bin/sh", "-c", "printf abcdef")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "abc") || !strings.Contains(out, "[output truncated]") {
		t.Fatalf("out = %q", out)
	}
}
