package system

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestTryAcquireReturnsBusyForConcurrentLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purewrt.lock")

	first, err := TryAcquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	second, err := TryAcquire(path)
	if !errors.Is(err, ErrLockBusy) {
		t.Fatalf("expected ErrLockBusy, got lock=%v err=%v", second, err)
	}
	if second != nil {
		_ = second.Close()
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	third, err := TryAcquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = third.Close() }()
}
