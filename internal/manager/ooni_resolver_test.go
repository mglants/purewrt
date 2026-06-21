package manager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestLookupUID(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "passwd")
	os.WriteFile(pw, []byte("root:x:0:0:root:/root:/bin/ash\n# comment\nooniprobe:x:8377:8377:ooni:/tmp/ooni:/bin/false\n"), 0o644)

	if got := lookupUID("ooniprobe", pw); got != 8377 {
		t.Fatalf("ooniprobe uid = %d, want 8377", got)
	}
	if got := lookupUID("root", pw); got != 0 {
		t.Fatalf("root uid = %d, want 0", got)
	}
	if got := lookupUID("nobody-here", pw); got != 0 {
		t.Fatalf("missing user uid = %d, want 0", got)
	}
	if got := lookupUID("ooniprobe", filepath.Join(dir, "nope")); got != 0 {
		t.Fatalf("missing file uid = %d, want 0", got)
	}
}

func TestResolveOONIUserDisabled(t *testing.T) {
	c := config.Default()
	c.OONI.Enabled = false
	c.OONI.UID = 9999
	c = ResolveOONIUser(c)
	if c.OONI.UID != 0 {
		t.Fatalf("disabled OONI must zero the uid, got %d", c.OONI.UID)
	}
}
