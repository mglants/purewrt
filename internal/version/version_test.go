package version

import (
	"os"
	"strings"
	"testing"
)

// The default Version must track the repo VERSION file so plain `go build`
// binaries report the right release; package builds overwrite it via
// -ldflags -X. A release bump that forgets this constant fails here.
func TestDefaultVersionMatchesVersionFile(t *testing.T) {
	b, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if want := strings.TrimSpace(string(b)); Version != want {
		t.Fatalf("internal/version.Version = %q, VERSION file = %q — bump both", Version, want)
	}
}
