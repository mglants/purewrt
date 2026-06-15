package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/purewrt/purewrt/internal/manager"
)

// TestExitCodeFor guards the CLI exit-code contract: soft-continue
// partial update failures exit 3, everything else exits 1. The
// init-script retry loop only requires non-zero; operators and scripts
// rely on the 3-vs-1 distinction.
func TestExitCodeFor(t *testing.T) {
	partial := fmt.Errorf("update: 2 provider(s) failed: x; y: %w", manager.ErrPartialUpdate)
	if got := exitCodeFor(partial); got != 3 {
		t.Fatalf("partial update failure must exit 3, got %d", got)
	}
	if got := exitCodeFor(errors.New("nft -f failed")); got != 1 {
		t.Fatalf("hard failure must exit 1, got %d", got)
	}
}
