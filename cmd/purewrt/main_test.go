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
// TestCommandRegistry guards the dispatch table: every name and alias is
// unique (a duplicate would shadow a command), every entry has help metadata,
// and every group is rendered by `purewrt help` (an unknown group string
// would silently hide its commands from the listing).
func TestCommandRegistry(t *testing.T) {
	groups := map[string]bool{}
	for _, g := range groupOrder {
		groups[g] = true
	}
	seen := map[string]bool{}
	for _, c := range commands {
		for _, n := range append([]string{c.name}, c.aliases...) {
			if seen[n] {
				t.Errorf("duplicate command name/alias %q", n)
			}
			seen[n] = true
		}
		if c.desc == "" {
			t.Errorf("command %q has no description", c.name)
		}
		if !groups[c.group] {
			t.Errorf("command %q group %q missing from groupOrder — hidden from help", c.name, c.group)
		}
		if c.run == nil {
			t.Errorf("command %q has no handler", c.name)
		}
	}
}

// TestLookupCommand covers canonical-name, alias, and unknown resolution.
func TestLookupCommand(t *testing.T) {
	if c, ok := lookupCommand("apply"); !ok || c.name != "apply" {
		t.Fatalf("apply not found: %+v %v", c, ok)
	}
	if c, ok := lookupCommand("reload"); !ok || c.name != "apply" {
		t.Fatalf("alias reload must resolve to apply: %+v %v", c, ok)
	}
	if c, ok := lookupCommand("stats"); !ok || c.name != "statistics" {
		t.Fatalf("alias stats must resolve to statistics: %+v %v", c, ok)
	}
	if _, ok := lookupCommand("no-such-command"); ok {
		t.Fatal("unknown command must not resolve")
	}
}

func TestExitCodeFor(t *testing.T) {
	partial := fmt.Errorf("update: 2 provider(s) failed: x; y: %w", manager.ErrPartialUpdate)
	if got := exitCodeFor(partial); got != 3 {
		t.Fatalf("partial update failure must exit 3, got %d", got)
	}
	if got := exitCodeFor(errors.New("nft -f failed")); got != 1 {
		t.Fatalf("hard failure must exit 1, got %d", got)
	}
}
