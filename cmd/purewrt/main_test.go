package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
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

// Generation wall time on ARM routers is GC-pacing-bound: default GOGC gave
// erratic 0.3-10s runs where GOGC=800 gave a flat 0.12s for +1.2MB peak RSS
// (measured on cortex-a53, 80k-domain config). tuneGC applies that default
// for the short-lived CLI, but a user-supplied GOGC env must win.
func TestTuneGCSetsAggressivePercent(t *testing.T) {
	old := debug.SetGCPercent(100)
	defer debug.SetGCPercent(old)
	t.Setenv("GOGC", "")
	os.Unsetenv("GOGC")
	tuneGC()
	if got := debug.SetGCPercent(100); got != cliGCPercent {
		t.Fatalf("tuneGC must set GC percent to %d, got %d", cliGCPercent, got)
	}
}

func TestTuneGCRespectsUserGOGC(t *testing.T) {
	old := debug.SetGCPercent(100)
	defer debug.SetGCPercent(old)
	t.Setenv("GOGC", "50")
	tuneGC()
	if got := debug.SetGCPercent(100); got != 100 {
		t.Fatalf("tuneGC must not override user GOGC, got %d", got)
	}
}

// purewrt-check and purewrt-api install as symlinks to the purewrt binary
// (three separate Go binaries duplicated ~13MB of runtime/stdlib on flash);
// entry selection is by argv[0] basename, busybox-style. Anything else —
// including future symlink typos — falls through to the regular CLI.
func TestMultiCallEntry(t *testing.T) {
	cases := map[string]string{
		"purewrt-check": "check",
		"purewrt-api":   "api",
		"purewrt":       "",
		"purewrt-new":   "", // scp temp name from the deploy recipe
	}
	for argv0, want := range cases {
		if got := multiCallEntry(argv0); got != want {
			t.Fatalf("multiCallEntry(%q) = %q, want %q", argv0, got, want)
		}
	}
}
