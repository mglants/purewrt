package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseLevelKnownAliases(t *testing.T) {
	t.Parallel()
	cases := map[string]Level{
		"error":   Error,
		"ERR":     Error,
		"warn":    Warn,
		"warning": Warn, // unknown -> default Warn (current behaviour)
		"info":    Info,
		"notice":  Info,
		"debug":   Debug,
		"DEBUG":   Debug,
		"":        Warn, // empty -> Warn
		"garbage": Warn, // anything unknown -> Warn
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLoggerFiltersBelowLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := Logger{Level: Warn, Out: &buf}
	l.Info("hidden")  // Info > Warn → suppressed
	l.Debug("hidden") // Debug > Warn → suppressed
	l.Warn("shown")
	l.Error("shown-err")
	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Fatalf("Warn-level logger leaked Info/Debug output: %q", out)
	}
	if !strings.Contains(out, "shown") || !strings.Contains(out, "shown-err") {
		t.Fatalf("Warn-level logger dropped Warn/Error: %q", out)
	}
}

func TestLoggerEmitsLevelPrefix(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := Logger{Level: Debug, Out: &buf}
	l.Info("msg %d", 42)
	out := buf.String()
	if !strings.HasPrefix(out, "info ") {
		t.Fatalf("missing level prefix in %q", out)
	}
	if !strings.Contains(out, "msg 42") {
		t.Fatalf("format args not applied: %q", out)
	}
}

func TestDebugTimerNoOpWhenDebugDisabled(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := Logger{Level: Warn, Out: &buf}
	stop := l.DebugTimer("phase=%s", "x")
	stop()
	if buf.Len() != 0 {
		t.Fatalf("DebugTimer emitted with Debug disabled: %q", buf.String())
	}
}

func TestDebugTimerEmitsTookOnStop(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := Logger{Level: Debug, Out: &buf}
	stop := l.DebugTimer("phase=%s", "apply")
	stop()
	out := buf.String()
	if !strings.Contains(out, "phase=apply") {
		t.Fatalf("missing prefix in %q", out)
	}
	if !strings.Contains(out, "took=") {
		t.Fatalf("missing took= in %q", out)
	}
}

func TestEnabledIsMonotonic(t *testing.T) {
	t.Parallel()
	// A Debug-level logger must enable every lower level.
	l := Logger{Level: Debug}
	for _, lv := range []Level{Error, Warn, Info, Debug} {
		if !l.Enabled(lv) {
			t.Errorf("Debug logger should enable %v", lv)
		}
	}
	// An Error-level logger enables only Error.
	l = Logger{Level: Error}
	if !l.Enabled(Error) || l.Enabled(Warn) || l.Enabled(Info) || l.Enabled(Debug) {
		t.Fatal("Error logger should only enable Error")
	}
}
