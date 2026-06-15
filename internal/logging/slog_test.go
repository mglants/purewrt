package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestInfoFieldsEmitsTextWithKVPairs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := Logger{Level: Debug, Out: &buf, Format: FormatText}
	l.InfoFields("download complete", "section", "media", "bytes", 12345)
	out := buf.String()
	if !strings.HasPrefix(out, "info ") {
		t.Fatalf("missing legacy level prefix in %q", out)
	}
	if !strings.Contains(out, "section=media") || !strings.Contains(out, "bytes=12345") {
		t.Fatalf("missing structured fields in %q", out)
	}
}

func TestInfoFieldsEmitsJSONWhenFormatJSON(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := Logger{Level: Debug, Out: &buf, Format: FormatJSON}
	l.InfoFields("download complete", "section", "media", "bytes", 12345)
	out := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if got["msg"] != "download complete" || got["section"] != "media" {
		t.Fatalf("missing fields in JSON: %+v", got)
	}
	if v, _ := got["bytes"].(float64); int(v) != 12345 {
		t.Fatalf("bytes wrong: %+v", got)
	}
}

func TestFieldsTolerateOddArgs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := Logger{Level: Debug, Out: &buf, Format: FormatText}
	// odd argc — trailing key with no value becomes a Bool(true) marker.
	l.InfoFields("partial", "section", "media", "force")
	out := buf.String()
	if !strings.Contains(out, "force=true") {
		t.Fatalf("expected trailing key to become force=true, got %q", out)
	}
}

func TestFieldsFilterBelowLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := Logger{Level: Warn, Out: &buf, Format: FormatText}
	l.InfoFields("hidden", "k", "v")
	l.DebugFields("hidden-debug", "k", "v")
	l.WarnFields("shown", "k", "v")
	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Fatalf("level filter leak in %q", out)
	}
	if !strings.Contains(out, "shown") {
		t.Fatalf("warn record dropped: %q", out)
	}
}

func TestDebugTimerFieldsEmitsDurationMs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := Logger{Level: Debug, Out: &buf, Format: FormatJSON}
	stop := l.DebugTimerFields("phase complete", "phase", "apply")
	time.Sleep(2 * time.Millisecond)
	stop()
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if got["phase"] != "apply" {
		t.Fatalf("missing phase field: %+v", got)
	}
	if got["duration_ms"] == nil {
		t.Fatalf("missing duration_ms field: %+v", got)
	}
}

func TestParseFormatNormalisation(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"json":    FormatJSON,
		"JSON":    FormatJSON,
		"text":    FormatText,
		"":        FormatText,
		"garbage": FormatText,
	}
	for in, want := range cases {
		if got := ParseFormat(in); got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewWithFormatWiresLogger(t *testing.T) {
	t.Parallel()
	l := NewWithFormat("info", "json")
	if l.Format != FormatJSON {
		t.Fatalf("Format = %q, want %q", l.Format, FormatJSON)
	}
	if l.Level != Info {
		t.Fatalf("Level = %v, want Info", l.Level)
	}
}
