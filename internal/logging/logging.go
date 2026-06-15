package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type Level int

const (
	Error Level = iota
	Warn
	Info
	Debug
)

type Logger struct {
	Level Level
	Out   io.Writer
	// Format selects the structured-output backend used by the *Fields
	// methods (slog-backed). "" / "text" emit the legacy PureWRT shape;
	// "json" emits one JSON object per record (Loki / Vector friendly).
	// The printf API is unaffected — it never goes through slog and always
	// produces the legacy `<level> <msg>` lines.
	Format string
}

func New(level string) Logger {
	return Logger{Level: ParseLevel(level), Out: os.Stderr}
}

// NewWithFormat builds a Logger with both level and output format set.
// Used by callers that want their structured fields emitted as JSON for
// headless ingestion. Existing call sites that use `New(level)` keep the
// legacy text shape.
func NewWithFormat(level, format string) Logger {
	return Logger{Level: ParseLevel(level), Out: os.Stderr, Format: ParseFormat(format)}
}

func ParseLevel(level string) Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error", "err":
		return Error
	case "info", "notice":
		return Info
	case "debug":
		return Debug
	default:
		return Warn
	}
}

func (l Logger) Enabled(level Level) bool {
	return level <= l.Level
}

func (l Logger) Log(level Level, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	out := l.Out
	if out == nil {
		out = os.Stderr
	}
	_, _ = fmt.Fprintf(out, "%s %s\n", levelName(level), fmt.Sprintf(format, args...))
}

func (l Logger) Error(format string, args ...any) { l.Log(Error, format, args...) }
func (l Logger) Warn(format string, args ...any)  { l.Log(Warn, format, args...) }
func (l Logger) Info(format string, args ...any)  { l.Log(Info, format, args...) }
func (l Logger) Debug(format string, args ...any) { l.Log(Debug, format, args...) }

func (l Logger) DebugTimer(format string, args ...any) func() {
	if !l.Enabled(Debug) {
		return func() {}
	}
	msg := fmt.Sprintf(format, args...)
	start := time.Now()
	return func() {
		l.Debug("%s took=%s", msg, time.Since(start).Round(time.Millisecond))
	}
}

func levelName(level Level) string {
	switch level {
	case Error:
		return "error"
	case Info:
		return "info"
	case Debug:
		return "debug"
	default:
		return "warn"
	}
}
