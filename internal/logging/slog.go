package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// LogFormat constants — match the UCI `log_format` enum on Settings.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// slogFor returns a *slog.Logger configured for the given Logger's level +
// format. Constructed lazily on first field-aware call so the existing
// printf API (which the tests still build via Logger{Level, Out} value
// literals) doesn't have to know about slog at all. Concurrency-safe via
// once-per-process compute keyed by (out pointer, level, format).
//
// The implementation prefers slog.JSONHandler when Format == FormatJSON,
// otherwise a slim custom TextHandler that emits the legacy
// `<lowercase-level> <msg> key=value key=value` shape — preserves the
// existing tests' prefix assertions while adding the new field tail.
func (l Logger) slogLogger() *slog.Logger {
	out := l.Out
	if out == nil {
		out = os.Stderr
	}
	key := slogKey{out: writerKey(out), level: l.Level, format: strings.ToLower(strings.TrimSpace(l.Format))}
	slogCacheMu.Lock()
	defer slogCacheMu.Unlock()
	if sl, ok := slogCache[key]; ok {
		return sl
	}
	opts := &slog.HandlerOptions{Level: levelToSlog(l.Level)}
	var h slog.Handler
	switch key.format {
	case FormatJSON:
		h = slog.NewJSONHandler(out, opts)
	default:
		h = newPureWRTTextHandler(out, l.Level)
	}
	sl := slog.New(h)
	slogCache[key] = sl
	return sl
}

type slogKey struct {
	out    uintptr
	level  Level
	format string
}

var (
	slogCache   = map[slogKey]*slog.Logger{}
	slogCacheMu sync.Mutex
)

func writerKey(w io.Writer) uintptr {
	if w == nil {
		return 0
	}
	// Identity comparison via the interface value's underlying pointer.
	// Two Loggers sharing os.Stderr will share a cached *slog.Logger;
	// distinct *bytes.Buffer instances (tests) get distinct slog loggers.
	type ifaceHeader struct {
		_ *uintptr
		d *uintptr
	}
	h := (*ifaceHeader)(nil)
	_ = h
	return cacheableWriterID(w)
}

// cacheableWriterID returns a stable identity for an io.Writer. For known
// singletons (Stderr, Stdout) it returns a constant; for anything else it
// uses the pointer the runtime gave us. The constants let two Loggers built
// independently against os.Stderr share one *slog.Logger; everything else
// stays per-instance which matters for tests that aim a *bytes.Buffer.
func cacheableWriterID(w io.Writer) uintptr {
	switch w {
	case os.Stderr:
		return 1
	case os.Stdout:
		return 2
	}
	// Fall back to the pointer address via fmt — slow but called only on
	// first field-aware emit per (writer, level, format) tuple.
	return uintptr(stringHash(fmt.Sprintf("%p", w)))
}

func stringHash(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// levelToSlog maps the package's Level back to slog's level constants.
func levelToSlog(l Level) slog.Level {
	switch l {
	case Error:
		return slog.LevelError
	case Warn:
		return slog.LevelWarn
	case Info:
		return slog.LevelInfo
	case Debug:
		return slog.LevelDebug
	default:
		return slog.LevelWarn
	}
}

// ParseFormat normalises a UCI `log_format` string. Empty or unknown values
// default to FormatText.
func ParseFormat(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case FormatJSON:
		return FormatJSON
	default:
		return FormatText
	}
}

// ---- Field-aware API (slog-backed) ----

// InfoFields emits a structured Info-level log. kv pairs are passed through
// to slog: even indices are keys (strings), odd indices are values. Mirrors
// the slog.LogAttrs ergonomics without the slog.Attr dance.
func (l Logger) InfoFields(msg string, kv ...any) {
	if !l.Enabled(Info) {
		return
	}
	l.slogLogger().LogAttrs(context.Background(), slog.LevelInfo, msg, toAttrs(kv)...)
}

// WarnFields emits a structured Warn-level log.
func (l Logger) WarnFields(msg string, kv ...any) {
	if !l.Enabled(Warn) {
		return
	}
	l.slogLogger().LogAttrs(context.Background(), slog.LevelWarn, msg, toAttrs(kv)...)
}

// ErrorFields emits a structured Error-level log.
func (l Logger) ErrorFields(msg string, kv ...any) {
	if !l.Enabled(Error) {
		return
	}
	l.slogLogger().LogAttrs(context.Background(), slog.LevelError, msg, toAttrs(kv)...)
}

// DebugFields emits a structured Debug-level log.
func (l Logger) DebugFields(msg string, kv ...any) {
	if !l.Enabled(Debug) {
		return
	}
	l.slogLogger().LogAttrs(context.Background(), slog.LevelDebug, msg, toAttrs(kv)...)
}

// DebugTimerFields is the structured-fields version of DebugTimer. The
// returned closure emits one Debug record with the user-supplied msg + kv
// pairs PLUS a `duration_ms` attr carrying the elapsed time. No-op when
// debug isn't enabled — same fast-path as DebugTimer.
func (l Logger) DebugTimerFields(msg string, kv ...any) func() {
	if !l.Enabled(Debug) {
		return func() {}
	}
	start := time.Now()
	return func() {
		attrs := append(toAttrs(kv), slog.Int64("duration_ms", time.Since(start).Milliseconds()))
		l.slogLogger().LogAttrs(context.Background(), slog.LevelDebug, msg, attrs...)
	}
}

// toAttrs converts a variadic kv slice into []slog.Attr. Odd-length slices
// are tolerated by treating the trailing key as a Bool=true marker — saves
// callers from awkward error handling for malformed argument lists.
func toAttrs(kv []any) []slog.Attr {
	if len(kv) == 0 {
		return nil
	}
	out := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", kv[i])
		}
		if i+1 >= len(kv) {
			out = append(out, slog.Bool(key, true))
			continue
		}
		out = append(out, slog.Any(key, kv[i+1]))
	}
	return out
}

// ---- Custom text handler ----

// pureWRTTextHandler is a slog.Handler that emits the historical
// `<lowercase-level> <msg> key=value key=value` shape PureWRT has always
// produced. Keeps existing log scrapers and the test-suite prefix
// assertions working while still flowing structured attrs through.
type pureWRTTextHandler struct {
	w     io.Writer
	level Level
	attrs []slog.Attr
	mu    *sync.Mutex
}

func newPureWRTTextHandler(w io.Writer, level Level) slog.Handler {
	return &pureWRTTextHandler{w: w, level: level, mu: &sync.Mutex{}}
}

func (h *pureWRTTextHandler) Enabled(_ context.Context, lv slog.Level) bool {
	// Map slog level back to ours and reuse the same level math.
	target := slogToLevel(lv)
	return target <= h.level
}

func (h *pureWRTTextHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(levelNameForSlog(r.Level))
	b.WriteByte(' ')
	b.WriteString(r.Message)
	// Combined handler attrs (from WithAttrs) + per-record attrs.
	for _, a := range h.attrs {
		appendAttr(&b, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(&b, a)
		return true
	})
	b.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *pureWRTTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &cp
}

func (h *pureWRTTextHandler) WithGroup(_ string) slog.Handler {
	// Groups aren't used by PureWRT — flatten and ignore.
	return h
}

func appendAttr(b *strings.Builder, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	b.WriteByte(' ')
	b.WriteString(a.Key)
	b.WriteByte('=')
	v := a.Value.String()
	if strings.ContainsAny(v, " \t\n\"=") {
		fmt.Fprintf(b, "%q", v)
		return
	}
	b.WriteString(v)
}

func slogToLevel(lv slog.Level) Level {
	switch {
	case lv >= slog.LevelError:
		return Error
	case lv >= slog.LevelWarn:
		return Warn
	case lv >= slog.LevelInfo:
		return Info
	default:
		return Debug
	}
}

func levelNameForSlog(lv slog.Level) string {
	switch {
	case lv >= slog.LevelError:
		return "error"
	case lv >= slog.LevelWarn:
		return "warn"
	case lv >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}
