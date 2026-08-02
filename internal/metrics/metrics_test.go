package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounterIncRendersLine(t *testing.T) {
	// Use a fresh registry rather than mutating Default — keeps tests
	// isolated when run in parallel.
	r := freshRegistry(t)
	c := r.newCounter("purewrt_test_total", "Test counter")
	c.Inc()
	c.Inc()
	c.AddLabels(3)
	out := r.Render()
	if !strings.Contains(out, "# HELP purewrt_test_total Test counter") {
		t.Fatalf("missing HELP line:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE purewrt_test_total counter") {
		t.Fatalf("missing TYPE line:\n%s", out)
	}
	if !strings.Contains(out, "purewrt_test_total 5") {
		t.Fatalf("missing sample line:\n%s", out)
	}
}

func TestCounterWithLabelsRendersEscapedValues(t *testing.T) {
	r := freshRegistry(t)
	c := r.newCounter("purewrt_apply_total", "Apply count by result", "result")
	c.WithLabelValues("ok")
	c.WithLabelValues("ok")
	c.WithLabelValues("fail")
	out := r.Render()
	if !strings.Contains(out, `purewrt_apply_total{result="ok"} 2`) {
		t.Fatalf("missing OK line:\n%s", out)
	}
	if !strings.Contains(out, `purewrt_apply_total{result="fail"} 1`) {
		t.Fatalf("missing fail line:\n%s", out)
	}
}

func TestLabelValueWithCommaRendersValidPair(t *testing.T) {
	r := freshRegistry(t)
	c := r.newCounter("purewrt_probe_total", "Probe", "endpoint", "result")
	c.WithLabelValues("https://example.test/a,b", "ok")
	out := r.Render()
	if !strings.Contains(out, `purewrt_probe_total{endpoint="https://example.test/a,b",result="ok"} 1`) {
		t.Fatalf("comma-bearing label was corrupted:\n%s", out)
	}
}

func TestGaugeSetGet(t *testing.T) {
	r := freshRegistry(t)
	g := r.newGauge("purewrt_subscription_seconds_to_expiry", "Time until subscription expiry")
	g.Set(86400.5)
	if got := g.Value(); got != 86400.5 {
		t.Fatalf("Value = %v, want 86400.5", got)
	}
	out := r.Render()
	if !strings.Contains(out, "purewrt_subscription_seconds_to_expiry 86400.5") {
		t.Fatalf("gauge line missing:\n%s", out)
	}
}

func TestUnsetGaugeDoesNotRenderSample(t *testing.T) {
	r := freshRegistry(t)
	r.newGauge("purewrt_unknown", "Unknown")
	out := r.Render()
	if strings.Contains(out, "purewrt_unknown 0") {
		t.Fatalf("unset gauge rendered as a real zero:\n%s", out)
	}
}

func TestLabelledGaugeSetAndDelete(t *testing.T) {
	r := freshRegistry(t)
	g := r.newGauge("purewrt_members", "Members", "state")
	g.Set(3, "healthy")
	g.Set(1, "suspect")
	g.Delete("suspect")
	out := r.Render()
	if !strings.Contains(out, `purewrt_members{state="healthy"} 3`) || strings.Contains(out, `state="suspect"`) {
		t.Fatalf("labelled gauge set/delete failed:\n%s", out)
	}
}

func TestHandlerServesContentType(t *testing.T) {
	// Use Default for the handler smoke-test.
	original := Default
	Default = NewRegistry()
	defer func() { Default = original }()
	NewCounter("purewrt_test_total", "X").Inc()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, req)
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestEscapeHandlesQuotesAndNewlines(t *testing.T) {
	got := escape(`a"b\n` + "\nc")
	if !strings.Contains(got, `\\n`) || !strings.Contains(got, `\"`) {
		t.Fatalf("escape didn't quote special chars: %q", got)
	}
}

// freshRegistry builds an isolated Registry + helpers since Counter/Gauge
// constructors register on Default by design. Tests that want isolation
// reach for these.
type testRegistry struct{ *Registry }

func freshRegistry(t *testing.T) *testRegistry {
	t.Helper()
	return &testRegistry{Registry: NewRegistry()}
}

func (r *testRegistry) newCounter(name, help string, keys ...string) *Counter {
	return r.Registry.NewCounter(name, help, keys...)
}

func (r *testRegistry) newGauge(name, help string, keys ...string) *Gauge {
	return r.Registry.NewGauge(name, help, keys...)
}
