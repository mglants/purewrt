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

func TestHandlerServesContentType(t *testing.T) {
	// Use Default for the handler smoke-test.
	defer resetDefault()
	NewCounter("purewrt_test_total", "X").Inc()
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
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
	c := &Counter{name: name, help: help, labelKey: append([]string(nil), keys...), samples: map[string]*uint64{}}
	r.mu.Lock()
	r.counters[name] = c
	r.mu.Unlock()
	return c
}

func (r *testRegistry) newGauge(name, help string) *Gauge {
	g := &Gauge{name: name, help: help}
	r.mu.Lock()
	r.gauges[name] = g
	r.mu.Unlock()
	return g
}

func resetDefault() {
	Default = NewRegistry()
}
