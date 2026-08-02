package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/manager"
	"github.com/purewrt/purewrt/internal/metrics"
)

func TestNewHandlerStatus(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rr := httptest.NewRecorder()
	newHandler(manager.Manager{}).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "status") {
		t.Fatalf("body = %s", rr.Body.String())
	}
}

func TestMetricsComposesPersistentAndLiveFamilies(t *testing.T) {
	metrics.Default.ResetObservations()
	defer metrics.Default.ResetObservations()

	dir := t.TempDir()
	c := config.Default()
	c.Settings.MetricsEnabled = true
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.ProxyGuardEnabled = false
	configPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(configPath, c); err != nil {
		t.Fatal(err)
	}

	r := metrics.NewRegistry()
	r.NewCounter("purewrt_apply_total", "Apply attempts by outcome", "result").WithLabelValues("ok")
	state, _, err := metrics.MergePersistent(nil, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.Settings.RuntimeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.MetricsStatePath(c), state, 0600); err != nil {
		t.Fatal(err)
	}
	// API-local latest-state observations must be added for rendering but must
	// not be persisted or reset by a scrape.
	metrics.ApplyLastRunSuccess.Set(0)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler := newHandler(manager.Manager{ConfigPath: configPath})
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	out := rr.Body.String()
	for _, want := range []string{
		`purewrt_apply_last_run_success 0`,
		"purewrt_metrics_persistent_state_valid 1",
		"purewrt_proxy_guard_enabled 0",
		"purewrt_zapret_strategies_active 0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "purewrt_apply_total") || strings.Contains(out, "# TYPE purewrt_apply_total counter") {
		t.Fatalf("removed counter survived persisted-state filtering:\n%s", out)
	}
	if strings.Contains(out, " counter\n") {
		t.Fatalf("metrics endpoint exported a counter family:\n%s", out)
	}
	if count := strings.Count(out, "# TYPE purewrt_proxy_guard_enabled gauge"); count != 1 {
		t.Fatalf("proxy guard family rendered %d times:\n%s", count, out)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rr.Body.String(), `purewrt_apply_last_run_success 0`) {
		t.Fatalf("scraping lost the API-local latest-state gauge:\n%s", rr.Body.String())
	}
	if err := os.WriteFile(manager.MetricsStatePath(c), []byte(`{"version":1,"histograms":{"broken":{"buckets":[1],"samples":{"[]":{"counts":[]}}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rr.Body.String(), "purewrt_metrics_persistent_state_valid 0") {
		t.Fatalf("invalid persistent state was not surfaced:\n%s", rr.Body.String())
	}
}

// TestLiveSubscribeFailureReturns502 guards the /live error contract:
// when mihomo is unreachable the response must carry HTTP 502 (so
// programmatic clients can detect the failure from the status line) plus
// the SSE error event in the body for human debugging.
func TestLiveSubscribeFailureReturns502(t *testing.T) {
	t.Parallel()

	c := config.Default()
	c.Settings.MetricsEnabled = true
	// Closed port → SubscribeTraffic fails immediately with ECONNREFUSED.
	c.Settings.ExternalController = "127.0.0.1:1"
	cfgPath := filepath.Join(t.TempDir(), "purewrt.conf")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/live?stream=traffic", nil)
	rr := httptest.NewRecorder()
	newHandler(manager.Manager{ConfigPath: cfgPath}).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status code = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "subscribe-traffic") {
		t.Fatalf("body should carry the SSE error event, got %s", rr.Body.String())
	}
}

func TestNewHandlerAnalyzeError(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/analyze", nil)
	rr := httptest.NewRecorder()
	newHandler(manager.Manager{}).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d body=%s", rr.Code, rr.Body.String())
	}
}
