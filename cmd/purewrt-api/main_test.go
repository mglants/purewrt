package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/manager"
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
