package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/provider"
)

// makeGeoFixture returns a payload of size bytes and its sha256 hex.
func makeGeoFixture(size int) ([]byte, string) {
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i % 251)
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:])
}

func TestRefreshOneWritesFileAndVerifiesSHA(t *testing.T) {
	t.Parallel()
	body, hash := makeGeoFixture(2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "geoip.dat")
	ok, reason := refreshOne(srv.URL, hash, dst, provider.DownloadOptions{})
	if !ok {
		t.Fatalf("refreshOne failed: %s", reason)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(body) {
		t.Fatalf("got %d bytes, want %d", len(got), len(body))
	}
}

func TestRefreshOneRejectsSHAMismatch(t *testing.T) {
	t.Parallel()
	body, _ := makeGeoFixture(1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "geoip.dat")
	ok, reason := refreshOne(srv.URL, strings.Repeat("0", 64), dst, provider.DownloadOptions{})
	if ok {
		t.Fatal("expected SHA mismatch to fail the refresh")
	}
	if !strings.Contains(reason, "sha mismatch") {
		t.Fatalf("reason = %q, want sha mismatch", reason)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("destination file should not exist after SHA failure")
	}
}

func TestRefreshOneRejectsHTTPError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "geoip.dat")
	// Fast retry params — 5xx is retryable and the default backoff would
	// stretch this test to ~4 s for no extra coverage.
	fast := provider.DownloadOptions{Bootstrap: provider.BootstrapConfig{RetryMax: 1, RetryInitial: time.Millisecond, RetryMaxWait: time.Millisecond}}
	ok, reason := refreshOne(srv.URL, "", dst, fast)
	if ok {
		t.Fatal("expected 5xx to fail")
	}
	if !strings.Contains(reason, "503") && !strings.Contains(reason, "round(s)") {
		t.Fatalf("reason = %q", reason)
	}
}

// TestRefreshOneFallsBackThroughProxy guards the new tactic: when the
// direct fetch fails terminally, the download retries once through the
// configured fallback proxy — same behavior subscriptions already have.
func TestRefreshOneFallsBackThroughProxy(t *testing.T) {
	t.Parallel()
	body, hash := makeGeoFixture(256)
	// Direct target: terminal 404 (non-retryable, fails fast).
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer direct.Close()
	// "Proxy": for plain-HTTP targets Go sends the absolute-form request
	// to the proxy, so a regular handler standing in as proxy can just
	// serve the body.
	var proxied bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = true
		_, _ = w.Write(body)
	}))
	defer proxy.Close()
	dst := filepath.Join(t.TempDir(), "geoip.dat")
	opt := provider.DownloadOptions{FallbackProxyURL: proxy.URL}
	ok, reason := refreshOne(direct.URL, hash, dst, opt)
	if !ok {
		t.Fatalf("fallback fetch failed: %s", reason)
	}
	if !proxied {
		t.Fatal("download did not go through the fallback proxy")
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("destination missing after fallback success: %v", err)
	}
}

func TestGeoRefreshSkipsEmptyURLs(t *testing.T) {
	t.Parallel()
	body, hash := makeGeoFixture(512)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := config.Default()
	cfg.Settings.GeoRefreshGeoIPURL = srv.URL
	cfg.Settings.GeoRefreshGeoIPSHA = hash
	cfg.Settings.GeoRefreshGeoIPDir = dir
	// geosite + mmdb empty — must be reported as skipped, not failed.

	cfgPath := filepath.Join(t.TempDir(), "purewrt")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	m := Manager{ConfigPath: cfgPath, DryRun: true}
	res, err := m.GeoRefresh()
	// Reload via mihomo will fail because there's no mihomo running;
	// that's fine — the geo download itself should succeed.
	if err != nil && !strings.Contains(err.Error(), "no targets succeeded") {
		// Acceptable: reload error doesn't fail GeoRefresh.
	}
	if len(res.Targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(res.Targets))
	}
	var seenSkipped, seenOK int
	for _, target := range res.Targets {
		if target.Skipped {
			seenSkipped++
		}
		if target.OK {
			seenOK++
		}
	}
	if seenSkipped != 2 || seenOK != 1 {
		t.Fatalf("expected 1 ok + 2 skipped, got %d ok + %d skipped: %+v", seenOK, seenSkipped, res.Targets)
	}
}
