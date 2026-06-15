package provider

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadRetriesOnTransientError(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := DownloadWithOptions(srv.URL, DownloadOptions{
		Bootstrap: BootstrapConfig{RetryMax: 5, RetryInitial: 5 * time.Millisecond, RetryMaxWait: 50 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if string(res.Data) != "ok" || hits.Load() != 3 {
		t.Fatalf("data=%q hits=%d", res.Data, hits.Load())
	}
}

func TestDownloadFailsAfterExhaustingRetries(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := DownloadWithOptions(srv.URL, DownloadOptions{
		Bootstrap: BootstrapConfig{RetryMax: 2, RetryInitial: 1 * time.Millisecond, RetryMaxWait: 5 * time.Millisecond},
	})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("hits=%d, want 3 (1 initial + 2 retries)", got)
	}
}

func TestDownload4xxNotRetried(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := DownloadWithOptions(srv.URL, DownloadOptions{
		Bootstrap: BootstrapConfig{RetryMax: 5, RetryInitial: 1 * time.Millisecond, RetryMaxWait: 5 * time.Millisecond},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits=%d, want 1 (4xx is not retried)", got)
	}
}

func TestDownload304ReturnsNotModified(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"abc"` {
			w.Header().Set("ETag", `"abc"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc"`)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := DownloadWithOptions(srv.URL, DownloadOptions{
		PriorETag: `"abc"`,
		Bootstrap: BootstrapConfig{RetryMax: 1, RetryInitial: 1 * time.Millisecond, RetryMaxWait: 5 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if !res.NotModified {
		t.Fatalf("expected NotModified=true, got %+v", res)
	}
	if res.ETag != `"abc"` {
		t.Fatalf("ETag = %q", res.ETag)
	}
}

func TestDownloadFailsOverToMirror(t *testing.T) {
	t.Parallel()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("from-mirror"))
	}))
	defer mirror.Close()

	res, err := DownloadWithOptions(primary.URL, DownloadOptions{
		Mirrors:   []string{mirror.URL},
		Bootstrap: BootstrapConfig{RetryMax: 1, RetryInitial: 1 * time.Millisecond, RetryMaxWait: 5 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if string(res.Data) != "from-mirror" {
		t.Fatalf("data = %q, want from-mirror", res.Data)
	}
}

func TestDownloadFallbackProxyAfterDirectFails(t *testing.T) {
	t.Parallel()
	// The "real" origin always 502s when reached directly.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Through-Proxy") == "1" {
			_, _ = w.Write([]byte("via-proxy"))
			return
		}
		http.Error(w, "blocked", http.StatusBadGateway)
	}))
	defer origin.Close()

	// A trivial HTTP CONNECT-free forward proxy that tags requests so the
	// origin can tell direct from proxied. Acts only as a stub; the real
	// scenario is identical — the proxy is mihomo's mixed-port.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// http.ProxyURL on a plaintext request causes the client to send a
		// full absolute-URI in the request line; we forward by stripping
		// the absolute form and re-issuing.
		out, _ := http.NewRequest(r.Method, r.URL.String(), r.Body)
		out.Header = r.Header.Clone()
		out.Header.Set("X-Through-Proxy", "1")
		resp, err := http.DefaultClient.Do(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer proxy.Close()

	res, err := DownloadWithOptions(origin.URL, DownloadOptions{
		FallbackProxyURL: proxy.URL,
		Bootstrap:        BootstrapConfig{RetryMax: 1, RetryInitial: 1 * time.Millisecond, RetryMaxWait: 5 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if string(res.Data) != "via-proxy" {
		t.Fatalf("data = %q, want via-proxy", res.Data)
	}
}

func TestDownloadReturnsETagAndLastModified(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2020 07:28:00 GMT")
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	res, err := DownloadWithOptions(srv.URL, DownloadOptions{})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if res.ETag != `"v1"` || res.LastModified == "" {
		t.Fatalf("missing conditional headers in result: %+v", res)
	}
}
