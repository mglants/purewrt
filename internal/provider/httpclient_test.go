package provider

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewClientUsesResolverIPs(t *testing.T) {
	t.Parallel()
	// Start a TLS-less test server bound to 127.0.0.1.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(u.Host)

	// A DoHResolver instance with no endpoints is fine; we'll bypass its
	// network path by passing an IP literal in the URL itself when needed.
	// For exercising the dial-by-resolver code path we instead build a
	// resolver that points at a fake DoH server which always returns
	// 127.0.0.1 — that lets the client transparently dial the loopback
	// httptest server even though the URL host is a synthetic name.
	dohSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reply with an answer for any query type, pointing at 127.0.0.1.
		// We reuse the same wire format as TestDoHResolverLookupHost.
		body := make([]byte, 1024)
		n, _ := r.Body.Read(body)
		body = body[:n]
		if len(body) < 12 {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		// Build a minimal A-answer response.
		resp := []byte{
			0, 0, // txid
			0x81, 0x80, // flags
			0, 1, // qdcount
			0, 1, // ancount
			0, 0, 0, 0,
		}
		resp = append(resp, body[12:]...)
		resp = append(resp,
			0xC0, 0x0C,
			0, 1, 0, 1,
			0, 0, 0, 60,
			0, 4,
			127, 0, 0, 1,
		)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	defer dohSrv.Close()

	resolver := NewDoHResolver([]string{dohSrv.URL}, 3*time.Second)
	client, err := NewClient(ClientOptions{
		Timeout:   5 * time.Second,
		Resolver:  resolver,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Hostname that the system DNS cannot resolve; only our DoH stub can.
	req, _ := http.NewRequest(http.MethodGet, "http://test-host.invalid:"+port+"/", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewClientInvalidProxyURL(t *testing.T) {
	t.Parallel()
	_, err := NewClient(ClientOptions{ProxyURL: "://bad"})
	if err == nil || !strings.Contains(err.Error(), "invalid update proxy url") {
		t.Fatalf("expected invalid update proxy url error, got: %v", err)
	}
}

func TestClientFromBootstrapDisabledFallsBackToSystem(t *testing.T) {
	t.Parallel()
	// When DoH is disabled the client should still build and reach a
	// loopback httptest server via the stdlib resolver.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client, err := ClientFromBootstrap(BootstrapConfig{DoHEnabled: false}, "", "")
	if err != nil {
		t.Fatalf("ClientFromBootstrap: %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

