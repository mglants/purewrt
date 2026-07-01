package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestThroughputProbeDownloadCountsBytes(t *testing.T) {
	const n = 256 * 1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, n))
	}))
	defer srv.Close()

	res := ThroughputProbe(context.Background(), srv.Client(), srv.URL, false, 0)
	if !res.OK {
		t.Fatalf("expected OK, got %+v", res)
	}
	if res.Bytes != n {
		t.Fatalf("expected %d bytes, got %d", n, res.Bytes)
	}
	if res.Kbps <= 0 {
		t.Fatalf("expected positive throughput, got %v", res.Kbps)
	}
}

func TestThroughputProbeUploadCountsSentBytes(t *testing.T) {
	const n = 128 * 1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// drain so the client actually sends the whole body
		buf := make([]byte, 32*1024)
		for {
			if _, err := r.Body.Read(buf); err != nil {
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := ThroughputProbe(context.Background(), srv.Client(), srv.URL, true, n)
	if !res.OK {
		t.Fatalf("expected OK upload, got %+v", res)
	}
	if res.Bytes != n {
		t.Fatalf("expected %d sent, got %d", n, res.Bytes)
	}
}

func TestThroughputProbeFailsOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(2 * time.Second) // stall past the ctx deadline
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	res := ThroughputProbe(ctx, srv.Client(), srv.URL, false, 0)
	if res.OK {
		t.Fatalf("expected failure on timeout, got OK %+v", res)
	}
	if res.Error == "" {
		t.Fatalf("expected an error string on timeout, got %+v", res)
	}
	if res.Seconds <= 0 {
		t.Fatalf("expected elapsed time recorded, got %v", res.Seconds)
	}
}

func TestThroughputProbeBadStatusNotOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	res := ThroughputProbe(context.Background(), srv.Client(), srv.URL, false, 0)
	if res.OK {
		t.Fatalf("expected !OK for 502, got %+v", res)
	}
	if res.HTTPStatus != http.StatusBadGateway {
		t.Fatalf("expected status 502 recorded, got %d", res.HTTPStatus)
	}
}
