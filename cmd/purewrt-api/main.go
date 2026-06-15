package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/purewrt/purewrt/internal/manager"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/mihomoapi"
)

func main() {
	m := manager.Manager{}
	handler := newHandler(m)
	// api_listen UCI list selects bind addresses; empty = all interfaces.
	// OpenWrt's default firewall still blocks WAN input, so 0.0.0.0 means
	// LAN exposure — users who want loopback-only set 127.0.0.1:8787.
	addrs := []string{"0.0.0.0:8787"}
	if c, err := m.Load(); err == nil && len(c.Settings.APIListen) > 0 {
		addrs = c.Settings.APIListen
	}
	errs := make(chan error, len(addrs))
	for _, addr := range addrs {
		go func(a string) {
			fmt.Fprintln(os.Stderr, "purewrt-api: listening on", a)
			errs <- http.ListenAndServe(a, handler)
		}(addr)
	}
	// Any listener failing (port taken, bad address) takes the daemon
	// down — procd's respawn handles retries, and a partially-bound
	// daemon would silently hide the misconfiguration otherwise.
	fatal(<-errs)
}

func newHandler(m manager.Manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]string{"status": m.Status()}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/analyze", func(w http.ResponseWriter, r *http.Request) {
		a, err := m.Analyze(r.URL.Query().Get("url"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := json.NewEncoder(w).Encode(a); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	// /metrics — Prometheus text exposition. Gated by Settings.MetricsEnabled
	// because exposing operational metrics without authorisation can leak
	// subscription names + apply cadence to anyone who can hit 127.0.0.1.
	// Defaults to off; user must opt in via UCI before LuCI scrape works.
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		c, _ := m.Load()
		if !c.Settings.MetricsEnabled {
			http.Error(w, "metrics disabled (set option metrics_enabled '1' in /etc/config/purewrt)", http.StatusForbidden)
			return
		}
		// Apply/update observations live in the short-lived `purewrt` CLI
		// process, which dumps its registry to metrics.prom on every
		// apply/update. Prefer that snapshot — this daemon's own registry
		// only ever sees the handful of in-process manager calls. (Serving
		// both would emit duplicate TYPE lines, which Prometheus rejects.)
		if data, err := os.ReadFile(filepath.Join(c.RuntimeDir(), "metrics.prom")); err == nil && len(data) > 0 {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		metrics.Handler().ServeHTTP(w, r)
	})
	// /live — Server-Sent Events bridge over mihomo's /traffic and
	// /connections WebSockets. Query param ?stream=traffic|connections|both
	// (default "traffic") selects which channel(s) feed the stream.
	//
	// SSE was chosen over forwarding the WebSocket because browsers parse
	// SSE natively (EventSource API) and rpcd/LuCI's stack doesn't have a
	// WebSocket primitive. One connection per stream type — multiplexing
	// both onto one /live request emits "event: traffic\n" and
	// "event: connections\n" so the LuCI panel can demux.
	mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		serveLive(m, w, r)
	})
	return mux
}

// serveLive bridges mihomo's WebSocket streams to an SSE response. Runs
// until the client disconnects, ctx is cancelled, or mihomo drops us.
func serveLive(m manager.Manager, w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	c, _ := m.Load()
	if !c.Settings.MetricsEnabled {
		// SSE shares the metrics gate — same threat model (anyone on the
		// loopback can subscribe).
		http.Error(w, "live stream disabled (set option metrics_enabled '1' in /etc/config/purewrt)", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	streamQ := r.URL.Query().Get("stream")
	if streamQ == "" {
		streamQ = "traffic"
	}
	wantTraffic := streamQ == "traffic" || streamQ == "both"
	wantConns := streamQ == "connections" || streamQ == "both"

	cli := mihomoapi.Client{Base: c.Settings.ExternalController, Secret: c.Settings.Secret}
	ctx := r.Context()

	if wantTraffic {
		ch, _, err := cli.SubscribeTraffic(ctx)
		if err != nil {
			// Nothing written yet, so the status line is still ours to set;
			// 502 lets programmatic clients detect the failure without
			// parsing the SSE error event (kept for human debugging).
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", jsonString("subscribe-traffic: "+err.Error()))
			flusher.Flush()
			return
		}
		go func() {
			for s := range ch {
				b, err := json.Marshal(s)
				if err != nil {
					fmt.Fprintln(os.Stderr, "live: marshal traffic event:", err)
					continue
				}
				if _, err := fmt.Fprintf(w, "event: traffic\ndata: %s\n\n", b); err != nil {
					return
				}
				flusher.Flush()
			}
		}()
	}
	if wantConns {
		ch, _, err := cli.SubscribeConnections(ctx)
		if err != nil {
			// With stream=both the traffic goroutine may already be
			// writing, which commits the 200 status — only claim the
			// status line when traffic wasn't requested.
			if !wantTraffic {
				w.WriteHeader(http.StatusBadGateway)
			}
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", jsonString("subscribe-connections: "+err.Error()))
			flusher.Flush()
			return
		}
		go func() {
			for s := range ch {
				b, err := json.Marshal(s)
				if err != nil {
					fmt.Fprintln(os.Stderr, "live: marshal connections event:", err)
					continue
				}
				if _, err := fmt.Fprintf(w, "event: connections\ndata: %s\n\n", b); err != nil {
					return
				}
				flusher.Flush()
			}
		}()
	}
	// Block until the client disconnects; the goroutines exit on ctx cancel.
	<-ctx.Done()
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
