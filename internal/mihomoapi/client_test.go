package mihomoapi

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientGet(t *testing.T) {
	t.Parallel()

	srv := mihomoTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/proxies" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("Authorization = %q", got)
		}
		_, _ = w.Write([]byte(`{"proxies":{"GLOBAL":{"name":"GLOBAL","now":"Node"}}}`))
	}))
	defer srv.Close()

	proxies, err := (Client{Base: listenerHost(t, srv), Secret: "secret"}).Proxies()
	if err != nil {
		t.Fatalf("Proxies: %v", err)
	}
	if proxies["GLOBAL"].Now != "Node" {
		t.Fatalf("proxies = %+v", proxies)
	}
}

func TestClientGetNon2xx(t *testing.T) {
	t.Parallel()

	srv := mihomoTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusBadGateway)
	}))
	defer srv.Close()

	var out map[string]any
	err := (Client{Base: listenerHost(t, srv)}).Get("/x", &out)
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("err = %v, want 502", err)
	}
}

func TestClientPutAndHelpers(t *testing.T) {
	t.Parallel()

	seenSelect := false
	seenHealth := false
	srv := mihomoTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/proxies/GLOBAL":
			seenSelect = true
			if r.Method != http.MethodPut {
				t.Fatalf("method = %s", r.Method)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["name"] != "Node" || r.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("body=%v content-type=%q", body, r.Header.Get("Content-Type"))
			}
		case "/providers/proxies/p1/healthcheck":
			seenHealth = true
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := Client{Base: listenerHost(t, srv)}
	if err := c.SelectProxy("GLOBAL", "Node"); err != nil {
		t.Fatalf("SelectProxy: %v", err)
	}
	if err := c.HealthCheckProvider("p1"); err != nil {
		t.Fatalf("HealthCheckProvider: %v", err)
	}
	if !seenSelect || !seenHealth {
		t.Fatalf("seenSelect=%v seenHealth=%v", seenSelect, seenHealth)
	}
}

func mihomoTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = ln
	srv.Start()
	return srv
}

func listenerHost(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return srv.Listener.Addr().String()
}
