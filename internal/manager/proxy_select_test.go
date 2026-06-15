package manager

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// fakeController spins an httptest server emulating mihomo's
// external-controller endpoints used by the proxy-select feature.
func fakeController(t *testing.T, deleted *[]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/proxies", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{
			"Common": map[string]any{"name": "Common", "type": "Selector", "now": "node-a", "all": []string{"node-a", "node-b"}},
			"Auto":   map[string]any{"name": "Auto", "type": "URLTest", "now": "node-a", "all": []string{"node-a"}},
			// GLOBAL is mihomo's built-in, inert under mode:rule — must be
			// filtered out of the switcher.
			"GLOBAL": map[string]any{"name": "GLOBAL", "type": "Selector", "now": "DIRECT", "all": []string{"Common", "Auto", "node-a", "node-b", "DIRECT"}},
			"node-a": map[string]any{"name": "node-a", "type": "vless", "alive": true, "delay": 42},
			"node-b": map[string]any{"name": "node-b", "type": "vless", "alive": false, "delay": 0},
			"DIRECT": map[string]any{"name": "DIRECT", "type": "Direct"},
		}})
	})
	mux.HandleFunc("/proxies/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"connections": []map[string]any{
			{"id": "c1", "chains": []string{"node-a", "Common"}},
			{"id": "c2", "chains": []string{"node-x", "Other"}},
			{"id": "c3", "chains": []string{"node-a", "Common"}},
		}})
	})
	mux.HandleFunc("/connections/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			*deleted = append(*deleted, strings.TrimPrefix(r.URL.Path, "/connections/"))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/group/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]int{"node-a": 55})
	})
	return httptest.NewServer(mux)
}

func proxyTestManager(t *testing.T, controllerURL string) Manager {
	t.Helper()
	dir := t.TempDir()
	c := config.Default()
	c.Settings.ExternalController = strings.TrimPrefix(controllerURL, "http://")
	c.Settings.Secret = ""
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	return Manager{ConfigPath: cfgPath}
}

func TestProxyGroupsFiltersAndEnriches(t *testing.T) {
	var deleted []string
	srv := fakeController(t, &deleted)
	defer srv.Close()
	m := proxyTestManager(t, srv.URL)
	groups, err := m.ProxyGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (Common, Auto — GLOBAL filtered), got %d: %+v", len(groups), groups)
	}
	for _, g := range groups {
		if g.Name == "GLOBAL" {
			t.Fatal("GLOBAL must be filtered out (inert under mode:rule)")
		}
	}
	common := groups[1] // sorted: Auto, Common
	if common.Name != "Common" || common.Now != "node-a" || len(common.Members) != 2 {
		t.Fatalf("common group: %+v", common)
	}
	if !common.Members[0].Alive || common.Members[0].Delay != 42 {
		t.Fatalf("member enrichment lost: %+v", common.Members[0])
	}
	// Common is the default sections' ProxyGroup → owning section resolved.
	if common.Section == "" {
		t.Fatalf("expected owning section for Common, got %+v", common)
	}
}

func TestProxySelectDrainsOnlyGroupConnections(t *testing.T) {
	var deleted []string
	srv := fakeController(t, &deleted)
	defer srv.Close()
	m := proxyTestManager(t, srv.URL)
	res, err := m.ProxySelect("Common", "node-b", true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Drained != 2 {
		t.Fatalf("drained = %d, want 2 (only Common-chained connections)", res.Drained)
	}
	if len(deleted) != 2 || deleted[0] != "c1" || deleted[1] != "c3" {
		t.Fatalf("deleted = %v", deleted)
	}
}

// TestProxySelectRejectsNonSelector guards the "no fake switches"
// contract: url-test/fallback/load-balance groups pick nodes
// automatically, so a manual selection must be refused up front instead
// of pretending to work (and draining live connections for nothing).
func TestProxySelectRejectsNonSelector(t *testing.T) {
	var deleted []string
	srv := fakeController(t, &deleted)
	defer srv.Close()
	m := proxyTestManager(t, srv.URL)
	_, err := m.ProxySelect("Auto", "node-a", true)
	if err == nil || !strings.Contains(err.Error(), "Selector") {
		t.Fatalf("expected non-Selector rejection, got %v", err)
	}
	if len(deleted) != 0 {
		t.Fatalf("rejected select must not drain connections, deleted=%v", deleted)
	}
}

func TestProxySelectNoDrain(t *testing.T) {
	var deleted []string
	srv := fakeController(t, &deleted)
	defer srv.Close()
	m := proxyTestManager(t, srv.URL)
	res, err := m.ProxySelect("Common", "node-b", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Drained != 0 || len(deleted) != 0 {
		t.Fatalf("no-drain still deleted: %+v %v", res, deleted)
	}
}

func TestProxyDelayTest(t *testing.T) {
	var deleted []string
	srv := fakeController(t, &deleted)
	defer srv.Close()
	m := proxyTestManager(t, srv.URL)
	delays, err := m.ProxyDelayTest("Common")
	if err != nil {
		t.Fatal(err)
	}
	if delays["node-a"] != 55 {
		t.Fatalf("delays = %v", delays)
	}
}
