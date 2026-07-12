package manager

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mesh"
)

// fakePeersRunner fakes `easytier-cli -o json peer` with one live friend row
// (plus the self + IP-less rendezvous rows the wrapper must skip).
func fakePeersRunner(friendIP string) mesh.Runner {
	return func(bin string, args ...string) ([]byte, error) {
		sub := args[len(args)-1]
		switch sub {
		case "peer":
			return []byte(fmt.Sprintf(`[
				{"ipv4":"10.126.126.1","cidr":"10.126.126.1/24","hostname":"alpha","cost":"Local","lat_ms":"-","nat_type":"","id":"1","version":"2.6.4"},
				{"ipv4":%q,"cidr":"","hostname":"beta","cost":"p2p","lat_ms":"12.3","nat_type":"PortRestricted","id":"2","version":"2.6.4"},
				{"ipv4":"","cidr":"","hostname":"PublicServer","cost":"p2p","lat_ms":"50","nat_type":"","id":"3","version":"2.6.4"}
			]`, friendIP)), nil
		case "node":
			return []byte(`{"ipv4_addr":"10.126.126.1/24","peer_id":1,"hostname":"alpha","listeners":[],"version":"2.6.4"}`), nil
		}
		return nil, fmt.Errorf("unexpected sub %q", sub)
	}
}

// meshSyncPair returns a synced (manager, remote-info httptest server) pair:
// the manager is mesh-active as "alpha", the server answers /mesh/v1/info as
// "beta" using the SAME group PSK.
func meshSyncPair(t *testing.T) (Manager, *httptest.Server, config.Mesh) {
	t.Helper()
	m := meshTestManager(t)
	if _, err := m.MeshInit("alpha"); err != nil {
		t.Fatal(err)
	}
	c, err := m.Load()
	if err != nil {
		t.Fatal(err)
	}

	// Remote "beta": reuse the real handler wired to a beta-flavoured config.
	remote := meshTestManager(t)
	rc, _ := remote.Load()
	rc.Mesh = c.Mesh
	rc.Mesh.NodeName = "beta"
	rc.Mesh.HWID = "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb"
	if err := config.Save(remote.ConfigPath, rc); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(remote.MeshInfoHandler())
	t.Cleanup(srv.Close)
	return m, srv, c.Mesh
}

func TestMeshSyncDiscoversAndPersistsPeer(t *testing.T) {
	m, srv, _ := meshSyncPair(t)
	m.meshRunner = fakePeersRunner("10.126.126.2")
	m.meshProbeBase = func(ip string, port int) string { return srv.URL }

	rep, err := m.MeshSync()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", rep.Errors)
	}
	if rep.Probed != 1 || rep.Added != 1 || !rep.Applied {
		t.Fatalf("unexpected report: %+v", rep)
	}
	c, _ := m.Load()
	if len(c.MeshPeers) != 1 {
		t.Fatalf("peer not persisted: %+v", c.MeshPeers)
	}
	p := c.MeshPeers[0]
	if p.Name != "beta" || p.OverlayIP != "10.126.126.2" || !p.Enabled || !p.ExitOffered {
		t.Fatalf("peer material wrong: %+v", p)
	}
	// The GC clock: a day-granular stamp lands in UCI (one flash write per
	// day at most); fine-grained liveness stays in the runtime file.
	if p.LastSeen != time.Now().UTC().Format(meshDay) {
		t.Fatalf("day stamp missing/wrong in UCI: %+v", p)
	}
	b, err := os.ReadFile(meshStatusPath(c))
	if err != nil {
		t.Fatal(err)
	}
	var st meshRuntimeStatus
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.Peers["beta"].LastSeen == "" {
		t.Fatalf("runtime status missing beta: %+v", st)
	}

	// Second sync: nothing material changed → no apply.
	rep, err = m.MeshSync()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added != 0 || rep.Updated != 0 || rep.Applied {
		t.Fatalf("idempotent sync dirtied config: %+v", rep)
	}
}

func TestMeshSyncSoftContinuesOnDeadPeer(t *testing.T) {
	m, _, _ := meshSyncPair(t)
	m.meshRunner = fakePeersRunner("10.126.126.9")
	// Probe points at a dead port.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	m.meshProbeBase = func(ip string, port int) string { return dead.URL }

	rep, err := m.MeshSync()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) != 1 || rep.Added != 0 {
		t.Fatalf("expected one soft error: %+v", rep)
	}
}

func TestMeshSyncKeepsUnreachablePersistedPeers(t *testing.T) {
	m, srv, _ := meshSyncPair(t)
	// Pre-persist gamma, currently absent from the overlay.
	c, _ := m.Load()
	c.MeshPeers = []config.MeshPeer{{HWID: "purewrt-cccccccccccccccccccccccc", Name: "gamma", Enabled: true, OverlayIP: "10.126.126.7", ListenPort: 7897, ExitOffered: true}}
	if err := config.Save(m.ConfigPath, c); err != nil {
		t.Fatal(err)
	}
	m.meshRunner = fakePeersRunner("10.126.126.2")
	m.meshProbeBase = func(ip string, port int) string { return srv.URL }
	if _, err := m.MeshSync(); err != nil {
		t.Fatal(err)
	}
	c, _ = m.Load()
	names := map[string]bool{}
	for _, p := range c.MeshPeers {
		names[p.Name] = true
	}
	if !names["gamma"] || !names["beta"] {
		t.Fatalf("unreachable persisted peer pruned: %+v", c.MeshPeers)
	}
}

func TestMeshInfoHandlerAuth(t *testing.T) {
	m := meshTestManager(t)
	if _, err := m.MeshInit("alpha"); err != nil {
		t.Fatal(err)
	}
	c, _ := m.Load()
	psk, _ := hex.DecodeString(c.Mesh.PSK)
	key := mesh.DeriveAPIKey(psk)
	srv := httptest.NewServer(m.MeshInfoHandler())
	defer srv.Close()

	get := func(ts int64, nonce, mac string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/mesh/v1/info", nil)
		req.Header.Set(mesh.HeaderTime, strconv.FormatInt(ts, 10))
		req.Header.Set(mesh.HeaderNonce, nonce)
		req.Header.Set(mesh.HeaderMAC, mac)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	// No auth → 401.
	if resp := get(0, "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d", resp.StatusCode)
	}
	// Valid signature → 200 + signed body.
	ts := time.Now().Unix()
	mac := mesh.SignRequest(key, ts, "nonce-1", http.MethodGet, "/mesh/v1/info")
	resp := get(ts, "nonce-1", mac)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := mesh.VerifyResponse(key, ts, "nonce-1", body, resp.Header.Get(mesh.HeaderMAC)); err != nil {
		t.Fatalf("response signature invalid: %v", err)
	}
	var info MeshInfo
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatal(err)
	}
	if info.NodeName != "alpha" || !info.ExitOffered || info.ListenPort != 7897 {
		t.Fatalf("unexpected info: %+v", info)
	}
	// Replay of the same nonce → 401.
	if resp := get(ts, "nonce-1", mac); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed nonce got %d", resp.StatusCode)
	}
	// Stale timestamp → 401.
	old := time.Now().Add(-10 * time.Minute).Unix()
	oldMac := mesh.SignRequest(key, old, "nonce-2", http.MethodGet, "/mesh/v1/info")
	if resp := get(old, "nonce-2", oldMac); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale timestamp got %d", resp.StatusCode)
	}
}

func TestMeshPeerGC(t *testing.T) {
	m, srv, _ := meshSyncPair(t)
	m.meshRunner = fakePeersRunner("10.126.126.2")
	m.meshProbeBase = func(ip string, port int) string { return srv.URL }

	old := time.Now().UTC().AddDate(0, 0, -40).Format(meshDay)
	fresh := time.Now().UTC().AddDate(0, 0, -3).Format(meshDay)
	c, _ := m.Load()
	c.MeshPeers = []config.MeshPeer{
		// Absent + stamped 40d ago → GC'd (default TTL 30d).
		{HWID: "purewrt-cccccccccccccccccccccccc", Name: "gamma", Enabled: true, OverlayIP: "10.126.126.7", ExitOffered: true, LastSeen: old},
		// Absent + stamped 3d ago → kept.
		{HWID: "purewrt-dddddddddddddddddddddddd", Name: "delta", Enabled: true, OverlayIP: "10.126.126.8", ExitOffered: true, LastSeen: fresh},
		// Absent + never stamped (pre-GC entry) → grace-stamped, kept.
		{HWID: "purewrt-eeeeeeeeeeeeeeeeeeeeeeee", Name: "eps", Enabled: true, OverlayIP: "10.126.126.9", ExitOffered: true},
	}
	if err := config.Save(m.ConfigPath, c); err != nil {
		t.Fatal(err)
	}
	rep, err := m.MeshSync()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Removed != 1 {
		t.Fatalf("expected 1 GC'd peer: %+v", rep)
	}
	c, _ = m.Load()
	byName := map[string]config.MeshPeer{}
	for _, p := range c.MeshPeers {
		byName[p.Name] = p
	}
	if _, ok := byName["gamma"]; ok {
		t.Fatal("expired peer survived GC")
	}
	if _, ok := byName["delta"]; !ok {
		t.Fatal("fresh-stamped peer was GC'd")
	}
	today := time.Now().UTC().Format(meshDay)
	if p := byName["eps"]; p.LastSeen != today {
		t.Fatalf("unstamped peer not grace-stamped: %+v", p)
	}
	// beta (live) also stamped today.
	if p := byName["beta"]; p.LastSeen != today {
		t.Fatalf("live peer not stamped: %+v", p)
	}
}

func TestMeshPeerGCDisabled(t *testing.T) {
	m, srv, _ := meshSyncPair(t)
	m.meshRunner = fakePeersRunner("10.126.126.2")
	m.meshProbeBase = func(ip string, port int) string { return srv.URL }

	old := time.Now().UTC().AddDate(0, 0, -400).Format(meshDay)
	c, _ := m.Load()
	c.Mesh.PeerTTLDays = 0 // GC off
	c.MeshPeers = []config.MeshPeer{
		{HWID: "purewrt-cccccccccccccccccccccccc", Name: "gamma", Enabled: true, OverlayIP: "10.126.126.7", ExitOffered: true, LastSeen: old},
	}
	if err := config.Save(m.ConfigPath, c); err != nil {
		t.Fatal(err)
	}
	rep, err := m.MeshSync()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Removed != 0 {
		t.Fatalf("GC ran with TTL 0: %+v", rep)
	}
	c, _ = m.Load()
	found := false
	for _, p := range c.MeshPeers {
		if p.Name == "gamma" {
			found = true
			// Absent peer's old stamp must NOT be refreshed.
			if p.LastSeen != old {
				t.Fatalf("absent peer stamp rewritten: %+v", p)
			}
		}
	}
	if !found {
		t.Fatal("peer dropped despite TTL 0")
	}
}

func TestMeshPeerGCKeepsOverlayAliveProbelessPeer(t *testing.T) {
	// A peer alive on the overlay whose purewrt API is down must be stamped
	// present, never aged toward GC.
	m, _, _ := meshSyncPair(t)
	m.meshRunner = fakePeersRunner("10.126.126.7")
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	m.meshProbeBase = func(ip string, port int) string { return dead.URL }

	old := time.Now().UTC().AddDate(0, 0, -40).Format(meshDay)
	c, _ := m.Load()
	c.MeshPeers = []config.MeshPeer{
		{HWID: "purewrt-cccccccccccccccccccccccc", Name: "gamma", Enabled: true, OverlayIP: "10.126.126.7", ExitOffered: true, LastSeen: old},
	}
	if err := config.Save(m.ConfigPath, c); err != nil {
		t.Fatal(err)
	}
	rep, err := m.MeshSync()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Removed != 0 {
		t.Fatalf("overlay-alive peer GC'd: %+v", rep)
	}
	c, _ = m.Load()
	if len(c.MeshPeers) != 1 || c.MeshPeers[0].LastSeen != time.Now().UTC().Format(meshDay) {
		t.Fatalf("overlay-alive peer not kept+stamped: %+v", c.MeshPeers)
	}
}
