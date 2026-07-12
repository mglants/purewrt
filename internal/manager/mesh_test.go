package manager

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mesh"
)

// meshTestManager returns a DryRun manager over a temp config whose paths
// all live under the test dir, so the full init→save→apply pipeline runs
// without touching the real system. The optional hwid overrides the faked
// hardware id (default a0…) so two managers can be distinct devices.
func meshTestManager(t *testing.T, hwid ...string) Manager {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PUREWRT_UCI_DIR", filepath.Join(dir, "uci"))
	c := config.Default()
	c.Settings.Workdir = filepath.Join(dir, "workdir")
	c.Settings.GeneratedDir = filepath.Join(dir, "generated")
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.MihomoConfig = filepath.Join(dir, "generated", "mihomo.yaml")
	c.DNS.HijackLANDNS = false
	c.Mwan3.IntegratedRules = false
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	id := "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa"
	if len(hwid) > 0 {
		id = hwid[0]
	}
	return Manager{ConfigPath: cfgPath, DryRun: true, hwidReader: func() (string, error) { return id, nil }}
}

func TestMeshInitJoinRoundTrip(t *testing.T) {
	a := meshTestManager(t)
	res, err := a.MeshInit("alpha")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Code, "PWMESH1-") || !strings.HasPrefix(res.NetworkName, "pwmesh-") {
		t.Fatalf("unexpected init result: %+v", res)
	}
	ca, err := a.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !ca.MeshActive() || ca.Mesh.NodeName != "alpha" || !ca.Mesh.ExitEnabled {
		t.Fatalf("mesh not active after init: %+v", ca.Mesh)
	}
	if ca.Mesh.Code == "" || ca.Mesh.PSK == "" || ca.Mesh.CredSalt() == "" {
		t.Fatal("credentials not derivable after init")
	}
	// Second init must refuse.
	if _, err := a.MeshInit(""); err == nil {
		t.Fatal("second mesh-init did not refuse")
	}

	// A friend joins with the same code → identical group identity; its salt
	// derives from its own node name, so it differs per host.
	b := meshTestManager(t, "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb")
	jres, err := b.MeshJoin(res.Code, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if jres.NetworkName != res.NetworkName {
		t.Fatalf("join derived different network: %q vs %q", jres.NetworkName, res.NetworkName)
	}
	cb, err := b.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cb.Mesh.PSK != ca.Mesh.PSK || cb.Mesh.NetworkSecret != ca.Mesh.NetworkSecret {
		t.Fatal("join did not reproduce group secrets")
	}
	if cb.Mesh.CredSalt() == ca.Mesh.CredSalt() {
		t.Fatal("joiner must derive its OWN cred salt (name-scoped)")
	}
	if _, err := mesh.DecodeCode(jres.Code); err != nil {
		t.Fatalf("re-printed code does not decode: %v", err)
	}
}

func TestMeshCodeReprintsExactCode(t *testing.T) {
	m := meshTestManager(t)
	res, err := m.MeshInit("alpha")
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.MeshCode()
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != res.Code {
		t.Fatalf("mesh-code reprint differs:\n init: %s\ncode: %s", res.Code, got.Code)
	}
}

func TestMeshRotateKeepsNameKillsSecrets(t *testing.T) {
	m := meshTestManager(t)
	res, err := m.MeshInit("alpha")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := m.Load()
	rot, err := m.MeshRotate()
	if err != nil {
		t.Fatal(err)
	}
	if rot.NetworkName != res.NetworkName {
		t.Fatalf("rotate changed network name: %q -> %q", res.NetworkName, rot.NetworkName)
	}
	if rot.Code == res.Code {
		t.Fatal("rotate did not change the code")
	}
	after, _ := m.Load()
	if after.Mesh.PSK == before.Mesh.PSK || after.Mesh.NetworkSecret == before.Mesh.NetworkSecret || after.Mesh.CredSalt() == before.Mesh.CredSalt() {
		t.Fatal("rotate must mint new PSK and secret (and with them the derived salt)")
	}
}

func TestMeshLeaveAndPeerSet(t *testing.T) {
	m := meshTestManager(t)
	if _, err := m.MeshInit("alpha"); err != nil {
		t.Fatal(err)
	}
	// Persist a peer, then toggle it.
	c, _ := m.Load()
	c.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	if err := config.Save(m.ConfigPath, c); err != nil {
		t.Fatal(err)
	}
	if err := m.MeshPeerSet("purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", false); err != nil {
		t.Fatal(err)
	}
	c, _ = m.Load()
	if len(c.MeshPeers) != 1 || c.MeshPeers[0].Enabled {
		t.Fatalf("peer toggle lost: %+v", c.MeshPeers)
	}
	if err := m.MeshPeerSet("nosuch", true); err == nil {
		t.Fatal("unknown peer did not error")
	}

	if err := m.MeshLeave(); err != nil {
		t.Fatal(err)
	}
	c, _ = m.Load()
	if c.MeshActive() || len(c.MeshPeers) != 0 {
		t.Fatalf("leave did not clear mesh: %+v peers=%d", c.Mesh, len(c.MeshPeers))
	}
	if err := m.MeshLeave(); err == nil {
		t.Fatal("second leave did not error")
	}
}

func TestMeshStatusConfigOnly(t *testing.T) {
	m := meshTestManager(t)
	rep := m.MeshStatus()
	if rep.Active || rep.DaemonRunning {
		t.Fatalf("inactive mesh reported active: %+v", rep)
	}
	if _, err := m.MeshInit("alpha"); err != nil {
		t.Fatal(err)
	}
	c, _ := m.Load()
	c.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ExitOffered: true, LastSeen: "2026-07-12T00:00:00Z"}}
	// Point the easytier bin at nothing so liveness stays config-only.
	c.Mesh.EasytierBin = filepath.Join(t.TempDir(), "missing", "easytier-core")
	if err := config.Save(m.ConfigPath, c); err != nil {
		t.Fatal(err)
	}
	rep = m.MeshStatus()
	if !rep.Active || rep.Installed || rep.DaemonRunning {
		t.Fatalf("unexpected status: %+v", rep)
	}
	if len(rep.Peers) != 1 || rep.Peers[0].Name != "beta" || rep.Peers[0].Live {
		t.Fatalf("unexpected peers: %+v", rep.Peers)
	}
}
