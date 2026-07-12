package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/mesh"
)

func testCode(t *testing.T, extras ...string) mesh.Code {
	t.Helper()
	code, err := mesh.GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	code.ExtraPeers = extras
	return code
}

func TestMeshConfigRoundTrip(t *testing.T) {
	code := testCode(t, "tcp://relay.example.org:11010")
	c := Default()
	c.Mesh = DefaultMesh()
	c.Mesh.Enabled = true
	c.Mesh.Code = code.Encode()
	c.Mesh.NodeName = "router-alpha"
	c.Mesh.HWID = "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa"
	c.Mesh.ExitEnabled = true
	c.Mesh.ListenPort = 7899 // non-default, must survive
	c.MeshPeers = []MeshPeer{
		{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "router-beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true, LastSeen: "2026-07-12T10:00:00Z"},
		{HWID: "purewrt-cccccccccccccccccccccccc", Name: "router-gamma", Enabled: false, OverlayIP: "10.126.126.3", ListenPort: 7897, ExitOffered: false, LastError: "probe timeout"},
	}

	path := filepath.Join(t.TempDir(), "purewrt")
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// The decoded fields must be repopulated from the code on load.
	want := c.Mesh
	want.NetworkName = code.NetworkName()
	want.ExtraPeers = []string{"tcp://relay.example.org:11010"}
	if got.Mesh.Code != want.Code || got.Mesh.NetworkName != want.NetworkName ||
		got.Mesh.PSK == "" || got.Mesh.NetworkSecret == "" ||
		got.Mesh.NodeName != want.NodeName || got.Mesh.ListenPort != 7899 {
		t.Fatalf("mesh mismatch\ngot:  %#v\nwant: %#v", got.Mesh, want)
	}
	if !reflect.DeepEqual(got.Mesh.ExtraPeers, want.ExtraPeers) {
		t.Fatalf("extra peers mismatch: %#v", got.Mesh.ExtraPeers)
	}
	if !reflect.DeepEqual(got.MeshPeers, c.MeshPeers) {
		t.Fatalf("mesh peers mismatch\ngot:  %#v\nwant: %#v", got.MeshPeers, c.MeshPeers)
	}
}

func TestMeshSerializeMinimal(t *testing.T) {
	// A joined config with all-default plumbing serializes to exactly the
	// minimal option set: one secret line, nothing derivable.
	code := testCode(t)
	c := Default()
	c.Mesh = DefaultMesh()
	c.Mesh.Enabled = true
	c.Mesh.Code = code.Encode()
	c.Mesh.NodeName = "alpha"
	c.Mesh.HWID = "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa"
	c.Mesh.ExitEnabled = true
	c.MeshPeers = []MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}

	out := string(Serialize(c))
	for _, banned := range []string{"psk", "network_secret", "network_name", "cred_salt", "listen_port", "api_mesh_port", "device_name", "easytier_bin", "rpc_portal", "sync_cron", "extra_peer"} {
		if strings.Contains(out, "option "+banned) || strings.Contains(out, "list "+banned) {
			t.Errorf("minimal mesh config still writes %q:\n%s", banned, out)
		}
	}
	for _, required := range []string{"option code", "option node_name 'alpha'", "config mesh_peer", "option overlay_ip '10.126.126.2'"} {
		if !strings.Contains(out, required) {
			t.Errorf("minimal mesh config missing %q:\n%s", required, out)
		}
	}
}

func TestMeshCodeCarriesExtraPeers(t *testing.T) {
	// Extras equal to the code TLVs are not written; a diverged list is.
	code := testCode(t, "tcp://relay.example.org:11010")
	c := Default()
	c.Mesh = DefaultMesh()
	c.Mesh.Enabled = true
	c.Mesh.Code = code.Encode()
	c.Mesh.NodeName = "alpha"
	c.Mesh.HWID = "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa"
	c.Mesh.ExtraPeers = []string{"tcp://relay.example.org:11010"}
	if out := string(Serialize(c)); strings.Contains(out, "extra_peer") {
		t.Fatalf("extras matching code TLVs must not serialize:\n%s", out)
	}
	c.Mesh.ExtraPeers = append(c.Mesh.ExtraPeers, "udp://other.example.org:11010")
	out := string(Serialize(c))
	if !strings.Contains(out, "list extra_peer 'tcp://relay.example.org:11010'") ||
		!strings.Contains(out, "list extra_peer 'udp://other.example.org:11010'") {
		t.Fatalf("diverged extras must serialize in full:\n%s", out)
	}
	// And a round-trip keeps the diverged list.
	path := filepath.Join(t.TempDir(), "purewrt")
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Mesh.ExtraPeers, c.Mesh.ExtraPeers) {
		t.Fatalf("diverged extras lost on round-trip: %#v", got.Mesh.ExtraPeers)
	}
}

func TestMeshInvalidCodeStaysDormant(t *testing.T) {
	raw := `config mesh 'mesh'
	option enabled '1'
	option code 'PWMESH1-GARBAGE'
	option node_name 'r1'
`
	path := filepath.Join(t.TempDir(), "purewrt")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.MeshActive() {
		t.Fatalf("mesh with invalid code reports active: %#v", got.Mesh)
	}
}

func TestMeshAbsentStaysAbsent(t *testing.T) {
	// Untouched installs must keep byte-identical configs: no mesh sections
	// are emitted unless the feature was initialised.
	out := string(Serialize(Default()))
	if strings.Contains(out, "config mesh") {
		t.Fatalf("default config serializes mesh sections:\n%s", out)
	}
}

func TestMeshDefaults(t *testing.T) {
	d := Default().Mesh
	if d.Enabled {
		t.Fatal("mesh enabled by default")
	}
	if d.ListenPort != 7897 || d.APIMeshPort != 8788 || d.DeviceName != "pwmesh0" ||
		d.EasytierBin != "/usr/bin/easytier-core" || d.RPCPortal != "127.0.0.1:15888" || d.SyncCron != "*/5 * * * *" {
		t.Fatalf("unexpected mesh defaults: %#v", d)
	}
}

func TestMeshParseAppliesDefaults(t *testing.T) {
	// A minimal joined config picks up defaults for unset options.
	code := testCode(t)
	raw := `config mesh 'mesh'
	option enabled '1'
	option code '` + code.Encode() + `'
	option node_name 'r1'

config mesh_peer 'pwpeer_router_beta'
	option hwid 'purewrt-bbbbbbbbbbbbbbbbbbbbbbbb'
	option name 'router-beta'
	option overlay_ip '10.126.126.2'
	option exit_offered '1'
`
	path := filepath.Join(t.TempDir(), "purewrt")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Mesh.Enabled || got.Mesh.NetworkName != code.NetworkName() {
		t.Fatalf("mesh not parsed: %#v", got.Mesh)
	}
	if got.Mesh.ListenPort != 7897 || got.Mesh.APIMeshPort != 8788 || got.Mesh.DeviceName != "pwmesh0" {
		t.Fatalf("mesh defaults not applied on parse: %#v", got.Mesh)
	}
	if len(got.MeshPeers) != 1 {
		t.Fatalf("expected 1 peer, got %#v", got.MeshPeers)
	}
	p := got.MeshPeers[0]
	if p.Name != "router-beta" || !p.Enabled || p.ListenPort != 7897 || !p.ExitOffered {
		t.Fatalf("peer defaults wrong: %#v", p)
	}
	if !got.MeshActive() {
		t.Fatal("MeshActive() false for enabled+named mesh")
	}
}

func TestMeshCredSaltDerivation(t *testing.T) {
	code := testCode(t)
	c := Default()
	c.Mesh = DefaultMesh()
	c.Mesh.Enabled = true
	c.Mesh.Code = code.Encode()
	c.Mesh.NodeName = "alpha"
	c.Mesh.HWID = "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa"
	// Repopulate decoded fields the way Load does.
	path := filepath.Join(t.TempDir(), "purewrt")
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	own := got.Mesh.CredSalt()
	if own == "" {
		t.Fatal("own cred salt not derivable")
	}
	// A peer with the same hwid derives the same salt from the same PSK —
	// that is exactly what lets friends compute this router's password.
	peer := MeshPeer{HWID: "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa"}
	if peer.CredSalt(got.Mesh.PSK) != own {
		t.Fatal("peer-side derivation disagrees with own derivation")
	}
	if (MeshPeer{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb"}).CredSalt(got.Mesh.PSK) == own {
		t.Fatal("different hwids must derive different salts")
	}
	if (MeshPeer{HWID: "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa"}).CredSalt("zz-not-hex") != "" {
		t.Fatal("malformed PSK must yield empty salt")
	}
	if (MeshPeer{Name: "alpha"}).CredSalt(got.Mesh.PSK) != "" {
		t.Fatal("peer without hwid must yield empty salt")
	}
}

func TestMeshActive(t *testing.T) {
	c := Default()
	if c.MeshActive() {
		t.Fatal("default config reports mesh active")
	}
	c.Mesh.Enabled = true
	if c.MeshActive() {
		t.Fatal("enabled but unjoined mesh reports active")
	}
	c.Mesh.NetworkName = "pwmesh-x"
	if !c.MeshActive() {
		t.Fatal("joined mesh not active")
	}
}
