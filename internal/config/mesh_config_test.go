package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMeshConfigRoundTrip(t *testing.T) {
	c := Default()
	c.Mesh = Mesh{
		Enabled:       true,
		NetworkName:   "pwmesh-0011223344556677",
		NetworkSecret: "c2VjcmV0LXNlY3JldC1zZWNyZXQtMjRi",
		PSK:           "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		NodeName:      "router-alpha",
		CredSalt:      "000102030405060708090a0b0c0d0e0f",
		ExitEnabled:   true,
		ListenPort:    7897,
		APIMeshPort:   8788,
		DeviceName:    "pwmesh0",
		ExtraPeers:    []string{"tcp://relay.example.org:11010"},
		EasytierBin:   "/usr/bin/easytier-core",
		RPCPortal:     "127.0.0.1:15888",
		SyncCron:      "*/5 * * * *",
	}
	c.MeshPeers = []MeshPeer{
		{Name: "router-beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, CredSalt: "0f0e0d0c0b0a09080706050403020100", ExitOffered: true, LastSeen: "2026-07-12T10:00:00Z"},
		{Name: "router-gamma", Enabled: false, OverlayIP: "10.126.126.3", ListenPort: 7897, CredSalt: "aa", ExitOffered: false, LastError: "probe timeout"},
	}

	path := filepath.Join(t.TempDir(), "purewrt")
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Mesh, c.Mesh) {
		t.Fatalf("mesh mismatch\ngot:  %#v\nwant: %#v", got.Mesh, c.Mesh)
	}
	if !reflect.DeepEqual(got.MeshPeers, c.MeshPeers) {
		t.Fatalf("mesh peers mismatch\ngot:  %#v\nwant: %#v", got.MeshPeers, c.MeshPeers)
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
	raw := `config mesh 'mesh'
	option enabled '1'
	option network_name 'pwmesh-aabbccddeeff0011'
	option network_secret 'c2VjcmV0'
	option psk 'ff00'
	option node_name 'r1'
	option cred_salt 'ab'

config mesh_peer 'pwpeer_router_beta'
	option name 'router-beta'
	option overlay_ip '10.126.126.2'
	option cred_salt 'cd'
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
	if !got.Mesh.Enabled || got.Mesh.NetworkName != "pwmesh-aabbccddeeff0011" {
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
