package generator

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// joinedMesh returns a Default config joined to a mesh, with one enabled
// proxy provider so the exit is viable.
func joinedMesh() config.Config {
	c := config.Default()
	c.ProxyProviders = []config.ProxyProvider{{Name: "sub", Enabled: true, Type: "http", URL: "https://e/sub", Path: "/etc/purewrt/providers/sub.yaml", HealthCheck: true, HealthCheckURL: "https://cp/204", HealthCheckInterval: 300}}
	c.Mesh = config.Mesh{
		Enabled:     true,
		NetworkName: "pwmesh-0011223344556677",
		PSK:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		NodeName:    "alpha",
		ExitEnabled: true,
		ListenPort:  7897,
		APIMeshPort: 8788,
		DeviceName:  "pwmesh0",
	}
	return c
}

func TestMeshOffLeavesMihomoUntouched(t *testing.T) {
	out := string(Mihomo(config.Default()))
	for _, s := range []string{"mesh-in", "MeshExit", "friend_", "_local"} {
		if strings.Contains(out, s) {
			t.Fatalf("mesh-off config contains %q:\n%s", s, out)
		}
	}
}

func TestMeshListenerAndExitGroupEmitted(t *testing.T) {
	out := string(Mihomo(joinedMesh()))
	if !strings.Contains(out, "name: mesh-in") || !strings.Contains(out, "type: shadowsocks") {
		t.Fatalf("mesh listener missing:\n%s", out)
	}
	if !strings.Contains(out, "cipher: aes-128-gcm") {
		t.Fatal("mesh listener cipher wrong")
	}
	if !strings.Contains(out, "IN-NAME,mesh-in,MeshExit") {
		t.Fatal("IN-NAME mesh rule missing")
	}
	if !strings.Contains(out, "name: MeshExit") {
		t.Fatal("MeshExit group missing")
	}
}

// The core safety invariant: a friend's inbound traffic can only leave via
// this host's own proxies — never DIRECT (host's home IP) and never bounced
// back into the mesh (loop).
func TestMeshExitGroupNeverLeaksDirectOrFriendOrSection(t *testing.T) {
	c := joinedMesh()
	// Add a consumable friend so friend_* proxies also exist in the config.
	c.MeshPeers = []config.MeshPeer{{Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	out := string(Mihomo(c))

	block := meshExitBlock(t, out)
	for _, forbidden := range []string{"DIRECT", "friend_beta", "Media", "AI", "Common"} {
		if strings.Contains(block, forbidden) {
			t.Fatalf("MeshExit group leaks %q:\n%s", forbidden, block)
		}
	}
	// It must still route somewhere: the host's own provider via use:.
	if !strings.Contains(block, "sub") {
		t.Fatalf("MeshExit has no own-provider members:\n%s", block)
	}
}

func TestMeshExitNotEmittedWhenNotViable(t *testing.T) {
	c := joinedMesh()
	c.ProxyProviders = nil // no providers, no VPNs → exit could only fail
	out := string(Mihomo(c))
	if strings.Contains(out, "mesh-in") || strings.Contains(out, "MeshExit") {
		t.Fatalf("non-viable exit still emitted listener/group:\n%s", out)
	}
}

func TestFriendProxyAndFallbackWiring(t *testing.T) {
	c := joinedMesh()
	c.Mesh.ExitEnabled = false // pure consumer
	c.MeshPeers = []config.MeshPeer{{Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	out := string(Mihomo(c))

	if !strings.Contains(out, "name: friend_beta") || !strings.Contains(out, "server: 10.126.126.2") {
		t.Fatalf("friend proxy missing:\n%s", out)
	}
	// The section group named Common must become a fallback wrapping Common_local + friend_beta.
	if !strings.Contains(out, "name: Common_local") {
		t.Fatalf("section _local group missing:\n%s", out)
	}
	fb := groupBlock(t, out, "Common")
	if !strings.Contains(fb, "type: fallback") {
		t.Fatalf("Common not a fallback group:\n%s", fb)
	}
	if !strings.Contains(fb, "Common_local") || !strings.Contains(fb, "friend_beta") {
		t.Fatalf("fallback missing members:\n%s", fb)
	}
	// IN-NAME rule name stays the public group name.
	if !strings.Contains(out, "IN-NAME,tproxy-common,Common") {
		t.Fatalf("IN-NAME rule changed:\n%s", out)
	}
}

func TestFriendDisabledOrNoExitNotEmitted(t *testing.T) {
	c := joinedMesh()
	c.MeshPeers = []config.MeshPeer{
		{Name: "beta", Enabled: false, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true},
		{Name: "gamma", Enabled: true, OverlayIP: "10.126.126.3", ListenPort: 7897, ExitOffered: false},
		{Name: "delta", Enabled: true, OverlayIP: "", ListenPort: 7897, ExitOffered: true},
	}
	out := string(Mihomo(c))
	for _, n := range []string{"friend_beta", "friend_gamma", "friend_delta"} {
		if strings.Contains(out, n) {
			t.Fatalf("ineligible friend %q emitted:\n%s", n, out)
		}
	}
}

// meshExitBlock extracts the YAML block for the MeshExit group.
func meshExitBlock(t *testing.T, out string) string {
	t.Helper()
	return groupBlock(t, out, "MeshExit")
}

// groupBlock returns the proxy-group entry starting at "  - name: <name>" up
// to the next "  - " at the same indent (or end of proxy-groups).
func groupBlock(t *testing.T, out, name string) string {
	t.Helper()
	marker := "  - name: " + name + "\n"
	i := strings.Index(out, marker)
	if i < 0 {
		t.Fatalf("group %q not found in:\n%s", name, out)
	}
	rest := out[i+len(marker):]
	end := strings.Index(rest, "\n  - ")
	if end < 0 {
		// Truncate at rules section if present.
		if r := strings.Index(rest, "\nrules:"); r >= 0 {
			end = r
		} else {
			end = len(rest)
		}
	}
	return marker + rest[:end]
}

func TestEasytierConfigGolden(t *testing.T) {
	if EasytierConfig(config.Default()) != nil {
		t.Fatal("easytier config emitted for inactive mesh")
	}
	c := joinedMesh()
	c.Mesh.NetworkSecret = "c2VjcmV0"
	c.Mesh.ExtraPeers = []string{"tcp://relay.example.org:11010"}
	out := string(EasytierConfig(c))
	for _, want := range []string{
		`hostname = "alpha"`,
		`network_name = "pwmesh-0011223344556677"`,
		`network_secret = "c2VjcmV0"`,
		`uri = "tcp://150.241.85.145:11010"`,
		`uri = "tcp://relay.example.org:11010"`,
		`dev_name = "pwmesh0"`,
		"enable_kcp_proxy = false",
		"dhcp = true",
		`rpc_portal = "127.0.0.1:15888"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("easytier.toml missing %q:\n%s", want, out)
		}
	}
}

func TestMeshFirewallZoneAndRules(t *testing.T) {
	base := string(FirewallRules(config.Default()))
	if strings.Contains(base, "purewrt_mesh") {
		t.Fatal("mesh firewall emitted for inactive mesh")
	}
	c := joinedMesh()
	out := string(FirewallRules(c))
	for _, want := range []string{
		"config zone 'purewrt_mesh'",
		"list device 'pwmesh0'",
		"option forward 'REJECT'",
		"option input 'REJECT'",
		"config rule 'purewrt_mesh_ss'",
		"option dest_port '7897'",
		"config rule 'purewrt_mesh_api'",
		"option dest_port '8788'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("firewall missing %q:\n%s", want, out)
		}
	}
	c.Mesh.ExitEnabled = false
	out = string(FirewallRules(c))
	if strings.Contains(out, "purewrt_mesh_ss") {
		t.Errorf("ss accept rule emitted with exit disabled:\n%s", out)
	}
	if !strings.Contains(out, "purewrt_mesh_api") {
		t.Errorf("api rule must stay for discovery with exit disabled:\n%s", out)
	}
}

// Peer material changes must dirty mesh + mihomo groups; liveness fields
// (LastSeen/LastError) must dirty nothing — mesh-sync heartbeats would
// otherwise regenerate every 5 minutes.
func TestMeshFingerprintGroupSemantics(t *testing.T) {
	hashes := func(c config.Config) map[string]string {
		fp, err := currentGenerationFingerprint(c)
		if err != nil {
			t.Fatal(err)
		}
		return fp.Groups
	}
	c := joinedMesh()
	c.MeshPeers = []config.MeshPeer{{Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	base := hashes(c)

	material := c
	material.MeshPeers = []config.MeshPeer{{Name: "beta", Enabled: true, OverlayIP: "10.126.126.9", ListenPort: 7897, ExitOffered: true}}
	got := hashes(material)
	if got["mesh"] == base["mesh"] {
		t.Error("peer overlay IP change did not dirty mesh group")
	}
	if got["mihomo"] == base["mihomo"] {
		t.Error("peer overlay IP change did not dirty mihomo group")
	}

	liveness := c
	liveness.MeshPeers = []config.MeshPeer{{Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true, LastSeen: "2026-07-12T00:00:00Z", LastError: "boom"}}
	got = hashes(liveness)
	for name, h := range got {
		if base[name] != h {
			t.Errorf("liveness-only change dirtied group %q", name)
		}
	}
}

// The overlay is invisible to nftables: mesh inbound terminates at the local
// mihomo listener (fw4 input path), and overlay egress rides the friend ss
// proxies — TPROXY must not see any of it.
func TestMeshLeavesNFTablesUntouched(t *testing.T) {
	off := NFTables(config.Default())
	on := joinedMesh()
	on.MeshPeers = []config.MeshPeer{{Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	got := NFTables(on)
	if string(off) != string(got) {
		t.Error("mesh config altered nftables output")
	}
}
