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
		HWID:        "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa",
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
	for _, s := range []string{"mesh-in", "MeshExit", "friend_", "_local", "Friends"} {
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
	c.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	out := string(Mihomo(c))

	block := meshExitBlock(t, out)
	for _, forbidden := range []string{"DIRECT", "friend_bbbbbbbbbbbbbbbbbbbbbbbb", "Friends", "Media", "AI", "Common"} {
		if strings.Contains(block, forbidden) {
			t.Fatalf("MeshExit group leaks %q:\n%s", forbidden, block)
		}
	}
	// It must still route somewhere: the host's own provider via use:.
	if !strings.Contains(block, "sub") {
		t.Fatalf("MeshExit has no own-provider members:\n%s", block)
	}
}

func TestMeshExitGroupFilters(t *testing.T) {
	// Defaults: no filter keys at all.
	block := meshExitBlock(t, string(Mihomo(joinedMesh())))
	if strings.Contains(block, "filter:") {
		t.Fatalf("default MeshExit emits filter keys:\n%s", block)
	}
	// Set: both keys pass through to the group verbatim (quoted).
	c := joinedMesh()
	c.Mesh.ExitFilter = "(?i)NL|DE"
	c.Mesh.ExitExcludeFilter = "(?i)expire"
	block = meshExitBlock(t, string(Mihomo(c)))
	if !strings.Contains(block, `filter: "(?i)NL|DE"`) {
		t.Fatalf("MeshExit missing include filter:\n%s", block)
	}
	if !strings.Contains(block, `exclude-filter: "(?i)expire"`) {
		t.Fatalf("MeshExit missing exclude filter:\n%s", block)
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
	c.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	out := string(Mihomo(c))

	if !strings.Contains(out, "name: friend_bbbbbbbbbbbbbbbbbbbbbbbb") || !strings.Contains(out, "server: 10.126.126.2") {
		t.Fatalf("friend proxy missing:\n%s", out)
	}
	// The section group named Common must become a fallback wrapping
	// Common_local + the shared Friends group (friends never appear in the
	// fallback directly).
	if !strings.Contains(out, "name: Common_local") {
		t.Fatalf("section _local group missing:\n%s", out)
	}
	fb := groupBlock(t, out, "Common")
	if !strings.Contains(fb, "type: fallback") {
		t.Fatalf("Common not a fallback group:\n%s", fb)
	}
	if !strings.Contains(fb, "Common_local") || !strings.Contains(fb, "- Friends") {
		t.Fatalf("fallback missing members:\n%s", fb)
	}
	if strings.Contains(fb, "friend_bbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatalf("fallback references a friend directly instead of Friends:\n%s", fb)
	}
	// The Friends group spreads across friends: load-balance + sticky.
	fr := groupBlock(t, out, "Friends")
	for _, want := range []string{"type: load-balance", "strategy: sticky-sessions", "- friend_bbbbbbbbbbbbbbbbbbbbbbbb", "url: ", "interval: "} {
		if !strings.Contains(fr, want) {
			t.Fatalf("Friends group missing %q:\n%s", want, fr)
		}
	}
	// IN-NAME rule name stays the public group name.
	if !strings.Contains(out, "IN-NAME,tproxy-common,Common") {
		t.Fatalf("IN-NAME rule changed:\n%s", out)
	}
}

func TestFriendsGroupSingleFriendStillEmitted(t *testing.T) {
	// One friend still gets the Friends wrapper — uniform YAML shape.
	c := joinedMesh()
	c.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	out := string(Mihomo(c))
	fr := groupBlock(t, out, "Friends")
	if !strings.Contains(fr, "- friend_bbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatalf("Friends group missing its only member:\n%s", fr)
	}
}

func TestNoConsumableFriendsNoFriendsGroup(t *testing.T) {
	// Mesh active but every peer ineligible: no Friends group, no _local
	// wrappers — sections emit plainly.
	c := joinedMesh()
	c.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: false, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	out := string(Mihomo(c))
	for _, s := range []string{"name: Friends", "_local"} {
		if strings.Contains(out, s) {
			t.Fatalf("friendless mesh still emits %q:\n%s", s, out)
		}
	}
}

func TestFriendDisabledOrNoExitNotEmitted(t *testing.T) {
	c := joinedMesh()
	c.MeshPeers = []config.MeshPeer{
		{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: false, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true},
		{HWID: "purewrt-cccccccccccccccccccccccc", Name: "gamma", Enabled: true, OverlayIP: "10.126.126.3", ListenPort: 7897, ExitOffered: false},
		{HWID: "purewrt-dddddddddddddddddddddddd", Name: "delta", Enabled: true, OverlayIP: "", ListenPort: 7897, ExitOffered: true},
	}
	out := string(Mihomo(c))
	for _, n := range []string{"friend_bbbb", "friend_cccc", "friend_dddd"} {
		if strings.Contains(out, n) {
			t.Fatalf("ineligible friend %q emitted:\n%s", n, out)
		}
	}
}

func TestNetCheckProbeIncludesFriends(t *testing.T) {
	// Friend exits are probe-able in isolation: net-check --per-node and
	// throughput tests pin one friend via the NetCheckProbe select group.
	c := joinedMesh()
	c.Sections = []config.Section{{Name: "common", Enabled: true, Action: "proxy", TPROXYPort: 7894, ProxyGroup: "Common", IPv4Enabled: true}}
	c.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	probe := groupBlock(t, string(Mihomo(c)), "NetCheckProbe")
	if !strings.Contains(probe, "- friend_bbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatalf("NetCheckProbe missing friend member:\n%s", probe)
	}
}

func TestFriendKeyedByHWIDNotName(t *testing.T) {
	// The display name is cosmetic: a hostile name must not block the peer
	// (identity is the hwid) and must never reach the YAML; a malformed
	// hwid skips the peer entirely.
	c := joinedMesh()
	c.MeshPeers = []config.MeshPeer{
		{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "evil\nproxies: []", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true},
		{HWID: "not-a-hwid", Name: "ok", Enabled: true, OverlayIP: "10.126.126.3", ListenPort: 7897, ExitOffered: true},
	}
	out := string(Mihomo(c))
	if !strings.Contains(out, "name: friend_bbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatalf("hostile display name blocked an hwid-valid friend:\n%s", out)
	}
	if strings.Contains(out, "evil") {
		t.Fatalf("display name leaked into YAML:\n%s", out)
	}
	if strings.Contains(out, "10.126.126.3") {
		t.Fatalf("malformed-hwid peer emitted:\n%s", out)
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
		`hostname = "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa"`,
		`machine_id = "purewrt-aaaaaaaaaaaaaaaaaaaaaaaa"`,
		`tcp_whitelist = ["7897", "8788"]`,
		`udp_whitelist = ["7897"]`,
		`network_name = "pwmesh-0011223344556677"`,
		`network_secret = "c2VjcmV0"`,
		`uri = "wss://pwmesh.glants.xyz/pwmesh"`,
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
	c.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	base := hashes(c)

	material := c
	material.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.9", ListenPort: 7897, ExitOffered: true}}
	got := hashes(material)
	if got["mesh"] == base["mesh"] {
		t.Error("peer overlay IP change did not dirty mesh group")
	}
	if got["mihomo"] == base["mihomo"] {
		t.Error("peer overlay IP change did not dirty mihomo group")
	}

	liveness := c
	liveness.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true, LastSeen: "2026-07-12T00:00:00Z", LastError: "boom"}}
	got = hashes(liveness)
	for name, h := range got {
		if base[name] != h {
			t.Errorf("liveness-only change dirtied group %q", name)
		}
	}
}

// The overlay is invisible to nftables while no throughput cap is set: mesh
// inbound terminates at the local mihomo listener (fw4 input path), and
// overlay egress rides the friend ss proxies — TPROXY must not see any of it.
func TestMeshLeavesNFTablesUntouched(t *testing.T) {
	off := NFTables(config.Default())
	on := joinedMesh()
	on.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	got := NFTables(on)
	if string(off) != string(got) {
		t.Error("capless mesh config altered nftables output")
	}
}

func TestMeshExitRateLimiterChains(t *testing.T) {
	capped := joinedMesh()
	capped.Mesh.ExitMaxMbit = 100

	cases := []struct {
		name string
		c    config.Config
		want bool
	}{
		{"capped", capped, true},
		{"no cap", joinedMesh(), false},
		{"exit disabled", func() config.Config { c := capped; c.Mesh.ExitEnabled = false; return c }(), false},
		{"mesh inactive", func() config.Config { c := capped; c.Mesh.NetworkName = ""; return c }(), false},
	}
	for _, tc := range cases {
		out := string(NFTables(tc.c))
		has := strings.Contains(out, "chain mesh_limit_in")
		if has != tc.want {
			t.Errorf("%s: limiter chains present=%v want=%v:\n%s", tc.name, has, tc.want, out)
		}
	}

	out := string(NFTables(capped))
	for _, want := range []string{
		"chain mesh_limit_in {\n    type filter hook input priority filter; policy accept;",
		"chain mesh_limit_out {\n    type filter hook output priority filter; policy accept;",
		// 100 Mbit/s = 12_500_000 bytes/s, decimal — not nft's 1024-based mbytes.
		`iifname "pwmesh0" meta l4proto { tcp, udp } th dport 7897 limit rate over 12500000 bytes/second counter drop`,
		`oifname "pwmesh0" meta l4proto { tcp, udp } th sport 7897 limit rate over 12500000 bytes/second counter drop`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("limiter output missing %q:\n%s", want, out)
		}
	}

	custom := capped
	custom.Mesh.DeviceName = "pwx1"
	custom.Mesh.ListenPort = 7911
	custom.Mesh.ExitMaxMbit = 8
	out = string(NFTables(custom))
	if !strings.Contains(out, `iifname "pwx1" meta l4proto { tcp, udp } th dport 7911 limit rate over 1000000 bytes/second counter drop`) {
		t.Errorf("custom device/port/cap not honoured:\n%s", out)
	}
}

func TestEasytierFingerprintIgnoresPeerChurn(t *testing.T) {
	// mesh-sync peer updates must never dirty the easytier group: an
	// easytier restart renegotiates the DHCP overlay IP, invalidating the
	// peer records the sync just wrote (sync→apply→restart loop).
	hashes := func(c config.Config) map[string]string {
		fp, err := currentGenerationFingerprint(c)
		if err != nil {
			t.Fatal(err)
		}
		return fp.Groups
	}
	c := joinedMesh()
	base := hashes(c)

	peered := c
	peered.MeshPeers = []config.MeshPeer{{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.126.126.2", ListenPort: 7897, ExitOffered: true}}
	got := hashes(peered)
	if got["easytier"] != base["easytier"] {
		t.Error("peer churn dirtied the easytier group (would restart the daemon)")
	}
	if got["mesh"] == base["mesh"] {
		t.Error("peer churn did not dirty the mesh group")
	}

	// A rendezvous edit rewrites easytier.toml — it must dirty easytier.
	rendezvous := c
	rendezvous.Mesh.CommunityPeers = []string{"tcp://203.0.113.9:11010"}
	if hashes(rendezvous)["easytier"] == base["easytier"] {
		t.Error("community_peer change did not dirty the easytier group")
	}

	// exit_filter is mihomo-only — the daemon must not restart for it.
	filtered := c
	filtered.Mesh.ExitFilter = "(?i)NL"
	if hashes(filtered)["easytier"] != base["easytier"] {
		t.Error("exit_filter change dirtied the easytier group")
	}

	// log_level maps onto ET_CONSOLE_LOG_LEVEL in the init script —
	// flipping it must restart the daemon for the new level to take effect.
	leveled := c
	leveled.Settings.LogLevel = "debug"
	if hashes(leveled)["easytier"] == base["easytier"] {
		t.Error("log_level change did not dirty the easytier group")
	}

	// ListenPort shapes the overlay port whitelist in easytier.toml.
	ported := c
	ported.Mesh.ListenPort = 7911
	if hashes(ported)["easytier"] == base["easytier"] {
		t.Error("listen_port change did not dirty the easytier group")
	}
}

func TestMeshExitCapFingerprintSemantics(t *testing.T) {
	hashes := func(c config.Config) map[string]string {
		fp, err := currentGenerationFingerprint(c)
		if err != nil {
			t.Fatal(err)
		}
		return fp.Groups
	}
	base := hashes(joinedMesh())

	// exit_max_mbit shapes purewrt.nft — it must dirty openwrt_bundle.
	capped := joinedMesh()
	capped.Mesh.ExitMaxMbit = 50
	got := hashes(capped)
	if got["openwrt_bundle"] == base["openwrt_bundle"] {
		t.Error("exit_max_mbit change did not dirty openwrt_bundle")
	}

	// exit_filter is mihomo-only — it must dirty mihomo but NOT the
	// expensive openwrt_bundle (dnsmasq fragments) regeneration.
	filtered := joinedMesh()
	filtered.Mesh.ExitFilter = "(?i)NL"
	got = hashes(filtered)
	if got["mihomo"] == base["mihomo"] {
		t.Error("exit_filter change did not dirty mihomo")
	}
	if got["openwrt_bundle"] != base["openwrt_bundle"] {
		t.Error("exit_filter change dirtied openwrt_bundle")
	}
}
