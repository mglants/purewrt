package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mesh"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/mihomoapi"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/proxyguard"
)

func TestLiveProxyGuardMetricsReflectStateAndLastResorts(t *testing.T) {
	c := config.Default()
	c.Settings.RuntimeDir = t.TempDir()
	c.Settings.ProxyGuardEnabled = true
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	state := proxyguard.NewState()
	state.LastRun = now
	state.Nodes[`node,"one`] = &proxyguard.NodeState{Name: `node,"one`, Provider: "sub-a", Kind: "vless", State: proxyguard.Healthy, LastProbe: now, LastDownKbps: 4200, LatenciesMS: []int{40, 50}, LastDelayMS: 50, JitterMS: 10}
	state.Nodes["slow"] = &proxyguard.NodeState{Name: "slow", Provider: "sub-a", Kind: "vless", State: proxyguard.Quarantined, Reason: "download 100 kbps below 2000 kbps", QuarantinedAt: now.Add(-time.Minute), RetryAfter: now.Add(time.Minute), BadStreak: 2}
	state.Groups["Common"] = &proxyguard.GroupState{
		Name:        "Common",
		Members:     []string{`node,"one`, "slow", "slow"},
		LastResorts: []string{"slow", "missing", `node,"one`},
	}
	if err := proxyguard.Save(c, state); err != nil {
		t.Fatal(err)
	}

	r := metrics.NewRegistry()
	recordLiveProxyGuardMetrics(r, c)
	out := r.Render()
	for _, want := range []string{
		"purewrt_proxy_guard_enabled 1",
		`purewrt_proxy_guard_members{state="healthy",kind="vless"} 1`,
		`purewrt_proxy_guard_members{state="quarantined",kind="vless"} 1`,
		`purewrt_proxy_guard_group_members{group="Common",role="candidate"} 2`,
		`purewrt_proxy_guard_group_members{group="Common",role="effective"} 2`,
		`purewrt_proxy_guard_group_members{group="Common",role="last_resort"} 1`,
		`purewrt_proxy_guard_node_info{node="node,\"one",provider="sub-a",kind="vless",state="healthy",reason="none"} 1`,
		`purewrt_proxy_guard_node_info{node="slow",provider="sub-a",kind="vless",state="quarantined",reason="throughput"} 1`,
		`purewrt_proxy_guard_node_download_kbps{node="node,\"one"} 4200`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `purewrt_proxy_guard_node_download_kbps{node="slow"}`) {
		t.Fatalf("untested node rendered an ambiguous zero throughput:\n%s", out)
	}
}

func TestLiveConfigMetricsAreComputedAtScrapeTime(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.Workdir = filepath.Join(dir, "work")
	c.Settings.GeoRefreshGeoIPDir = filepath.Join(dir, "geo")
	c.Subscriptions = []config.Subscription{{Name: "sub", Enabled: true, URL: "https://example.test/sub"}}
	providerPath := filepath.Join(c.Settings.Workdir, "providers", "sub.yaml")
	expire := time.Now().Add(48 * time.Hour)
	if err := provider.WriteMetadata(providerPath, provider.Metadata{SubExpire: expire, SubUsedBytes: 20, SubTotalBytes: 100}); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(dir, "rules.txt")
	proxyPath := filepath.Join(dir, "proxies.yaml")
	if err := os.WriteFile(rulePath, []byte("example.org\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxyPath, []byte("proxies:\n- name: one\n  type: direct\n"), 0644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-time.Hour)
	if err := provider.WriteMetadata(rulePath, provider.Metadata{LastUpdate: when, LastSuccess: when, EntryCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := provider.WriteMetadata(proxyPath, provider.Metadata{LastUpdate: when, LastSuccess: when, EntryCount: 1}); err != nil {
		t.Fatal(err)
	}
	c.RuleProviders = []config.RuleProvider{{Name: "rules", Enabled: true, Path: rulePath}}
	c.ProxyProviders = []config.ProxyProvider{{Name: "proxies", Enabled: true, Path: proxyPath}}
	if err := os.MkdirAll(c.Settings.GeoRefreshGeoIPDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.Settings.GeoRefreshGeoIPDir, "geoip.dat"), []byte("geo"), 0644); err != nil {
		t.Fatal(err)
	}
	r := metrics.NewRegistry()
	recordLiveConfigMetrics(r, c)
	out := r.Render()
	for _, name := range []string{
		"purewrt_subscription_min_seconds_to_expiry ",
		"purewrt_subscription_min_expiry_timestamp_seconds ",
		`purewrt_geodata_modified_timestamp_seconds{dataset="geoip"} `,
		`purewrt_provider_update_success{provider="rules",type="rule"} 1`,
		`purewrt_provider_entries{provider="proxies",type="proxy"} 1`,
		`purewrt_subscription_expiry_timestamp_seconds{subscription="sub"} `,
		`purewrt_subscription_used_bytes{subscription="sub"} 20`,
		`purewrt_subscription_total_bytes{subscription="sub"} 100`,
		"purewrt_zapret_strategies_active 0",
	} {
		if !strings.Contains(out, name) {
			t.Fatalf("missing live metric %q:\n%s", name, out)
		}
	}
}

func TestServiceMetricsExposeDownAndStartTime(t *testing.T) {
	r := metrics.NewRegistry()
	recordServiceMetrics(r, []ServiceStatus{
		{Name: "mihomo", PID: 7, StartedUnix: 1234},
		{Name: "dnsmasq"},
		{Name: "purewrt-api", PID: 8, StartedUnix: 2345},
	}, true)
	out := r.Render()
	for _, want := range []string{
		`purewrt_service_up{service="mihomo"} 1`,
		`purewrt_service_up{service="dnsmasq"} 0`,
		`purewrt_service_start_time_seconds{service="mihomo"} 1234`,
		`purewrt_mihomo_controller_up 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `purewrt_service_start_time_seconds{service="dnsmasq"}`) {
		t.Fatalf("stopped service rendered a bogus start time:\n%s", out)
	}
}

func TestZapretInstancesJoinServiceUpFamily(t *testing.T) {
	original := zapretProcs
	zapretProcs = func() map[int]int { return map[int]int{200: 424242} }
	defer func() { zapretProcs = original }()
	c := config.Default()
	c.Sections = []config.Section{{Name: "blocked", Enabled: true, Action: "zapret", ZapretStrategies: []string{"tls"}}}
	c.ZapretStrategies = []config.ZapretStrategy{{Name: "tls", Enabled: true, QueueNum: 200}}
	statuses := zapretServiceStatuses(c)
	if len(statuses) != 1 || statuses[0].Name != "zapret/tls" || statuses[0].PID != 424242 {
		t.Fatalf("unexpected zapret service statuses: %+v", statuses)
	}
	r := metrics.NewRegistry()
	recordServiceMetrics(r, statuses, true)
	if out := r.Render(); !strings.Contains(out, `purewrt_service_up{service="zapret/tls"} 1`) {
		t.Fatalf("zapret instance missing from service family:\n%s", out)
	}
}

func TestMeshFriendMetricsCoverLinkLatencyAndExitHealth(t *testing.T) {
	c := config.Default()
	c.Mesh.Enabled = true
	c.Mesh.NetworkName = "friends"
	c.MeshPeers = []config.MeshPeer{
		{HWID: "purewrt-bbbbbbbbbbbbbbbbbbbbbbbb", Name: "beta", Enabled: true, OverlayIP: "10.1.0.2", ExitOffered: true},
		{HWID: "purewrt-cccccccccccccccccccccccc", Name: "gamma", Enabled: true, OverlayIP: "10.1.0.3", ExitOffered: true},
	}
	snapshot := liveMeshSnapshot{
		overlayOK: true,
		peers: map[string]mesh.OverlayPeer{
			"10.1.0.2": {IPv4: "10.1.0.2", Relay: true, LatencyMs: 42.5},
		},
		exitOK: true,
		exits: map[string]mihomoapi.Proxy{
			"friend_bbbbbbbbbbbbbbbbbbbbbbbb": {Alive: true, Delay: 91},
			"friend_cccccccccccccccccccccccc": {Alive: false},
		},
	}
	r := metrics.NewRegistry()
	recordMeshMetrics(r, c, snapshot)
	out := r.Render()
	for _, want := range []string{
		`purewrt_mesh_friends{state="configured"} 2`,
		`purewrt_mesh_friends{state="live"} 1`,
		`purewrt_mesh_friends{state="exit_healthy"} 1`,
		`purewrt_mesh_friend_link_up{friend="beta",hwid="purewrt-bbbbbbbbbbbbbbbbbbbbbbbb"} 1`,
		`purewrt_mesh_friend_link_info{friend="beta",hwid="purewrt-bbbbbbbbbbbbbbbbbbbbbbbb",link="relay"} 1`,
		`purewrt_mesh_friend_latency_milliseconds{friend="beta",hwid="purewrt-bbbbbbbbbbbbbbbbbbbbbbbb"} 42.5`,
		`purewrt_mesh_friend_exit_up{friend="beta",hwid="purewrt-bbbbbbbbbbbbbbbbbbbbbbbb"} 1`,
		`purewrt_mesh_friend_exit_delay_milliseconds{friend="beta",hwid="purewrt-bbbbbbbbbbbbbbbbbbbbbbbb"} 91`,
		`purewrt_mesh_friend_link_up{friend="gamma",hwid="purewrt-cccccccccccccccccccccccc"} 0`,
		`purewrt_mesh_friend_exit_up{friend="gamma",hwid="purewrt-cccccccccccccccccccccccc"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

func TestUpgradeAvailableMetrics(t *testing.T) {
	r := metrics.NewRegistry()
	recordUpgradeMetrics(r, []PackageUpdate{
		{Name: "purewrt", Installed: "1.0-r0", Available: "1.1-r0", UpgradeAvailable: true},
		{Name: "zapret", Installed: "2.0-r0"},
	}, true, time.Unix(1234, 0))
	out := r.Render()
	for _, want := range []string{
		`purewrt_upgrade_check_success 1`,
		`purewrt_upgrade_check_timestamp_seconds 1234`,
		`purewrt_upgrade_available{package="purewrt"} 1`,
		`purewrt_upgrade_available{package="zapret"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "purewrt_upgrade_info") || strings.Contains(out, `installed="`) || strings.Contains(out, `available="`) {
		t.Fatalf("upgrade metrics must not expose versions as labels:\n%s", out)
	}
}

func TestNFTMetricTargetsUseDynamicDNSsets(t *testing.T) {
	c := config.Default()
	c.Settings.IPv6 = false
	c.Sections = []config.Section{{Name: "media", Enabled: true, Action: "proxy"}}
	targets := nftMetricTargets(c)
	found := false
	for _, target := range targets {
		if target.section == "media" && target.family == "ipv4" && target.set == "dns_proxy_media4" {
			found = true
		}
		if target.section == "media" && target.family == "ipv6" {
			t.Fatal("IPv6 target emitted while IPv6 is disabled")
		}
	}
	if !found {
		t.Fatalf("media dynamic set missing: %+v", targets)
	}
}

func TestNFTMetricTargetKeyChangesWithCollectedSets(t *testing.T) {
	first := []nftMetricTarget{{set: "dns_direct4"}}
	second := []nftMetricTarget{{set: "dns_direct4"}, {set: "dns_media4"}}
	if nftMetricTargetsKey(first) == nftMetricTargetsKey(second) {
		t.Fatal("cache key did not change when a set was added")
	}
}
