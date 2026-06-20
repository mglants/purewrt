package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfigRoundTripPreservesKeyFields(t *testing.T) {
	c := Default()
	c.Settings.ConfigVersion = 7
	c.Settings.DNSBackend = "dnsmasq"
	c.Settings.FirewallBackend = "nftables"
	c.Settings.AutoReload = false
	c.Settings.SafeApply = false
	c.Settings.RollbackOnFail = false
	c.Settings.ApplyBackupMaxBytes = 654321
	c.Settings.LogLevel = "debug"
	c.Settings.ResourceProfile = "low"
	c.Settings.CacheMode = "tmpfs"
	c.Settings.CacheDir = "/tmp/purewrt/cache"
	c.Settings.ArtifactCacheMode = "off"
	c.Settings.ArtifactCacheMaxBytes = 1234567
	c.Settings.ArtifactCacheMaxEntries = 1234
	c.Settings.RuleDedupMode = "section"
	c.Settings.MihomoGeodataEnabled = true
	c.Settings.RouterOutputProxy = true
	c.Settings.CgroupV2Path = "services/purewrt-test/inst"
	c.Settings.WizardVPNPending = true
	c.Settings.WizardZapretPending = true
	c.Settings.IPv6WANInterfaces = []string{"wan6", "wan2_6"}
	c.Settings.MihomoAllowLAN = true
	c.Settings.DefaultListsBaseURL = "https://example.com/lists/"
	c.Settings.APIListen = []string{"0.0.0.0:8787", "[::1]:8787"}
	c.Settings.NotifyURL = "https://ntfy.example.com/purewrt"
	c.Settings.NotifyFormat = "ntfy"
	c.Settings.NotifyOn = []string{"update_failure", "mihomo_revert"}
	c.DNS.DoHPolicy = "direct"
	c.DNS.FakeIP = true
	c.ZapretProfiles = []ZapretProfile{{Name: "wan_a", Enabled: true, Network: "wan_a", Interfaces: []string{"wan_a"}, FwMark: "0x40000001", NFQWSBin: "/usr/bin/nfqws", TPWSBin: "/usr/bin/tpws"}}
	c.ZapretStrategies = []ZapretStrategy{{Name: "zap_a", Enabled: true, Profile: "wan_a", QueueNum: 201, Protocols: []string{"tcp", "udp"}, TCPPorts: "443", UDPPorts: "443", TCPPktOut: 15, TCPPktIn: 6, UDPPktOut: 9, UDPPktIn: 3, Preset: "custom", Params: "--strategy-a", FakeDir: "/usr/lib/zapret/fake"}}
	c.Subscriptions = []Subscription{{Name: "sub", Enabled: true, URL: "https://example.com/sub.yaml", Mode: "auto", PresetIfNoRules: "minimal", ImportRulesOnLowResource: true, AutoApply: true, Interval: 123, HWID: "sub-hwid", DeviceName: "router", UserAgent: "sub-agent", Headers: []string{"X-Sub: yes"}}}
	c.ProxyProviders = []ProxyProvider{{Name: "pp", Enabled: true, Type: "http", URL: "https://example.com/pp.yaml", Interval: 456, Path: "/tmp/pp.yaml", HealthCheck: true, HealthCheckURL: "https://example.com/204", HealthCheckInterval: 30, Mwan3Policy: "wan", HWID: "pp-hwid", DeviceName: "pp-device", UserAgent: "pp-agent", Headers: []string{"X-PP: yes"}}}
	c.RuleProviders = []RuleProvider{{Name: "rp", Enabled: true, Behavior: "domain", Format: "text", ParseMode: "native_import", URL: "https://example.com/rp.txt", Interval: 789, Path: "/tmp/rp.txt", Section: "common", HWID: "rp-hwid", DeviceName: "rp-device", UserAgent: "rp-agent", Headers: []string{"X-RP: yes"}}}
	c.Devices = []Device{{Name: "pixel-7", MAC: "aa:bb:cc:dd:ee:ff", Section: "media", Enabled: true}, {Name: "tv", MAC: "11:22:33:44:55:66", Section: "", Enabled: false}}
	c.Sections[0].SourceCIDR4 = []string{"10.13.14.0/24"}
	c.Sections[0].SourceCIDR6 = []string{"fd00::1/128"}
	c.Sections[0].ProxyGroupType = "load-balance"
	c.Sections[0].ProxyFilter = "♾️"
	c.Sections[0].ProxyExcludeFilter = "🇷🇺|NoGemini"
	c.Sections[0].ProxyStrategy = "sticky-sessions"
	c.Sections[0].ProxyHealthCheckURL = "https://cp.cloudflare.com/generate_204"
	c.Sections[0].ProxyHealthCheckInterval = 600
	c.Sections[0].UserOverriddenProxyGroup = true
	c.Sections[0].ZapretStrategies = []string{"zap_a"}
	c.Bypass = Bypass{Name: "bypass", SourceCIDR4: []string{"172.16.10.11"}, SourceCIDR6: []string{"fd00::2/128"}}
	c.OONI = OONI{Enabled: true, Upload: false, Schedule: "30 */4 * * *", Proxy: "socks5://127.0.0.1:7890", Home: "/srv/ooni", User: "ooni"}

	path := filepath.Join(t.TempDir(), "purewrt")
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(written), "config zapret_profile '") {
		t.Fatalf("zapret profile must be anonymous for UCI interface names with dash, got:\n%s", written)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Settings, c.Settings) {
		t.Fatalf("settings mismatch\ngot:  %#v\nwant: %#v", got.Settings, c.Settings)
	}
	if !reflect.DeepEqual(got.DNS, c.DNS) {
		t.Fatalf("dns mismatch\ngot:  %#v\nwant: %#v", got.DNS, c.DNS)
	}
	if !reflect.DeepEqual(got.ZapretProfiles, c.ZapretProfiles) {
		t.Fatalf("zapret profiles mismatch\ngot:  %#v\nwant: %#v", got.ZapretProfiles, c.ZapretProfiles)
	}
	if !reflect.DeepEqual(got.ZapretStrategies, c.ZapretStrategies) {
		t.Fatalf("zapret strategies mismatch\ngot:  %#v\nwant: %#v", got.ZapretStrategies, c.ZapretStrategies)
	}
	if !reflect.DeepEqual(got.Subscriptions, c.Subscriptions) {
		t.Fatalf("subscriptions mismatch\ngot:  %#v\nwant: %#v", got.Subscriptions, c.Subscriptions)
	}
	if !reflect.DeepEqual(got.ProxyProviders, c.ProxyProviders) {
		t.Fatalf("proxy providers mismatch\ngot:  %#v\nwant: %#v", got.ProxyProviders, c.ProxyProviders)
	}
	if !reflect.DeepEqual(got.RuleProviders, c.RuleProviders) {
		t.Fatalf("rule providers mismatch\ngot:  %#v\nwant: %#v", got.RuleProviders, c.RuleProviders)
	}
	if !reflect.DeepEqual(got.Devices, c.Devices) {
		t.Fatalf("devices mismatch\ngot:  %#v\nwant: %#v", got.Devices, c.Devices)
	}
	if !reflect.DeepEqual(got.Sections, c.Sections) {
		t.Fatalf("sections mismatch\ngot:  %#v\nwant: %#v", got.Sections, c.Sections)
	}
	if !reflect.DeepEqual(got.Bypass, c.Bypass) {
		t.Fatalf("bypass mismatch\ngot:  %#v\nwant: %#v", got.Bypass, c.Bypass)
	}
	if !reflect.DeepEqual(got.OONI, c.OONI) {
		t.Fatalf("ooni mismatch\ngot:  %#v\nwant: %#v", got.OONI, c.OONI)
	}
}

func TestUpsertSectionProxyGroupRespectsManualOverride(t *testing.T) {
	c := Default()
	c.Sections = []Section{{Name: "media", ProxyGroup: "Media", ProxyGroupType: "url-test", ProxyFilter: "old", ProxyExcludeFilter: "old-exclude", ProxyStrategy: "sticky-sessions", ProxyHealthCheckURL: "https://old.example/204", ProxyHealthCheckInterval: 111, UserOverriddenProxyGroup: true}}
	c = UpsertSectionProxyGroup(c, Section{Name: "media", ProxyGroup: "Media", ProxyGroupType: "load-balance", ProxyFilter: "♾️", ProxyExcludeFilter: "🇷🇺", ProxyStrategy: "round-robin", ProxyHealthCheckURL: "https://cp.cloudflare.com/generate_204", ProxyHealthCheckInterval: 300})
	if got := c.Sections[0]; got.ProxyGroupType != "url-test" || got.ProxyFilter != "old" || got.ProxyExcludeFilter != "old-exclude" || got.ProxyStrategy != "sticky-sessions" || got.ProxyHealthCheckURL != "https://old.example/204" || got.ProxyHealthCheckInterval != 111 {
		t.Fatalf("manual section was overwritten: %+v", got)
	}

	c.Sections[0].UserOverriddenProxyGroup = false
	c = UpsertSectionProxyGroup(c, Section{Name: "media", ProxyGroup: "Media", ProxyGroupType: "load-balance", ProxyFilter: "♾️", ProxyExcludeFilter: "🇷🇺", ProxyStrategy: "round-robin", ProxyHealthCheckURL: "https://cp.cloudflare.com/generate_204", ProxyHealthCheckInterval: 300})
	if got := c.Sections[0]; got.ProxyGroupType != "load-balance" || got.ProxyFilter != "♾️" || got.ProxyExcludeFilter != "🇷🇺" || got.ProxyStrategy != "round-robin" || got.ProxyHealthCheckURL != "https://cp.cloudflare.com/generate_204" || got.ProxyHealthCheckInterval != 300 {
		t.Fatalf("default section was not updated: %+v", got)
	}
}
