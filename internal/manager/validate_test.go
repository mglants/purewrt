package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestValidateZapretProfileMarkOverlapsPureWRTMask(t *testing.T) {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "bad", Enabled: true, Interfaces: []string{"wan"}, FwMark: "0x1"}}
	err := validateZapretProfileMarks(c)
	if err == nil || !strings.Contains(err.Error(), "PureWRT") {
		t.Fatalf("expected PureWRT mark conflict, got %v", err)
	}
}

func TestZapretStrategyQueueAutoDerivation(t *testing.T) {
	c := config.Default()
	c.ZapretStrategies = []config.ZapretStrategy{
		{Name: "auto_a", Enabled: true},
		{Name: "manual", Enabled: true, QueueNum: 250},
		{Name: "auto_b", Enabled: true},
	}
	if got := c.NormalizeZapretStrategyAt(c.ZapretStrategies[0], 0).QueueNum; got != 200 {
		t.Fatalf("first auto queue = %d, want 200", got)
	}
	if got := c.NormalizeZapretStrategyAt(c.ZapretStrategies[1], 1).QueueNum; got != 250 {
		t.Fatalf("manual queue = %d, want 250", got)
	}
	if got := c.NormalizeZapretStrategyAt(c.ZapretStrategies[2], 2).QueueNum; got != 202 {
		t.Fatalf("third auto queue = %d, want 202", got)
	}
}

func TestValidateRejectsZapretAutoQueueCollision(t *testing.T) {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, Interfaces: []string{"wan"}, FwMark: "0x40000000"}}
	c.ZapretStrategies = []config.ZapretStrategy{
		{Name: "auto", Enabled: true, Profile: "wan", QueueNum: 0, Protocols: []string{"tcp"}, TCPPorts: "443"},
		{Name: "manual", Enabled: true, Profile: "wan", QueueNum: 200, Protocols: []string{"tcp"}, TCPPorts: "443"},
	}
	if err := validateZapretStrategies(c); err == nil || !strings.Contains(err.Error(), "duplicates queue_num") {
		t.Fatalf("expected queue collision, got %v", err)
	}
}

func TestValidateCommandRejectsZapretMarkConflict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "purewrt")
	data := "config main 'settings'\n    option fwmark '0x1'\n    option fwmark_mask '0xff'\n\nconfig zapret_profile 'bad'\n    option enabled '1'\n    list interface 'wan'\n    option fwmark '0x1'\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	err := (Manager{ConfigPath: path}).Validate()
	if err == nil || !strings.Contains(err.Error(), "zapret profile") {
		t.Fatalf("expected zapret validation error, got %v", err)
	}
}

func TestValidateRejectsZapretOnProxySection(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{
		Name: "media", Enabled: true, Action: "proxy",
		TPROXYPort: 7894, IPv4Enabled: true, IPv6Enabled: true,
		ZapretStrategies: []string{"youtube_tcp"},
	}}
	err := validateConfigHardening(c)
	if err == nil || !strings.Contains(err.Error(), "zapret_strategies") {
		t.Fatalf("expected zapret-on-proxy validation error, got %v", err)
	}
}

func TestValidateRejectsZapretOnVPNSection(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{
		Name: "vpn_only", Enabled: true, Action: "proxy",
		TPROXYPort: 7894, IPv4Enabled: true, IPv6Enabled: true,
		ZapretStrategies: []string{"youtube_tcp"},
	}}
	err := validateConfigHardening(c)
	if err == nil || !strings.Contains(err.Error(), "zapret_strategies") {
		t.Fatalf("expected zapret-on-vpn validation error, got %v", err)
	}
}

func TestValidateAcceptsZapretOnZapretAction(t *testing.T) {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, Network: "auto", Interfaces: []string{"wan"}, FwMark: "0x40000000", NFQWSBin: "/usr/libexec/zapret/nfqws2"}}
	c.ZapretStrategies = []config.ZapretStrategy{{Name: "youtube_tcp", Enabled: true, Profile: "wan", Protocols: []string{"tcp"}, TCPPorts: "443", QueueNum: 200, Params: "--lua-desync=multisplit"}}
	c.Sections = []config.Section{{
		Name: "media", Enabled: true, Action: "zapret",
		TPROXYPort: 7894, IPv4Enabled: true, IPv6Enabled: true,
		ZapretStrategies: []string{"youtube_tcp"},
	}}
	if err := validateConfigHardening(c); err != nil {
		t.Fatalf("zapret-on-zapret-action should be allowed: %v", err)
	}
}

func TestValidateRejectsUnsafeSectionName(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{Name: "bad-name", Enabled: true, Action: "proxy", TPROXYPort: 7893, IPv4Enabled: true, IPv6Enabled: true}}
	err := validateConfigHardening(c)
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("expected unsafe section validation error, got %v", err)
	}
}

func TestValidateAllowsDisabledProxySectionWithoutPort(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{Name: "fallback", Enabled: false, Action: "proxy", TPROXYPort: 0}}
	if err := validateConfigHardening(c); err != nil {
		t.Fatalf("disabled helper section must not require tproxy_port: %v", err)
	}
}

func TestValidateRejectsInvalidPortsAndMarks(t *testing.T) {
	c := config.Default()
	c.Sections[0].TPROXYPort = 70000
	if err := validateConfigHardening(c); err == nil || !strings.Contains(err.Error(), "tproxy_port") {
		t.Fatalf("expected tproxy port validation error, got %v", err)
	}
	c = config.Default()
	c.Settings.FwMark = "not-hex"
	if err := validateConfigHardening(c); err == nil || !strings.Contains(err.Error(), "fwmark") {
		t.Fatalf("expected fwmark validation error, got %v", err)
	}
}

func TestValidateRejectsUnsafeProviderPathAndInterface(t *testing.T) {
	c := config.Default()
	c.RuleProviders = []config.RuleProvider{{Name: "rules", Enabled: true, Path: "/etc/purewrt/../bad", Section: "common"}}
	if err := validateConfigHardening(c); err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("expected provider path validation error, got %v", err)
	}
	c = config.Default()
	c.VPNs = []config.VPN{{Name: "vpn", Enabled: true, Interface: "wg0;reboot"}}
	if err := validateConfigHardening(c); err == nil || !strings.Contains(err.Error(), "interface") {
		t.Fatalf("expected interface validation error, got %v", err)
	}
}

func TestValidateRejectsInvalidDNSListenAndPriority(t *testing.T) {
	c := config.Default()
	c.DNS.Listen = "127.0.0.1"
	if err := validateConfigHardening(c); err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("expected DNS listen validation error, got %v", err)
	}
	c = config.Default()
	c.Settings.IPRulePriority = "999999"
	if err := validateConfigHardening(c); err == nil || !strings.Contains(err.Error(), "ip_rule_priority") {
		t.Fatalf("expected priority validation error, got %v", err)
	}
}

func TestValidateRejectsReservedProxyProviderName(t *testing.T) {
	c := config.Default()
	c.ProxyProviders = []config.ProxyProvider{{Name: "default", Enabled: true, URL: "https://example.com/sub", Path: "/etc/purewrt/providers/main.yaml"}}
	err := validateConfigHardening(c)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved provider name error, got %v", err)
	}
}

func TestValidateRejectsDuplicateProxyProviderNames(t *testing.T) {
	c := config.Default()
	c.ProxyProviders = []config.ProxyProvider{
		{Name: "main", Enabled: true, URL: "https://example.com/a", Path: "/etc/purewrt/providers/a.yaml"},
		{Name: "main", Enabled: true, URL: "https://example.com/b", Path: "/etc/purewrt/providers/b.yaml"},
	}
	err := validateConfigHardening(c)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate provider name error, got %v", err)
	}
}

func TestValidateRejectsReservedProxyGroupNames(t *testing.T) {
	for _, group := range []string{"GLOBAL", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "DNSProxy", "NetCheckProbe", "MeshExit", "Friends"} {
		c := config.Default()
		c.Sections = []config.Section{{Name: "media", Enabled: true, Action: "proxy", TPROXYPort: 7894, ProxyGroup: group, IPv4Enabled: true, IPv6Enabled: true}}
		err := validateConfigHardening(c)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("group %q: expected reserved group name error, got %v", group, err)
		}
	}
}

func TestValidateRejectsUnsafeMeshDeviceName(t *testing.T) {
	c := config.Default()
	c.Mesh.Enabled = true
	c.Mesh.NetworkName = "pwmesh-x" // MeshActive
	c.Mesh.DeviceName = `pw"m0`     // would break the quoted nft iifname
	err := validateConfigHardening(c)
	if err == nil || !strings.Contains(err.Error(), "unsafe device name") {
		t.Fatalf("expected unsafe mesh device name error, got %v", err)
	}
	c.Mesh.DeviceName = "pwmesh0"
	if err := validateConfigHardening(c); err != nil {
		t.Fatalf("safe mesh device name rejected: %v", err)
	}
}

func TestValidateRejectsDuplicateProxyGroupNames(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{
		{Name: "media", Enabled: true, Action: "proxy", TPROXYPort: 7894, ProxyGroup: "Media", IPv4Enabled: true, IPv6Enabled: true},
		{Name: "ai", Enabled: true, Action: "proxy", TPROXYPort: 7895, ProxyGroup: "Media", IPv4Enabled: true, IPv6Enabled: true},
	}
	err := validateConfigHardening(c)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate group name error, got %v", err)
	}
}

func TestValidateAllowsDuplicateGroupOnDisabledSection(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{
		{Name: "media", Enabled: true, Action: "proxy", TPROXYPort: 7894, ProxyGroup: "Media", IPv4Enabled: true, IPv6Enabled: true},
		{Name: "old", Enabled: false, Action: "proxy", TPROXYPort: 7895, ProxyGroup: "Media", IPv4Enabled: true, IPv6Enabled: true},
	}
	if err := validateConfigHardening(c); err != nil {
		t.Fatalf("disabled section duplicate group should pass, got %v", err)
	}
}
