package generator

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// zapretClaimsConfig builds a config with one enabled zapret profile and the
// given strategies, and a zapret section "zap" referencing them by name.
func zapretClaimsConfig(strategies ...config.ZapretStrategy) config.Config {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, FwMark: "0x40000000", QueueNum: 200}}
	names := make([]string, 0, len(strategies))
	for i := range strategies {
		strategies[i].Profile = "wan"
		strategies[i].Enabled = true
		names = append(names, strategies[i].Name)
	}
	c.ZapretStrategies = strategies
	c.Sections = append(c.Sections, config.Section{
		Name: "zap", Enabled: true, Action: "zapret", IPv4Enabled: true, IPv6Enabled: true,
		ZapretStrategies: names,
	})
	return c
}

func TestZapretSectionPortClaimsUnion(t *testing.T) {
	c := zapretClaimsConfig(
		config.ZapretStrategy{Name: "quic", Protocols: []string{"udp"}, UDPPorts: "443"},
		config.ZapretStrategy{Name: "quic2", Protocols: []string{"udp"}, UDPPorts: "443,50000-50099"},
		config.ZapretStrategy{Name: "tls", Protocols: []string{"tcp"}, TCPPorts: "443"},
	)
	s, _ := c.SectionByName("zap")
	claims := zapretSectionPortClaims(c, s)
	udp, ok := claims["udp"]
	if !ok || udp.all || udp.ports != "443, 50000-50099" {
		t.Fatalf("udp claim = %+v ok=%v, want union without duplicates", udp, ok)
	}
	tcp, ok := claims["tcp"]
	if !ok || tcp.all || tcp.ports != "443" {
		t.Fatalf("tcp claim = %+v ok=%v", tcp, ok)
	}
}

func TestZapretSectionPortClaimsEmptyPortsCoverProtocol(t *testing.T) {
	c := zapretClaimsConfig(
		config.ZapretStrategy{Name: "alltcp", Protocols: []string{"tcp"}, TCPPorts: ""},
		config.ZapretStrategy{Name: "sometcp", Protocols: []string{"tcp"}, TCPPorts: "443"},
	)
	s, _ := c.SectionByName("zap")
	claims := zapretSectionPortClaims(c, s)
	tcp, ok := claims["tcp"]
	if !ok || !tcp.all {
		t.Fatalf("empty port list on an enabled protocol must widen the claim to the whole protocol, got %+v ok=%v", tcp, ok)
	}
	if _, ok := claims["udp"]; ok {
		t.Fatal("udp never enabled, must not be claimed")
	}
}

func TestZapretSectionPortClaimsDisabledOrMissingStrategies(t *testing.T) {
	c := zapretClaimsConfig(config.ZapretStrategy{Name: "quic", Protocols: []string{"udp"}, UDPPorts: "443"})
	c.ZapretStrategies[0].Enabled = false // ZapretStrategyByName filters disabled
	s, _ := c.SectionByName("zap")
	if claims := zapretSectionPortClaims(c, s); len(claims) != 0 {
		t.Fatalf("disabled strategy must claim nothing, got %+v", claims)
	}
}

// extractPreroutingChain returns the prerouting chain body. The generator
// emits `chain prerouting {` ... up to the next `}` at two-space indent.
func extractPreroutingChain(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "chain prerouting {")
	if i < 0 {
		t.Fatalf("no prerouting chain in:\n%s", out)
	}
	j := strings.Index(out[i:], "\n  }")
	if j < 0 {
		t.Fatalf("unterminated prerouting chain in:\n%s", out)
	}
	return out[i : i+j]
}

func TestNFTZapretPreroutingPortScopedReturn(t *testing.T) {
	c := zapretClaimsConfig(
		config.ZapretStrategy{Name: "quic", Protocols: []string{"udp"}, UDPPorts: "443"},
	)
	chain := extractPreroutingChain(t, string(NFTables(c)))
	want := `ip daddr @proxy_zap4 meta l4proto udp udp dport { 443 } counter name "proxy_zap4" return`
	if !strings.Contains(chain, want) {
		t.Fatalf("missing port-scoped return %q in:\n%s", want, chain)
	}
	if strings.Contains(chain, "ip daddr @proxy_zap4 meta l4proto tcp") {
		t.Fatalf("tcp never covered by the strategy, must not be claimed:\n%s", chain)
	}
	// The claim is port-scoped, never a blanket return on the set.
	if strings.Contains(chain, `ip daddr @proxy_zap4 counter name "proxy_zap4" return`) {
		t.Fatalf("blanket return must not be emitted in prerouting:\n%s", chain)
	}
}

func TestNFTZapretPreroutingReturnRespectsSectionOrder(t *testing.T) {
	c := zapretClaimsConfig(
		config.ZapretStrategy{Name: "quic", Protocols: []string{"udp"}, UDPPorts: "443"},
	)
	// Move the zapret section to the FRONT so it outranks the default
	// proxy sections; its return must appear before their tproxy rules.
	zap := c.Sections[len(c.Sections)-1]
	c.Sections = append([]config.Section{zap}, c.Sections[:len(c.Sections)-1]...)
	chain := extractPreroutingChain(t, string(NFTables(c)))
	ret := strings.Index(chain, `udp dport { 443 } counter name "proxy_zap4" return`)
	tproxy := strings.Index(chain, "tproxy ip to :")
	if ret < 0 || tproxy < 0 {
		t.Fatalf("expected both a zapret return and a tproxy rule:\n%s", chain)
	}
	if ret > tproxy {
		t.Fatalf("zapret section listed first must emit its return before proxy tproxy rules (ret=%d tproxy=%d):\n%s", ret, tproxy, chain)
	}
}

func TestNFTZapretOutputPortScopedReturn(t *testing.T) {
	c := zapretClaimsConfig(
		config.ZapretStrategy{Name: "quic", Protocols: []string{"udp"}, UDPPorts: "443"},
	)
	c.Settings.RouterOutputProxy = true
	chain := extractOutputChain(string(NFTables(c)))
	want := `ip daddr @proxy_zap4 meta l4proto udp udp dport { 443 } counter name "proxy_zap4" return`
	if !strings.Contains(chain, want) {
		t.Fatalf("missing port-scoped return %q in OUTPUT:\n%s", want, chain)
	}
	if strings.Contains(chain, `ip daddr @proxy_zap4 counter name "proxy_zap4" return`) {
		t.Fatalf("blanket zapret return must be gone from OUTPUT:\n%s", chain)
	}
	if strings.Contains(chain, "@proxy_zap4 meta mark set") {
		t.Fatalf("zapret set must not be marked in OUTPUT:\n%s", chain)
	}
}

func TestNFTZapretPreroutingNoStrategiesClaimsNothing(t *testing.T) {
	c := config.Default()
	c.Sections = append(c.Sections, config.Section{
		Name: "zap", Enabled: true, Action: "zapret", IPv4Enabled: true,
	})
	chain := extractPreroutingChain(t, string(NFTables(c)))
	if strings.Contains(chain, `counter name "proxy_zap4" return`) {
		t.Fatalf("a zapret section without strategies covers nothing and must not claim:\n%s", chain)
	}
}

// Full dedup gives a domain to exactly one set, which breaks port-scoped
// zapret claims in both directions: zapret wins → the proxy set never sees
// the host, so non-covered ports can't fall through; proxy wins → the
// zapret set is empty. Providers feeding zapret sections are exempt: they
// neither claim nor honor claims (mirrors TestRuleProviderPriorityClaims*).
func TestFullDedupExemptsZapretSectionProviders(t *testing.T) {
	dir := t.TempDir()
	zapPath := filepath.Join(dir, "zap.list")
	proxyPath := filepath.Join(dir, "proxy.list")
	if err := os.WriteFile(zapPath, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxyPath, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Settings.Workdir = dir
	c.Settings.RuleDedupMode = "full"
	c.Sections = append(c.Sections, config.Section{Name: "zap", Enabled: true, Action: "zapret", IPv4Enabled: true})
	c.RuleProviders = []config.RuleProvider{
		// Zapret provider first: under plain full dedup it would claim
		// example.com and starve the proxy set.
		{Name: "zap", Enabled: true, Format: "text", Path: zapPath, Section: "zap", Priority: 10},
		{Name: "proxy", Enabled: true, Format: "text", Path: proxyPath, Section: "common", Priority: 100},
	}
	var dns bytes.Buffer
	if err := streamRuleOutputs(c, generationSinks{dns: &dns}); err != nil {
		t.Fatal(err)
	}
	out := dns.String()
	if !strings.Contains(out, "#dns_proxy_zap4") {
		t.Fatalf("zapret set must contain the host:\n%s", out)
	}
	if !strings.Contains(out, "#dns_proxy_common4") {
		t.Fatalf("proxy set must ALSO contain the host (fall-through target):\n%s", out)
	}
}
