package generator

import (
	"bytes"
	"github.com/purewrt/purewrt/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSectionPortsFallThroughToProxy(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{
		{Name: "fallback", Enabled: true, IPv4Enabled: true, IPv6Enabled: true, Action: "proxy", Priority: 20, TPROXYPort: 7893},
		{Name: "game", Enabled: true, IPv4Enabled: true, IPv6Enabled: true, Action: "proxy", TPROXYPort: 7894, Priority: 10, MatchProtocol: "udp", DestinationPorts: "7770,10000-11000"},
	}
	c.Sections[1].SourceCIDR4 = []string{"192.0.2.10/32"}
	c.Devices = []config.Device{{Name: "test", MAC: "02:00:00:00:00:01", Enabled: true, Section: "game"}}
	nft := string(NFTables(c))
	for _, family := range []struct{ ip, suffix string }{{"ip", "4"}, {"ip6", "6"}} {
		first := family.ip + " daddr @proxy_game" + family.suffix + " meta l4proto udp udp dport { 7770, 10000-11000 }"
		second := family.ip + " daddr @proxy_fallback" + family.suffix + " meta l4proto tcp"
		if strings.Count(nft, first) != 2 || strings.Index(nft, first) > strings.Index(nft, second) {
			t.Fatalf("missing or unordered forwarding/output rules: %s\n%s", first, nft)
		}
		if !strings.Contains(nft, "set proxy_game"+family.suffix+" {") {
			t.Fatal("missing section set")
		}
		if strings.Contains(nft, family.ip+" daddr @proxy_game"+family.suffix+" counter") {
			t.Fatal("unrestricted rule bypasses ports")
		}
	}
	for _, match := range []string{"ether saddr { 02:00:00:00:00:01 }", "ip saddr 192.0.2.10/32"} {
		if !strings.Contains(nft, match+" meta l4proto udp udp dport { 7770, 10000-11000 } meta mark set meta mark | 0x1 tproxy ip to :7894 accept") {
			t.Fatalf("missing scoped client match %s", match)
		}
	}
}

func TestSectionMatchAllActions(t *testing.T) {
	for _, action := range []string{"proxy"} {
		t.Run(action, func(t *testing.T) {
			c := config.Default()
			c.Sections = []config.Section{{Name: "filtered", Enabled: true, IPv4Enabled: true, IPv6Enabled: true, Action: action, MatchProtocol: "udp", DestinationPorts: "10000-11000", TPROXYPort: 7893}}
			nft := string(NFTables(c))
			if strings.Contains(nft, "@proxy_filtered4 meta l4proto tcp") {
				t.Fatal("TCP must fall through")
			}
			if !strings.Contains(nft, "@proxy_filtered4 meta l4proto udp udp dport { 10000-11000 }") {
				t.Fatal("missing UDP restriction")
			}
		})
	}
}

func TestZapretSectionScopeMatchesQueue(t *testing.T) {
	c := zapretClaimsConfig(config.ZapretStrategy{Name: "combined", Protocols: []string{"tcp", "udp"}, TCPPorts: "443", UDPPorts: "10000-11000", UDPPktOut: 10})
	s, _ := c.SectionByName("zap")
	s.MatchProtocol = "udp"
	s.DestinationPorts = "10500-12000"
	claims := zapretSectionPortClaims(c, s)
	if len(claims) != 1 || claims["udp"].ports != "10500-11000" {
		t.Fatalf("claims: %+v", claims)
	}
	var q strings.Builder
	writeZapretPostroutingRules(&q, c, s, true)
	if strings.Contains(q.String(), "meta l4proto tcp") || !strings.Contains(q.String(), "udp dport { 10500-11000 }") {
		t.Fatalf("queue scope: %s", q.String())
	}
	s.DestinationPorts = "53"
	if len(zapretSectionPortClaims(c, s)) != 0 {
		t.Fatal("empty intersection must claim nothing")
	}
	q.Reset()
	writeZapretPostroutingRules(&q, c, s, true)
	if q.Len() != 0 {
		t.Fatal("empty intersection must queue nothing")
	}
}

func TestOverlappingProvidersKeepEverySection(t *testing.T) {
	for _, mode := range []string{"", "native_import"} {
		t.Run(mode, func(t *testing.T) {
			c := config.Default()
			c.Settings.ResourceProfile = "high"
			c.Settings.Workdir = t.TempDir()
			c.Sections = []config.Section{{Name: "game", Enabled: true, IPv4Enabled: true, IPv6Enabled: true, Action: "proxy", TPROXYPort: 7894}, {Name: "fallback", Enabled: true, IPv4Enabled: true, IPv6Enabled: true, Action: "proxy"}}
			data := "example.com\nexample.com\n203.0.113.0/24\n2001:db8::/32\n"
			if mode != "" {
				data = "example.com\nexample.com\n@cidr\n203.0.113.0/24\n2001:db8::/32\n"
			}
			path := filepath.Join(t.TempDir(), "provider.txt")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			for _, sec := range c.Sections {
				for _, suffix := range []string{"a", "b"} {
					c.RuleProviders = append(c.RuleProviders, config.RuleProvider{Name: sec.Name + suffix, Section: sec.Name, Enabled: true, Format: "text", ParseMode: mode, Path: path})
				}
			}
			var dns, sets bytes.Buffer
			if err := streamRuleOutputs(c, generationSinks{dns: &dns, nftset: &sets}); err != nil {
				t.Fatal(err)
			}
			for _, sec := range c.Sections {
				if strings.Count(dns.String(), "nftset=/example.com/4#inet#purewrt#dns_"+sec.NFTSet4()+"\n") != 1 {
					t.Fatalf("domain missing or duplicated: %s", dns.String())
				}
				for _, set := range []string{sec.NFTSet4(), sec.NFTSet6()} {
					if strings.Count(sets.String(), "add element inet purewrt "+set+" ") != 1 {
						t.Fatalf("CIDR missing or duplicated: %s", sets.String())
					}
				}
			}
		})
	}
}

func TestSectionFiltersInvalidateGeneration(t *testing.T) {
	c := config.Default()
	a, err := currentGenerationFingerprint(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Sections[0].MatchProtocol = "udp"
	c.Sections[0].DestinationPorts = "10000-11000"
	b, err := currentGenerationFingerprint(c)
	if err != nil {
		t.Fatal(err)
	}
	if a.Groups["openwrt_bundle"] == b.Groups["openwrt_bundle"] {
		t.Fatal("section filter edit did not invalidate nft generation")
	}
}

func TestGlobalExclusionsIgnoreSectionPortFilters(t *testing.T) {
	c := config.Default()
	c.Sections = append(c.Sections,
		config.Section{Name: "excluded", Enabled: true, Action: "direct", Priority: 999, MatchProtocol: "udp", DestinationPorts: "10000-11000"},
		config.Section{Name: "blocked", Enabled: true, Action: "reject", Priority: 999, MatchProtocol: "tcp", DestinationPorts: "443"},
	)
	nft := string(NFTables(c))
	proxy := strings.Index(nft, "ip daddr @proxy_media4 meta l4proto")
	for _, want := range []string{`ip daddr @direct4 counter name "direct4" return`, `ip daddr @reject4 counter name "reject4" reject`} {
		pos := strings.Index(nft, want)
		if pos < 0 || pos > proxy {
			t.Fatalf("global exclusion lost precedence: %s", want)
		}
	}
	for _, line := range strings.Split(nft, "\n") {
		if (strings.Contains(line, "@direct") || strings.Contains(line, "@reject")) && strings.Contains(line, "dport") {
			t.Fatalf("global exclusion restricted: %s", line)
		}
	}
}

func TestNativeSectionFiltersAndRouterOutput(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{Name: "game", Enabled: true, Action: "proxy", MatchProtocol: "udp", DestinationPorts: "10000-11000", TPROXYPort: 7893}}
	nft := string(NFTablesWithNative(c, map[string][]string{"game": {"ip daddr 203.0.113.0/24 meta l4proto udp th dport 10500-12000", "ip daddr 198.51.100.0/24 meta l4proto tcp th dport 443"}}))
	if strings.Contains(nft, "198.51.100.0/24") {
		t.Fatal("native TCP expression bypassed UDP restriction")
	}
	want := "ip daddr 203.0.113.0/24 meta l4proto udp th dport 10500-12000 meta l4proto udp udp dport { 10000-11000 }"
	if strings.Count(nft, want) != 2 {
		t.Fatalf("native expression must retain provider and section ports in both hooks: %s", nft)
	}
}

func TestMRSSectionLocalDedup(t *testing.T) {
	for _, fixture := range []string{"youtube.mrs", "telegram-ips.mrs"} {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../testdata/mrs", fixture))
			if err != nil {
				t.Fatal(err)
			}
			c := config.Default()
			var dns, sets bytes.Buffer
			sinks := generationSinks{dns: &dns, nftset: &sets}
			dedup := &streamDedup{domainSeen: map[string]map[string]struct{}{}, cidr4Seen: map[string]map[string]struct{}{}, cidr6Seen: map[string]map[string]struct{}{}}
			first, err := streamMRSData(c, c.Sections[0], data, sinks, dedup)
			if err != nil {
				t.Fatal(err)
			}
			if first.domains+first.cidr4+first.cidr6 == 0 {
				t.Fatal("empty fixture")
			}
			duplicate, err := streamMRSData(c, c.Sections[0], data, sinks, dedup)
			if err != nil {
				t.Fatal(err)
			}
			if duplicate.domains+duplicate.cidr4+duplicate.cidr6 != 0 {
				t.Fatal("same section emitted duplicates")
			}
			other, err := streamMRSData(c, c.Sections[1], data, sinks, dedup)
			if err != nil {
				t.Fatal(err)
			}
			if other != first {
				t.Fatalf("cross-section destinations lost: first=%+v other=%+v", first, other)
			}
		})
	}
}
