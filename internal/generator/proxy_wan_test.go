package generator

import (
	"github.com/purewrt/purewrt/internal/config"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestProxyWANProviders(t *testing.T) {
	c := config.Default()
	c.ProxyProviders = []config.ProxyProvider{{Name: "subscription", Enabled: true, Type: "http", URL: "https://example.com/sub", Path: "/etc/purewrt/providers/sub.yaml", HealthCheck: true, HealthCheckURL: "https://example.com/check", HealthCheckInterval: 120}}
	original := string(Mihomo(c))
	if strings.Contains(original, "routing-mark:") || strings.Contains(original, "PureWRTWAN_") {
		t.Fatal("WANs emitted by default")
	}
	c.Mwan3.ProxyWANEnabled = true
	c.Mwan3.ProxyWANs = []string{"wan", "wanb"}
	c.Mwan3.ResolvedProxyWANs = []config.ProxyWAN{{Name: "wan", Device: "eth1", Mark: 256}, {Name: "wanb", Device: "eth2", Mark: 512}}
	var out struct {
		Providers map[string]struct {
			Type     string
			Path     string
			URL      string
			Override map[string]any
		} `yaml:"proxy-providers"`
		Groups []struct {
			Name string
			Use  []string
		} `yaml:"proxy-groups"`
	}
	if e := yaml.Unmarshal(Mihomo(c), &out); e != nil {
		t.Fatal(e)
	}
	if len(out.Providers) != 2 {
		t.Fatal("want two independent providers")
	}
	suffixes := map[string]bool{}
	for name, p := range out.Providers {
		if p.Type != "file" || p.Path != c.ProxyProviders[0].Path || p.URL != "" {
			t.Fatalf("provider %s must reuse downloaded file: %+v", name, p)
		}
		mark := p.Override["routing-mark"]
		if mark != 256 && mark != 512 {
			t.Fatal(mark)
		}
		suffix := p.Override["additional-suffix"].(string)
		if suffixes[suffix] {
			t.Fatal("duplicate node suffix")
		}
		suffixes[suffix] = true
		if p.Override["ip-version"] != "ipv4" || p.Override["dialer-proxy"] != "" {
			t.Fatal(p.Override)
		}
	}
	for _, g := range out.Groups {
		if g.Name == "DNSProxy" || g.Name == "Common" || g.Name == "NetCheckProbe" {
			if len(g.Use) != 2 {
				t.Fatalf("%s missing WAN providers", g.Name)
			}
			for _, n := range g.Use {
				if _, ok := out.Providers[n]; !ok {
					t.Fatal(n)
				}
			}
		}
	}
	c.Mwan3.ProxyWANEnabled = false
	if string(Mihomo(c)) != original {
		t.Fatal("disabling does not restore original generation")
	}
}

func TestProxyWANFingerprintTracksResolvedMark(t *testing.T) {
	c := config.Default()
	c.Mwan3.ProxyWANEnabled = true
	c.Mwan3.ProxyWANs = []string{"wan"}
	c.Mwan3.ResolvedProxyWANs = []config.ProxyWAN{{Name: "wan", Device: "eth1", Mark: 256}}
	before, e := currentGenerationFingerprint(c)
	if e != nil {
		t.Fatal(e)
	}
	c.Mwan3.ResolvedProxyWANs[0].Mark = 512
	after, e := currentGenerationFingerprint(c)
	if e != nil {
		t.Fatal(e)
	}
	if before.Hash == after.Hash || before.Groups["mihomo"] == after.Groups["mihomo"] {
		t.Fatal("changed WAN mark must invalidate generated Mihomo")
	}
}

func TestProxyWANUnresolvedNeverFallsBackToUnmarked(t *testing.T) {
	c := config.Default()
	c.Mwan3.ProxyWANEnabled = true
	c.Mwan3.ProxyWANs = []string{"wan"}
	if _, e := MihomoWithProxyGuardState(c, nil); e == nil {
		t.Fatal("must reject unresolved WAN")
	}
}
