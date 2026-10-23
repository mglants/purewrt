package generator

import (
	"reflect"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
	"gopkg.in/yaml.v3"
)

func TestMihomoExplicitDNSFallback(t *testing.T) {
	for _, geodata := range []bool{false, true} {
		c := config.Default()
		c.Settings.MihomoGeodataEnabled = geodata
		c.DNS.FallbackUpstreams = nil
		c.DNS.FallbackDomains = nil
		c.DNS.UDPUpstreams = []string{"77.88.8.8#DIRECT"}
		c.DNS.DoHUpstreams = []string{"https://dns.google/dns-query#DNSProxy"}
		var base map[string]any
		if err := yaml.Unmarshal(Mihomo(c), &base); err != nil {
			t.Fatal(err)
		}
		c.DNS.FallbackUpstreams = []string{"https://common.dot.dns.yandex.net/dns-query#DIRECT"}
		c.DNS.FallbackDomains = []string{"+.ru", "+.su", "+.xn--p1ai"}
		var got map[string]any
		if err := yaml.Unmarshal(Mihomo(c), &got); err != nil {
			t.Fatal(err)
		}
		dns := got["dns"].(map[string]any)
		for key, want := range map[string]any{
			"fallback":                []any{"https://common.dot.dns.yandex.net/dns-query#DIRECT"},
			"fallback-lazy-query":     false,
			"nameserver":              []any{"https://dns.google/dns-query#DNSProxy"},
			"default-nameserver":      []any{"77.88.8.8#DIRECT"},
			"proxy-server-nameserver": []any{"77.88.8.8#DIRECT"},
			"fallback-filter":         map[string]any{"geoip": false, "geosite": []any{}, "ipcidr": []any{}, "domain": []any{"+.ru", "+.su", "+.xn--p1ai"}},
		} {
			if !reflect.DeepEqual(dns[key], want) {
				t.Fatalf("geodata=%v dns.%s = %#v, want %#v", geodata, key, dns[key], want)
			}
		}
		delete(base, "dns")
		delete(got, "dns")
		if !reflect.DeepEqual(base, got) {
			t.Fatal("DNS fallback changed unrelated routing or proxy groups")
		}
	}
}
