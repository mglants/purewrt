package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPackagedDNSMatchesDefaults(t *testing.T) {
	c, err := Load("../../openwrt/files/etc/config/purewrt")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.DNS, Default().DNS) {
		t.Fatalf("packaged DNS and Go defaults differ: got %+v want %+v", c.DNS, Default().DNS)
	}
}

func TestDNSFallbackExplicitSettingsOverrideDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purewrt")
	for _, custom := range []bool{false, true} {
		body := "config dns 'dns'\n option fallback_upstream ''\n option fallback_domain ''\n"
		if custom {
			body = "config dns 'dns'\n list fallback_upstream 'https://resolver.example/dns-query#DIRECT'\n list fallback_domain '+.example'\n"
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if custom {
			if !reflect.DeepEqual(c.DNS.FallbackUpstreams, []string{"https://resolver.example/dns-query#DIRECT"}) || !reflect.DeepEqual(c.DNS.FallbackDomains, []string{"+.example"}) {
				t.Fatal("explicit custom DNS settings were replaced by defaults")
			}
		} else if len(c.DNS.FallbackUpstreams) != 0 || len(c.DNS.FallbackDomains) != 0 {
			t.Fatal("explicitly cleared DNS settings inherited defaults")
		}
		if err := Save(path, c); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(c.DNS, got.DNS) {
			t.Fatal("DNS settings changed after save/load")
		}
	}
}
