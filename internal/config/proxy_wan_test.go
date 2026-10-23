package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProxyWANRoundTrip(t *testing.T) {
	c := Default()
	if c.Mwan3.ProxyWANEnabled {
		t.Fatal("must default off")
	}
	c.Mwan3.ProxyWANEnabled = true
	c.Mwan3.ProxyWANs = []string{"wan", "wanb"}
	p := filepath.Join(t.TempDir(), "config")
	if e := Save(p, c); e != nil {
		t.Fatal(e)
	}
	got, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if !got.Mwan3.ProxyWANEnabled || !reflect.DeepEqual(c.Mwan3.ProxyWANs, got.Mwan3.ProxyWANs) {
		t.Fatal("lost WAN selection")
	}
}

func TestRemovedMwan3SettingsAreNotSaved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	legacy := "config mwan3 'mwan3'\n option mode 'integrated'\n option integrated_rules '1'\n option detect '0'\n option purewrt_mark '0x100'\n option proxy_wan_enabled '1'\n list proxy_wan 'wan'\nconfig proxy_provider 'pp'\n option mwan3_policy 'wan_only'\n"
	if e := os.WriteFile(p, []byte(legacy), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = Save(p, c); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, removed := range []string{"integrated_rules", "mwan3_policy", "purewrt_mark", "option detect"} {
		if strings.Contains(string(b), removed) {
			t.Fatalf("obsolete setting retained: %s", removed)
		}
	}
	if !c.Mwan3.ProxyWANEnabled || len(c.Mwan3.ProxyWANs) != 1 {
		t.Fatal("new feature lost")
	}
}
