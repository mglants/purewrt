package manager

import (
	"github.com/purewrt/purewrt/internal/config"
	"reflect"
	"testing"
)

func wanFixture() (config.Config, zapretResolverRunner) {
	c := config.Default()
	c.Mwan3.ProxyWANEnabled = true
	c.Mwan3.ProxyWANs = []string{"wan", "wanb"}
	r := zapretResolverRunner{
		"uci -q show mwan3":                "mwan3.wan=interface\nmwan3.wan.enabled='1'\nmwan3.wanb=interface\nmwan3.wanb.enabled='1'\n",
		"ubus call network.interface dump": `{"interface":[{"interface":"wan","l3_device":"eth1"},{"interface":"wanb","l3_device":"pppoe-wanb"}]}`,
		"ip -4 rule show":                  "1001: from all iif eth1 lookup 1\n1002: from all iif pppoe-wanb lookup 2\n2001: from all fwmark 0x100/0x3f00 lookup 1\n2002: from all fwmark 0x200/0x3f00 lookup 2\n2062: from all fwmark 0x3e00/0x3f00 unreachable\n",
	}
	return c, r
}
func TestProxyWANResolution(t *testing.T) {
	c, r := wanFixture()
	got, e := resolveProxyWANs(c, r)
	if e != nil {
		t.Fatal(e)
	}
	want := []config.ProxyWAN{{Name: "wan", Device: "eth1", Mark: 256, Mask: 0x3f00, Table: "1"}, {Name: "wanb", Device: "pppoe-wanb", Mark: 512, Mask: 0x3f00, Table: "2"}}
	if !reflect.DeepEqual(got.Mwan3.ResolvedProxyWANs, want) {
		t.Fatalf("got %+v", got.Mwan3.ResolvedProxyWANs)
	}
}
func TestProxyWANDisabledNeedsNoSystem(t *testing.T) {
	c := config.Default()
	c.Mwan3.ProxyWANs = []string{"missing"}
	got, e := resolveProxyWANs(c, nil)
	if e != nil || len(got.Mwan3.ResolvedProxyWANs) != 0 {
		t.Fatalf("disabled: %v", e)
	}
}
func TestProxyWANRejectsUnresolvedSelections(t *testing.T) {
	for _, kind := range []string{"empty", "missing", "disabled", "rules", "ambiguous", "overlap"} {
		t.Run(kind, func(t *testing.T) {
			c, r := wanFixture()
			switch kind {
			case "empty":
				c.Mwan3.ProxyWANs = nil
			case "missing":
				c.Mwan3.ProxyWANs = []string{"absent"}
			case "disabled":
				r["uci -q show mwan3"] += "mwan3.wan.enabled='0'\n"
			case "rules":
				r["ip -4 rule show"] = ""
			case "ambiguous":
				r["ip -4 rule show"] += "2004: from all fwmark 0x400/0x3f00 lookup 1\n"
			case "overlap":
				c.Settings.FwMarkMask = "0xffff"
			}
			if _, e := resolveProxyWANs(c, r); e == nil {
				t.Fatal("expected failure")
			}
		})
	}
}
