package manager

import (
	"strings"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
)

type zapretResolverRunner map[string]string

func (r zapretResolverRunner) Run(name string, args ...string) (string, error) {
	return r[name+" "+strings.Join(args, " ")], nil
}

func (r zapretResolverRunner) RunWithTimeout(_ time.Duration, name string, args ...string) (string, error) {
	return r.Run(name, args...)
}

func TestResolveZapretProfileInterfacesMwan3Members(t *testing.T) {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, Network: "auto", InterfaceMode: "mwan3_members", Interfaces: []string{"wan"}}}
	r := zapretResolverRunner{
		"ubus call network.interface dump": `{"interface":[{"interface":"wan","l3_device":"pppoe-wan"},{"interface":"wanb","l3_device":"eth2"}]}`,
		"uci -q show mwan3":                "mwan3.wan=interface\nmwan3.wan.interface='wan'\nmwan3.wanb=interface\nmwan3.wanb.interface='wanb'\n",
	}
	out := resolveZapretProfileInterfacesWithRunner(c, r)
	p := out.EnabledZapretProfiles()[0]
	if got := strings.Join(p.Interfaces, ","); got != "pppoe-wan,eth2" {
		t.Fatalf("resolved interfaces = %q", got)
	}
}

func TestResolveZapretProfileInterfacesFallback(t *testing.T) {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, Interfaces: []string{"wan"}, InterfaceMode: "mwan3_members"}}
	out := resolveZapretProfileInterfacesWithRunner(c, zapretResolverRunner{})
	p := out.EnabledZapretProfiles()[0]
	if got := strings.Join(p.Interfaces, ","); got != "wan" {
		t.Fatalf("fallback interfaces = %q", got)
	}
}
