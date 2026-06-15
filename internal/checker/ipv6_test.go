package checker

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

type stubRunner struct{ out map[string]string }

func (s stubRunner) Run(name string, args ...string) (string, error) {
	return s.out[name+" "+strings.Join(args, " ")], nil
}

func TestInspectIPv6WarnsWhenOffButHasGlobal(t *testing.T) {
	t.Parallel()
	c := config.Default()
	c.Settings.IPv6Mode = "off"
	c.Settings.IPv6RejectWhenOff = false
	r := stubRunner{out: map[string]string{
		"ip -6 route show default":      "default via fe80::1 dev wan",
		"ip -6 addr show scope global":  "    inet6 2001:db8::1/64 scope global dynamic",
	}}
	p := inspectIPv6WithRunner(c, r)
	if !p.GlobalAddress {
		t.Fatal("expected global v6 address detection")
	}
	if len(p.Warnings) == 0 || !strings.Contains(strings.Join(p.Warnings, " "), "bypass") {
		t.Fatalf("expected bypass warning, got %+v", p.Warnings)
	}
}

func TestInspectIPv6WarnsWhenOnButNoAddress(t *testing.T) {
	t.Parallel()
	c := config.Default()
	c.Settings.IPv6Mode = "on"
	r := stubRunner{out: map[string]string{}}
	p := inspectIPv6WithRunner(c, r)
	if p.GlobalAddress || p.DefaultRoute {
		t.Fatalf("expected absent v6 state, got %+v", p)
	}
	if len(p.Warnings) < 2 {
		t.Fatalf("expected warnings about missing address and route, got %+v", p.Warnings)
	}
}

func TestInspectIPv6AutoLowResourceWarning(t *testing.T) {
	t.Parallel()
	c := config.Default()
	c.Settings.ResourceProfile = "low"
	c.Settings.IPv6 = true
	c.Settings.IPv6Mode = "auto"
	r := stubRunner{out: map[string]string{}}
	p := inspectIPv6WithRunner(c, r)
	if len(p.Warnings) == 0 || !strings.Contains(p.Warnings[0], "silently disables") {
		t.Fatalf("expected low-resource silently-disables warning, got %+v", p.Warnings)
	}
}
