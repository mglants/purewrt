package manager

import (
	"errors"
	"github.com/purewrt/purewrt/internal/config"
	"os"
	"strings"
	"testing"
	"time"
)

type ooniRouteRunner struct {
	calls    []string
	fail     string
	occupied bool
}

func (r *ooniRouteRunner) Run(name string, args ...string) (string, error) {
	s := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, s)
	if strings.Contains(s, "rule show") && r.occupied {
		return "97: from all lookup main", nil
	}
	if r.fail != "" && strings.Contains(s, r.fail) {
		return "", errors.New("injected failure")
	}
	return "", nil
}
func (r *ooniRouteRunner) RunWithTimeout(_ time.Duration, n string, a ...string) (string, error) {
	return r.Run(n, a...)
}
func TestOONIRoutesFailClosedAndCleanup(t *testing.T) {
	r := &ooniRouteRunner{}
	cleanup, err := installOONIRoutes(r, 8377, "2")
	if err != nil {
		t.Fatal(err)
	}
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(r.calls, "\n")
	want := strings.Join([]string{
		"ip -4 rule show", "ip -6 rule show",
		"ip -4 rule add pref 98 uidrange 8377-8377 unreachable",
		"ip -6 rule add pref 98 uidrange 8377-8377 unreachable",
		"ip -4 rule add pref 97 uidrange 8377-8377 lookup 2",
		"ip -4 rule del pref 97 uidrange 8377-8377 lookup 2",
		"ip -6 rule del pref 98 uidrange 8377-8377 unreachable",
		"ip -4 rule del pref 98 uidrange 8377-8377 unreachable"}, "\n")
	if got != want {
		t.Fatalf("unsafe route order:\n%s", got)
	}
}
func TestOONIRoutesPartialFailureAndCollision(t *testing.T) {
	r := &ooniRouteRunner{fail: "-6 rule add"}
	if _, err := installOONIRoutes(r, 8377, "2"); err == nil {
		t.Fatal("expected failure")
	}
	if r.calls[len(r.calls)-1] != "ip -4 rule del pref 98 uidrange 8377-8377 unreachable" {
		t.Fatal(r.calls)
	}
	r = &ooniRouteRunner{occupied: true}
	if _, err := installOONIRoutes(r, 8377, "2"); err == nil {
		t.Fatal("expected collision")
	}
	if len(r.calls) != 1 {
		t.Fatal("modified foreign rules", r.calls)
	}
}
func TestOONIDNSUsesSelectedWAN(t *testing.T) {
	for _, s := range []string{
		`{"up":true,"l3_device":"eth1","dns-server":["192.0.2.53"]}`,
		`{"up":true,"l3_device":"eth1","inactive":{"dns-server":["192.0.2.53"]}}`,
	} {
		got, err := ooniWANDNS(s, "eth1")
		if err != nil || got != "nameserver 192.0.2.53\n" {
			t.Fatal(got, err)
		}
	}
	for _, s := range []string{
		`{"up":false,"l3_device":"eth1","dns-server":["192.0.2.53"]}`,
		`{"up":true,"l3_device":"eth2","dns-server":["192.0.2.53"]}`,
		`{"up":true,"l3_device":"eth1","dns-server":["127.0.0.1","::1"]}`,
		`{"up":true,"l3_device":"eth1"}`,
	} {
		if _, err := ooniWANDNS(s, "eth1"); err == nil {
			t.Fatal("unsafe DNS accepted", s)
		}
	}
}

type ooniNFTRunner struct {
	script  string
	exists  bool
	removed bool
}

func (r *ooniNFTRunner) Run(n string, a ...string) (string, error) {
	if a[0] == "list" {
		if r.exists {
			return "", nil
		}
		return "", errors.New("absent")
	}
	if a[0] == "-f" {
		b, e := os.ReadFile(a[1])
		r.script = string(b)
		return "", e
	}
	if a[0] == "delete" {
		r.removed = true
	}
	return "", nil
}
func (r *ooniNFTRunner) RunWithTimeout(_ time.Duration, n string, a ...string) (string, error) {
	return r.Run(n, a...)
}
func TestOONIMarkAndWrongWANGuard(t *testing.T) {
	r := &ooniNFTRunner{}
	cleanup, e := installOONIMark(r, 8377, config.ProxyWAN{Device: "eth2", Mark: 512, Mask: 0x3f00})
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"priority -149", "meta skuid 8377", "meta mark & 0xffffc0ff) | 0x200", "priority 1", "meta nfproto ipv6 reject", `oifname != "eth2" reject`} {
		if !strings.Contains(r.script, want) {
			t.Fatalf("missing %q in %s", want, r.script)
		}
	}
	if e = cleanup(); e != nil || !r.removed {
		t.Fatal("cleanup failed", e)
	}
	r = &ooniNFTRunner{exists: true}
	if _, e = installOONIMark(r, 8377, config.ProxyWAN{}); e == nil || r.script != "" {
		t.Fatal("overwrote stale table")
	}
}
