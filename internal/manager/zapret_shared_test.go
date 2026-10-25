package manager

import (
	"github.com/purewrt/purewrt/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedZapretRestart(t *testing.T) {
	c := config.Default()
	r := &fakeRunner{}
	path := filepath.Join(t.TempDir(), "zapret")
	m := Manager{}
	if err := m.restartZapret(c, r, path); err != nil || len(r.calls) != 0 {
		t.Fatal("optional absent service", err, r.calls)
	}
	c.ZapretStrategies = []config.ZapretStrategy{{Name: "active", Enabled: true}}
	if err := m.restartZapret(c, r, path); err == nil {
		t.Fatal("active Zapret must require its service")
	}
	if err := os.WriteFile(path, nil, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.restartZapret(c, r, path); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || r.calls[0] != path+" restart" {
		t.Fatal(r.calls)
	}
}

func TestSharedSelectorRoutingMasks(t *testing.T) {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "test", Enabled: true, FwMark: "0x40000000"}}
	for _, tc := range []struct {
		rule     string
		conflict bool
	}{
		{"2001: from all fwmark 0x100/0x3f00 lookup 1", false},
		{"100: from all fwmark 0x1/0xff lookup 100", false},
		{"2001: from all fwmark 0x10000/0xff0000 lookup 1", true},
	} {
		r := &fakeRunner{respond: func(string) (string, bool) { return tc.rule, true }}
		if err := validateZapretRoutingMasks(c, r); (err != nil) != tc.conflict {
			t.Fatalf("%s: %v", tc.rule, err)
		}
	}
}
