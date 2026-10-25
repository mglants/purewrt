package generator

import (
	"github.com/purewrt/purewrt/internal/config"
	"strings"
	"testing"
)

func TestZapretOutputUsesEnabledProfileMarks(t *testing.T) {
	c := config.Default()
	if strings.Contains(string(NFTables(c)), "meta mark & 0x40000000 != 0 return") {
		t.Fatal("disabled Zapret emitted exemption")
	}
	c.ZapretProfiles = []config.ZapretProfile{
		{Name: "a", Enabled: true, FwMark: "0x20000000"},
		{Name: "b", Enabled: true, FwMark: "0x20000000"},
		{Name: "c", Enabled: true, FwMark: "0x40000000"},
		{Name: "unused", Enabled: false, FwMark: "0x80000000"},
	}
	out := string(NFTables(c))
	for _, mark := range []string{"0x20000000", "0x40000000"} {
		rule := "meta mark & " + mark + " != 0 return"
		if strings.Count(out, rule) != 1 {
			t.Fatalf("missing or duplicated %s", rule)
		}
		if strings.Index(out, rule) > strings.Index(out, "fib daddr type { local") {
			t.Fatal("exemption comes after dispatch")
		}
	}
	if strings.Contains(out, "meta mark & 0x80000000") {
		t.Fatal("disabled mark emitted")
	}
}
