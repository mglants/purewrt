package generator

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestNFTablesDeviceRules(t *testing.T) {
	c := config.Default()
	c.Devices = []config.Device{
		{Name: "phone", MAC: "aa:bb:cc:dd:ee:ff", Section: "media", Enabled: true},
		{Name: "tv", MAC: "11:22:33:44:55:66", Section: "media", Enabled: true},
		{Name: "off", MAC: "de:ad:be:ef:00:01", Section: "media", Enabled: false},
		{Name: "other", MAC: "de:ad:be:ef:00:02", Section: "nonexistent", Enabled: true},
	}
	out := string(NFTables(c))
	if !strings.Contains(out, "ether saddr { aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66 }") {
		t.Fatalf("missing combined ether saddr set:\n%s", out)
	}
	// media is a proxy section → expect tproxy arms for both families and
	// both protocols (default UDPMode=proxy, IPv6 routed by default).
	for _, want := range []string{
		"meta nfproto ipv4 ether saddr { aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66 } meta l4proto tcp",
		"meta nfproto ipv4 ether saddr { aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66 } meta l4proto udp",
		"meta nfproto ipv6 ether saddr { aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66 } meta l4proto tcp",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "de:ad:be:ef") {
		t.Fatalf("disabled/unmatched devices leaked into rules:\n%s", out)
	}
}

func TestNFTablesDeviceRulesDirectAction(t *testing.T) {
	c := config.Default()
	c.Sections = append(c.Sections, config.Section{Name: "lan_direct", Enabled: true, Action: "direct", Priority: 5})
	c.Devices = []config.Device{{Name: "nas", MAC: "aa:aa:aa:aa:aa:01", Section: "lan_direct", Enabled: true}}
	out := string(NFTables(c))
	if !strings.Contains(out, "ether saddr { aa:aa:aa:aa:aa:01 } return") {
		t.Fatalf("missing direct return rule:\n%s", out)
	}
}

// TestFingerprintChangesOnDeviceEdit guards the apply short-circuit: a
// device-only config change must flip the openwrt_bundle and policy group
// hashes, otherwise `apply` would skip nft regeneration and the
// assignment would silently not take effect.
func TestFingerprintChangesOnDeviceEdit(t *testing.T) {
	c := config.Default()
	before, err := currentGenerationFingerprint(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Devices = []config.Device{{Name: "phone", MAC: "aa:bb:cc:dd:ee:ff", Section: "media", Enabled: true}}
	after, err := currentGenerationFingerprint(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.Hash == after.Hash {
		t.Fatal("overall fingerprint did not change on device edit")
	}
	for _, group := range []string{"openwrt_bundle", "policy"} {
		if before.Groups[group] == after.Groups[group] {
			t.Fatalf("group %q hash did not change on device edit", group)
		}
	}
	if before.Groups["mwan3"] != after.Groups["mwan3"] {
		t.Fatal("mwan3 group should be unaffected by device edits")
	}
}
