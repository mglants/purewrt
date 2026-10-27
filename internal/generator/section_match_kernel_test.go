package generator

import (
	"github.com/purewrt/purewrt/internal/config"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Opt-in kernel syntax validation in a private network namespace. Never touches
// the host firewall; NFT_TEST_BINARY selects an installed nft executable.
func TestSectionFiltersKernelSyntax(t *testing.T) {
	nft := os.Getenv("NFT_TEST_BINARY")
	if nft == "" {
		t.Skip("set NFT_TEST_BINARY for isolated nft syntax checks")
	}
	for _, protocol := range []string{"", "tcp", "udp", "tcp_udp"} {
		t.Run(protocol, func(t *testing.T) {
			c := zapretClaimsConfig(config.ZapretStrategy{Name: "combined", Protocols: []string{"tcp", "udp"}, TCPPorts: "443", UDPPorts: "10000-11000", UDPPktOut: 10})
			c.Settings.CgroupV2Path = ""
			for i := range c.Sections {
				c.Sections[i].MatchProtocol = protocol
				c.Sections[i].DestinationPorts = "443,10500-12000"
			}
			path := filepath.Join(t.TempDir(), "rules.nft")
			rules := NFTablesWithNative(c, map[string][]string{"media": {"ip daddr 203.0.113.0/24 meta l4proto udp th dport 10500-12000"}})
			// The host need not have the router service cgroup.
			rules = []byte(strings.ReplaceAll(string(rules), cgroupExemptionRule(c), ""))
			if err := os.WriteFile(path, rules, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("unshare", "-Urn", nft, "-c", "-f", path).CombinedOutput(); err != nil {
				t.Fatalf("nft validation: %v\n%s", err, out)
			}
		})
	}
}
