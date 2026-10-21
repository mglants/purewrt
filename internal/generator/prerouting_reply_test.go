package generator

import (
	"fmt"
	"strings"
	"testing"
)

// A port-forwarded service may reply to a client in a proxy destination set
// (for example, a Cloudflare WARP exit). Those replies must reach normal NAT
// and routing before device or destination dispatch can intercept them.
func TestPreroutingReplyBypassPrecedesDispatch(t *testing.T) {
	for _, ipv6Mode := range []string{"on", "off"} {
		for _, routerOutput := range []bool{true, false} {
			t.Run(fmt.Sprintf("ipv6_%s/router_output_%t", ipv6Mode, routerOutput), func(t *testing.T) {
				c := orderConfig()
				c.Settings.IPv6Mode = ipv6Mode
				c.Settings.RouterOutputProxy = routerOutput
				out := string(NFTables(c))
				_, chain, ok := strings.Cut(out, "chain prerouting {\n")
				if !ok {
					t.Fatal("missing prerouting chain")
				}
				chain, _, _ = strings.Cut(chain, "\n  }")
				lines := strings.Split(strings.TrimSpace(chain), "\n")
				if len(lines) < 2 || strings.TrimSpace(lines[1]) != "ct direction reply return" {
					t.Fatalf("reply packets must bypass dispatch as the first prerouting rule:\n%s", chain)
				}
				// Keep proxy dispatch for the original direction, including
				// subsequent packets; do not bypass all established traffic.
				if strings.Contains(chain, "ct state established") {
					t.Fatal("reply bypass must not exempt established original-direction packets")
				}
				for _, rule := range []string{"ether saddr { aa:bb:cc:00:00:01 }", "ip daddr @proxy_common4 meta l4proto tcp", "tproxy ip to :"} {
					if !strings.Contains(chain, rule) {
						t.Fatalf("missing original-direction proxy dispatch %q", rule)
					}
				}
				if ipv6Mode == "on" && !strings.Contains(chain, "tproxy ip6 to :") {
					t.Fatal("IPv6 proxy dispatch must remain enabled")
				}
			})
		}
	}
}
