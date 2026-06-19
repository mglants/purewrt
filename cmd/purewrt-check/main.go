package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/purewrt/purewrt/internal/checker"
	"github.com/purewrt/purewrt/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: purewrt-check <domain>")
		os.Exit(2)
	}
	domain := os.Args[1]
	c, _ := config.Load("/etc/config/purewrt")
	dns := checker.Resolve(domain)
	ruleMatch := checker.MatchRuleProviders(c, domain)
	rm := checker.MatchDomain(c, domain)
	var sec config.Section
	if ruleMatch.Matched {
		rm.Section = ruleMatch.Section
		rm.Action = ruleMatch.Action
		if s, ok := c.SectionByName(ruleMatch.Section); ok {
			sec = s
			rm.Action = s.Action
			rm.NFTSet4 = s.NFTSet4()
			rm.TPROXYPort = s.TPROXYPort
		}
	}
	nftHit := false
	if len(dns.A) > 0 {
		nftHit, _ = checker.NFTSetContains(rm.NFTSet4, dns.A[0])
		if !nftHit {
			nftHit, _ = checker.NFTSetContains("dns_"+rm.NFTSet4, dns.A[0])
		}
	}
	mw := checker.Mwan3(c)
	v6 := checker.InspectIPv6(c)

	var b strings.Builder
	fmt.Fprintf(&b, "Domain: %s\n\n", domain)
	fmt.Fprintf(&b, "DNS:\n  resolver: dnsmasq -> mihomo DNS %s\n  A: %v\n  AAAA: %v\n  error: %s\n\n",
		c.DNS.Listen, dns.A, dns.AAAA, dns.Error)
	fmt.Fprintf(&b, "Rule:\n  matched provider: %s\n  matched rule: %s,%s\n  section: %s\n  action: %s\n\n",
		ruleProvider(ruleMatch), ruleType(ruleMatch, domain), domain, rm.Section, rm.Action)
	fmt.Fprintf(&b, "OpenWrt:\n  nftset: %s\n  tproxy port: %d\n  fwmark: %s/%s\n  route table: %s\n  first A in nftset: %v\n\n",
		rm.NFTSet4, rm.TPROXYPort, rm.Mark, rm.Mask, rm.RouteTable, nftHit)
	fmt.Fprintf(&b, "IPv6:\n  mode: %s\n  global address: %v\n  default route: %v\n  warnings: %v\n\n",
		v6.Mode, v6.GlobalAddress, v6.DefaultRoute, v6.Warnings)
	fmt.Fprintf(&b, "Mwan3:\n  installed: %v\n  mode: %s\n  direct traffic: %s\n  proxy outbound: %s\n\n",
		mw.Installed, mw.Mode, mw.DirectTraffic, mw.ProxyOutbound)

	// Mihomo + full route only make sense for a proxy section. Direct/reject/no
	// match never enters mihomo.
	if sec.Action == "proxy" {
		mh := checker.MihomoForSection(c, sec)
		writeMihomo(&b, mh)
		writeRoute(&b, domain, ruleMatch, sec, mh, rm.TPROXYPort)
	} else {
		fmt.Fprintf(&b, "Mihomo:\n  n/a — action %q does not route through mihomo\n\n", rm.Action)
		writeRoute(&b, domain, ruleMatch, sec, checker.MihomoPath{}, rm.TPROXYPort)
	}
	fmt.Print(b.String())
}

func writeMihomo(b *strings.Builder, mh checker.MihomoPath) {
	fmt.Fprintf(b, "Mihomo:\n  inbound: %s\n  group: %s\n  type: %s\n", mh.Inbound, mh.Group, orNA(mh.GroupType))
	if mh.GroupType == "load-balance" && mh.Strategy != "" {
		fmt.Fprintf(b, "  strategy: %s\n", mh.Strategy)
	}
	if mh.Filter != "" {
		fmt.Fprintf(b, "  filter: %s\n", mh.Filter)
	}
	fmt.Fprintf(b, "  pool: providers=%s vpns=%s\n", listOrNone(mh.Providers), listOrNone(mh.VPNs))
	if !mh.Reachable {
		fmt.Fprintf(b, "  selected node: unknown\n  node status: unknown (%s)\n\n", orNA(mh.Note))
		return
	}
	if mh.SelectedNode == "" && isLoadBalance(mh.GroupType) {
		fmt.Fprintf(b, "  selected node: n/a (load-balance — chosen per connection)\n")
	} else {
		fmt.Fprintf(b, "  selected node: %s\n  node status: %s\n", orNA(mh.SelectedNode), nodeStatus(mh.SelectedAlive, mh.SelectedDelayMS))
	}
	fmt.Fprintf(b, "  members (%d):\n", len(mh.Members))
	for _, m := range mh.Members {
		fmt.Fprintf(b, "    - %s  %s\n", m.Name, nodeStatus(m.Alive, m.DelayMS))
	}
	if mh.Note != "" {
		fmt.Fprintf(b, "  note: %s\n", mh.Note)
	}
	b.WriteString("\n")
}

// writeRoute prints the end-to-end chain: domain → rule-provider → section →
// mihomo group/node → egress, so it's obvious what carries the traffic.
func writeRoute(b *strings.Builder, domain string, rmatch checker.RuleProviderMatch, sec config.Section, mh checker.MihomoPath, tproxyPort int) {
	b.WriteString("Route (full chain):\n  ")
	parts := []string{domain}
	if rmatch.Provider != "" {
		parts = append(parts, "rule-provider "+rmatch.Provider)
	} else {
		parts = append(parts, "no rule match")
	}
	if sec.Name != "" {
		parts = append(parts, fmt.Sprintf("section %q (%s)", sec.Name, sec.Action))
	} else {
		parts = append(parts, "default route")
	}
	if sec.Action == "proxy" {
		grp := mh.Group
		if mh.GroupType != "" {
			grp += " [" + mh.GroupType + "]"
		}
		parts = append(parts, "mihomo "+grp)
		node := mh.SelectedNode
		if node == "" {
			if isLoadBalance(mh.GroupType) {
				node = "any (load-balance)"
			} else {
				node = "unknown"
			}
		}
		parts = append(parts, "node "+node)
		parts = append(parts, fmt.Sprintf("tproxy :%d → egress", tproxyPort))
	} else if sec.Action == "direct" || sec.Name == "" {
		parts = append(parts, "kernel direct (WAN / mwan3)")
	} else {
		parts = append(parts, sec.Action)
	}
	b.WriteString(strings.Join(parts, " → "))
	b.WriteString("\n")
}

// isLoadBalance matches both the config value ("load-balance") and mihomo's
// live API value ("LoadBalance").
func isLoadBalance(t string) bool {
	return strings.Contains(strings.ToLower(strings.ReplaceAll(t, "-", "")), "loadbalance")
}

func nodeStatus(alive bool, delayMS int) string {
	if alive {
		if delayMS > 0 {
			return fmt.Sprintf("alive, %dms", delayMS)
		}
		return "alive"
	}
	return "down/untested"
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "[]"
	}
	return "[" + strings.Join(s, " ") + "]"
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

func ruleProvider(m checker.RuleProviderMatch) string {
	if m.Provider == "" {
		return "(no match — default route)"
	}
	return m.Provider
}

func ruleType(m checker.RuleProviderMatch, query string) string {
	if m.Matched {
		return string(m.Rule.Type)
	}
	if _, err := netip.ParseAddr(query); err == nil {
		return "IP-CIDR (no match)"
	}
	return "DOMAIN-SUFFIX (no match)"
}
