package main

import (
	"fmt"
	"net/netip"
	"os"

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
	if ruleMatch.Matched {
		rm.Section = ruleMatch.Section
		rm.Action = ruleMatch.Action
		if sec, ok := c.SectionByName(ruleMatch.Section); ok {
			rm.Action = sec.Action
			rm.NFTSet4 = sec.NFTSet4()
			rm.TPROXYPort = sec.TPROXYPort
			// NFTSet6 isn't used in the report output (IPv4-only view).
		}
	}
	// Static set holds IPs/CIDRs from rule-provider IP rules; dynamic
	// (dns_-prefixed) set holds IPs that dnsmasq just resolved for a
	// domain-based rule. The CLI used to look only at the static set and
	// reported "first A in nftset: false" for the common case where the
	// domain matched a domain-based rule (the IP lives in the dynamic set
	// only). Mirror the leak-check semantics: hit in either is a hit.
	nftHit := false
	if len(dns.A) > 0 {
		nftHit, _ = checker.NFTSetContains(rm.NFTSet4, dns.A[0])
		if !nftHit {
			nftHit, _ = checker.NFTSetContains("dns_"+rm.NFTSet4, dns.A[0])
		}
	}
	mw := checker.Mwan3(c)
	mh := checker.MihomoForSection(rm.Section)
	v6 := checker.InspectIPv6(c)
	fmt.Printf("Domain: %s\n\nDNS:\n  resolver: dnsmasq -> mihomo DNS %s\n  A: %v\n  AAAA: %v\n  error: %s\n\nRule:\n  matched provider: %s\n  matched rule: %s,%s\n  section: %s\n  action: %s\n\nOpenWrt:\n  nftset: %s\n  tproxy port: %d\n  fwmark: %s/%s\n  route table: %s\n  first A in nftset: %v\n\nIPv6:\n  mode: %s\n  global address: %v\n  default route: %v\n  warnings: %v\n\nMwan3:\n  installed: %v\n  mode: %s\n  direct traffic: %s\n  proxy outbound: %s\n\nMihomo:\n  inbound: %s\n  group: %s\n  selected node: %s\n  node status: %s\n", domain, c.DNS.Listen, dns.A, dns.AAAA, dns.Error, ruleProvider(ruleMatch), ruleType(ruleMatch, domain), domain, rm.Section, rm.Action, rm.NFTSet4, rm.TPROXYPort, rm.Mark, rm.Mask, rm.RouteTable, nftHit, v6.Mode, v6.GlobalAddress, v6.DefaultRoute, v6.Warnings, mw.Installed, mw.Mode, mw.DirectTraffic, mw.ProxyOutbound, mh.Inbound, mh.Group, mh.SelectedNode, mh.NodeStatus)
}

func ruleProvider(m checker.RuleProviderMatch) string {
	if m.Provider == "" {
		return "(no match — default route)"
	}
	return m.Provider
}

// ruleType reports the type of probe we actually performed. For matched
// queries the provider's rule type is authoritative. For unmatched
// queries we distinguish IP-CIDR lookups from DOMAIN-SUFFIX lookups based
// on the input shape — saying "DOMAIN-SUFFIX,1.2.3.4" for an IP probe is
// misleading because no domain-suffix matching happened.
func ruleType(m checker.RuleProviderMatch, query string) string {
	if m.Matched {
		return string(m.Rule.Type)
	}
	if _, err := netip.ParseAddr(query); err == nil {
		return "IP-CIDR (no match)"
	}
	return "DOMAIN-SUFFIX (no match)"
}
