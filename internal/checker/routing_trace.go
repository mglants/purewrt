package checker

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

// Flow describes a destination check, not client identity or established state.
type Flow struct {
	Protocol string
	Port     int
	WAN      string
}

func (f Flow) Validate() error {
	if f.Protocol != "" && f.Protocol != "tcp" && f.Protocol != "udp" {
		return fmt.Errorf("protocol must be tcp or udp")
	}
	if f.Port < 0 || f.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

type RoutingStep struct {
	Section   string
	Priority  int
	Action    string
	Providers []string
	Status    string
	Reason    string
}
type RoutingTrace struct {
	Warnings []string
	Steps    []RoutingStep
	Action   string
	Section  string
}

// Scope reports whether a section can handle this flow. Unknown inputs remain
// conditional, rather than being mistaken for either a match or a mismatch.
func SectionFlowScope(c config.Config, s config.Section, f Flow) (string, string) {
	if s.Action == "direct" || s.Action == "reject" {
		return "match", "global destination exclusion (protocol and ports do not restrict it)"
	}
	if s.Action != "proxy" && s.Action != "zapret" {
		return "skip", "unsupported section action"
	}
	if f.Protocol != "" && !s.MatchesProtocol(f.Protocol) {
		return "skip", "protocol does not match; fall through"
	}
	if f.Protocol == "udp" && s.Action == "proxy" && s.UDPMode == "tcp_only" {
		return "skip", "TCP-only section; fall through"
	}
	if f.Port != 0 {
		if _, ok := config.IntersectDestinationPorts(s.DestinationPorts, strconv.Itoa(f.Port)); !ok {
			return "skip", "destination port does not match; fall through"
		}
	}
	if s.Action == "proxy" {
		if f.Protocol == "" || f.Port == 0 && (s.DestinationPorts != "" || s.UDPMode == "block_quic") {
			return "conditional", "specify protocol and destination port"
		}
		if f.Protocol == "udp" && f.Port == 443 && s.UDPMode == "block_quic" {
			return "reject", "section blocks QUIC (UDP/443)"
		}
		return "match", "protocol and destination port match"
	}
	possible, wanMatch := false, false
	for _, name := range s.ZapretStrategies {
		zs, ok := c.ZapretStrategyByName(name)
		if !ok {
			continue
		}
		p, profileOK := c.ZapretProfileByName(zs.Profile)
		for _, proto := range zs.Protocols {
			if f.Protocol != "" && proto != f.Protocol || !s.MatchesProtocol(proto) {
				continue
			}
			ports := zs.TCPPorts
			if proto == "udp" {
				ports = zs.UDPPorts
			}
			ports, ok = config.IntersectDestinationPorts(ports, s.DestinationPorts)
			if !ok {
				continue
			}
			if f.Port != 0 {
				if _, ok = config.IntersectDestinationPorts(ports, strconv.Itoa(f.Port)); !ok {
					continue
				}
			}
			possible = true
			if profileOK && (len(p.Interfaces) == 0 || containsString(p.Interfaces, f.WAN)) {
				wanMatch = true
			}
		}
	}
	if !possible {
		return "skip", "outside the enabled Zapret strategies’ protocol/port scope; fall through"
	}
	if f.Protocol == "" || f.Port == 0 || f.WAN == "" {
		return "conditional", "Zapret strategy may match; specify protocol, port and outgoing WAN device"
	}
	if !wanMatch {
		return "direct", "Zapret claims these ports, but this WAN has no matching strategy: stays direct, no lower-section fallthrough"
	}
	return "match", "section and WAN strategy scope match (NFQUEUE processing subject to runtime state)"
}
func containsString(list []string, value string) bool {
	for _, s := range list {
		if s == value {
			return true
		}
	}
	return false
}

func routingSections(c config.Config) []config.Section {
	out := append([]config.Section(nil), c.Sections...)
	rank := func(s config.Section) int {
		if s.Action == "reject" {
			return 0
		}
		if s.Action == "direct" {
			return 1
		}
		return 2
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank(out[i]) != rank(out[j]) {
			return rank(out[i]) < rank(out[j])
		}
		return out[i].Priority < out[j].Priority
	})
	return out
}

// TraceDestination reports all destination-list candidates in dispatch order.
// Client assignments, existing marks, native expressions and live DNS-set state
// are deliberately not inferred from a domain-only request.
func TraceDestination(c config.Config, query string, f Flow) RoutingTrace {
	matches := map[string][]string{}
	var warnings []string
	c.Sections = append([]config.Section(nil), c.Sections...)
	for _, rp := range c.RuleProviders {
		sec, ok := c.SectionByName(rp.Section)
		if !rp.Enabled {
			continue
		}
		if !ok {
			action := rp.RouteAction
			if rp.Section == "direct" || rp.Section == "reject" {
				action = rp.Section
			}
			if action != "direct" && action != "reject" {
				continue
			}
			sec = config.Section{Name: action, Action: action, Enabled: true, IPv4Enabled: true, IPv6Enabled: true}
			if existing, exists := c.SectionByName(action); exists {
				sec = existing
			} else {
				c.Sections = append(c.Sections, sec)
			}
			rp.Section = sec.Name
		}
		if !sec.Enabled {
			continue
		}
		if _, err := os.Stat(rp.Path); err != nil {
			warnings = append(warnings, fmt.Sprintf("provider %s unavailable: %v", rp.Name, err))
			continue
		}
		one := c
		one.RuleProviders = []config.RuleProvider{rp}
		idx := NewRuleProviderIndex(one)
		var match RuleProviderMatch
		if ip, err := netip.ParseAddr(strings.TrimSpace(query)); err == nil {
			match = idx.MatchIP(ip)
		} else {
			match = idx.Match(query)
		}
		warnings = append(warnings, idx.Warnings...)
		if match.Matched {
			matches[sec.Name] = append(matches[sec.Name], rp.Name)
		}
	}
	result := RoutingTrace{Action: "direct", Warnings: warnings}
	uncertain, terminal := false, false
	for _, s := range routingSections(c) {
		providers := matches[s.Name]
		if !s.Enabled || len(providers) == 0 {
			continue
		}
		sort.Strings(providers)
		status, reason := SectionFlowScope(c, s, f)
		if addr, err := netip.ParseAddr(strings.TrimSpace(query)); err == nil && (addr.Is6() && !c.IPv6Routed()) && s.Action != "direct" && s.Action != "reject" {
			status, reason = "skip", "address family disabled; fall through"
		}
		action := s.Action
		if status == "reject" || status == "direct" {
			action = status
			status = "match"
		}
		if status == "match" || status == "conditional" {
			if terminal {
				status = "shadowed"
				reason = "an earlier matching destination rule is terminal"
			} else if uncertain {
				status = "conditional"
				reason = "depends on an earlier conditional match"
			} else if status == "match" {
				result.Action = action
				result.Section = s.Name
				terminal = true
			}
			if status == "conditional" {
				uncertain = true
				result.Action = "conditional"
			}
		}
		result.Steps = append(result.Steps, RoutingStep{s.Name, s.Priority, action, providers, status, reason})
	}
	if len(warnings) > 0 {
		result.Action = "conditional"
		result.Section = ""
	}
	return result
}
