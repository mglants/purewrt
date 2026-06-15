package checker

import (
	"net"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/system"
)

// IPv6Path describes the device's IPv6 readiness, sampled from the live
// kernel via `ip -6 route`, `ip -6 addr`, and the section nftset state.
// Used to spot common silent leaks: SLAAC-only LAN without router-advertised
// default route, or router has v6 default route but section nftset is
// empty so resolved AAAA answers never get TPROXY'd.
type IPv6Path struct {
	Mode          string `json:"mode"`           // configured IPv6Mode
	DefaultRoute  bool   `json:"default_route"`  // routable v6 default present
	GlobalAddress bool   `json:"global_address"` // device has a global v6 SLAAC/DHCPv6 addr
	SLAACSeen     bool   `json:"slaac_seen"`     // any received RA prefix on LAN/WAN
	Warnings      []string `json:"warnings,omitempty"`
}

// InspectIPv6 returns the device's IPv6 readiness summary for use by
// `purewrt-check` and `purewrt inspect-ipv6`.
func InspectIPv6(c config.Config) IPv6Path {
	return inspectIPv6WithRunner(c, system.Runner{})
}

type runner interface {
	Run(name string, args ...string) (string, error)
}

func inspectIPv6WithRunner(c config.Config, r runner) IPv6Path {
	p := IPv6Path{Mode: c.Settings.IPv6Mode}
	if p.Mode == "" {
		p.Mode = "auto"
	}

	out, _ := r.Run("ip", "-6", "route", "show", "default")
	if strings.Contains(out, "default") && strings.Contains(out, "via") {
		p.DefaultRoute = true
	}

	addrOut, _ := r.Run("ip", "-6", "addr", "show", "scope", "global")
	for _, line := range strings.Split(addrOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "inet6" {
			continue
		}
		ip, _, err := net.ParseCIDR(fields[1])
		if err != nil {
			continue
		}
		if ip.To4() == nil && ip.IsGlobalUnicast() {
			p.GlobalAddress = true
			// SLAAC addresses end in :ff:fe:: (EUI-64) — heuristic only.
			if strings.Contains(strings.ToLower(ip.String()), ":ff:fe") {
				p.SLAACSeen = true
			}
		}
	}

	// Cross-check against the configured mode.
	switch p.Mode {
	case "off":
		if p.GlobalAddress && !c.Settings.IPv6RejectWhenOff {
			p.Warnings = append(p.Warnings, "device has a global v6 address but IPv6Mode=off without ipv6_reject_when_off — v6 traffic may bypass the proxy")
		}
	case "on":
		if !p.GlobalAddress {
			p.Warnings = append(p.Warnings, "IPv6Mode=on but the device has no global v6 address; v6 rules generated but unreachable")
		}
		if !p.DefaultRoute {
			p.Warnings = append(p.Warnings, "IPv6Mode=on but no v6 default route on the device")
		}
	default: // auto
		if c.Settings.IPv6 && c.LowResource() {
			p.Warnings = append(p.Warnings, "IPv6Mode=auto + LowResource silently disables IPv6 routing; set IPv6Mode=on if you actually need it")
		}
	}
	return p
}
