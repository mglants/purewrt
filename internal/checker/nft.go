package checker

import "github.com/purewrt/purewrt/internal/config"

type RouteMatch struct {
	Section, Action, NFTSet4, NFTSet6 string
	TPROXYPort                        int
	Mark, Mask, RouteTable            string
}

// MatchDomain returns the default-routing values for a query that doesn't
// have a rule-provider match. The PureWRT routing path is nftset-driven:
// if no rule provider lists the destination, no nftset gets hit, no fwmark
// is set, no policy route triggers — the packet goes out the standard
// WAN. That's "direct", not "proxy". Callers (purewrt-check) overlay the
// section's real metadata when ruleMatch.Matched == true, so this
// fallback is only displayed when nothing actually matched.
//
// FwMark/RouteTable are still populated for the "OpenWrt" section of the
// report — they describe the system's policy-routing config, independent
// of whether THIS destination uses them.
func MatchDomain(c config.Config, domain string) RouteMatch {
	return RouteMatch{
		Section:    "default",
		Action:     "direct",
		Mark:       c.Settings.FwMark,
		Mask:       c.Settings.FwMarkMask,
		RouteTable: c.Settings.RouteTable,
	}
}
