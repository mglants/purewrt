package generator

import (
	"fmt"
	"github.com/purewrt/purewrt/internal/config"
	"strconv"
	"strings"
)

func MarkConflict(c config.Config, mwanMask string) (bool, string) {
	if mwanMask == "" {
		return false, "mwan3 mask not detected"
	}
	pm, _ := strconv.ParseInt(strings.TrimPrefix(c.Mwan3.PureWRTMask, "0x"), 16, 64)
	mm, _ := strconv.ParseInt(strings.TrimPrefix(mwanMask, "0x"), 16, 64)
	if pm&mm != 0 {
		return true, fmt.Sprintf("PureWRT mask %s overlaps mwan3 mmx_mask %s", c.Mwan3.PureWRTMask, mwanMask)
	}
	return false, "no mark-mask overlap"
}
func PolicyCommands(c config.Config) []string {
	cmds := PolicyCommandArgs(c)
	out := make([]string, 0, len(cmds))
	for _, cmd := range cmds {
		out = append(out, strings.Join(cmd, " "))
	}
	return out
}

func PolicyCommandArgs(c config.Config) [][]string {
	rule := []string{"priority", c.Settings.IPRulePriority, "fwmark", c.Settings.FwMark + "/" + c.Settings.FwMarkMask, "table", c.Settings.RouteTable}
	// suppress_prefixlength rule sits just above the fwmark rule and consults main
	// while rejecting the default route. Any specific route in main (LAN subnets,
	// netifd-managed VPN peer host routes, user static routes) wins over the
	// proxy mark so router-originated VPN handshakes keep their tunnel even when
	// the peer IP happens to be in a proxy provider's set.
	suppressPrio := "99"
	if p, err := strconv.Atoi(c.Settings.IPRulePriority); err == nil && p > 1 {
		suppressPrio = strconv.Itoa(p - 1)
	}
	suppressRule := []string{"priority", suppressPrio, "from", "all", "lookup", "main", "suppress_prefixlength", "0"}
	cmds := [][]string{
		append([]string{"ip", "rule", "del"}, suppressRule...),
		append([]string{"ip", "rule", "add"}, suppressRule...),
		append([]string{"ip", "rule", "del"}, rule...),
		append([]string{"ip", "rule", "add"}, rule...),
		{"ip", "route", "replace", "local", "default", "dev", "lo", "table", c.Settings.RouteTable},
		append([]string{"ip", "-6", "rule", "del"}, suppressRule...),
		append([]string{"ip", "-6", "rule", "add"}, suppressRule...),
		append([]string{"ip", "-6", "rule", "del"}, rule...),
		append([]string{"ip", "-6", "rule", "add"}, rule...),
		{"ip", "-6", "route", "replace", "local", "default", "dev", "lo", "table", c.Settings.RouteTable},
	}
	// VPN routing is no longer kernel policy-routed — VPNs are mihomo `direct`
	// outbounds (interface-name), so there are no per-VPN ip rules/tables.
	return cmds
}
