package generator

import (
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

func DNSMasqUpstream(c config.Config) string {
	listen := c.DNS.Listen
	if listen == "" {
		listen = c.Settings.DNSListen
	}
	if listen == "" {
		listen = "127.0.0.1:7874"
	}
	if i := strings.LastIndex(listen, ":"); i > 0 && !strings.HasSuffix(listen, "]") {
		return listen[:i] + "#" + listen[i+1:]
	}
	return "127.0.0.1#7874"
}

func DNSUCIApplyCommands(c config.Config) [][]string {
	server := DNSMasqUpstream(c)
	return [][]string{
		{"uci", "-q", "del_list", "dhcp.@dnsmasq[0].server=" + server},
		{"uci", "add_list", "dhcp.@dnsmasq[0].server=" + server},
		{"uci", "set", "dhcp.@dnsmasq[0].noresolv=1"},
		{"uci", "commit", "dhcp"},
	}
}

func DNSUCIDisableCommands(c config.Config) [][]string {
	return [][]string{
		{"uci", "-q", "del_list", "dhcp.@dnsmasq[0].server=" + DNSMasqUpstream(c)},
		{"uci", "commit", "dhcp"},
	}
}

// DNSMasqIPv6FilterCommands toggles the dnsmasq `filter-aaaa` option based on
// the current IPv6 effective state. When IPv6 routing is off, we want AAAA
// queries to come back empty so apps don't waste 1–4 s waiting for the v6
// path to time out before falling back to A. When IPv6 is back on, remove
// the option so dnsmasq forwards AAAA again.
//
// Runs every OpenWrtBundle apply so manual edits to /etc/config/dhcp don't
// drift. Commit + restart is handled by the caller (the bundle restart
// already restarts dnsmasq).
func DNSMasqIPv6FilterCommands(c config.Config) [][]string {
	if c.IPv6Routed() {
		return [][]string{
			{"uci", "-q", "delete", "dhcp.@dnsmasq[0].filter_aaaa"},
			{"uci", "commit", "dhcp"},
		}
	}
	return [][]string{
		{"uci", "set", "dhcp.@dnsmasq[0].filter_aaaa=1"},
		{"uci", "commit", "dhcp"},
	}
}
