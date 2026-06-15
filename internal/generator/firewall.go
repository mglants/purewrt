package generator

import (
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

func FirewallDNSHijack(c config.Config) []byte {
	if !c.DNS.HijackLANDNS {
		return nil
	}

	var b strings.Builder
	b.WriteString("config redirect 'purewrt_dns_hijack_udp'\n")
	b.WriteString("    option name 'PureWRT DNS hijack UDP'\n")
	b.WriteString("    option src 'lan'\n")
	b.WriteString("    option proto 'udp'\n")
	b.WriteString("    option src_dport '53'\n")
	b.WriteString("    option dest_port '53'\n")
	b.WriteString("    option target 'DNAT'\n\n")
	b.WriteString("config redirect 'purewrt_dns_hijack_tcp'\n")
	b.WriteString("    option name 'PureWRT DNS hijack TCP'\n")
	b.WriteString("    option src 'lan'\n")
	b.WriteString("    option proto 'tcp'\n")
	b.WriteString("    option src_dport '53'\n")
	b.WriteString("    option dest_port '53'\n")
	b.WriteString("    option target 'DNAT'\n")
	return []byte(b.String())
}
