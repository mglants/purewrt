package manager

import (
	"reflect"
	"sort"
	"testing"
)

func TestPurewrtFirewallSectionNames(t *testing.T) {
	uciShow := `firewall.@defaults[0]=defaults
firewall.cfg01=zone
firewall.cfg01.name='lan'
firewall.purewrt_tproxy_accept_iot=rule
firewall.purewrt_tproxy_accept_iot.name='PureWRT TPROXY accept (iot)'
firewall.purewrt_tproxy_accept_iot.mark='0x1/0xff'
firewall.purewrt_dns_hijack_iot_udp=redirect
firewall.purewrt_dns_accept_guest=rule
firewall.some_other_rule=rule
firewall.purewrt_tproxy_accept_iot=rule
`
	got := purewrtFirewallSectionNames(uciShow)
	sort.Strings(got)
	want := []string{
		"purewrt_dns_accept_guest",
		"purewrt_dns_hijack_iot_udp",
		"purewrt_tproxy_accept_iot",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
