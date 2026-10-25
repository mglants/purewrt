package manager

import (
	"strings"
	"testing"
)

func TestClientSwitchOnlyReplacesQueues(t *testing.T) {
	post := `chain post {
 meta mark & 0x10000000 != 0 return # handle 16
 ct direction original tcp dport 1-65535 counter name "tcp_out" queue flags bypass to 9908 # handle 17
 ct direction original udp dport 1-65535 counter name "udp_out" queue flags bypass to 9908 # handle 18
 }`
	incoming := `ct direction reply meta l4proto { tcp, udp } ct reply packets 1-10 queue flags bypass to 9908 # handle 21`
	script, err := clientSwitchNFT(post, incoming, "9910")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(script, "replace rule inet purewrt_client_test ") != 3 || strings.Count(script, "queue flags bypass to 9910") != 3 {
		t.Fatal(script)
	}
	for _, forbidden := range []string{"delete", "flush", "ip rule", "timeout", "handle 16", "flowtable"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("switch alters routing state: %s", script)
		}
	}
	if !strings.Contains(script, `counter name "tcp_out"`) {
		t.Fatal("counter reference lost")
	}
	reverse, err := clientSwitchNFT(strings.ReplaceAll(post, "9908", "9910"), strings.ReplaceAll(incoming, "9908", "9910"), "9908")
	if err != nil || strings.Count(reverse, "queue flags bypass to 9908") != 3 {
		t.Fatalf("reverse switch: %s %v", reverse, err)
	}
	for _, bad := range []string{"", strings.ReplaceAll(post, "9908", "200"), strings.ReplaceAll(post, "handle 17", "handle invalid")} {
		if _, err := clientSwitchNFT(bad, incoming, "9910"); err == nil {
			t.Fatalf("accepted altered queue rules: %s", bad)
		}
	}
}
