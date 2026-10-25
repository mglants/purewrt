package manager

import (
	"fmt"
	"github.com/purewrt/purewrt/internal/config"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClientManualStrategy(t *testing.T) {
	params := "--filter-tcp=443 --lua-desync=fake:blob=fake_default_tls\n--new --filter-udp=443,50000-65535 --lua-desync=fake:blob=0x00000000"
	cs, err := clientTestCandidates(ZapretClientOptions{Candidate: "__manual__", Manual: params}, config.ZapretCandidateList{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].TCPPorts != "443" || cs[0].UDPPorts != "443,50000-65535" || len(cs[0].Protocols) != 2 || strings.Contains(cs[0].Params, "\n") {
		t.Fatalf("bad inferred metadata: %+v", cs)
	}
	args, err := (Manager{}).clientTestArgs(cs, clientTestQueue)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--fwmark="+clientTestFakeMark) || !strings.Contains(joined, "--new --filter-udp=443,50000-65535") {
		t.Fatal(joined)
	}
	for _, params := range []string{"", "--lua-desync=fake", "nfqws2 --filter-tcp=443", "--filter-tcp=443 --qnum=200", "--filter-tcp=443 --fwmark=1", "--filter-tcp=443 --lua-init=@/tmp/test.lua", "--filter-tcp=443; reboot", "--filter-tcp=443 --lua-desync=fake:blob=missing", "--filter-udp=65536", strings.Repeat(" ", 16385)} {
		if _, err := clientManualCandidate(params); err == nil {
			t.Errorf("accepted invalid manual input: %.80q", params)
		}
	}
	for _, o := range []ZapretClientOptions{
		{Candidate: "__manual__", Extra: "udp", Manual: params},
		{Candidate: "__direct__", Manual: params},
	} {
		if _, err := clientTestCandidates(o, config.ZapretCandidateList{}); err == nil {
			t.Fatal("accepted ambiguous manual selection")
		}
	}
}

func TestClientSessionValidation(t *testing.T) {
	good := ZapretClientOptions{IP: "192.168.1.20", MAC: "02:00:00:00:00:20", Interface: "eth1.20"}
	if e := clientTestValidate(good); e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"127.0.0.1", "8.8.8.8", "::1", "192.168.1.20; flush ruleset"} {
		o := good
		o.IP = ip
		if clientTestValidate(o) == nil {
			t.Fatalf("accepted %q", ip)
		}
	}
	for _, mac := range []string{"ff:ff:ff:ff:ff:ff", "bad", "02:00:00:00:00:20;"} {
		o := good
		o.MAC = mac
		if clientTestValidate(o) == nil {
			t.Fatalf("accepted %q", mac)
		}
	}
}
func TestClientSessionCombinesDisjointProtocols(t *testing.T) {
	list := config.ZapretCandidateList{Candidates: []config.ZapretCandidate{
		{Name: "tcp", Protocols: []string{"tcp"}, Params: "--filter-tcp=443 --lua-desync=multisplit:pos=midsld"},
		{Name: "udp", Protocols: []string{"udp"}, Params: "--filter-udp=443 --lua-desync=fake"},
		{Name: "bad", Protocols: []string{"tcp"}, Params: "--qnum=200"},
	}}
	if _, e := clientTestCandidates(ZapretClientOptions{Candidate: "tcp", Extra: "udp"}, list); e != nil {
		t.Fatal(e)
	}
	for _, o := range []ZapretClientOptions{{Candidate: "tcp", Extra: "tcp"}, {Candidate: "missing"}, {Candidate: "bad"}, {}} {
		if _, e := clientTestCandidates(o, list); e == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}
func TestClientSessionRouteSelection(t *testing.T) {
	routes := "default via 198.51.100.1 dev eth0 metric 1\ndefault via 203.0.113.1 dev eth1 metric 9\n"
	a, e := clientTestDefaultRoute(routes, "eth1")
	if e != nil {
		t.Fatal(e)
	}
	if s := strings.Join(a, " "); !strings.Contains(s, "via 203.0.113.1 dev eth1 onlink") || strings.Contains(s, "198.51.100.1") {
		t.Fatal(s)
	}
	if _, e = clientTestDefaultRoute(routes, "missing"); e == nil {
		t.Fatal("missing WAN fell back")
	}
}
func TestClientSessionNFTIsolation(t *testing.T) {
	s := clientTestNFT(ZapretClientOptions{IP: "192.168.1.20", MAC: "02:00:00:00:00:20", Interface: "eth1"}, "0xff")
	for _, v := range []string{"timeout 300s", "ip saddr @clients", "ct original ip saddr @clients", "ether saddr @macs", "oifname != \"eth1\" reject", "priority 102", "priority -402", "queue num 9908 bypass", "ct direction reply", "insert rule inet purewrt prerouting", "meta mark set meta mark & 0xffffff00 | 0x08000000"} {
		if !strings.Contains(s, v) {
			t.Errorf("missing %s", v)
		}
	}
	if strings.Contains(s, "flush ruleset") || strings.Contains(s, "queue num 200") {
		t.Fatal("touches production queue")
	}
	// Optional router nft --check fixture; no real client identifiers in this file.
	if p := os.Getenv("PUREWRT_TEST_NFT_OUTPUT"); p != "" {
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
}

type clientCleanupRunner struct{ calls []string }

func (r *clientCleanupRunner) Run(name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	if strings.HasPrefix(cmd, "nft -a list chain") {
		return "ip saddr 192.168.1.20 return comment \"purewrt_client_test\" # handle 123\nip saddr 192.168.1.21 return comment \"production\" # handle 456\n", nil
	}
	if strings.HasPrefix(cmd, "nft list table") || strings.HasPrefix(cmd, "nft list set") {
		return "", fmt.Errorf("not found")
	}
	return "", nil
}
func TestClientSessionCleanupPreservesProduction(t *testing.T) {
	r := &clientCleanupRunner{}
	if e := clientTestCleanup(r); e != nil {
		t.Fatal(e)
	}
	s := strings.Join(r.calls, "\n")
	for _, v := range []string{"delete rule inet purewrt prerouting handle 123", "delete rule inet purewrt output_mangle handle 123", "delete table inet purewrt_client_test", "rule del pref 101 fwmark 0x08000000/0x08000000 lookup 9908", "rule del pref 101 fwmark 0x10000000/0x10000000 lookup 9908"} {
		if !strings.Contains(s, v) {
			t.Errorf("missing cleanup %s", v)
		}
	}
	if strings.Contains(s, "handle 456") || strings.Contains(s, "flush table inet purewrt") || strings.Contains(s, "delete table inet purewrt\n") {
		t.Fatal("production state touched")
	}
}

func (r *clientCleanupRunner) RunWithTimeout(_ time.Duration, name string, args ...string) (string, error) {
	return r.Run(name, args...)
}

func TestClientOffloadGuardPreservesRule(t *testing.T) {
	original := `meta l4proto { tcp, udp } flow add @ft comment "!fw4: flow offload"`
	rule, e := clientOffloadFind(original + " # handle 42\nct state established accept # handle 43\n")
	if e != nil || rule == nil {
		t.Fatalf("%v %v", rule, e)
	}
	script := clientOffloadNFT(rule, "192.168.1.20")
	for _, v := range []string{original, "ct original ip saddr @purewrt_client_offload return", "timeout 300s", "replace rule inet fw4 forward handle 42 jump purewrt_client_offload"} {
		if !strings.Contains(script, v) {
			t.Errorf("missing %s", v)
		}
	}
	if strings.Contains(script, "accept") {
		t.Fatal("offload guard bypasses firewall policy")
	}
	if _, e := clientOffloadFind(original + " # handle 42\n" + original + " # handle 44"); e == nil {
		t.Fatal("ambiguous offload rules accepted")
	}
	if p := os.Getenv("PUREWRT_TEST_OFFLOAD_OUTPUT"); p != "" {
		os.WriteFile(p, []byte(script), 0600)
	}
}

func TestClientSessionRealPacketsAreNotGenerated(t *testing.T) {
	route, _ := strconv.ParseUint(clientTestMark, 0, 32)
	fake, _ := strconv.ParseUint(clientTestFakeMark, 0, 32)
	// Model nfqws's any-bit generated-packet test, including an mwan3 mark.
	if (route|0x200)&fake != 0 {
		t.Fatal("nfqws would skip real client packets")
	}
	script := clientTestNFT(ZapretClientOptions{IP: "192.168.1.20", MAC: "02:00:00:00:00:20", Interface: "eth1"}, "0xff")
	for _, rule := range []string{
		"raw meta mark & 0x10000000 != 0 notrack",
		"output_mangle meta mark & 0x10000000 != 0 return",
	} {
		if !strings.Contains(script, rule) {
			t.Fatalf("missing fake exemption: %s", rule)
		}
	}
}

func TestClientSessionOptionalFeatureMarkConflicts(t *testing.T) {
	c := config.Default()
	for _, rules := range []string{"", "100: from all fwmark 0x1/0xff lookup 100\n2001: from all fwmark 0x100/0x3f00 lookup 1"} {
		if e := clientTestValidateMarks(c, rules); e != nil {
			t.Fatal(e)
		}
	}
	for _, rules := range []string{"2001: from all fwmark 0x100/0x8003f00 lookup 1", "2001: from all fwmark 0x10000000/0x10000000 lookup 2", "2001: from all fwmark 0x100 lookup 1"} {
		if clientTestValidateMarks(c, rules) == nil {
			t.Fatalf("accepted %s", rules)
		}
	}
	c.ZapretProfiles = []config.ZapretProfile{{Name: "custom", Enabled: true, FwMark: "0x08000000"}}
	if clientTestValidateMarks(c, "") == nil {
		t.Fatal("accepted conflicting profile")
	}
	c.ZapretProfiles[0].Enabled = false
	if e := clientTestValidateMarks(c, ""); e != nil {
		t.Fatal(e)
	}
}
