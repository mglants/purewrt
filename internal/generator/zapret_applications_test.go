package generator

import (
	"github.com/purewrt/purewrt/internal/config"
	"strings"
	"testing"
)

func TestApplicationWANAssignments(t *testing.T) {
	c := config.Default()
	c.ZapretApplications = []config.ZapretApplication{{Name: "discord", Enabled: true, Assignments: []string{"wan_a=tcp_a", "wan_b=tcp_b"}}}
	c.Sections = []config.Section{{Name: "chat", Enabled: true, Action: "zapret", IPv4Enabled: true, ZapretStrategies: []string{"discord"}}}
	list := config.ZapretCandidateList{Candidates: []config.ZapretCandidate{{Name: "tcp_a", Protocols: []string{"tcp"}, TCPPorts: "443", Params: "--filter-tcp=443 --lua-desync=multisplit:pos=1"}, {Name: "tcp_b", Protocols: []string{"tcp"}, TCPPorts: "443", Params: "--filter-tcp=443 --lua-desync=multisplit:pos=2"}}}
	if err := c.CompileZapretApplications(list); err != nil {
		t.Fatal(err)
	}
	env := string(ZapretEnv(c))
	for _, want := range []string{"INSTANCE_COUNT=\"1\"", "QUEUE=\"200\"", "--filter-mark=0x10000/0xff0000", "--filter-mark=0x20000/0xff0000", "multisplit:pos=1", "multisplit:pos=2"} {
		if !strings.Contains(env, want) {
			t.Fatalf("missing %s: %s", want, env)
		}
	}
	for i, want := range []string{"wan_a", "wan_b"} {
		if c.ZapretProfiles[i].Interfaces[0] != want {
			t.Fatal(c.ZapretProfiles)
		}
	}
	out := string(config.Serialize(c))
	if strings.Contains(out, "option params") || strings.Contains(out, "zapret_profile") || strings.Contains(out, "list zapret_strategy 'discord_w") {
		t.Fatal("serialized runtime copies", out)
	}
	if !strings.Contains(out, "list zapret_strategy 'discord'") {
		t.Fatal("lost application reference", out)
	}
	if err := c.CompileZapretApplications(list); err != nil {
		t.Fatal("second compile", err)
	}
	if string(ZapretEnv(c)) != env {
		t.Fatal("unstable runtime expansion")
	}
	c.ZapretApplications[0].Assignments = []string{"wan_a=tcp_a", "wan_b=tcp_a"}
	if err := c.CompileZapretApplications(list); err != nil {
		t.Fatal(err)
	}
	if len(c.ZapretStrategies) != 1 || len(c.ZapretProfiles[0].Interfaces) != 2 {
		t.Fatal("same strategy should share one instance", c.ZapretProfiles)
	}
	c.ZapretApplications[0].Assignments = append(c.ZapretApplications[0].Assignments, "wan_a=tcp_b")
	if err := c.CompileZapretApplications(list); err == nil {
		t.Fatal("duplicate WAN accepted")
	}
}

func TestRouterOutputHonorsZapretPriority(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{
		{Name: "proxy", Enabled: true, Action: "proxy", Priority: 20, IPv4Enabled: true},
		{Name: "direct", Enabled: true, Action: "direct", Priority: 1, IPv4Enabled: true},
	}
	var b strings.Builder
	writeOutputChain(&b, c, false)
	text := b.String()
	if strings.Index(text, "@proxy_direct4") > strings.Index(text, "@proxy_proxy4") {
		t.Fatal("output ignores section priority", text)
	}
}

func TestSharedCombinedProfilesAndBlobIsolation(t *testing.T) {
	instances := []zapretInstance{
		{strategy: config.ZapretStrategy{SelectorMark: 0x10000, Params: "--filter-tcp=443 --lua-desync=fake:blob=hello --new --filter-udp=443 --lua-desync=fake:blob=hello", LibraryBlobs: []string{"hello:0x01"}}},
		{strategy: config.ZapretStrategy{SelectorMark: 0x20000, Params: "--filter-tcp=443 --lua-desync=fake:blob=hello", LibraryBlobs: []string{"hello:0x02"}}},
	}
	params, blobs := zapretSharedParams(instances)
	if strings.Count(params, "--filter-mark=0x10000/0xff0000") != 2 || strings.Count(params, "--filter-mark=0x20000/0xff0000") != 1 {
		t.Fatal(params)
	}
	for _, want := range []string{"--blob=pw_10000_hello:0x01", "--blob=pw_20000_hello:0x02"} {
		if !strings.Contains(blobs, want) {
			t.Fatal(blobs)
		}
	}
	if strings.Contains(params, "blob=hello") || !strings.Contains(params, "blob=pw_20000_hello") {
		t.Fatal(params)
	}
}
