package generator

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// makeZapretConfig builds a Default()-rooted config with one enabled zapret
// section + one or more strategies, suitable for exercising ZapretUpstreamConfig.
func makeZapretConfig(t *testing.T, strategies ...config.ZapretStrategy) config.Config {
	t.Helper()
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{
		Name: "wan", Enabled: true, Network: "auto",
		Interfaces: []string{"wan"}, FwMark: "0x40000000",
		NFQWSBin: "/usr/libexec/zapret/nfqws2", LuaBundleDir: "/usr/libexec/zapret/lua",
	}}
	c.ZapretStrategies = strategies
	c.Sections = []config.Section{{
		Name: "youtube", Enabled: true, Action: "zapret",
		ZapretStrategies: zapretStrategyNames(strategies),
	}}
	return c
}

func zapretStrategyNames(s []config.ZapretStrategy) []string {
	n := make([]string, 0, len(s))
	for _, x := range s {
		n = append(n, x.Name)
	}
	return n
}

func TestZapretUpstreamConfigDisabledWhenNoStrategies(t *testing.T) {
	t.Parallel()
	c := config.Default()
	out := string(ZapretUpstreamConfig(c))
	if !strings.Contains(out, "NFQWS2_ENABLE=0") {
		t.Fatalf("expected NFQWS2_ENABLE=0 when no strategies, got:\n%s", out)
	}
}

func TestZapretUpstreamConfigEmitsLuaInitBundle(t *testing.T) {
	t.Parallel()
	c := makeZapretConfig(t, config.ZapretStrategy{
		Name: "youtube_tcp", Enabled: true, Profile: "wan",
		Protocols: []string{"tcp"}, TCPPorts: "443", QueueNum: 200,
		Params: "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls",
	})
	out := string(ZapretUpstreamConfig(c))
	for _, want := range []string{
		"--lua-init=@/usr/libexec/zapret/lua/zapret-lib.lua",
		"--lua-init=@/usr/libexec/zapret/lua/zapret-antidpi.lua",
		"--lua-init=@/usr/libexec/zapret/lua/zapret-auto.lua",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in generated config:\n%s", want, out)
		}
	}
}

func TestZapretUpstreamConfigJoinsProfilesWithNew(t *testing.T) {
	t.Parallel()
	c := makeZapretConfig(t,
		config.ZapretStrategy{
			Name: "tcp_tls", Enabled: true, Profile: "wan",
			Protocols: []string{"tcp"}, TCPPorts: "443", QueueNum: 200,
			Params: "--lua-desync=multisplit",
		},
		config.ZapretStrategy{
			Name: "udp_quic", Enabled: true, Profile: "wan",
			Protocols: []string{"udp"}, UDPPorts: "443", QueueNum: 201,
			Params: "--lua-desync=fake:repeats=6",
		},
	)
	out := string(ZapretUpstreamConfig(c))
	// One --new between each profile (and the lua-init bundle counts as the
	// first profile too, so 2 strategies + lua-init = 2 --new separators).
	if got := strings.Count(out, "--new"); got != 2 {
		t.Fatalf("--new count = %d, want 2, in:\n%s", got, out)
	}
	if !strings.Contains(out, "--filter-tcp=443") {
		t.Fatal("expected --filter-tcp=443 for tcp_tls strategy")
	}
	if !strings.Contains(out, "--filter-udp=443") {
		t.Fatal("expected --filter-udp=443 for udp_quic strategy")
	}
	if !strings.Contains(out, "--lua-desync=multisplit") || !strings.Contains(out, "--lua-desync=fake:repeats=6") {
		t.Fatalf("expected both strategies' params in output:\n%s", out)
	}
}

func TestZapretUpstreamConfigPreservesParamFilters(t *testing.T) {
	t.Parallel()
	// When Params already specifies --filter-tcp / --filter-udp, don't add
	// our auto-derived filter — trust the user.
	c := makeZapretConfig(t, config.ZapretStrategy{
		Name: "manual", Enabled: true, Profile: "wan",
		Protocols: []string{"tcp"}, TCPPorts: "443", QueueNum: 200,
		Params: "--filter-tcp=80,443 --filter-l7=http --lua-desync=multidisorder",
	})
	out := string(ZapretUpstreamConfig(c))
	if !strings.Contains(out, "--filter-tcp=80,443") {
		t.Fatal("expected user's --filter-tcp=80,443 to pass through")
	}
	if strings.Count(out, "--filter-tcp=") != 1 {
		t.Fatalf("expected exactly one --filter-tcp= (user's), got:\n%s", out)
	}
}

func TestZapretUpstreamConfigEscapesQuotes(t *testing.T) {
	t.Parallel()
	c := makeZapretConfig(t, config.ZapretStrategy{
		Name: "weird", Enabled: true, Profile: "wan",
		Protocols: []string{"tcp"}, TCPPorts: "443", QueueNum: 200,
		Params: `--lua-desync=fake:cookie="hello"`,
	})
	out := string(ZapretUpstreamConfig(c))
	// shellEscape replaces " with \"
	if !strings.Contains(out, `\"hello\"`) {
		t.Fatalf("expected embedded quotes to be shell-escaped, got:\n%s", out)
	}
}
