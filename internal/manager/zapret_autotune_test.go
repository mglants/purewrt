package manager

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

const sampleBlockcheckOutput = `
* checking ipv4 example.com
* probing default tcp http
* tpws not applicable
* nfqws : trying strategies

!!!!! check_domain_http: working strategy found for ipv4 example.com : nfqws --filter-tcp=80 --dpi-desync=fake --dpi-desync-ttl=5 !!!!!

* probing default tcp https tls12
!!!!! check_domain_https_tls12: working strategy found for ipv4 example.com : nfqws --filter-tcp=443 --dpi-desync=split2 --dpi-desync-split-pos=1 !!!!!

* checking ipv4 youtube.com
!!!!! check_domain_https_tls13: working strategy found for ipv4 youtube.com : nfqws --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=0x16030101 !!!!!
!!!!! check_domain_http3: working strategy found for ipv4 youtube.com : nfqws --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 !!!!!

* SUMMARY
example.com check_domain_http ipv4 : nfqws --filter-tcp=80 --dpi-desync=fake --dpi-desync-ttl=5
example.com check_domain_https_tls12 ipv4 : nfqws --filter-tcp=443 --dpi-desync=split2 --dpi-desync-split-pos=1
youtube.com check_domain_https_tls13 ipv4 : nfqws --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=0x16030101
youtube.com check_domain_http3 ipv4 : nfqws --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6

* COMMON
--filter-tcp=443 --dpi-desync=split2 --dpi-desync-split-pos=1
--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6

Please note this SUMMARY does not guarantee a magic pill for you to copy/paste and be happy.
`

func TestParseBlockcheckOutputCollectsPerHostWinners(t *testing.T) {
	t.Parallel()
	res := parseBlockcheckOutput([]byte(sampleBlockcheckOutput), []string{"example.com", "youtube.com"})
	if len(res.PerHost) != 4 {
		t.Fatalf("per-host count = %d, want 4: %+v", len(res.PerHost), res.PerHost)
	}
	gotHosts := map[string]int{}
	for _, e := range res.PerHost {
		gotHosts[e.Host]++
		if e.IPVer != 4 {
			t.Errorf("entry %+v: want IPVer=4", e)
		}
		if e.Daemon != "nfqws" {
			t.Errorf("entry %+v: want Daemon=nfqws", e)
		}
	}
	if gotHosts["example.com"] != 2 || gotHosts["youtube.com"] != 2 {
		t.Fatalf("per-host hosts = %v, want 2+2", gotHosts)
	}
}

func TestParseBlockcheckOutputCollectsCommonIntersection(t *testing.T) {
	t.Parallel()
	res := parseBlockcheckOutput([]byte(sampleBlockcheckOutput), []string{"example.com", "youtube.com"})
	if len(res.Common) != 2 {
		t.Fatalf("common count = %d, want 2: %+v", len(res.Common), res.Common)
	}
	wantProtos := map[string]string{"tcp": "443", "udp": "443"}
	for _, e := range res.Common {
		if want, ok := wantProtos[e.Protocol]; !ok || want != e.Ports {
			t.Errorf("common entry protocol=%q ports=%q unexpected", e.Protocol, e.Ports)
		}
	}
}

func TestInferProtocolPortsFromStrategy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, proto, ports string
	}{
		{"--filter-tcp=443 --dpi-desync=fake", "tcp", "443"},
		{"--filter-udp=443,853 --dpi-desync=fake", "udp", "443,853"},
		{"--dpi-desync=multisplit", "", ""},
	}
	for _, c := range cases {
		gotProto, gotPorts := inferProtocolPorts(c.in)
		if gotProto != c.proto || gotPorts != c.ports {
			t.Errorf("inferProtocolPorts(%q) = (%q, %q), want (%q, %q)", c.in, gotProto, gotPorts, c.proto, c.ports)
		}
	}
}

func TestChooseAutotuneStrategiesPrefersCommonOverPerHost(t *testing.T) {
	t.Parallel()
	res := parseBlockcheckOutput([]byte(sampleBlockcheckOutput), []string{"example.com", "youtube.com"})
	picks := chooseAutotuneStrategies(res, "autotune")
	if len(picks) != 2 {
		t.Fatalf("chose %d strategies, want 2: %+v", len(picks), picks)
	}
	gotName := map[string]bool{}
	for _, p := range picks {
		gotName[p.Name] = true
		if !p.Enabled {
			t.Errorf("strategy %s should be enabled", p.Name)
		}
		if !strings.Contains(p.Params, "--filter-") {
			t.Errorf("strategy %s missing --filter- in Params: %q", p.Name, p.Params)
		}
	}
	if !gotName["autotune_tcp_443"] || !gotName["autotune_udp_443"] {
		t.Fatalf("expected autotune_tcp_443 and autotune_udp_443 names, got %v", gotName)
	}
}

func TestChooseAutotuneStrategiesFallsBackToPerHost(t *testing.T) {
	t.Parallel()
	// Synthetic input with NO * COMMON section.
	out := `!!!!! check_domain_https_tls12: working strategy found for ipv4 only-host.example : nfqws --filter-tcp=443 --dpi-desync=multisplit !!!!!`
	res := parseBlockcheckOutput([]byte(out), []string{"only-host.example"})
	if len(res.Common) != 0 {
		t.Fatalf("expected no COMMON entries, got %d", len(res.Common))
	}
	picks := chooseAutotuneStrategies(res, "autotune")
	if len(picks) != 1 {
		t.Fatalf("want 1 fallback pick, got %d", len(picks))
	}
	if !strings.Contains(picks[0].Params, "multisplit") {
		t.Fatalf("fallback strategy missing param: %q", picks[0].Params)
	}
}

func TestApplyAutotuneStrategiesUpsertsByName(t *testing.T) {
	t.Parallel()
	c := config.Default()
	c.ZapretStrategies = []config.ZapretStrategy{
		{Name: "existing", Enabled: false, Profile: "wan"},
		{Name: "autotune_tcp_443", Enabled: false, Profile: "wan", Params: "old"},
	}
	c2 := applyAutotuneStrategiesToConfig(c, []config.ZapretStrategy{
		{Name: "autotune_tcp_443", Enabled: true, Profile: "wan", Params: "new"},
		{Name: "autotune_udp_443", Enabled: true, Profile: "wan", Params: "u"},
	})
	if len(c2.ZapretStrategies) != 3 {
		t.Fatalf("want 3 strategies (existing + 2 autotune), got %d", len(c2.ZapretStrategies))
	}
	for _, zs := range c2.ZapretStrategies {
		if zs.Name == "autotune_tcp_443" && zs.Params != "new" {
			t.Fatalf("autotune_tcp_443 not upserted with new Params; got %q", zs.Params)
		}
		if zs.Name == "existing" && zs.Enabled {
			t.Fatalf("existing strategy was clobbered")
		}
	}
}
