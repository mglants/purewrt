package manager

import (
	"testing"

	"github.com/purewrt/purewrt/internal/checker"
	"github.com/purewrt/purewrt/internal/config"
)

func TestDetectMode(t *testing.T) {
	cases := []struct {
		name string
		c    config.Config
		want string
	}{
		{"proxy", config.Config{
			ProxyProviders: []config.ProxyProvider{{Name: "p", Enabled: true}},
			Sections:       []config.Section{{Name: "common", Enabled: true, Action: "proxy"}},
		}, "proxy"},
		{"vpn_only", config.Config{
			VPNs:     []config.VPN{{Name: "w", Enabled: true, Interface: "wg0"}},
			Sections: []config.Section{{Name: "common", Enabled: true, Action: "proxy", VPNs: []string{"w"}}},
		}, "vpn_only"},
		{"zapret_only", config.Config{
			Sections: []config.Section{{Name: "z", Enabled: true, Action: "zapret"}},
		}, "zapret_only"},
		{"direct", config.Config{
			Sections: []config.Section{{Name: "d", Enabled: true, Action: "direct"}},
		}, "direct"},
	}
	for _, tc := range cases {
		if got := detectMode(tc.c); got != tc.want {
			t.Errorf("%s: detectMode = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// okThroughput / failThroughput build ThroughputResult fixtures.
func okThroughput(kbps float64) checker.ThroughputResult {
	return checker.ThroughputResult{OK: true, Bytes: 1 << 20, Seconds: 1, Kbps: kbps}
}
func failThroughput() checker.ThroughputResult {
	return checker.ThroughputResult{OK: false, Error: "timeout"}
}

func TestSynthesizeProxyVerdicts(t *testing.T) {
	mk := func(mod func(*NetCheckReport)) NetCheckReport {
		r := NetCheckReport{Mode: "proxy"}
		r.addLayer("mihomo", "ok", "")
		mod(&r)
		r.synthesize()
		return r
	}

	t.Run("all healthy", func(t *testing.T) {
		r := mk(func(r *NetCheckReport) {
			r.Download = okThroughput(50000)
			r.Upload = okThroughput(20000)
			r.DirectDomestic = okThroughput(10000)
		})
		if r.Verdict != "ok" {
			t.Fatalf("want ok, got %q (%s)", r.Verdict, r.Diagnosis)
		}
	})

	t.Run("url-test green but data dead, WAN up", func(t *testing.T) {
		r := mk(func(r *NetCheckReport) {
			r.Download = failThroughput()
			r.Upload = failThroughput()
			r.DirectDomestic = okThroughput(10000)
		})
		if r.Verdict != "broken" || r.BrokenLayer != "download" {
			t.Fatalf("want broken/download, got %q/%q", r.Verdict, r.BrokenLayer)
		}
	})

	t.Run("both proxy and WAN dead", func(t *testing.T) {
		r := mk(func(r *NetCheckReport) {
			r.Download = failThroughput()
			r.DirectDomestic = failThroughput()
		})
		if r.Verdict != "broken" || r.BrokenLayer != "wan" {
			t.Fatalf("want broken/wan, got %q/%q", r.Verdict, r.BrokenLayer)
		}
	})

	t.Run("mihomo down", func(t *testing.T) {
		r := NetCheckReport{Mode: "proxy"}
		r.addLayer("mihomo", "fail", "")
		r.synthesize()
		if r.Verdict != "broken" || r.BrokenLayer != "mihomo" {
			t.Fatalf("want broken/mihomo, got %q/%q", r.Verdict, r.BrokenLayer)
		}
	})

	t.Run("slow proxy is degraded", func(t *testing.T) {
		r := mk(func(r *NetCheckReport) {
			r.Download = okThroughput(200) // < slowKbps
			r.Upload = okThroughput(200)
			r.DirectDomestic = okThroughput(10000)
		})
		if r.Verdict != "degraded" || r.BrokenLayer != "download" {
			t.Fatalf("want degraded/download, got %q/%q", r.Verdict, r.BrokenLayer)
		}
	})
}

func TestSynthesizeZapretVerdicts(t *testing.T) {
	t.Run("wan down", func(t *testing.T) {
		r := NetCheckReport{Mode: "zapret_only", DirectDomestic: failThroughput()}
		r.synthesize()
		if r.Verdict != "broken" || r.BrokenLayer != "wan" {
			t.Fatalf("want broken/wan, got %q/%q", r.Verdict, r.BrokenLayer)
		}
	})
	t.Run("zapret not defeating dpi", func(t *testing.T) {
		r := NetCheckReport{Mode: "zapret_only", DirectDomestic: okThroughput(5000)}
		r.addLayer("zapret", "fail", "")
		r.synthesize()
		if r.Verdict != "degraded" || r.BrokenLayer != "zapret" {
			t.Fatalf("want degraded/zapret, got %q/%q", r.Verdict, r.BrokenLayer)
		}
	})
	t.Run("healthy", func(t *testing.T) {
		r := NetCheckReport{Mode: "zapret_only", DirectDomestic: okThroughput(5000)}
		r.addLayer("zapret", "ok", "")
		r.synthesize()
		if r.Verdict != "ok" {
			t.Fatalf("want ok, got %q", r.Verdict)
		}
	})
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"🇵🇱 ♾️ grpc YTRU vpn5-frind2-pl-itdc": "grpc_ytru_vpn5-frind2-pl-itdc",
		"plain":                                "plain",
		"🇱🇻♾️THROTTL grpc vpn4-lv-veesp":       "throttl_grpc_vpn4-lv-veesp",
		"":                                     "node",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}
