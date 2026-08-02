package manager

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/checker"
	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/proxyguard"
	"github.com/purewrt/purewrt/internal/system"
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

func TestNetCheckMetricsExposeOnlyLatestLayerAndNodeStatus(t *testing.T) {
	metrics.Default.ResetObservations()
	defer metrics.Default.ResetObservations()

	first := NetCheckReport{
		Verdict: "ok",
		Layers:  []LayerResult{{Name: "dns", Status: "ok"}, {Name: "routing", Status: "fail"}},
		Nodes:   []NodeResult{{Node: "removed", Verdict: "ok"}},
	}
	first.recordMetrics()
	latest := NetCheckReport{
		Verdict: "broken",
		Layers:  []LayerResult{{Name: "dns", Status: "fail"}},
		Nodes:   []NodeResult{{Node: "current", Verdict: "throttled"}},
	}
	latest.recordMetrics()
	out := metrics.Default.Render()
	for _, want := range []string{
		`purewrt_netcheck_layer_status{layer="dns",status="fail"} 1`,
		`purewrt_netcheck_node_status{node="current",status="throttled"} 1`,
		`purewrt_netcheck_verdict 0`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing latest-state metric %q:\n%s", want, out)
		}
	}
	for _, stale := range []string{`status="ok"`, `layer="routing"`, `node="removed"`} {
		if strings.Contains(out, stale) {
			t.Fatalf("stale status %q survived reconciliation:\n%s", stale, out)
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

func TestNetCheckSkipsWhenProxyProbeLockIsBusy(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.RuntimeDir = filepath.Join(dir, "run")
	configPath := filepath.Join(dir, "purewrt")
	if err := config.Save(configPath, c); err != nil {
		t.Fatal(err)
	}

	lock, err := system.TryAcquire(proxyguard.ProbeLockPath(c))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()

	rep := (Manager{ConfigPath: configPath}).NetCheck(context.Background(), NetCheckOpts{})
	if !rep.Skipped || rep.Verdict != "skipped" || rep.BrokenLayer != "probe_lock" {
		t.Fatalf("expected a clean lock-contention skip, got %+v", rep)
	}
	if !strings.Contains(rep.Diagnosis, "sent no traffic") {
		t.Fatalf("skip must state that no probe traffic was sent: %q", rep.Diagnosis)
	}
	if len(rep.Layers) != 0 || rep.Download.Bytes != 0 || rep.Upload.Bytes != 0 {
		t.Fatalf("busy net-check performed work: %+v", rep)
	}
	if got := FormatNetCheck(rep); !strings.Contains(got, "verdict=SKIPPED") {
		t.Fatalf("formatted result does not expose skip: %q", got)
	}
}
