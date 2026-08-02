package manager

import (
	"strings"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/checker"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/mihomoapi"
	"github.com/purewrt/purewrt/internal/proxyguard"
)

func TestRecordProxyGuardRunOutcomeUsesBoundedLabels(t *testing.T) {
	metrics.Default.ResetObservations()
	defer metrics.Default.ResetObservations()
	recordProxyGuardRunOutcome(ProxyGuardReport{Transitions: []ProxyGuardTransition{{From: proxyguard.Suspect, To: proxyguard.Quarantined, Reason: "download 100 kbps below 2000 kbps"}}}, nil, time.Now().Add(-time.Second))
	out := metrics.Default.Render()
	for _, want := range []string{
		"purewrt_proxy_guard_last_run_success 1",
		"purewrt_proxy_guard_last_attempt_timestamp_seconds ",
		"purewrt_proxy_guard_last_success_timestamp_seconds ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "below 2000") {
		t.Fatalf("free-form reason leaked into metric labels:\n%s", out)
	}
	if strings.Contains(out, "# TYPE purewrt_proxy_guard_") && strings.Contains(out, " counter\n") {
		t.Fatalf("proxy-guard exported a counter family:\n%s", out)
	}
}

func TestProxyGuardLatencyUnstable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		samples []int
		want    bool
	}{
		{"stable", []int{80, 90, 85, 95, 88}, false},
		{"two failures", []int{80, 0, 90, 0, 85}, true},
		{"large swing", []int{80, 90, 85, 600, 88}, true},
		{"large absolute but not ratio", []int{800, 900, 850, 1100, 880}, false},
		{"insufficient", []int{80, 0, 90}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := latencyUnstable(tc.samples, 250); got != tc.want {
				t.Fatalf("latencyUnstable(%v)=%v want %v", tc.samples, got, tc.want)
			}
		})
	}
}

func TestProxyGuardSpeedResultAndThreeMemberFloor(t *testing.T) {
	n := &proxyguard.NodeState{Name: "slow", State: proxyguard.Healthy}
	applySpeedResult(n, checker.ThroughputResult{OK: true, Kbps: 500}, 2000, 250, testNow())
	if n.State != proxyguard.Suspect || n.BadStreak != 1 {
		t.Fatalf("slow result not marked suspect: %+v", n)
	}
	applySpeedResult(n, checker.ThroughputResult{OK: true, Kbps: 400}, 2000, 250, testNow())
	if n.BadStreak != 2 {
		t.Fatalf("second slow result did not confirm: %+v", n)
	}

	s := proxyguard.NewState()
	s.Nodes["slow"] = &proxyguard.NodeState{Name: "slow", State: proxyguard.Quarantined, LastDownKbps: 400, LastDelayMS: 100}
	s.Nodes["less_slow"] = &proxyguard.NodeState{Name: "less_slow", State: proxyguard.Quarantined, LastDownKbps: 800, LastDelayMS: 200}
	s.Nodes["fast"] = &proxyguard.NodeState{Name: "fast", State: proxyguard.Quarantined, LastDownKbps: 1600, LastDelayMS: 300}
	s.Nodes["healthy"] = &proxyguard.NodeState{Name: "healthy", State: proxyguard.Healthy, LastDownKbps: 3000}
	s.Groups["Common"] = &proxyguard.GroupState{Name: "Common", Members: []string{"slow", "less_slow", "fast", "healthy"}}
	s.Groups["Tiny"] = &proxyguard.GroupState{Name: "Tiny", Members: []string{"slow", "less_slow"}}
	recomputeLastResorts(&s, 3)
	if got := s.Groups["Common"].LastResorts; len(got) != 2 || got[0] != "fast" || got[1] != "less_slow" {
		t.Fatalf("Common last resorts=%v want [fast less_slow]", got)
	}
	if got := s.Groups["Tiny"].LastResorts; len(got) != 2 || got[0] != "less_slow" || got[1] != "slow" {
		t.Fatalf("Tiny last resorts=%v want [less_slow slow]", got)
	}
	recomputeLastResorts(&s, 1)
	if got := s.Groups["Common"].LastResorts; len(got) != 0 {
		t.Fatalf("custom one-member floor retained unnecessary nodes: %v", got)
	}
	if got := s.Groups["Tiny"].LastResorts; len(got) != 1 || got[0] != "less_slow" {
		t.Fatalf("custom Tiny last resorts=%v want [less_slow]", got)
	}
}

func TestGuardNodeBetterRanksSpeedTierJitterAndLatency(t *testing.T) {
	faster := &proxyguard.NodeState{LastDownKbps: 5000, JitterMS: 400, LastDelayMS: 900}
	slower := &proxyguard.NodeState{LastDownKbps: 4000, JitterMS: 10, LastDelayMS: 20}
	if !guardNodeBetter(faster, slower) {
		t.Fatal("higher download tier must rank first even when its jitter is worse")
	}

	similarFast := &proxyguard.NodeState{LastDownKbps: 5400, JitterMS: 400, LastDelayMS: 900}
	similarStable := &proxyguard.NodeState{LastDownKbps: 5100, JitterMS: 10, LastDelayMS: 20}
	if !guardNodeBetter(similarStable, similarFast) {
		t.Fatal("jitter must decide between nodes in the same rounded speed tier")
	}

	stable := &proxyguard.NodeState{LastDownKbps: 5000, JitterMS: 20, LastDelayMS: 900}
	jittery := &proxyguard.NodeState{LastDownKbps: 5000, JitterMS: 200, LastDelayMS: 20}
	if !guardNodeBetter(stable, jittery) {
		t.Fatal("lower jitter must rank first within a speed tier")
	}

	highLatency := &proxyguard.NodeState{LastDownKbps: 5000, JitterMS: 20, LastDelayMS: 900}
	lowLatency := &proxyguard.NodeState{LastDownKbps: 5000, JitterMS: 20, LastDelayMS: 20}
	if !guardNodeBetter(lowLatency, highLatency) {
		t.Fatal("lower latency must break equal-tier/equal-jitter ties")
	}

	failedLatency := &proxyguard.NodeState{LastDownKbps: 5100, JitterMS: 0, LastDelayMS: 0, LatenciesMS: []int{0, 0, 0, 0, 0}}
	validLatency := &proxyguard.NodeState{LastDownKbps: 5100, JitterMS: 100, LastDelayMS: 200, LatenciesMS: []int{100, 200, 150, 120, 180}}
	if !guardNodeBetter(validLatency, failedLatency) {
		t.Fatal("failed zero-latency window must not rank as perfect jitter")
	}
}

func TestProxyGuardEligibleMembersPreserveBuiltinsAndNestedGroups(t *testing.T) {
	proxies := map[string]mihomoapi.Proxy{
		"nested": {Name: "nested", All: []string{"node"}},
		"node":   {Name: "node", Type: "VLESS"},
		"vpn_wg": {Name: "vpn_wg", Type: "Direct"},
	}
	for _, name := range []string{"DIRECT", "nested"} {
		if guardEligibleMember(name, proxies) {
			t.Fatalf("%q should not be managed by the guard", name)
		}
	}
	for _, name := range []string{"node", "vpn_wg"} {
		if !guardEligibleMember(name, proxies) {
			t.Fatalf("%q should be guard eligible", name)
		}
	}
}

func TestProxyGuardRollingCandidatesOldestFirst(t *testing.T) {
	now := time.Date(2026, 7, 31, 1, 0, 0, 0, time.UTC)
	s := proxyguard.NewState()
	s.Nodes["never-b"] = &proxyguard.NodeState{Name: "never-b", State: proxyguard.Healthy}
	s.Nodes["never-a"] = &proxyguard.NodeState{Name: "never-a", State: proxyguard.Healthy}
	s.Nodes["old"] = &proxyguard.NodeState{Name: "old", State: proxyguard.Healthy, LastProbe: now.Add(-7 * time.Hour)}
	s.Nodes["recent"] = &proxyguard.NodeState{Name: "recent", State: proxyguard.Healthy, LastProbe: now.Add(-time.Hour)}
	s.Nodes["quarantined"] = &proxyguard.NodeState{Name: "quarantined", State: proxyguard.Quarantined}

	got := rollingProbeCandidates(s, now, 6*time.Hour, map[string]bool{"never-b": true})
	want := []string{"never-a", "old"}
	if len(got) != len(want) {
		t.Fatalf("rolling candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rolling candidates = %v, want %v", got, want)
		}
	}
}

func TestFormatProxyGuardDistinguishesUntestedFromMeasuredZero(t *testing.T) {
	s := proxyguard.NewState()
	s.Nodes["untested"] = &proxyguard.NodeState{Name: "untested", State: proxyguard.Healthy}
	s.Nodes["failed"] = &proxyguard.NodeState{Name: "failed", State: proxyguard.Suspect, LastProbe: time.Unix(1, 0)}
	out := FormatProxyGuard(ProxyGuardReport{Enabled: true, State: s})
	if !strings.Contains(out, "down=not tested") {
		t.Fatalf("untested node is ambiguous:\n%s", out)
	}
	if !strings.Contains(out, "down=0") {
		t.Fatalf("measured zero is missing:\n%s", out)
	}
}

func testNow() (z time.Time) { return }
