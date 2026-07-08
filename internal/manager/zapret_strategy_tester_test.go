package manager

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
)

func TestZapretStrategyTestRejectsBadInput(t *testing.T) {
	t.Parallel()
	m := Manager{DryRun: true}
	cases := []struct {
		name string
		opt  ZapretStrategyTestOptions
	}{
		{"empty cmd_opts", ZapretStrategyTestOptions{CmdOpts: "   "}},
		{"cmd_opts injection", ZapretStrategyTestOptions{CmdOpts: "--filter-tcp=443; rm -rf /"}},
		{"cmd_opts backtick", ZapretStrategyTestOptions{CmdOpts: "--filter-tcp=443 `id`"}},
		{"interface injection", ZapretStrategyTestOptions{CmdOpts: "--filter-tcp=443", Interface: "eth0; reboot"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.ZapretStrategyTest(tc.opt); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestZapretVerdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		baseline, strategy    bool
		verdict               string
		wantPassed, wantFixed bool
	}{
		{false, true, "fixed", true, true},        // strategy unblocked a blocked site
		{true, true, "already-ok", true, false},   // site worked direct anyway
		{false, false, "still-blocked", false, false},
		{true, false, "still-blocked", false, false}, // regressed: worked direct, fails with strategy
	}
	for _, tc := range cases {
		v, passed, fixed := zapretVerdict(tc.baseline, tc.strategy)
		if v != tc.verdict || passed != tc.wantPassed || fixed != tc.wantFixed {
			t.Errorf("zapretVerdict(%v,%v) = (%q,%v,%v), want (%q,%v,%v)",
				tc.baseline, tc.strategy, v, passed, fixed, tc.verdict, tc.wantPassed, tc.wantFixed)
		}
	}
}

func TestZapretSelectCandidates(t *testing.T) {
	t.Parallel()
	cands := []config.ZapretCandidate{
		{Name: "a", ISP: "common"},
		{Name: "b", ISP: "Rostelecom (RU)"},
		{Name: "c", ISP: "common"},
		{Name: "d", ISP: "MТС (RU)"},
	}
	if got := zapretSelectCandidates(cands, ""); len(got) != 4 {
		t.Fatalf("empty isp: got %d, want all 4", len(got))
	}
	got := zapretSelectCandidates(cands, "common")
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
		t.Fatalf("isp=common: got %+v, want a,c", got)
	}
	if got := zapretSelectCandidates(cands, "nonexistent"); len(got) != 0 {
		t.Fatalf("unknown isp: got %d, want 0", len(got))
	}
}

func TestRankStrategyResults(t *testing.T) {
	t.Parallel()
	// Fixed dominates Passed; ties keep input order (stable).
	out := []ZapretStrategyTestResult{
		{Strategy: "low", Fixed: 0, Passed: 3},
		{Strategy: "best", Fixed: 4, Passed: 4},
		{Strategy: "mid-a", Fixed: 2, Passed: 5},
		{Strategy: "mid-b", Fixed: 2, Passed: 5},
		{Strategy: "mid-lesspass", Fixed: 2, Passed: 2},
	}
	rankStrategyResults(out)
	wantOrder := []string{"best", "mid-a", "mid-b", "mid-lesspass", "low"}
	for i, w := range wantOrder {
		if out[i].Strategy != w {
			t.Fatalf("rank[%d] = %q, want %q (full: %+v)", i, out[i].Strategy, w, out)
		}
	}
}

func TestZapretProbeOK(t *testing.T) {
	t.Parallel()
	// Handshake mode keys on time_appconnect > 0; download mode on bytes > 0.
	if !zapretProbeOK(0.12, 0, false) {
		t.Error("handshake mode: appconnect>0 should be ok")
	}
	if zapretProbeOK(0, 0, false) {
		t.Error("handshake mode: appconnect==0 should be fail")
	}
	if zapretProbeOK(0, 4096, false) {
		t.Error("handshake mode: bytes must not decide the verdict")
	}
	if !zapretProbeOK(0.5, 4096, true) {
		t.Error("download mode: bytes>0 should be ok")
	}
	if zapretProbeOK(0.5, 0, true) {
		t.Error("download mode: 0 bytes (handshake ok but throttled/RST) should be fail")
	}
}

// ranPrefix reports whether some call recorded by the shared fakeRunner
// (apply_test.go) starts with the given command prefix.
func ranPrefix(f *fakeRunner, prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// stubZapretSeams swaps every strategy-tester seam for a benign fake (all
// probes succeed, nfqws "starts" without a process, no bind delay) and
// restores the real implementations on cleanup. Tests that mutate seams must
// NOT call t.Parallel() — the seams are package globals.
func stubZapretSeams(t *testing.T) *fakeRunner {
	t.Helper()
	fr := &fakeRunner{}
	origResolve := zapretResolveHostFn
	origProbe := zapretProbeSitesFn
	origStart := zapretStartCmd
	origFind := zapretFindNFQWS
	origRunner := zapretNewRunner
	origDelay := zapretBindDelay
	origBlob := zapretResolveBlobFn
	t.Cleanup(func() {
		zapretResolveHostFn = origResolve
		zapretProbeSitesFn = origProbe
		zapretStartCmd = origStart
		zapretFindNFQWS = origFind
		zapretNewRunner = origRunner
		zapretBindDelay = origDelay
		zapretResolveBlobFn = origBlob
	})
	zapretResolveHostFn = func(host string) ([]string, error) { return []string{"192.0.2.1"}, nil }
	zapretProbeSitesFn = func(ctx context.Context, iface string, hosts, ips []string, download bool) []zapretProbeVal {
		out := make([]zapretProbeVal, len(hosts))
		for i := range out {
			out[i] = zapretProbeVal{ms: 0.1}
		}
		return out
	}
	zapretStartCmd = func(*exec.Cmd) error { return nil }
	zapretFindNFQWS = func(Manager) string { return "/usr/bin/nfqws2-under-test" }
	zapretNewRunner = func(Manager) commandRunner { return fr }
	zapretBindDelay = 0
	return fr
}

func TestZapretStrategyTestNFTSetupFailureCleansUp(t *testing.T) {
	fr := stubZapretSeams(t)
	fr.failContains = "nft add table"
	_, err := Manager{}.ZapretStrategyTest(ZapretStrategyTestOptions{
		CmdOpts: "--filter-tcp=443 --dpi-desync=fake", Sites: []string{"a.example"},
	})
	if err == nil {
		t.Fatal("expected error when nft table creation fails")
	}
	if !ranPrefix(fr, "nft delete table inet "+zapretTestTable) {
		t.Errorf("test table not deleted after setup failure; calls: %v", fr.calls)
	}
	if !ranPrefix(fr, "nft delete element inet purewrt bypass4") {
		t.Errorf("bypass entry not removed after setup failure; calls: %v", fr.calls)
	}
}

func TestZapretStrategyTestBlobResolveFailureCleansUp(t *testing.T) {
	fr := stubZapretSeams(t)
	started := false
	zapretStartCmd = func(*exec.Cmd) error { started = true; return nil }
	zapretResolveBlobFn = func(m Manager, file, sha string) (string, error) {
		return "", fmt.Errorf("blob %s not shipped and fetch failed", file)
	}
	_, err := Manager{}.ZapretStrategyTest(ZapretStrategyTestOptions{
		CmdOpts: "--filter-tcp=443 --dpi-desync=fake",
		Sites:   []string{"a.example"},
		Blobs:   []config.ZapretBlobRef{{Name: "tls", File: "definitely-missing-blob.bin"}},
	})
	if err == nil || !strings.Contains(err.Error(), "resolve blob") {
		t.Fatalf("expected resolve blob error, got %v", err)
	}
	if started {
		t.Error("nfqws2 must not be started when blob resolution fails")
	}
	if !ranPrefix(fr, "nft delete table inet "+zapretTestTable) {
		t.Errorf("test table not deleted after blob failure; calls: %v", fr.calls)
	}
	if !ranPrefix(fr, "nft delete element inet purewrt bypass4") {
		t.Errorf("bypass entry not removed after blob failure; calls: %v", fr.calls)
	}
}

func TestZapretStrategyTestKillsNFQWSOnReturn(t *testing.T) {
	stubZapretSeams(t)
	// Stand in a real long-lived process for nfqws2 so the deferred
	// Kill+Wait path is exercised for real (orphan-daemon regression).
	var stub *exec.Cmd
	zapretStartCmd = func(cmd *exec.Cmd) error {
		real := exec.Command("sleep", "60")
		if err := real.Start(); err != nil {
			return err
		}
		cmd.Process = real.Process
		stub = real
		return nil
	}
	_, err := Manager{}.ZapretStrategyTest(ZapretStrategyTestOptions{
		CmdOpts: "--filter-tcp=443 --dpi-desync=fake", Sites: []string{"a.example"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub == nil || stub.Process == nil {
		t.Fatal("stub nfqws2 process was never started")
	}
	if sigErr := stub.Process.Signal(syscall.Signal(0)); sigErr == nil {
		_ = stub.Process.Kill()
		t.Fatal("nfqws2 stand-in still alive after ZapretStrategyTest returned")
	}
}

func TestZapretStrategyTestTimeoutMidProbe(t *testing.T) {
	fr := stubZapretSeams(t)
	// Probes hang until the run watchdog fires — the whole test must still
	// finish promptly, report still-blocked, and tear the firewall down.
	zapretProbeSitesFn = func(ctx context.Context, iface string, hosts, ips []string, download bool) []zapretProbeVal {
		<-ctx.Done()
		return make([]zapretProbeVal, len(hosts))
	}
	start := time.Now()
	res, err := Manager{}.ZapretStrategyTest(ZapretStrategyTestOptions{
		CmdOpts: "--filter-tcp=443 --dpi-desync=fake",
		Sites:   []string{"a.example", "b.example"},
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("timed-out run took %s, watchdog not honoured", elapsed)
	}
	if res.Total != 2 || res.Passed != 0 {
		t.Errorf("got Total=%d Passed=%d, want 2/0", res.Total, res.Passed)
	}
	for _, s := range res.Sites {
		if s.Verdict != "still-blocked" {
			t.Errorf("site %s verdict %q, want still-blocked", s.Site, s.Verdict)
		}
	}
	if !ranPrefix(fr, "nft delete table inet "+zapretTestTable) {
		t.Errorf("test table not deleted after timeout; calls: %v", fr.calls)
	}
}

func TestZapretStrategyTestUnresolvedSiteSkipped(t *testing.T) {
	stubZapretSeams(t)
	zapretResolveHostFn = func(host string) ([]string, error) {
		if host == "bad.example" {
			return nil, fmt.Errorf("NXDOMAIN")
		}
		return []string{"192.0.2.7"}, nil
	}
	res, err := Manager{}.ZapretStrategyTest(ZapretStrategyTestOptions{
		CmdOpts: "--filter-tcp=443 --dpi-desync=fake",
		Sites:   []string{"bad.example", "good.example"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Total != 2 {
		t.Fatalf("Total = %d, want 2 (unresolved still counted)", res.Total)
	}
	byName := map[string]ZapretSiteResult{}
	for _, s := range res.Sites {
		byName[s.Site] = s
	}
	if byName["bad.example"].Verdict != "unresolved" {
		t.Errorf("bad.example verdict %q, want unresolved", byName["bad.example"].Verdict)
	}
	if byName["good.example"].Verdict == "unresolved" || byName["good.example"].IP == "" {
		t.Errorf("good.example should have been probed: %+v", byName["good.example"])
	}
}

func TestZapretStrategyTestVerdictAggregation(t *testing.T) {
	stubZapretSeams(t)
	// First zapretProbeSitesFn call is the baseline (a fails, b works); the
	// second is with the strategy (both work) → a is fixed, b already-ok.
	call := 0
	zapretProbeSitesFn = func(ctx context.Context, iface string, hosts, ips []string, download bool) []zapretProbeVal {
		call++
		out := make([]zapretProbeVal, len(hosts))
		for i, h := range hosts {
			if call == 1 && h == "a.example" {
				continue // baseline fail: ms stays 0
			}
			out[i] = zapretProbeVal{ms: 0.2}
		}
		return out
	}
	res, err := Manager{}.ZapretStrategyTest(ZapretStrategyTestOptions{
		CmdOpts: "--filter-tcp=443 --dpi-desync=fake",
		Sites:   []string{"a.example", "b.example"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Passed != 2 || res.Fixed != 1 || res.Total != 2 {
		t.Fatalf("got Passed=%d Fixed=%d Total=%d, want 2/1/2", res.Passed, res.Fixed, res.Total)
	}
	byName := map[string]string{}
	for _, s := range res.Sites {
		byName[s.Site] = s.Verdict
	}
	if byName["a.example"] != "fixed" || byName["b.example"] != "already-ok" {
		t.Errorf("verdicts %v, want a=fixed b=already-ok", byName)
	}
}

func TestProtoList(t *testing.T) {
	t.Parallel()
	if got := protoList(false); len(got) != 1 || got[0] != "tcp" {
		t.Errorf("protoList(false) = %v, want [tcp]", got)
	}
	if got := protoList(true); len(got) != 2 || got[0] != "tcp" || got[1] != "udp" {
		t.Errorf("protoList(true) = %v, want [tcp udp]", got)
	}
}
