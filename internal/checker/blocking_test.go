package checker

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestClassifyDialErrCategorizesCommonCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want Verdict
	}{
		{errors.New("dial tcp 1.2.3.4:443: connect: connection refused"), VerdictTCPRefused},
		{errors.New("dial tcp 1.2.3.4:443: connect: connection reset by peer"), VerdictTCPRST},
		{errors.New("dial tcp 1.2.3.4:443: connect: no route to host"), VerdictTCPNoRoute},
		{&timeoutErr{}, VerdictTCPTimeout},
	}
	for _, c := range cases {
		if got := classifyDialErr(c.err); got != c.want {
			t.Errorf("classifyDialErr(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestClassifyTLSErrCategorizesCommonCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want Verdict
	}{
		{errors.New("remote error: tls: protocol version not supported"), VerdictTLSRemoteError},
		{errors.New("read tcp: connection reset by peer"), VerdictTLSRST},
		{&timeoutErr{}, VerdictTLSTimeout},
		{errors.New("EOF"), VerdictTLSFail},
	}
	for _, c := range cases {
		if got := classifyTLSErr(c.err); got != c.want {
			t.Errorf("classifyTLSErr(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestBlockingSummaryDNSDominant(t *testing.T) {
	t.Parallel()
	rs := []CanaryResult{{Verdict: "dns"}, {Verdict: "dns"}, {Verdict: "ok"}}
	got := blockingSummary(rs)
	if !strings.Contains(got, "DNS hijack") {
		t.Fatalf("expected DNS-hijack summary, got %q", got)
	}
}

func TestBlockingSummaryTLSRSTDominant(t *testing.T) {
	t.Parallel()
	rs := []CanaryResult{{Verdict: "tls_rst"}, {Verdict: "tls_remote_error"}, {Verdict: "ok"}}
	got := blockingSummary(rs)
	if !strings.Contains(got, "SNI-based DPI") {
		t.Fatalf("expected SNI-DPI summary, got %q", got)
	}
}

func TestBlockingSummaryAllOK(t *testing.T) {
	t.Parallel()
	rs := []CanaryResult{{Verdict: "ok"}, {Verdict: "ok"}}
	got := blockingSummary(rs)
	if !strings.Contains(got, "no blocking signal") {
		t.Fatalf("expected no-blocking summary, got %q", got)
	}
}

func TestFormatBlockingResultsCountsOK(t *testing.T) {
	t.Parallel()
	rs := []CanaryResult{
		{Target: "a:443", Verdict: "ok", Latency: 12 * time.Millisecond},
		{Target: "b:443", Verdict: "tls_rst", Latency: 3 * time.Millisecond, Reason: "reset"},
	}
	got := FormatBlockingResults(rs)
	if !strings.Contains(got, "1/2 canaries OK") {
		t.Fatalf("missing summary count, got:\n%s", got)
	}
	if !strings.Contains(got, "a:443") || !strings.Contains(got, "b:443") {
		t.Fatalf("missing per-canary line: %s", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string       { return "i/o timeout" }
func (timeoutErr) Timeout() bool       { return true }
func (timeoutErr) Temporary() bool     { return false }

// Ensure timeoutErr satisfies net.Error so isTimeout returns true.
var _ net.Error = timeoutErr{}
