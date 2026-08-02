package checker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestParseTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in     string
		target string
		useTLS bool
		path   string
	}{
		{"example.com", "example.com:443", true, ""},
		{"example.com:8443", "example.com:8443", true, ""},
		{"https://example.com", "example.com:443", true, ""},
		{"https://example.com:8443/probe/path", "example.com:8443", true, "/probe/path"},
		{"http://example.com", "example.com:80", false, ""},
		{"http://example.com:8080/x", "example.com:8080", false, "/x"},
		{"::1", "[::1]:443", true, ""},
		{"http://[::1]:8080/x", "[::1]:8080", false, "/x"},
		// Unsupported scheme: raw string kept so runCanary reports "config".
		{"ftp://example.com", "ftp://example.com", true, ""},
	}
	for _, c := range cases {
		p := ParseTarget(c.in)
		if p.Target != c.target || p.UseTLS != c.useTLS || p.Path != c.path {
			t.Errorf("ParseTarget(%q) = {Target:%q UseTLS:%v Path:%q}, want {%q %v %q}",
				c.in, p.Target, p.UseTLS, p.Path, c.target, c.useTLS, c.path)
		}
	}
}

func TestHTTPSUpgrade(t *testing.T) {
	t.Parallel()
	cases := []struct {
		loc  string
		host string
		want bool
	}{
		{"https://example.com/", "example.com", true},
		{"https://www.example.com/login", "example.com", true},
		{"https://example.com/", "www.example.com", true},
		{"https://other.example.net/", "example.com", false},
		{"http://example.com/", "example.com", false}, // not an https upgrade
		{"/relative/path", "example.com", false},
		{"", "example.com", false},
	}
	for _, c := range cases {
		_, got := httpsUpgrade(c.loc, c.host, c.host)
		if got != c.want {
			t.Errorf("httpsUpgrade(%q, %q) = %v, want %v", c.loc, c.host, got, c.want)
		}
	}
}

// The curated defaults are now spelled as https:// URLs (shared spelling
// with the LuCI DEFAULT_* mirrors) but must expand to the exact probes the
// historical host:443 literals produced — TLS on, port 443, no path.
func TestDefaultCanariesExpandToHostPort443(t *testing.T) {
	t.Parallel()
	for _, list := range [][]CanaryProbe{DefaultBlacklistCanaries(), DefaultWhitelistCanaries()} {
		if len(list) == 0 {
			t.Fatal("default canary list is empty")
		}
		for _, p := range list {
			if !strings.HasSuffix(p.Target, ":443") || !p.UseTLS || p.Path != "" || p.Timeout != 5*time.Second {
				t.Errorf("default probe %+v: want host:443, TLS, no path, 5s timeout", p)
			}
			if strings.Contains(p.Target, "://") {
				t.Errorf("default probe target %q kept its URL scheme — ParseTarget regression", p.Target)
			}
		}
	}
	if got := DefaultBlacklistCanaries()[0].Target; got != "www.instagram.com:443" {
		t.Errorf("first blacklist target = %q, want www.instagram.com:443", got)
	}
}

func TestUnsupportedSchemeIsConfigError(t *testing.T) {
	t.Parallel()
	r := runCanary(context.Background(), ParseTarget("ftp://example.com"))
	if r.Verdict != VerdictConfig {
		t.Fatalf("verdict = %q (reason %q), want config", r.Verdict, r.Reason)
	}
}

// plainProbe builds a UseTLS=false probe pointed at a httptest server URL.
func plainProbe(t *testing.T, serverURL string) CanaryProbe {
	t.Helper()
	p := ParseTarget(serverURL)
	if p.UseTLS {
		t.Fatalf("expected plain-HTTP probe for %q", serverURL)
	}
	p.Timeout = 5 * time.Second
	return p
}

func TestPlainHTTPStubPageDetected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte("<html>Доступ ограничен по решению Роскомнадзора</html>"))
	}))
	defer srv.Close()
	r := runCanary(context.Background(), plainProbe(t, srv.URL))
	if r.Verdict != VerdictHTTPStub {
		t.Fatalf("verdict = %q (reason %q), want http_stub", r.Verdict, r.Reason)
	}
	if r.Confidence != ConfidenceHigh {
		t.Fatalf("confidence = %q, want high", r.Confidence)
	}
}

func TestPlainHTTPCleanOK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	r := runCanary(context.Background(), plainProbe(t, srv.URL))
	if r.Verdict != VerdictOK {
		t.Fatalf("verdict = %q (reason %q), want ok", r.Verdict, r.Reason)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "plain HTTP") {
		t.Fatalf("expected plain-HTTP note, got %v", r.Notes)
	}
	// The wire field is integer milliseconds — a raw Duration under the
	// latency_ms tag would leak nanoseconds to LuCI ("3200442570 ms").
	if r.LatencyMS != r.Latency.Milliseconds() || r.Latency <= 0 {
		t.Fatalf("LatencyMS = %d, Latency = %v — wire field must be Latency in ms", r.LatencyMS, r.Latency)
	}
	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"latency_ms":`+strconv.FormatInt(r.LatencyMS, 10)) {
		t.Fatalf("latency_ms not serialized as milliseconds: %s", wire)
	}
}

func TestPlainHTTPOffsiteRedirect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "https://blockpage.example.net/", http.StatusFound)
	}))
	defer srv.Close()
	r := runCanary(context.Background(), plainProbe(t, srv.URL))
	if r.Verdict != VerdictHTTPRedirect {
		t.Fatalf("verdict = %q (reason %q), want http_redirect", r.Verdict, r.Reason)
	}
	if !strings.Contains(r.Reason, "blockpage.example.net") {
		t.Fatalf("reason should carry the Location, got %q", r.Reason)
	}
}

func TestPlainHTTPUpgradeChainsToTLS(t *testing.T) {
	t.Parallel()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte("secure"))
	}))
	defer tlsSrv.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Same host (127.0.0.1), different port — qualifies for auto-upgrade.
		http.Redirect(w, req, tlsSrv.URL+"/", http.StatusMovedPermanently)
	}))
	defer srv.Close()
	r := runCanary(context.Background(), plainProbe(t, srv.URL))
	if !strings.Contains(strings.Join(r.Notes, " "), "auto-upgraded") {
		t.Fatalf("expected auto-upgrade note, got verdict=%q notes=%v", r.Verdict, r.Notes)
	}
	// The chained TLS handshake runs with certificate verification, so the
	// httptest self-signed cert must surface as tls_fail — proof the probe
	// actually continued onto the TLS ladder rather than stopping at 301.
	if r.Verdict != VerdictTLSFail {
		t.Fatalf("verdict = %q (reason %q), want tls_fail from self-signed upgrade target", r.Verdict, r.Reason)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string       { return "i/o timeout" }
func (timeoutErr) Timeout() bool       { return true }
func (timeoutErr) Temporary() bool     { return false }

// Ensure timeoutErr satisfies net.Error so isTimeout returns true.
var _ net.Error = timeoutErr{}
