package checker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// CanaryProbe drives one classification attempt against a single target.
// "Target" is host:port. The probe runs in a strict order — DNS → TCP →
// TLS → HTTP — and stops at the first failure point, so the reported
// verdict points at the actual block plane (DNS hijack vs IP block vs SNI
// RST vs HTTP 451 etc).
//
// With UseTLS=false the probe speaks plain HTTP after the TCP phase. When
// the server answers with a redirect to https:// on the same host (or its
// www. twin) the probe automatically upgrades: it dials the redirect
// target and continues with the TLS → HTTPS ladder, so `http://host`
// targets still surface SNI-DPI signatures when the site itself insists
// on TLS. Off-host redirects are never chased — an ISP 302-to-block-page
// must not drag the probe to an attacker-chosen destination.
type CanaryProbe struct {
	Target   string // "youtube.com:443"
	UseTLS   bool   // try a TLS handshake (port 443/8443 etc.)
	HTTPHost string // override Host header on the post-TLS GET; empty derives from Target
	Path     string // request path for the HTTP phase; empty means "/"
	Timeout  time.Duration
}

// ParseTarget converts a user-supplied target string into a CanaryProbe.
// Accepted forms:
//
//	host                        → host:443, TLS
//	host:port                   → TLS on that port
//	https://host[:port][/path]  → TLS (default 443), GET path
//	http://host[:port][/path]   → plain HTTP (default 80); a same-host
//	                              redirect to https:// auto-upgrades to
//	                              the TLS ladder (see CanaryProbe)
//
// Malformed URLs keep the raw string as Target so runCanary reports the
// "config" verdict instead of silently probing something else.
func ParseTarget(raw string) CanaryProbe {
	s := strings.TrimSpace(raw)
	p := CanaryProbe{Target: s, UseTLS: true}
	if !strings.Contains(s, "://") {
		if _, _, err := net.SplitHostPort(s); err != nil {
			p.Target = net.JoinHostPort(s, "443")
		}
		return p
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return p
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	p.Target = net.JoinHostPort(u.Hostname(), port)
	p.UseTLS = u.Scheme == "https"
	if u.Path != "" && u.Path != "/" {
		p.Path = u.Path
	}
	return p
}

// CanaryResult is the per-target outcome.
//
// Verdict vocabulary:
//   - "ok"            : full DNS→TCP→TLS→HTTP path completed cleanly
//   - "dns"           : the system resolver (dnsmasq → mihomo, i.e. the same
//                        path LAN clients use) returns no address — NXDOMAIN,
//                        a downed authoritative, or a DNS-level block
//   - "tcp_rst"       : TCP handshake answered with RST
//   - "tcp_refused"   : RST or "connection refused" before handshake
//   - "tcp_timeout"   : TCP layer timed out
//   - "tcp_no_route"  : no route to host (interface/route table)
//   - "tcp_fail"      : other TCP error
//   - "tls_rst"       : TCP succeeded but TLS handshake was reset — classic
//                        SNI-DPI signature (TSPU watches ClientHello)
//   - "tls_remote_error" : server-side alert during handshake
//   - "tls_timeout"   : TLS handshake stalled
//   - "tls_fail"      : other TLS error
//   - "http_error"    : connection died during the request
//   - "http_redirect" : plain-HTTP probe answered with a redirect that is
//                        NOT a same-host https upgrade (those are followed
//                        automatically) — a legit domain move or an ISP
//                        block-page bounce; probe the Location to tell
//   - "http_451"      : explicit "Unavailable For Legal Reasons"
//   - "http_stub"     : status 200 with a known ISP stub-page marker in the
//                        body ("заблокирован Роскомнадзор", etc.) — covers
//                        the polite-block case where ISPs serve a fake page
//   - "http_<code>"   : any other 4xx/5xx
//   - "config"        : probe input was malformed (bad host:port)
//
// Confidence semantics (added 2026-05 to align with rkn-block-checker):
//   - "high"   : a clean path or an unambiguous censorship fingerprint
//                (explicit HTTP 451, ISP stub-page marker in the body)
//   - "medium" : pattern matches a censorship technique but one signal alone
//                can't rule out server-side flakiness (TLS reset, TCP RST)
//   - "low"    : ambiguous (timeouts, generic errors)
// Verdict is the per-target classification produced by the canary probe.
// Named string so typos in callers are at least caught by `go vet`'s
// fieldalignment-style checks and so a future refactor can grep `Verdict\b`
// instead of every possible literal value. JSON wire shape is unchanged —
// Go marshals named string types as their underlying string.
type Verdict string

const (
	VerdictOK             Verdict = "ok"
	VerdictDNS            Verdict = "dns"
	VerdictTCPRST         Verdict = "tcp_rst"
	VerdictTCPRefused     Verdict = "tcp_refused"
	VerdictTCPTimeout     Verdict = "tcp_timeout"
	VerdictTCPNoRoute     Verdict = "tcp_no_route"
	VerdictTCPFail        Verdict = "tcp_fail"
	VerdictTLSRST         Verdict = "tls_rst"
	VerdictTLSRemoteError Verdict = "tls_remote_error"
	VerdictTLSTimeout     Verdict = "tls_timeout"
	VerdictTLSFail        Verdict = "tls_fail"
	VerdictHTTPError      Verdict = "http_error"
	VerdictHTTPRedirect   Verdict = "http_redirect"
	VerdictHTTP451        Verdict = "http_451"
	VerdictHTTPStub       Verdict = "http_stub"
	VerdictConfig         Verdict = "config"
)

// Confidence carries the trust level of a verdict diagnosis. See the
// CanaryResult docstring above for what each level means in practice.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type CanaryResult struct {
	Target      string        `json:"target"`
	Verdict     Verdict       `json:"verdict"`
	Confidence  Confidence    `json:"confidence,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Notes       []string      `json:"notes,omitempty"`
	// Latency is kept as a Duration for Go callers; the wire field is
	// integer milliseconds. A bare `json:"latency_ms"` tag on the Duration
	// would serialize nanoseconds under a _ms name — LuCI then shows
	// "3200442570 ms" for a 3.2 s probe.
	Latency     time.Duration `json:"-"`
	LatencyMS   int64         `json:"latency_ms"`
	ResolvedA   []string      `json:"resolved_a,omitempty"` // legacy: == SysIPs (kept for old JS callers)
	SysIPs      []string      `json:"sys_ips,omitempty"`
	StatusCode  int           `json:"status_code,omitempty"`
	StubMarker  string        `json:"stub_marker,omitempty"`
}

// canaryUserAgent is sent on every canary HTTP request. Chosen empirically —
// both extremes distort the answer we're trying to measure:
//   - Go's default "Go-http-client/…" trips informative-UA policies
//     (Wikimedia serves 403 over HTTPS to anonymous default UAs);
//   - a fake browser UA trips anti-bot consistency checks, because the
//     accompanying headers/TLS fingerprint don't match the claimed browser
//     (Facebook serves 400 to a Chrome UA coming from a Go client).
//
// An honest, identifiable product UA passes both. Don't "upgrade" this to
// a Mozilla/Chrome string — that's the regression, not the fix.
const canaryUserAgent = "PureWRT-canary/1.0 (OpenWrt; +https://github.com/purewrt/purewrt)"

// StubMarkers are substrings that appear on the polite "you're blocked"
// pages ISPs sometimes serve back as HTTP 200. Matched against the first
// 4 KiB of the response body, lowercased, by-value. Borrowed verbatim from
// rkn-block-checker's targets.py (which has gone through several rounds of
// narrowing to avoid false positives on unrelated news articles that happen
// to mention Roskomnadzor). Add new markers as they're reported.
var StubMarkers = []string{
	"доступ ограничен",
	"доступ к запрашиваемому ресурсу",
	"решению роскомнадзора",
	"решением суда",
	"заблокирован",
	"blocked by roskomnadzor",
	"blocked by rkn",
	"rkn.gov.ru/org/register",
	"единый реестр",
	"запрещен",
}

// DefaultBlockingCanaries is the legacy curated probe list — kept for
// callers that pre-date the whitelist/blacklist split. New code should use
// DefaultBlacklistCanaries (suspected-blocked) and DefaultWhitelistCanaries
// (control) instead.
func DefaultBlockingCanaries() []CanaryProbe {
	return DefaultBlacklistCanaries()
}

// DefaultBlacklistCanaries returns the "suspected blocked" probe list. These
// are sites commonly restricted by RKN-class censors — if your network is
// in a blocked zone, most of these will fail with telltale signatures.
// Aligned with rkn-block-checker's BLACK_URLS.
func DefaultBlacklistCanaries() []CanaryProbe {
	return defaultCanaries([]string{
		"https://www.instagram.com",
		"https://www.facebook.com",
		"https://x.com",
		"https://www.linkedin.com",
		"https://discord.com",
		"https://rutracker.org",
		"https://www.torproject.org",
		"https://protonvpn.com",
		"https://www.deepl.com",
		"https://www.patreon.com",
		"https://meduza.io",
		"https://www.dw.com",
	})
}

// DefaultWhitelistCanaries returns the "control should always work" probe
// list — sites that even an aggressive censor won't typically block because
// they're government/financial/local. If most of these fail, the network is
// broken (rather than censored) and the overall verdict drops to
// "inconclusive". Aligned with rkn-block-checker's WHITE_URLS; localized
// for RU. For other locales the operator should override via UCI.
func DefaultWhitelistCanaries() []CanaryProbe {
	return defaultCanaries([]string{
		"https://www.gosuslugi.ru",
		"https://ya.ru",
		"https://www.sberbank.ru",
		"https://vk.com",
		"https://www.ozon.ru",
		"https://www.avito.ru",
		"https://lenta.ru",
		"https://rutube.ru",
	})
}

// defaultCanaries expands URL-form default targets through the same
// ParseTarget path user input takes, so the curated lists and the LuCI
// DEFAULT_* mirrors (resources/view/purewrt/blocking.js) can share one
// spelling. https://host parses to host:443 + TLS — identical probes to
// the historical host:443 literals.
func defaultCanaries(urls []string) []CanaryProbe {
	out := make([]CanaryProbe, 0, len(urls))
	for _, u := range urls {
		p := ParseTarget(u)
		p.Timeout = 5 * time.Second
		out = append(out, p)
	}
	return out
}

// BlockingHeuristics runs every probe and returns one result each. The DoH
// Probes run concurrently with a small fan-out cap so a default 20-target
// report finishes in ~5-10 s instead of the ~100 s a strictly-sequential
// loop would take. The LuCI XHR call has a ~30 s ubus timeout — sequential
// wouldn't fit. Order of the output slice matches the input slice so
// callers can keep their indexed labels intact.
func BlockingHeuristics(ctx context.Context, probes []CanaryProbe) []CanaryResult {
	if len(probes) == 0 {
		probes = DefaultBlockingCanaries()
	}
	if len(probes) == 0 {
		return nil
	}
	const fanout = 8 // cap concurrent sockets — keeps router from OOM-ing on bursty leases
	out := make([]CanaryResult, len(probes))
	sem := make(chan struct{}, fanout)
	var wg sync.WaitGroup
	for i := range probes {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p CanaryProbe) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = runCanary(ctx, p)
		}(i, probes[i])
	}
	wg.Wait()
	return out
}

func runCanary(ctx context.Context, p CanaryProbe) (r CanaryResult) {
	// Named return: the deferred Latency stamp must land in the value the
	// caller sees, not in a local copied away by `return r`.
	r.Target = p.Target
	t0 := time.Now()
	defer func() {
		r.Latency = time.Since(t0)
		r.LatencyMS = r.Latency.Milliseconds()
	}()

	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// A scheme surviving into Target means ParseTarget rejected the URL
	// (bad syntax or a non-http scheme). Without this guard SplitHostPort
	// happily splits "ftp://x" into host "ftp" and misreports a DNS block.
	if strings.Contains(p.Target, "://") {
		r.Verdict, r.Confidence = VerdictConfig, ConfidenceLow
		r.Reason = "unsupported target URL — use host, host:port, or an http(s):// URL"
		return r
	}

	host, port, err := net.SplitHostPort(p.Target)
	if err != nil {
		r.Verdict, r.Reason, r.Confidence = "config", err.Error(), "low"
		return r
	}

	// DNS phase. Resolve via the system resolver only — dnsmasq → mihomo, the
	// exact path LAN clients use — so the verdict reflects the real client
	// experience. We deliberately do NOT compare against a DoH control: CDNs
	// and GeoDNS legitimately hand out different addresses per resolver and per
	// country, so a system-vs-DoH disagreement is noise, not "poisoning".
	//
	// Retry transient failures: under a burst of ~20 concurrent probes the
	// dnsmasq→mihomo resolver can stall or drop a UDP answer (mihomo resolves
	// uncached names upstream, serially-ish), so a single missed lookup must
	// not masquerade as a DNS block. Each attempt gets its own short budget;
	// a definitive NXDOMAIN stops retrying immediately.
	sysIPs, dnsTimedOut := resolveSystemIPv4(ctx, host)
	r.SysIPs = sysIPs
	r.ResolvedA = r.SysIPs // legacy alias

	if len(r.SysIPs) == 0 {
		r.Verdict, r.Confidence = "dns", "low"
		if dnsTimedOut {
			r.Reason = "system resolver (dnsmasq → mihomo) timed out after retries — overloaded or upstream stalled, not necessarily a block"
		} else {
			r.Reason = "domain doesn't resolve via system DNS (NXDOMAIN or downed authoritative)"
		}
		return r
	}

	// TCP phase. Dial the IP the system resolver already returned, rather than
	// handing the hostname to the dialer — which would trigger a SECOND
	// system-DNS lookup. That redundant lookup doubled DNS load and, under a
	// burst of concurrent probes, timed out against dnsmasq → mihomo, surfacing
	// as bogus "tcp_timeout: lookup … i/o timeout" for sites that resolve fine.
	d := &net.Dialer{Timeout: timeout}
	conn, dialErr := d.DialContext(cctx, "tcp", net.JoinHostPort(r.SysIPs[0], port))
	if dialErr != nil {
		r.Verdict, r.Reason = classifyDialErr(dialErr), dialErr.Error()
		r.Confidence = confidenceFor(r.Verdict)
		if note := tcpNote(r.Verdict); note != "" {
			r.Notes = append(r.Notes, note)
		}
		return r
	}
	defer func() { _ = conn.Close() }()

	httpHost := p.HTTPHost
	if httpHost == "" {
		httpHost = host
	}
	path := p.Path
	if path == "" {
		path = "/"
	}

	if p.UseTLS {
		probeTLSHTTP(cctx, &r, conn, host, httpHost, path, timeout)
		return r
	}

	// Plain-HTTP phase — single bounded GET over the existing conn with
	// redirect-following disabled so we see the raw first answer. ISP block
	// pages are most often injected on plain HTTP (a stub 200 or a 302 to
	// the operator's page), so the stub-marker scan runs here too.
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, "http://"+httpHost+path, nil)
	req.Header.Set("User-Agent", canaryUserAgent)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
		MaxIdleConns:    1,
		IdleConnTimeout: time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, httpErr := client.Do(req)
	if httpErr != nil {
		r.Verdict, r.Reason, r.Confidence = "http_error", httpErr.Error(), "low"
		return r
	}
	defer func() { _ = resp.Body.Close() }()
	r.StatusCode = resp.StatusCode

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if stubVerdict(&r, body) {
		return r
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		u, upgrade := httpsUpgrade(loc, host, httpHost)
		if !upgrade {
			r.Verdict, r.Confidence = VerdictHTTPRedirect, ConfidenceLow
			r.Reason = "plain-HTTP redirect to " + loc
			r.Notes = append(r.Notes, "redirect points off-host — a legit domain move or an ISP block-page bounce; probe the Location target directly to tell")
			return r
		}

		// Same-host https upgrade: chain the TLS ladder against the
		// redirect target on a fresh connection. A www. twin needs its own
		// DNS resolution; the bare host reuses the address we already have.
		r.Notes = append(r.Notes, "plain HTTP redirected to "+loc+" — auto-upgraded to the TLS probe")
		newHost := u.Hostname()
		newPort := u.Port()
		if newPort == "" {
			newPort = "443"
		}
		newPath := u.Path
		if newPath == "" {
			newPath = "/"
		}
		ip := r.SysIPs[0]
		if !strings.EqualFold(newHost, host) {
			ips, _ := resolveSystemIPv4(cctx, newHost)
			if len(ips) == 0 {
				r.Verdict, r.Confidence = VerdictDNS, ConfidenceLow
				r.Reason = "https upgrade target " + newHost + " doesn't resolve via system DNS"
				return r
			}
			ip = ips[0]
		}
		conn2, dialErr := d.DialContext(cctx, "tcp", net.JoinHostPort(ip, newPort))
		if dialErr != nil {
			r.Verdict, r.Reason = classifyDialErr(dialErr), dialErr.Error()
			r.Confidence = confidenceFor(r.Verdict)
			if note := tcpNote(r.Verdict); note != "" {
				r.Notes = append(r.Notes, note)
			}
			return r
		}
		defer func() { _ = conn2.Close() }()
		probeTLSHTTP(cctx, &r, conn2, newHost, newHost, newPath, timeout)
		return r
	}

	statusVerdict(&r, resp.StatusCode)
	if r.Verdict == VerdictOK {
		r.Notes = append(r.Notes, "served over plain HTTP — TLS/SNI plane not probed")
	}
	return r
}

// probeTLSHTTP runs the TLS + HTTPS phases of the ladder over an
// already-dialed TCP conn, filling r in place. ServerName is forced from
// sniHost so SNI matches what censors actually inspect; SNI-DPI
// middleboxes blow up in the handshake and we see it as a
// reset/timeout/remote-error. The HTTP phase is a single bounded GET with
// a 4 KiB body cap for stub-page marker matching — polite-style blocks
// return HTTP 200 with a "blocked by RKN" body.
func probeTLSHTTP(cctx context.Context, r *CanaryResult, conn net.Conn, sniHost, httpHost, path string, timeout time.Duration) {
	tlsCfg := &tls.Config{ServerName: sniHost, MinVersion: tls.VersionTLS12}
	tconn := tls.Client(conn, tlsCfg)
	if err := tconn.HandshakeContext(cctx); err != nil {
		r.Verdict, r.Reason = classifyTLSErr(err), err.Error()
		r.Confidence = confidenceFor(r.Verdict)
		if note := tlsNote(r.Verdict); note != "" {
			r.Notes = append(r.Notes, note)
		}
		return
	}

	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, "https://"+httpHost+path, nil)
	req.Header.Set("User-Agent", canaryUserAgent)
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tconn, nil
		},
		MaxIdleConns:        1,
		IdleConnTimeout:     time.Second,
		TLSHandshakeTimeout: timeout,
	}
	// Redirects are NOT followed: the transport is pinned to this one TLS
	// conn, so chasing a cross-host Location would send the new host's
	// request over the old host's connection and produce bogus 403s. By
	// this point the full DNS→TCP→TLS→HTTP ladder has answered over a
	// cert-verified conn, so a redirect is a genuine origin answer — "ok".
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, httpErr := client.Do(req)
	if httpErr != nil {
		r.Verdict, r.Reason, r.Confidence = "http_error", httpErr.Error(), "low"
		return
	}
	defer func() { _ = resp.Body.Close() }()
	r.StatusCode = resp.StatusCode

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if stubVerdict(r, body) {
		return
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			r.Notes = append(r.Notes, "origin redirects to "+loc+" — ladder completed, redirect not followed")
		}
	}
	statusVerdict(r, resp.StatusCode)
}

// stubVerdict scans a (capped) response body for ISP stub-page markers and
// sets the http_stub verdict when one matches. Reports whether it did.
func stubVerdict(r *CanaryResult, body []byte) bool {
	lowered := strings.ToLower(string(body))
	for _, marker := range StubMarkers {
		if strings.Contains(lowered, marker) {
			r.Verdict, r.Confidence = "http_stub", "high"
			r.StubMarker = marker
			r.Reason = "ISP stub-page marker matched: " + marker
			r.Notes = append(r.Notes, "response body matches a known ISP stub-page marker — operator-mandated block served as HTTP 200")
			return true
		}
	}
	return false
}

// statusVerdict folds a non-stub HTTP status into the verdict. Redirect
// handling happens in the caller (plain-HTTP path only) before this runs.
func statusVerdict(r *CanaryResult, status int) {
	switch {
	case status == 451:
		r.Verdict, r.Confidence = "http_451", "high"
		r.Reason = "Unavailable For Legal Reasons — explicit censorship-mandated block"
		r.Notes = append(r.Notes, "HTTP 451 explicit block")
	case status >= 400:
		r.Verdict = Verdict(fmt.Sprintf("http_%d", status))
		r.Confidence = "low"
	default:
		r.Verdict = "ok"
		r.Confidence = ConfidenceHigh
	}
}

// httpsUpgrade reports whether a plain-HTTP redirect Location is a
// same-site upgrade to HTTPS the probe should follow automatically. Only
// https URLs pointing at the probed host (or its www. twin) qualify —
// anything else is reported as http_redirect rather than chased, so an
// ISP 302-to-block-page can't drag the probe to an arbitrary host.
func httpsUpgrade(loc, host, httpHost string) (*url.URL, bool) {
	u, err := url.Parse(loc)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, false
	}
	lh := strings.ToLower(u.Hostname())
	for _, h := range []string{host, httpHost} {
		h = strings.ToLower(h)
		if lh == h || lh == "www."+h || "www."+lh == h {
			return u, true
		}
	}
	return nil, false
}

// resolveSystemIPv4 resolves host to sorted IPv4 strings via the system
// resolver (dnsmasq → mihomo), retrying transient failures with a fresh short
// budget each attempt. Returns whether the final failure was a timeout
// (resolver overloaded — retry-worthy, not a verdict) vs a definitive NXDOMAIN.
func resolveSystemIPv4(ctx context.Context, host string) (ips []string, timedOut bool) {
	const attempts = 3
	for i := 0; i < attempts; i++ {
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := net.DefaultResolver.LookupIPAddr(lctx, host)
		cancel()
		for _, a := range addrs {
			if a.IP.To4() != nil {
				ips = append(ips, a.IP.String())
			}
		}
		if len(ips) > 0 {
			sort.Strings(ips)
			return ips, false
		}
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return nil, false // definitive negative — don't waste retries
		}
		timedOut = isTimeoutErr(err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, timedOut
}

// isTimeoutErr reports whether err is a network timeout / deadline (a slow or
// overloaded resolver) rather than a definitive negative answer.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func confidenceFor(v Verdict) Confidence {
	switch v {
	case VerdictOK, "":
		return ConfidenceHigh
	case VerdictHTTPStub, VerdictHTTP451:
		return ConfidenceHigh
	case VerdictTCPRST, VerdictTCPRefused, VerdictTLSRST, VerdictTLSRemoteError:
		return ConfidenceMedium
	case VerdictTCPTimeout, VerdictTLSTimeout, VerdictTCPNoRoute:
		return ConfidenceLow
	case VerdictHTTPError, VerdictHTTPRedirect, VerdictTCPFail, VerdictTLSFail, VerdictDNS:
		return ConfidenceLow
	}
	if strings.HasPrefix(string(v), "http_") {
		return ConfidenceLow
	}
	return ConfidenceLow
}

func tcpNote(v Verdict) string {
	switch v {
	case VerdictTCPRST:
		return "TCP RST received — pattern matches RST injection by a middlebox, but a busy server can also send RST"
	case VerdictTCPRefused:
		return "TCP refused — destination port not listening, or actively rejected"
	case VerdictTCPTimeout:
		return "TCP timeout — IP block or upstream congestion"
	case VerdictTCPNoRoute:
		return "no route to host — interface/route table issue, not censorship"
	}
	return ""
}

func tlsNote(v Verdict) string {
	switch v {
	case VerdictTLSRST:
		return "TLS reset right after ClientHello — consistent with SNI-based DPI filtering (typical TSPU/RKN signature)"
	case VerdictTLSRemoteError:
		return "TLS remote-error alert — server-side rejection, possibly SNI filter"
	case VerdictTLSTimeout:
		return "TLS handshake silently dropped — consistent with DPI filtering by ClientHello"
	}
	return ""
}

func classifyDialErr(err error) Verdict {
	s := strings.ToLower(err.Error())
	switch {
	case isTimeout(err) || strings.Contains(s, "deadline"):
		return VerdictTCPTimeout
	case strings.Contains(s, "connection refused"):
		return VerdictTCPRefused
	case strings.Contains(s, "no route"):
		return VerdictTCPNoRoute
	case strings.Contains(s, "reset"):
		return VerdictTCPRST
	default:
		return VerdictTCPFail
	}
}

func classifyTLSErr(err error) Verdict {
	s := strings.ToLower(err.Error())
	switch {
	case isTimeout(err) || strings.Contains(s, "deadline"):
		return VerdictTLSTimeout
	case strings.Contains(s, "reset"):
		return VerdictTLSRST
	case strings.Contains(s, "remote error"):
		return VerdictTLSRemoteError
	default:
		return VerdictTLSFail
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// BlockingReport groups whitelist (control) + blacklist (suspected) results
// with an overall verdict line. Patterned on rkn-block-checker: the
// whitelist tells us whether the network itself is working, the blacklist
// reveals censorship signal, and the verdict combines the two so the user
// gets a single "your network is in a blocked zone (high confidence)" line
// rather than having to interpret per-target details.
type BlockingReport struct {
	Whitelist []CanaryResult `json:"whitelist"`
	Blacklist []CanaryResult `json:"blacklist"`
	Verdict   string         `json:"verdict"` // "blocked_zone_high", "blocked_zone_medium", "no_blocking_detected", "inconclusive"
	Reason    string         `json:"reason"`
}

// BlockingReportRun probes both lists with a shared DoH resolver and folds
// the results into a BlockingReport. Empty lists fall back to the defaults.
func BlockingReportRun(ctx context.Context, whitelist, blacklist []CanaryProbe) BlockingReport {
	if len(whitelist) == 0 {
		whitelist = DefaultWhitelistCanaries()
	}
	if len(blacklist) == 0 {
		blacklist = DefaultBlacklistCanaries()
	}
	rep := BlockingReport{
		Whitelist: BlockingHeuristics(ctx, whitelist),
		Blacklist: BlockingHeuristics(ctx, blacklist),
	}
	rep.Verdict, rep.Reason = computeOverallVerdict(rep.Whitelist, rep.Blacklist)
	return rep
}

func countOK(rs []CanaryResult) int {
	n := 0
	for _, r := range rs {
		if r.Verdict == "ok" {
			n++
		}
	}
	return n
}

func computeOverallVerdict(whitelist, blacklist []CanaryResult) (verdict, reason string) {
	wOK := countOK(whitelist)
	bOK := countOK(blacklist)
	wTotal := len(whitelist)
	bTotal := len(blacklist)

	// No baseline → can't separate censorship from a broken uplink.
	if wTotal > 0 && wOK*2 < wTotal {
		return "inconclusive", fmt.Sprintf("whitelist baseline failing (%d/%d reachable) — can't separate censorship from broken uplink", wOK, wTotal)
	}

	// Empty or mostly-clean blacklist → no blocking signal.
	if bTotal == 0 {
		return "no_blocking_detected", "no blacklist targets configured"
	}
	if bOK*5 >= bTotal*4 { // ≥80% reachable
		return "no_blocking_detected", fmt.Sprintf("%d/%d blacklist targets reachable — no censorship signal", bOK, bTotal)
	}

	// Count blocked targets by confidence of their classification.
	high, medium := 0, 0
	for _, r := range blacklist {
		if r.Verdict == "ok" {
			continue
		}
		switch r.Confidence {
		case "high":
			high++
		case "medium":
			medium++
		}
	}
	bBlocked := bTotal - bOK
	// HIGH if at least half of the blocks carry HIGH-confidence signals
	// (HTTP 451, stub markers) — those are the unambiguous censorship
	// fingerprints.
	if high*2 >= bBlocked {
		return "blocked_zone_high", fmt.Sprintf("%d of %d blacklist targets blocked — %d high-confidence (451/stub), %d medium (DPI/RST)", bBlocked, bTotal, high, medium)
	}
	return "blocked_zone_medium", fmt.Sprintf("%d of %d blacklist targets blocked — mostly medium-confidence signals (DPI/RST). Server-side flakiness can't be fully ruled out", bBlocked, bTotal)
}

// FormatBlockingResults renders a CanaryResult list for human consumption.
// Used by purewrt doctor --canaries.
func FormatBlockingResults(rs []CanaryResult) string {
	var b strings.Builder
	okCount := 0
	for _, r := range rs {
		if r.Verdict == "ok" {
			okCount++
		}
	}
	fmt.Fprintf(&b, "%d/%d canaries OK\n", okCount, len(rs))
	for _, r := range rs {
		conf := r.Confidence
		if conf != "" {
			conf = "[" + conf + "]"
		}
		fmt.Fprintf(&b, "  %-9s %-6s %-40s  latency=%s", r.Verdict, conf, r.Target, r.Latency.Round(time.Millisecond))
		if r.Reason != "" {
			fmt.Fprintf(&b, "  reason=%s", r.Reason)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Summary: %s\n", blockingSummary(rs))
	return b.String()
}

// FormatBlockingReport renders a full BlockingReport (whitelist + blacklist
// + overall verdict) as plain text suitable for `purewrt doctor --canaries
// --report`.
func FormatBlockingReport(rep BlockingReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Overall verdict: %s\n  %s\n\n", rep.Verdict, rep.Reason)
	b.WriteString("Whitelist (control sites — should always work)\n")
	b.WriteString(FormatBlockingResults(rep.Whitelist))
	b.WriteString("\nBlacklist (suspected blocked)\n")
	b.WriteString(FormatBlockingResults(rep.Blacklist))
	return b.String()
}

// blockingSummary produces the legacy one-line interpretation used by the
// flat (no-report) output path. BlockingReport callers should use
// rep.Verdict/rep.Reason instead.
func blockingSummary(rs []CanaryResult) string {
	if len(rs) == 0 {
		return "no probes run"
	}
	counts := map[Verdict]int{}
	for _, r := range rs {
		counts[r.Verdict]++
	}
	n := len(rs)
	switch {
	case counts[VerdictOK] == n:
		return "no blocking signal — all canaries reached origin cleanly"
	case counts[VerdictDNS]*2 >= n:
		return "ISP DNS hijack or upstream filtering"
	case (counts[VerdictTLSRST]+counts[VerdictTLSRemoteError])*2 >= n:
		return "SNI-based DPI"
	case (counts[VerdictTCPRST]+counts[VerdictTCPTimeout])*2 >= n:
		return "IP-level filtering or upstream congestion"
	case counts[VerdictHTTPStub] >= 1 || counts[VerdictHTTP451] >= 1:
		return "operator-mandated block by the host itself (stub page / 451)"
	default:
		return "mixed verdicts"
	}
}
