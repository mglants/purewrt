package checker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/purewrt/purewrt/internal/provider"
)

// CanaryProbe drives one classification attempt against a single target.
// "Target" is host:port. The probe runs in a strict order — DNS → TCP →
// TLS → HTTP — and stops at the first failure point, so the reported
// verdict points at the actual block plane (DNS hijack vs IP block vs SNI
// RST vs HTTP 451 etc).
type CanaryProbe struct {
	Target   string // "youtube.com:443"
	UseTLS   bool   // try a TLS handshake (port 443/8443 etc.)
	HTTPHost string // override Host header on the post-TLS GET; empty derives from Target
	Timeout  time.Duration
}

// CanaryResult is the per-target outcome.
//
// Verdict vocabulary:
//   - "ok"            : full DNS→TCP→TLS→HTTP path completed cleanly
//   - "dns_poisoned"  : system resolver fails BUT DoH control succeeds — high
//                        confidence DNS poisoning (rkn-block-checker semantics)
//   - "dns"           : neither system nor DoH resolves — domain might be down,
//                        NXDOMAIN, or both resolvers blocked
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
//   - "http_451"      : explicit "Unavailable For Legal Reasons"
//   - "http_stub"     : status 200 with a known ISP stub-page marker in the
//                        body ("заблокирован Роскомнадзор", etc.) — covers
//                        the polite-block case where ISPs serve a fake page
//   - "http_<code>"   : any other 4xx/5xx
//   - "config"        : probe input was malformed (bad host:port)
//
// Confidence semantics (added 2026-05 to align with rkn-block-checker):
//   - "high"   : two independent signals agree (e.g. DNS poison confirmed by
//                DoH, explicit HTTP 451, stub marker in body)
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
	VerdictDNSPoisoned    Verdict = "dns_poisoned"
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
	Latency     time.Duration `json:"latency_ms"`
	ResolvedA   []string      `json:"resolved_a,omitempty"` // legacy: == SysIPs (kept for old JS callers)
	SysIPs      []string      `json:"sys_ips,omitempty"`
	DoHIPs      []string      `json:"doh_ips,omitempty"`
	DNSMismatch bool          `json:"dns_mismatch,omitempty"`
	StatusCode  int           `json:"status_code,omitempty"`
	StubMarker  string        `json:"stub_marker,omitempty"`
}

// ControlDoHEndpoint is the fixed DoH resolver used as the comparison side of
// the system-vs-control DNS check. Cloudflare's pinned IPs are unlikely to be
// MITM'd on most networks even when the canary domain itself is poisoned. A
// sufficiently capable censor could intercept here too — for stronger
// guarantees configure private DoH endpoints in BootstrapDoHResolvers and
// pass them via NewBlockingHeuristicsWithDoH.
const ControlDoHEndpoint = "https://cloudflare-dns.com/dns-query"

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
	t := 5 * time.Second
	return []CanaryProbe{
		{Target: "www.instagram.com:443", UseTLS: true, HTTPHost: "www.instagram.com", Timeout: t},
		{Target: "www.facebook.com:443", UseTLS: true, HTTPHost: "www.facebook.com", Timeout: t},
		{Target: "x.com:443", UseTLS: true, HTTPHost: "x.com", Timeout: t},
		{Target: "www.linkedin.com:443", UseTLS: true, HTTPHost: "www.linkedin.com", Timeout: t},
		{Target: "discord.com:443", UseTLS: true, HTTPHost: "discord.com", Timeout: t},
		{Target: "rutracker.org:443", UseTLS: true, HTTPHost: "rutracker.org", Timeout: t},
		{Target: "www.torproject.org:443", UseTLS: true, HTTPHost: "www.torproject.org", Timeout: t},
		{Target: "protonvpn.com:443", UseTLS: true, HTTPHost: "protonvpn.com", Timeout: t},
		{Target: "www.deepl.com:443", UseTLS: true, HTTPHost: "www.deepl.com", Timeout: t},
		{Target: "www.patreon.com:443", UseTLS: true, HTTPHost: "www.patreon.com", Timeout: t},
		{Target: "meduza.io:443", UseTLS: true, HTTPHost: "meduza.io", Timeout: t},
		{Target: "www.dw.com:443", UseTLS: true, HTTPHost: "www.dw.com", Timeout: t},
	}
}

// DefaultWhitelistCanaries returns the "control should always work" probe
// list — sites that even an aggressive censor won't typically block because
// they're government/financial/local. If most of these fail, the network is
// broken (rather than censored) and the overall verdict drops to
// "inconclusive". Aligned with rkn-block-checker's WHITE_URLS; localized
// for RU. For other locales the operator should override via UCI.
func DefaultWhitelistCanaries() []CanaryProbe {
	t := 5 * time.Second
	return []CanaryProbe{
		{Target: "www.gosuslugi.ru:443", UseTLS: true, HTTPHost: "www.gosuslugi.ru", Timeout: t},
		{Target: "ya.ru:443", UseTLS: true, HTTPHost: "ya.ru", Timeout: t},
		{Target: "www.sberbank.ru:443", UseTLS: true, HTTPHost: "www.sberbank.ru", Timeout: t},
		{Target: "vk.com:443", UseTLS: true, HTTPHost: "vk.com", Timeout: t},
		{Target: "www.ozon.ru:443", UseTLS: true, HTTPHost: "www.ozon.ru", Timeout: t},
		{Target: "www.avito.ru:443", UseTLS: true, HTTPHost: "www.avito.ru", Timeout: t},
		{Target: "lenta.ru:443", UseTLS: true, HTTPHost: "lenta.ru", Timeout: t},
		{Target: "rutube.ru:443", UseTLS: true, HTTPHost: "rutube.ru", Timeout: t},
	}
}

// BlockingHeuristics runs every probe and returns one result each. The DoH
// control resolver is built fresh per call from ControlDoHEndpoint; for
// custom resolvers / batch use, call BlockingHeuristicsWithDoH directly.
func BlockingHeuristics(ctx context.Context, probes []CanaryProbe) []CanaryResult {
	if len(probes) == 0 {
		probes = DefaultBlockingCanaries()
	}
	doh := provider.NewDoHResolver([]string{ControlDoHEndpoint}, 4*time.Second)
	return BlockingHeuristicsWithDoH(ctx, probes, doh)
}

// BlockingHeuristicsWithDoH lets the caller inject a pre-built DoH resolver,
// so the BlockingReport path can share one resolver across whitelist +
// blacklist runs instead of re-initializing the TLS/HTTP plumbing per call.
//
// Probes run concurrently with a small fan-out cap so a default 20-target
// report finishes in ~5-10 s instead of the ~100 s a strictly-sequential
// loop would take. The LuCI XHR call has a ~30 s ubus timeout — sequential
// wouldn't fit. Order of the output slice matches the input slice so
// callers can keep their indexed labels intact.
func BlockingHeuristicsWithDoH(ctx context.Context, probes []CanaryProbe, doh *provider.DoHResolver) []CanaryResult {
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
			out[i] = runCanary(ctx, p, doh)
		}(i, probes[i])
	}
	wg.Wait()
	return out
}

func runCanary(ctx context.Context, p CanaryProbe, doh *provider.DoHResolver) CanaryResult {
	r := CanaryResult{Target: p.Target}
	t0 := time.Now()
	defer func() { r.Latency = time.Since(t0) }()

	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host, port, err := net.SplitHostPort(p.Target)
	if err != nil {
		r.Verdict, r.Reason, r.Confidence = "config", err.Error(), "low"
		return r
	}

	// DNS phase. System resolver answers first, then DoH as control. If the
	// system says nothing but DoH does, that's high-confidence poisoning.
	// If sets disjoint but both non-empty, we flag mismatch but keep probing
	// (transparent rewriting still lets the request through some pipelines).
	sysAddrs, _ := net.DefaultResolver.LookupIPAddr(cctx, host)
	for _, a := range sysAddrs {
		if a.IP.To4() != nil {
			r.SysIPs = append(r.SysIPs, a.IP.String())
		}
	}
	sort.Strings(r.SysIPs)
	r.ResolvedA = r.SysIPs // legacy alias

	if doh != nil {
		ips, _ := doh.LookupHost(cctx, host)
		for _, ip := range ips {
			if ip.To4() != nil {
				r.DoHIPs = append(r.DoHIPs, ip.String())
			}
		}
		sort.Strings(r.DoHIPs)
	}

	switch {
	case len(r.SysIPs) == 0 && len(r.DoHIPs) > 0:
		r.Verdict, r.Confidence = "dns_poisoned", "high"
		r.Reason = "system resolver failed, DoH succeeded"
		r.Notes = append(r.Notes, "system DNS doesn't resolve, DoH does — consistent with DNS poisoning")
		return r
	case len(r.SysIPs) == 0 && len(r.DoHIPs) == 0:
		r.Verdict, r.Confidence = "dns", "low"
		r.Reason = "domain doesn't resolve via system DNS or DoH (NXDOMAIN, downed authoritative, or DNS-level block)"
		return r
	}

	if len(r.SysIPs) > 0 && len(r.DoHIPs) > 0 && disjoint(r.SysIPs, r.DoHIPs) {
		r.DNSMismatch = true
		r.Notes = append(r.Notes, fmt.Sprintf("DNS mismatch: sys=%v vs doh=%v (disjoint address sets — may indicate transparent DNS rewriting)", r.SysIPs, r.DoHIPs))
	}

	// TCP phase. Dial the IP the SYSTEM resolver (dnsmasq → mihomo) already
	// returned, rather than handing the hostname to the dialer — which would
	// trigger a SECOND system-DNS lookup. The page measures the LAN-client
	// experience, so we deliberately dial what dnsmasq gave us (NOT the DoH
	// control answer). Eliminating the redundant lookup also stops the
	// dnsmasq→mihomo resolver from being hammered by a burst of concurrent
	// probes, which surfaced as bogus "tcp_timeout: lookup … i/o timeout" for
	// sites that resolve fine. Fall back to the hostname only if the system
	// resolver returned nothing (shouldn't reach here — handled above).
	dialTarget := p.Target
	if len(r.SysIPs) > 0 {
		dialTarget = net.JoinHostPort(r.SysIPs[0], port)
	}
	d := &net.Dialer{Timeout: timeout}
	conn, dialErr := d.DialContext(cctx, "tcp", dialTarget)
	if dialErr != nil {
		r.Verdict, r.Reason = classifyDialErr(dialErr), dialErr.Error()
		r.Confidence = confidenceFor(r.Verdict)
		if note := tcpNote(r.Verdict); note != "" {
			r.Notes = append(r.Notes, note)
		}
		return r
	}
	defer func() { _ = conn.Close() }()

	if !p.UseTLS {
		r.Verdict = "ok"
		r.Confidence = okConfidence(r.DNSMismatch)
		return r
	}

	// TLS phase. ServerName forced from the host portion so SNI matches what
	// censors actually inspect; SNI-DPI middleboxes will blow up here and we
	// see it as a reset/timeout/remote-error.
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	tconn := tls.Client(conn, tlsCfg)
	if err := tconn.HandshakeContext(cctx); err != nil {
		r.Verdict, r.Reason = classifyTLSErr(err), err.Error()
		r.Confidence = confidenceFor(r.Verdict)
		if note := tlsNote(r.Verdict); note != "" {
			r.Notes = append(r.Notes, note)
		}
		return r
	}

	// HTTP phase — single bounded GET / over the existing TLS conn. We read
	// up to 4 KiB of the body for stub-page marker matching even on 2xx
	// responses, since polite-style blocks return HTTP 200 with a "blocked
	// by RKN" body. Body cap keeps memory predictable on the router.
	httpHost := p.HTTPHost
	if httpHost == "" {
		httpHost = host
	}
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, "https://"+httpHost+"/", nil)
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tconn, nil
		},
		MaxIdleConns:        1,
		IdleConnTimeout:     time.Second,
		TLSHandshakeTimeout: timeout,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	resp, httpErr := client.Do(req)
	if httpErr != nil {
		r.Verdict, r.Reason, r.Confidence = "http_error", httpErr.Error(), "low"
		return r
	}
	defer func() { _ = resp.Body.Close() }()
	r.StatusCode = resp.StatusCode

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	lowered := strings.ToLower(string(body))
	for _, marker := range StubMarkers {
		if strings.Contains(lowered, marker) {
			r.Verdict, r.Confidence = "http_stub", "high"
			r.StubMarker = marker
			r.Reason = "ISP stub-page marker matched: " + marker
			r.Notes = append(r.Notes, "response body matches a known ISP stub-page marker — operator-mandated block served as HTTP 200")
			return r
		}
	}

	switch {
	case resp.StatusCode == 451:
		r.Verdict, r.Confidence = "http_451", "high"
		r.Reason = "Unavailable For Legal Reasons — explicit censorship-mandated block"
		r.Notes = append(r.Notes, "HTTP 451 explicit block")
	case resp.StatusCode >= 400:
		r.Verdict = Verdict(fmt.Sprintf("http_%d", resp.StatusCode))
		r.Confidence = "low"
	default:
		r.Verdict = "ok"
		r.Confidence = okConfidence(r.DNSMismatch)
	}
	return r
}

// disjoint returns true if a and b share no element. Both are assumed sorted
// and deduped (caller's responsibility). Linear in len(a)+len(b).
func disjoint(a, b []string) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			return false
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return true
}

func confidenceFor(v Verdict) Confidence {
	switch v {
	case VerdictOK, "":
		return ConfidenceHigh
	case VerdictDNSPoisoned, VerdictHTTPStub, VerdictHTTP451:
		return ConfidenceHigh
	case VerdictTCPRST, VerdictTCPRefused, VerdictTLSRST, VerdictTLSRemoteError:
		return ConfidenceMedium
	case VerdictTCPTimeout, VerdictTLSTimeout, VerdictTCPNoRoute:
		return ConfidenceLow
	case VerdictHTTPError, VerdictTCPFail, VerdictTLSFail, VerdictDNS:
		return ConfidenceLow
	}
	if strings.HasPrefix(string(v), "http_") {
		return ConfidenceLow
	}
	return ConfidenceLow
}

func okConfidence(mismatch bool) Confidence {
	if mismatch {
		return ConfidenceMedium
	}
	return ConfidenceHigh
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
	doh := provider.NewDoHResolver([]string{ControlDoHEndpoint}, 4*time.Second)
	rep := BlockingReport{
		Whitelist: BlockingHeuristicsWithDoH(ctx, whitelist, doh),
		Blacklist: BlockingHeuristicsWithDoH(ctx, blacklist, doh),
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
	// (DNS poison, HTTP 451, stub markers) — those are the unambiguous
	// censorship fingerprints.
	if high*2 >= bBlocked {
		return "blocked_zone_high", fmt.Sprintf("%d of %d blacklist targets blocked — %d high-confidence (DNS poison/451/stub), %d medium (DPI/RST)", bBlocked, bTotal, high, medium)
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
	case (counts[VerdictDNSPoisoned]+counts[VerdictDNS])*2 >= n:
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
