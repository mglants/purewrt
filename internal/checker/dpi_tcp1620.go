package checker

// TCP 16-20 DPI prober. Ports the matrix-style probe from
// hyperion-cs/dpi-checkers (utils/tcp1620_prober.py) to Go. The premise of
// the technique: certain TSPU-class middleboxes inspect bytes 16-20 of the
// TCP payload and decide to allow/block based on what falls in that window.
// By varying TLS version, SNI, HTTP Host header, and protocol (plain HTTP
// vs HTTP-over-TLS vs HTTP on :443 without TLS) we shift different bytes
// into positions 16-20 and watch which combinations get through. Anything
// that times out *during* a POST body upload, while a plain HEAD succeeded,
// indicates an inline middlebox sitting between the client and the server
// — i.e., DPI is active for this combination.
//
// Output is a matrix the user can read directly: for each (port, proto,
// TLS version, SNI, Host header) tuple, was the connection alive, did the
// server wait for the request body before responding, and was DPI
// triggered. That information is concrete enough to drive zapret tuning:
// "TLS 1.3 with fake SNI succeeds, TLS 1.2 with real SNI doesn't — DPI is
// matching ClientHello bytes that change with TLS version."

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	tcp1620ThrBytes              = 64 * 1024
	tcp1620RecvBuf               = 8 * 1024
	tcp1620FakeDomainLen         = 15
	tcp1620DefaultReqTimeout     = 15 * time.Second
	tcp1620ServerWaitsCheckLimit = 3 * time.Second
	tcp1620DelayPerTask          = 150 * time.Millisecond
)

// TCP1620Probe controls one probe run.
type TCP1620Probe struct {
	Host    string        // domain or literal IP
	IP      string        // optional manual IP override; if empty we resolve Host
	Timeout time.Duration // per-task timeout; 0 → tcp1620DefaultReqTimeout
}

// TCP1620Result is one row of the probe matrix.
type TCP1620Result struct {
	IP             string `json:"ip"`
	Port           int    `json:"port"`
	Proto          string `json:"proto"` // "http" | "https" | "http-over-https"
	TLSVersion     string `json:"tls_version,omitempty"`
	SNI            string `json:"sni"`        // empty = none, "(host)", "(fake)"
	HTTPHostHeader string `json:"http_host"`  // empty = none, "(host)", "(ip)", "(fake)"
	Alive          bool   `json:"alive"`
	AliveError     string `json:"alive_error,omitempty"`
	ServerWaits    bool   `json:"server_waits"` // did server hold off until body sent?
	DPIDetected    bool   `json:"dpi_detected"`
	DPIError       string `json:"dpi_error,omitempty"`
}

// TCP1620Report wraps the per-host probe matrix with the inputs and a
// summary.
type TCP1620Report struct {
	Host       string          `json:"host"`
	IP         string          `json:"ip"`
	FakeDomain string          `json:"fake_domain"`
	Results    []TCP1620Result `json:"results"`
	// AliveCount / DPIDetectedCount give the user a one-glance breakdown.
	AliveCount       int `json:"alive_count"`
	DPIDetectedCount int `json:"dpi_detected_count"`
}

// RunTCP1620 builds the probe matrix and executes it. Each (host header)
// × (SNI × TLS-version) cell plus one plain-HTTP and one HTTP-on-:443
// cell — so per Host header roughly 8 probes, and we cycle through 4 Host
// header variants → 32-ish probes per target. At ~3-5 s each that's
// 90-150 s wall time — meant to be called from the async start/poll rpcd
// path, not the synchronous one.
func RunTCP1620(ctx context.Context, p TCP1620Probe) (TCP1620Report, error) {
	rep := TCP1620Report{Host: p.Host}
	if p.Timeout == 0 {
		p.Timeout = tcp1620DefaultReqTimeout
	}

	ip := p.IP
	if ip == "" {
		// Use the system resolver — same path the OS would. If we want a
		// censor-side IP picture, the caller can pass IP explicitly.
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, p.Host)
		if err != nil || len(addrs) == 0 {
			return rep, fmt.Errorf("resolve %s: %w", p.Host, err)
		}
		// Prefer IPv4 (the Russian DPI cases at issue are v4-only).
		for _, a := range addrs {
			if a.IP.To4() != nil {
				ip = a.IP.String()
				break
			}
		}
		if ip == "" {
			ip = addrs[0].IP.String()
		}
	}
	if !validIP(ip) {
		return rep, fmt.Errorf("invalid IP %q", ip)
	}
	rep.IP = ip
	rep.FakeDomain = randomDomain(tcp1620FakeDomainLen) + ".com"

	tlsVersions := []uint16{tls.VersionTLS12, tls.VersionTLS13}
	hostIsIP := p.Host == ip
	sniOptions := []string{p.Host, rep.FakeDomain, ""}
	if hostIsIP {
		sniOptions = []string{rep.FakeDomain, ""}
	}
	hostHdrOptions := []string{p.Host, ip, rep.FakeDomain, ""}
	if hostIsIP {
		hostHdrOptions = []string{ip, rep.FakeDomain, ""}
	}

	type task struct {
		port   int
		proto  string
		tlsVer uint16 // 0 if plain
		sni    string
		hh     string
	}
	tasks := make([]task, 0, 4*len(hostHdrOptions)*(len(sniOptions)*len(tlsVersions)+2))
	for _, hh := range hostHdrOptions {
		for _, sni := range sniOptions {
			for _, tv := range tlsVersions {
				tasks = append(tasks, task{port: 443, proto: "https", tlsVer: tv, sni: sni, hh: hh})
			}
		}
		// Plain HTTP on 443 (HTTP request body sent unencrypted) and on 80.
		tasks = append(tasks, task{port: 443, proto: "http-over-https", hh: hh})
		tasks = append(tasks, task{port: 80, proto: "http", hh: hh})
	}

	var (
		mu      sync.Mutex
		results = make([]TCP1620Result, 0, len(tasks))
		wg      sync.WaitGroup
	)
	for _, t := range tasks {
		wg.Add(1)
		// DELAY_PER_TASK matches the upstream Python pacing — keeps us from
		// fanning out 100 sockets at once and confusing flaky DPIs.
		time.Sleep(tcp1620DelayPerTask)
		go func(t task) {
			defer wg.Done()
			r := runTCP1620Task(ctx, ip, t.port, t.tlsVer, t.sni, t.hh, p.Host, rep.FakeDomain, p.Timeout)
			r.Proto = t.proto
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	rep.Results = results
	for _, r := range results {
		if r.Alive {
			rep.AliveCount++
		}
		if r.DPIDetected {
			rep.DPIDetectedCount++
		}
	}
	return rep, nil
}

func runTCP1620Task(ctx context.Context, ip string, port int, tlsVer uint16, sni, hh, host, fakeDomain string, timeout time.Duration) TCP1620Result {
	r := TCP1620Result{
		IP:             ip,
		Port:           port,
		SNI:            labelOption(sni, host, "host", fakeDomain, "fake"),
		HTTPHostHeader: labelOption(hh, host, "host", fakeDomain, "fake"),
		TLSVersion:     tlsLabel(tlsVer),
	}
	// Also stamp the IP variant for the host header label.
	if hh == ip {
		r.HTTPHostHeader = "(ip)"
	}

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	useTLS := tlsVer != 0

	// alive check: open conn, send HEAD with empty body. If anything fails
	// the connection is "not alive" for this combo — no point trying the
	// body upload phase.
	conn, err := dialMaybeTLS(ctx, addr, useTLS, sni, tlsVer, timeout)
	if err != nil {
		r.AliveError = simplifyErr(err)
		return r
	}
	if err := sendHTTP(conn, "HEAD", hh, nil, timeout, false); err != nil {
		r.AliveError = simplifyErr(err)
		_ = conn.Close()
		return r
	}
	_ = conn.Close()
	r.Alive = true

	// body upload phase: open a new conn, send POST with Content-Length,
	// check if server waits, then send body and read response. DPI usually
	// kills the connection during body transfer, surfacing as a timeout.
	conn2, err := dialMaybeTLS(ctx, addr, useTLS, sni, tlsVer, timeout)
	if err != nil {
		r.DPIError = simplifyErr(err)
		return r
	}
	defer func() { _ = conn2.Close() }()

	body := make([]byte, tcp1620ThrBytes)
	_, _ = rand.Read(body)

	hdrs := buildHTTPRequest("POST", hh, len(body))
	if err := writeWithDeadline(conn2, hdrs, timeout); err != nil {
		r.DPIError = simplifyErr(err)
		return r
	}
	r.ServerWaits = doesServerWait(conn2, tcp1620ServerWaitsCheckLimit)
	if err := writeWithDeadline(conn2, body, timeout); err != nil {
		r.DPIError = simplifyErr(err)
		return r
	}
	if err := drainResponse(conn2, timeout); err != nil {
		// timeout during drain == DPI killed the connection mid-flight
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			r.DPIDetected = true
			return r
		}
		r.DPIError = simplifyErr(err)
		return r
	}
	return r
}

func dialMaybeTLS(ctx context.Context, addr string, useTLS bool, sni string, tlsVer uint16, timeout time.Duration) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return conn, nil
	}
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // we're probing, not authenticating
		MinVersion:         tlsVer,
		MaxVersion:         tlsVer,
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(dctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

func buildHTTPRequest(method, hostHeader string, contentLen int) []byte {
	var b strings.Builder
	b.WriteString(method)
	b.WriteString(" / HTTP/1.1\r\n")
	if hostHeader != "" {
		b.WriteString("Host: ")
		b.WriteString(hostHeader)
		b.WriteString("\r\n")
	} else {
		b.WriteString("Host: \r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", contentLen)
	b.WriteString("Connection: close\r\n\r\n")
	return []byte(b.String())
}

func sendHTTP(conn net.Conn, method, hostHeader string, body []byte, timeout time.Duration, read bool) error {
	hdr := buildHTTPRequest(method, hostHeader, len(body))
	if err := writeWithDeadline(conn, hdr, timeout); err != nil {
		return err
	}
	if len(body) > 0 {
		if err := writeWithDeadline(conn, body, timeout); err != nil {
			return err
		}
	}
	if read {
		return drainResponse(conn, timeout)
	}
	return nil
}

func writeWithDeadline(conn net.Conn, data []byte, timeout time.Duration) error {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write(data)
	return err
}

func drainResponse(conn net.Conn, timeout time.Duration) error {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, tcp1620RecvBuf)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// doesServerWait checks whether the server has already emitted any bytes
// before we sent the request body. A "waits" server is HTTP-compliant; a
// "doesn't wait" peer is either keeping its early bytes warm or has
// already RST'd.
func doesServerWait(conn net.Conn, window time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(window))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	// Restoring deadline so caller's later read isn't bounded by the small
	// probe window.
	_ = conn.SetReadDeadline(time.Time{})
	// If the read timed out, the server hasn't sent anything → it's
	// waiting for the body. A successful read or any non-timeout error
	// means it didn't wait.
	if err == nil {
		return false
	}
	return isTimeout(err)
}

func tlsLabel(v uint16) string {
	switch v {
	case 0:
		return ""
	case tls.VersionTLS12:
		return "v1.2"
	case tls.VersionTLS13:
		return "v1.3"
	}
	return fmt.Sprintf("v0x%x", v)
}

func labelOption(actual, host, hostLbl, fake, fakeLbl string) string {
	switch actual {
	case "":
		return ""
	case host:
		return "(" + hostLbl + ")"
	case fake:
		return "(" + fakeLbl + ")"
	default:
		return actual
	}
}

func randomDomain(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	for i := range out {
		// crypto/rand for portability; the values themselves don't need to
		// be cryptographically uniform but rand.Read is what's there.
		bi, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			out[i] = alphabet[i%len(alphabet)]
			continue
		}
		out[i] = alphabet[bi.Int64()]
	}
	return string(out)
}

func validIP(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.IsValid()
}

// FormatTCP1620 renders the probe matrix as an ANSI-coloured table for
// SSH consumption. The JSON shape is the source of truth (rpcd uses it),
// but reading a 32-row matrix out of `jq` on a phone-terminal is no fun.
// Column widths are roughly auto-sized; cells use a small palette
// (green=alive/clean, red=dpi-detected, yellow=alive-error, grey=n/a).
//
// To keep the dependency surface small (no third-party table library)
// the renderer is a hand-rolled padded-column print. Plain text is also
// readable if the terminal lacks ANSI support.
func FormatTCP1620(rep TCP1620Report) string {
	const (
		ansiReset  = "\x1b[0m"
		ansiGreen  = "\x1b[32m"
		ansiRed    = "\x1b[31m"
		ansiYellow = "\x1b[33m"
		ansiGrey   = "\x1b[90m"
		ansiBold   = "\x1b[1m"
	)
	color := func(c, s string) string { return c + s + ansiReset }
	muted := func(s string) string { return color(ansiGrey, s) }

	cols := []struct {
		hdr string
		w   int
	}{
		{"port", 4},
		{"proto", 16},
		{"tls", 5},
		{"sni", 16},
		{"http host", 16},
		{"alive", 9},
		{"waits", 6},
		{"dpi", 14},
	}
	pad := func(s string, w int) string {
		// Strip any embedded ANSI before measuring length (so colour
		// codes don't push real text out of alignment).
		bare := s
		for {
			i := strings.Index(bare, "\x1b[")
			if i < 0 {
				break
			}
			j := strings.IndexByte(bare[i:], 'm')
			if j < 0 {
				break
			}
			bare = bare[:i] + bare[i+j+1:]
		}
		if n := w - len(bare); n > 0 {
			return s + strings.Repeat(" ", n)
		}
		return s
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s host=%s ip=%s fake=%s%s\n",
		color(ansiBold, "tcp-16-20 matrix"), rep.Host, rep.IP, rep.FakeDomain, "")
	fmt.Fprintf(&b, "%s\n", color(ansiBold, fmt.Sprintf("alive=%d/%d  dpi-detected=%d",
		rep.AliveCount, len(rep.Results), rep.DPIDetectedCount)))

	// Header row.
	for _, c := range cols {
		b.WriteString(pad(color(ansiBold, c.hdr), c.w))
	}
	b.WriteByte('\n')
	for _, c := range cols {
		b.WriteString(strings.Repeat("─", c.w-1))
		b.WriteByte(' ')
	}
	b.WriteByte('\n')

	// Pre-sort: by port ascending, then proto, then tls version so the
	// matrix reads predictably across runs.
	rows := make([]TCP1620Result, len(rep.Results))
	copy(rows, rep.Results)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Port != rows[j].Port {
			return rows[i].Port < rows[j].Port
		}
		if rows[i].Proto != rows[j].Proto {
			return rows[i].Proto < rows[j].Proto
		}
		return rows[i].TLSVersion < rows[j].TLSVersion
	})

	for _, r := range rows {
		alive := muted("—")
		if r.Alive {
			alive = color(ansiGreen, "yes")
		} else if r.AliveError != "" {
			alive = color(ansiYellow, r.AliveError)
		} else {
			alive = color(ansiRed, "no")
		}
		var waits, dpi string
		if !r.Alive {
			waits, dpi = muted("—"), muted("—")
		} else {
			if r.ServerWaits {
				waits = color(ansiGreen, "yes")
			} else {
				waits = muted("no")
			}
			switch {
			case r.DPIDetected:
				dpi = color(ansiRed, "DETECTED")
			case r.DPIError != "":
				dpi = color(ansiYellow, r.DPIError)
			default:
				dpi = color(ansiGreen, "clean")
			}
		}
		row := []string{
			fmt.Sprintf("%d", r.Port),
			r.Proto,
			func() string {
				if r.TLSVersion == "" {
					return muted("—")
				}
				return r.TLSVersion
			}(),
			func() string {
				if r.SNI == "" {
					return muted("—")
				}
				return r.SNI
			}(),
			func() string {
				if r.HTTPHostHeader == "" {
					return muted("—")
				}
				return r.HTTPHostHeader
			}(),
			alive, waits, dpi,
		}
		for i, c := range cols {
			b.WriteString(pad(row[i], c.w))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// simplifyErr collapses a Go error into a short label (tls err / conn err /
// timeout / internal err) so the result rows are scannable in a table.
func simplifyErr(err error) string {
	if err == nil {
		return ""
	}
	if isTimeout(err) {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "tls") || strings.Contains(msg, "ssl") || strings.Contains(msg, "handshake"):
		return "tls err"
	case strings.Contains(msg, "refused") || strings.Contains(msg, "connection") || strings.Contains(msg, "no route") || strings.Contains(msg, "reset"):
		return "conn err"
	}
	return "internal err"
}
