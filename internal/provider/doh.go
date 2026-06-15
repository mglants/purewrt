package provider

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// DoHResolver resolves hostnames via DNS-over-HTTPS using a configurable
// endpoint pool. Endpoints are tried in priority order; failing endpoints
// are parked for a short cooldown so subsequent lookups skip them. The pool
// SHOULD use IP-literal hosts (e.g. https://1.1.1.1/dns-query) so the
// resolver never depends on the system DNS to find itself — that is the
// whole point of the censorship-resistant bootstrap path.
type DoHResolver struct {
	endpoints []*dohEndpoint
	client    *http.Client
	timeout   time.Duration
}

type dohEndpoint struct {
	url        string
	cooldownNs atomic.Int64
}

// NewDoHResolver builds a resolver from a list of endpoint URLs. Empty
// entries are dropped; an empty list falls back to a default pool of
// well-known IP-literal endpoints. The per-endpoint timeout defaults to 8s.
func NewDoHResolver(endpoints []string, timeout time.Duration) *DoHResolver {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if len(endpoints) == 0 {
		endpoints = DefaultDoHEndpoints()
	}
	eps := make([]*dohEndpoint, 0, len(endpoints))
	for _, u := range endpoints {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		eps = append(eps, &dohEndpoint{url: u})
	}
	// The DoH HTTP client MUST NOT route through this resolver (it would
	// deadlock), so it gets a plain net.Dialer with short timeouts.
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
	return &DoHResolver{
		endpoints: eps,
		client:    &http.Client{Transport: tr, Timeout: timeout},
		timeout:   timeout,
	}
}

// DefaultDoHEndpoints returns the censorship-resistant default pool. All
// entries use IP literals so the resolver never depends on system DNS. The
// list is deliberately broader than the canonical Cloudflare/Google/Quad9
// trio — in censored regions those are the first IPs blocked, so AdGuard,
// Mullvad, and Yandex are seeded too. Mirrors config.DefaultBootstrapDoHResolvers.
func DefaultDoHEndpoints() []string {
	return []string{
		"https://1.1.1.1/dns-query",
		"https://1.0.0.1/dns-query",
		"https://8.8.8.8/dns-query",
		"https://9.9.9.9/dns-query",
		"https://94.140.14.14/dns-query",
		"https://94.140.15.15/dns-query",
		"https://194.242.2.2/dns-query",
		"https://77.88.8.1/dns-query",
	}
}

// LookupHost resolves host to A and AAAA records, trying endpoints in
// priority order and parking failed ones for a short cooldown. If host is
// already an IP literal it is returned as-is.
func (r *DoHResolver) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	now := time.Now().UnixNano()
	var lastErr error
	tried := 0
	for _, ep := range r.endpoints {
		if cool := ep.cooldownNs.Load(); cool > now {
			continue
		}
		tried++
		ips, err := r.queryOne(ctx, ep.url, host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		ep.cooldownNs.Store(time.Now().Add(30 * time.Second).UnixNano())
		if err != nil {
			lastErr = err
		}
	}
	if tried == 0 {
		// Every endpoint is parked; release cooldowns and retry once so we
		// don't return "no endpoints" after a transient outage cleared.
		for _, ep := range r.endpoints {
			ep.cooldownNs.Store(0)
		}
		var lastInner error
		for _, ep := range r.endpoints {
			ips, err := r.queryOne(ctx, ep.url, host)
			if err == nil && len(ips) > 0 {
				return ips, nil
			}
			if err != nil {
				lastInner = err
			}
		}
		if lastInner != nil {
			return nil, fmt.Errorf("doh: no endpoint resolved %q: %w", host, lastInner)
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("doh: no endpoint resolved %q: %w", host, lastErr)
	}
	return nil, fmt.Errorf("doh: no endpoint resolved %q", host)
}

func (r *DoHResolver) queryOne(ctx context.Context, endpoint, host string) ([]net.IP, error) {
	var all []net.IP
	for _, qtype := range []uint16{1, 28} { // A, AAAA
		ips, err := r.queryType(ctx, endpoint, host, qtype)
		if err != nil {
			return nil, err
		}
		all = append(all, ips...)
	}
	if len(all) == 0 {
		return nil, errors.New("no records")
	}
	return all, nil
}

func (r *DoHResolver) queryType(ctx context.Context, endpoint, host string, qtype uint16) ([]net.IP, error) {
	q, err := buildDNSQuery(host, qtype)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, endpoint, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("doh %s: %s", endpoint, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	return parseDNSAnswers(body, qtype)
}

func buildDNSQuery(host string, qtype uint16) ([]byte, error) {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, errors.New("empty host")
	}
	var buf bytes.Buffer
	// txid=0 is RECOMMENDED for DoH (RFC 8484 §4.1) to maximise cache hits.
	hdr := [12]byte{}
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD set
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // qdcount
	buf.Write(hdr[:])
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label %q", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	qt := [4]byte{}
	binary.BigEndian.PutUint16(qt[0:2], qtype)
	binary.BigEndian.PutUint16(qt[2:4], 1) // class IN
	buf.Write(qt[:])
	return buf.Bytes(), nil
}

func parseDNSAnswers(msg []byte, qtype uint16) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, errors.New("short DNS response")
	}
	qd := binary.BigEndian.Uint16(msg[4:6])
	an := binary.BigEndian.Uint16(msg[6:8])
	off := 12
	for i := uint16(0); i < qd; i++ {
		n, err := skipName(msg, off)
		if err != nil {
			return nil, err
		}
		off = n + 4
		if off > len(msg) {
			return nil, errors.New("truncated question")
		}
	}
	var out []net.IP
	for i := uint16(0); i < an; i++ {
		n, err := skipName(msg, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+10 > len(msg) {
			return nil, errors.New("truncated answer")
		}
		t := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := binary.BigEndian.Uint16(msg[off+8 : off+10])
		off += 10
		if off+int(rdlen) > len(msg) {
			return nil, errors.New("truncated rdata")
		}
		if t == qtype {
			switch t {
			case 1:
				if rdlen == 4 {
					out = append(out, net.IP(append([]byte{}, msg[off:off+4]...)))
				}
			case 28:
				if rdlen == 16 {
					out = append(out, net.IP(append([]byte{}, msg[off:off+16]...)))
				}
			}
		}
		off += int(rdlen)
	}
	return out, nil
}

func skipName(msg []byte, off int) (int, error) {
	hops := 0
	for {
		if off >= len(msg) {
			return 0, errors.New("name overrun")
		}
		l := int(msg[off])
		if l == 0 {
			return off + 1, nil
		}
		if l&0xC0 == 0xC0 {
			if off+2 > len(msg) {
				return 0, errors.New("pointer overrun")
			}
			return off + 2, nil
		}
		if l&0xC0 != 0 {
			return 0, errors.New("invalid label length")
		}
		off += 1 + l
		hops++
		if hops > 127 {
			return 0, errors.New("label hop limit")
		}
	}
}

