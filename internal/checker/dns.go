package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/provider"
)

type lookupIPFunc func(string) ([]net.IP, error)

type DNSResult struct {
	A, AAAA []string
	Error   string
}

func Resolve(domain string) DNSResult {
	return resolveWithLookup(domain, net.LookupIP)
}

func resolveWithLookup(domain string, lookup lookupIPFunc) DNSResult {
	ips, err := lookup(domain)
	r := DNSResult{}
	if err != nil {
		r.Error = err.Error()
		return r
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			r.A = append(r.A, ip.String())
		} else {
			r.AAAA = append(r.AAAA, ip.String())
		}
	}
	return r
}

// UpstreamHealth is the outcome of probing a single DoH/DoQ/UDP upstream.
type UpstreamHealth struct {
	URL     string        `json:"url"`
	OK      bool          `json:"ok"`
	Latency time.Duration `json:"latency_ms"`
	Error   string        `json:"error,omitempty"`
	IPs     []string      `json:"ips,omitempty"`
}

// ProbeDoHResolvers resolves a canary domain (default "cp.cloudflare.com")
// through each provided DoH endpoint URL and returns per-endpoint health.
// Used by `purewrt doctor --dns` to detect blocked upstreams quickly.
func ProbeDoHResolvers(ctx context.Context, endpoints []string, canary string) []UpstreamHealth {
	if canary == "" {
		canary = "cp.cloudflare.com"
	}
	out := make([]UpstreamHealth, 0, len(endpoints))
	for _, ep := range endpoints {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		h := UpstreamHealth{URL: ep}
		// Each endpoint gets its own resolver so a parked endpoint in one
		// probe doesn't poison a later probe in the same call.
		r := provider.NewDoHResolver([]string{ep}, 4*time.Second)
		t0 := time.Now()
		ips, err := r.LookupHost(ctx, canary)
		h.Latency = time.Since(t0)
		if err != nil {
			h.Error = err.Error()
		} else {
			h.OK = true
			for _, ip := range ips {
				h.IPs = append(h.IPs, ip.String())
			}
		}
		out = append(out, h)
	}
	return out
}

// FormatUpstreamHealth renders ProbeDoHResolvers output as a human-readable
// multi-line string, suitable for inclusion in a `doctor` report.
func FormatUpstreamHealth(report []UpstreamHealth) string {
	var b strings.Builder
	for _, h := range report {
		status := "OK"
		if !h.OK {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "  %-4s  %s  (%dms)", status, h.URL, h.Latency.Milliseconds())
		if h.Error != "" {
			fmt.Fprintf(&b, "  err=%s", h.Error)
		} else if len(h.IPs) > 0 {
			fmt.Fprintf(&b, "  -> %s", strings.Join(h.IPs, ","))
		}
		b.WriteString("\n")
	}
	return b.String()
}
