package manager

// Diagnostic-shaped Manager methods. Read-only inspection of the live
// system + persisted state — no apply side effects, no UCI writes. This
// file groups the surface that `purewrt doctor`, `doctor-warnings`,
// `subscription-expiry`, `inspect-ipv6`, `resolvers-probe`, and the
// LuCI rpcd diagnostic methods all hit. Carved out of manager.go (which
// had grown to ~1800 lines) so the apply pipeline isn't visually
// entangled with the inspection surface.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/checker"
	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/system"
)

// zapretBinaries is the install signal for the optional Zapret package.
// We check the userspace daemons (nfqws / tpws) rather than init scripts
// because the OpenWrt feed has historically shipped Zapret under several
// init-script names (`purewrt-zapret`, `zapret2`, plain `zapret`) while
// the userspace binaries have always lived at the same path. nfqws is
// the queue-based engine, tpws the transparent-proxy one; either being
// present is enough to consider Zapret installed.
var zapretBinaries = []string{
	"/usr/bin/nfqws",
	"/usr/sbin/nfqws",
	"/usr/bin/tpws",
	"/usr/sbin/tpws",
}

// ZapretInstalled returns true when at least one Zapret userspace binary
// is present. Used to gate Zapret-specific UI (menu entry, logs panel,
// diagnostics section) so installs without the package don't surface
// dead links or empty panels.
func (m Manager) ZapretInstalled() bool {
	for _, p := range zapretBinaries {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

func subscriptionExpiryLines(c config.Config) []string {
	now := time.Now()
	out := []string{}
	for _, s := range c.Subscriptions {
		if !s.Enabled || s.URL == "" {
			continue
		}
		// Subscription metadata lives next to the imported profile cache.
		// We don't track the exact path inside `config.Subscription`, so use
		// the standard derived path: <Workdir>/providers/<name>.yaml.meta.json.
		path := filepath.Join(c.Settings.Workdir, "providers", s.Name+".yaml")
		meta, err := provider.ReadMetadata(path)
		if err != nil {
			continue
		}
		if meta.SubExpire.IsZero() && meta.SubTotalBytes == 0 {
			continue
		}
		var parts []string
		if !meta.SubExpire.IsZero() {
			days := meta.SubExpire.Sub(now).Hours() / 24
			parts = append(parts, fmt.Sprintf("expires %s (in %.0fd)", meta.SubExpire.UTC().Format("2006-01-02"), days))
		}
		if meta.SubTotalBytes > 0 {
			pct := float64(meta.SubUsedBytes) / float64(meta.SubTotalBytes) * 100
			parts = append(parts, fmt.Sprintf("quota %.1f%% used (%d/%d MiB)", pct, meta.SubUsedBytes>>20, meta.SubTotalBytes>>20))
		}
		out = append(out, s.Name+": "+strings.Join(parts, ", "))
	}
	return out
}

func (m Manager) Doctor() string {
	c, _ := m.Load()
	c = ResolveZapretProfileInterfaces(c)
	conflict, msg := generator.MarkConflict(c, c.Mwan3.Mwan3Mask)
	deps := system.CheckDependencies("dnsmasq", "nft", "ip", "mihomo")
	var depLines []string
	for _, d := range deps {
		depLines = append(depLines, fmt.Sprintf("%s: %v %s", d.Name, d.OK, d.Path))
	}
	var zapretLines []string
	for _, p := range c.EnabledZapretProfiles() {
		zapretLines = append(zapretLines, fmt.Sprintf("%s: mode=%s network=%s interfaces=%s", p.Name, p.InterfaceMode, p.Network, strings.Join(p.Interfaces, ",")))
	}
	if len(zapretLines) == 0 {
		zapretLines = append(zapretLines, "none")
	}
	warnings := strings.Join(doctorBypassWarnings(c), "\n  ")
	if warnings == "" {
		warnings = "none"
	}
	return fmt.Sprintf("Dependencies:\n  %s\nMwan3 mode: %s\nMark conflict: %v (%s)\nZapret profiles:\n  %s\nPolicy commands:\n  %s\nBypass warnings:\n  %s\n", strings.Join(depLines, "\n  "), c.Mwan3.Mode, conflict, msg, strings.Join(zapretLines, "\n  "), strings.Join(generator.PolicyCommands(c), "\n  "), warnings)
}

// doctorBypassWarnings returns censorship-bypass-relevant warnings that the
// user should know about: disabled DNS hijack, disabled DoT/DoH3/DoQ block,
// missing dnsmasq-full (needed for nftset= directives), and disabled DoH
// bootstrap.
func doctorBypassWarnings(c config.Config) []string {
	var w []string
	if !c.DNS.HijackLANDNS {
		w = append(w, "DNS hijack disabled — devices with hardcoded resolvers (Smart TVs, Chromecast) will bypass the nftset path. Set option hijack_lan_dns '1' in /etc/config/purewrt.")
	}
	if !c.DNS.BlockDoT {
		w = append(w, "DoT (tcp/853) not blocked — clients that prefer DoT will bypass dnsmasq nftset population.")
	}
	if !c.DNS.BlockDoQ {
		w = append(w, "DoQ (udp/853) not blocked — same risk as DoT but over QUIC.")
	}
	if !c.DNS.BlockDoH3 {
		w = append(w, "DoH3 (udp/443 to known DoH endpoints) not blocked — modern browsers can use it to bypass plain DNS.")
	}
	if !c.Settings.BootstrapDoHEnabled {
		w = append(w, "Bootstrap DoH disabled — if the system resolver is blocked, subscription and mihomo update downloads will fail.")
	}
	// Subscription expiry warnings — flag any subscription whose proxy panel
	// reported expiry within 7 days. Saves the user from a silent outage
	// when an old subscription stops issuing nodes the day they're traveling.
	now := time.Now()
	for _, s := range c.Subscriptions {
		if !s.Enabled || s.URL == "" {
			continue
		}
		path := filepath.Join(c.Settings.Workdir, "providers", s.Name+".yaml")
		meta, err := provider.ReadMetadata(path)
		if err != nil || meta.SubExpire.IsZero() {
			continue
		}
		days := meta.SubExpire.Sub(now).Hours() / 24
		if days <= 0 {
			w = append(w, fmt.Sprintf("subscription %q EXPIRED on %s — renew or remove.", s.Name, meta.SubExpire.UTC().Format("2006-01-02")))
		} else if days <= 7 {
			w = append(w, fmt.Sprintf("subscription %q expires in %.0f days (%s) — renew soon.", s.Name, days, meta.SubExpire.UTC().Format("2006-01-02")))
		}
	}
	// dnsmasq-full carries the `--nftset` and `--ipset` directive support that
	// PureWRT relies on. Stock dnsmasq won't populate the section sets.
	if !hasDnsmasqFull() {
		w = append(w, "dnsmasq-full not detected — install it (the stock `dnsmasq` package lacks nftset= support).")
	}
	return w
}

// hasDnsmasqFull probes dnsmasq for the --nftset feature. Stock dnsmasq
// rejects --help nftset; dnsmasq-full prints help. Best-effort; returns
// true when we can't tell so we don't spam warnings on dev machines.
func hasDnsmasqFull() bool {
	out, err := (system.Runner{}).Run("dnsmasq", "--help", "nftset")
	if err != nil {
		return true
	}
	return strings.Contains(out, "nftset")
}

// InspectIPv6 returns the device's IPv6 readiness summary. Thin wrapper
// over checker.InspectIPv6 that loads the Manager's config first; lives on
// Manager so the CLI / rpcd plumbing has one consistent entry point for
// every diagnostic.
func (m Manager) InspectIPv6() checker.IPv6Path {
	c, _ := m.Load()
	return checker.InspectIPv6(c)
}

// DoctorWarnings returns the slice of warning strings doctor would print,
// shaped for JSON consumption by LuCI rpcd.
func (m Manager) DoctorWarnings() []string {
	c, _ := m.Load()
	return doctorBypassWarnings(c)
}

// SubscriptionExpiryEntry is the per-subscription expiry + quota state,
// parsed from the metadata file each provider download persists. Shape is
// designed for direct JSON consumption by the LuCI banner — empty
// ExpireUnix means "never received a subscription-userinfo header"; days
// remaining is computed against the wall clock so the LuCI client doesn't
// need to know about server time.
type SubscriptionExpiryEntry struct {
	Name           string  `json:"name"`
	URL            string  `json:"url_redacted"`
	ExpireUnix     int64   `json:"expire_unix,omitempty"`
	DaysRemaining  float64 `json:"days_remaining,omitempty"`
	UsedBytes      int64   `json:"used_bytes,omitempty"`
	TotalBytes     int64   `json:"total_bytes,omitempty"`
	QuotaPercent   float64 `json:"quota_percent,omitempty"`
	NeedsAttention bool    `json:"needs_attention,omitempty"` // expired or ≤7 days
}

func (m Manager) SubscriptionExpiry() []SubscriptionExpiryEntry {
	c, _ := m.Load()
	now := time.Now()
	out := []SubscriptionExpiryEntry{}
	for _, s := range c.Subscriptions {
		if !s.Enabled || s.URL == "" {
			continue
		}
		path := filepath.Join(c.Settings.Workdir, "providers", s.Name+".yaml")
		meta, err := provider.ReadMetadata(path)
		if err != nil {
			continue
		}
		if meta.SubExpire.IsZero() && meta.SubTotalBytes == 0 {
			continue
		}
		e := SubscriptionExpiryEntry{Name: s.Name, URL: meta.URLRedacted}
		if !meta.SubExpire.IsZero() {
			e.ExpireUnix = meta.SubExpire.Unix()
			e.DaysRemaining = meta.SubExpire.Sub(now).Hours() / 24
			if e.DaysRemaining <= 7 {
				e.NeedsAttention = true
			}
		}
		if meta.SubTotalBytes > 0 {
			e.UsedBytes = meta.SubUsedBytes
			e.TotalBytes = meta.SubTotalBytes
			e.QuotaPercent = float64(meta.SubUsedBytes) / float64(meta.SubTotalBytes) * 100
			// Quota ≥80% used is "running out" even if expiry is months away.
			// Surface it so the LuCI banner draws attention before traffic
			// actually cuts off.
			if e.QuotaPercent >= 80 {
				e.NeedsAttention = true
			}
		}
		out = append(out, e)
	}
	return out
}

// BlockingHeuristics runs the curated canary set (or a caller-supplied
// list) and returns per-target verdicts + a one-line "looks like X is
// blocking" summary. Used by `purewrt doctor --canaries` and the LuCI
// "What's blocked right now" panel via rpcd `blocking_heuristics`.
func (m Manager) BlockingHeuristics(targets []string) string {
	probes := []checker.CanaryProbe{}
	for _, t := range targets {
		probes = append(probes, checker.CanaryProbe{
			Target: ensureHostPort(t), UseTLS: true, Timeout: 5 * time.Second,
		})
	}
	if len(probes) == 0 {
		probes = checker.DefaultBlockingCanaries()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return checker.FormatBlockingResults(checker.BlockingHeuristics(ctx, probes))
}

func ensureHostPort(t string) string {
	if !strings.Contains(t, ":") {
		return t + ":443"
	}
	return t
}

// ResolversProbeReport wraps a bootstrap DoH probe result with the
// overall-health booleans LuCI banners consume directly.
type ResolversProbeReport struct {
	OK       bool                     `json:"ok"`
	Anywhere bool                     `json:"any_endpoint_ok"`
	Canary   string                   `json:"canary"`
	Entries  []checker.UpstreamHealth `json:"entries"`
}

// ResolversProbe probes the bootstrap DoH pool against a canary host.
// "Anywhere" is true if at least one endpoint resolved the canary; "OK" is a
// strict variant requiring at least half the endpoints to answer (so we don't
// declare the bootstrap healthy on a single flaky endpoint).
func (m Manager) ResolversProbe(canary string) ResolversProbeReport {
	c, _ := m.Load()
	if canary == "" {
		canary = "cp.cloudflare.com"
	}
	endpoints := c.Settings.BootstrapDoHResolvers
	if len(endpoints) == 0 {
		endpoints = config.DefaultBootstrapDoHResolvers()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	results := checker.ProbeDoHResolvers(ctx, endpoints, canary)
	ok := 0
	for _, r := range results {
		if r.OK {
			ok++
		}
	}
	return ResolversProbeReport{
		OK:       ok*2 >= len(results) && len(results) > 0,
		Anywhere: ok > 0,
		Canary:   canary,
		Entries:  results,
	}
}

// FormatResolversProbe renders ResolversProbe output as a human-readable
// block. Used by the CLI and the LuCI rpcd Button.
func FormatResolversProbe(r ResolversProbeReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Bootstrap DoH probe (canary=%s): ok_endpoints=%d/%d any=%v healthy=%v\n",
		r.Canary, countOK(r.Entries), len(r.Entries), r.Anywhere, r.OK)
	b.WriteString(checker.FormatUpstreamHealth(r.Entries))
	return b.String()
}

func countOK(hs []checker.UpstreamHealth) int {
	n := 0
	for _, h := range hs {
		if h.OK {
			n++
		}
	}
	return n
}
