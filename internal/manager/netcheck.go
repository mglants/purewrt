package manager

// net-check: a layered, topology-aware connectivity diagnostic. Unlike
// mihomo's url-test (which GETs an empty 204 and so measures only RTT), this
// drives real bytes through the proxy mixed-port and isolates the failing
// stage — mihomo vs node vs routing vs WAN. It also folds in the cheap
// existing summaries (config warnings + service liveness) so one command is
// the unified first-look; it points at the deep tools (dpi-check, zapret-*)
// rather than duplicating them.
//
// Probes are read-only (HTTP transfers + nft reads). The throughput
// measurement lives in checker.ThroughputProbe; this file orchestrates the
// layers, branches by detected topology, and synthesises the verdict.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/checker"
	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/mihomoapi"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/system"
)

const (
	speedDownURL = "https://speed.cloudflare.com/__down?bytes=%d"
	speedUpURL   = "https://speed.cloudflare.com/__up"
	// domesticLivenessURL gates WAN-up independent of foreign censorship: in a
	// censored env a foreign direct fetch is throttled even when the uplink is
	// healthy, so a domestic endpoint is the honest liveness signal.
	domesticLivenessURL = "https://ya.ru/"

	netCheckProbeGroup = "NetCheckProbe"

	defaultNetCheckBytes = 10 << 20 // 10 MiB interactive default
	slowKbps             = 1000     // < 1 Mbps proxy throughput → "slow"
	throttledKbps        = 500      // per-node: RTT-ok but < this → "throttled"
	foreignDirectTimeout = 5 * time.Second // informational censorship probe — short, never gates verdict
)

// NetCheckOpts tunes a run. Zero values get sensible defaults.
type NetCheckOpts struct {
	Bytes   int64         // down/up probe size (default 10 MiB; cron passes smaller)
	Timeout time.Duration // per-probe timeout (default 20s)
	Domain  string        // DNS/routing probe domain (default www.google.com)
	PerNode bool          // probe every node individually via the probe listener
}

// LayerResult is one diagnostic stage. Status ∈ ok|fail|na|warn.
type LayerResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// NodeResult is one node's real-throughput verdict from --per-node.
type NodeResult struct {
	Node     string  `json:"node"`
	DownKbps float64 `json:"down_kbps"`
	UpKbps   float64 `json:"up_kbps"`
	DelayMS  int     `json:"delay_ms,omitempty"`
	Verdict  string  `json:"verdict"` // ok|throttled|fail
}

// NetCheckReport is the full structured result (JSON for rpcd/metrics; the
// CLI also renders it via FormatNetCheck).
type NetCheckReport struct {
	Mode           string                  `json:"mode"` // proxy|vpn_only|zapret_only|direct
	Warnings       []string                `json:"warnings,omitempty"`
	Services       []ServiceStatus         `json:"services,omitempty"`
	Layers         []LayerResult           `json:"layers"`
	Download       checker.ThroughputResult `json:"download"`
	Upload         checker.ThroughputResult `json:"upload"`
	DirectDomestic checker.ThroughputResult `json:"direct_domestic"`
	ForeignDirect  checker.ThroughputResult `json:"foreign_direct"`
	DNS            checker.DNSResult       `json:"dns"`
	Blocking       *checker.BlockingReport `json:"blocking,omitempty"`
	Nodes          []NodeResult            `json:"nodes,omitempty"`
	Verdict        string                  `json:"verdict"` // ok|degraded|broken
	BrokenLayer    string                  `json:"broken_layer,omitempty"`
	Diagnosis      string                  `json:"diagnosis"`
}

// NetCheck runs the diagnostic and records metrics. The caller (CLI/cron)
// persists the registry via dumpMetrics afterwards.
func (m Manager) NetCheck(ctx context.Context, opts NetCheckOpts) NetCheckReport {
	if opts.Bytes <= 0 {
		opts.Bytes = defaultNetCheckBytes
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	if opts.Domain == "" {
		opts.Domain = "youtube.com"
	}
	c, _ := m.Load()

	rep := NetCheckReport{
		Mode:     detectMode(c),
		Warnings: doctorBypassWarnings(c),
		Services: serviceStatuses(),
	}

	// Universal layers (every mode).
	rep.DNS = checker.Resolve(opts.Domain)
	if rep.DNS.Error == "" && (len(rep.DNS.A) > 0 || len(rep.DNS.AAAA) > 0) {
		rep.addLayer("dns", "ok", fmt.Sprintf("%s → %s", opts.Domain, strings.Join(append(rep.DNS.A, rep.DNS.AAAA...), ",")))
	} else {
		rep.addLayer("dns", "fail", "resolve "+opts.Domain+": "+rep.DNS.Error)
	}

	directClient, _ := provider.NewClient(provider.ClientOptions{Timeout: opts.Timeout})
	rep.DirectDomestic = timedProbe(ctx, opts.Timeout, directClient, domesticLivenessURL, false, 0)
	if rep.DirectDomestic.OK {
		rep.addLayer("wan", "ok", fmt.Sprintf("domestic direct reachable (%.0f kbps)", rep.DirectDomestic.Kbps))
	} else {
		rep.addLayer("wan", "fail", "domestic direct unreachable: "+rep.DirectDomestic.Error)
	}

	switch rep.Mode {
	case "proxy", "vpn_only":
		m.netCheckProxy(ctx, c, opts, &rep)
	case "zapret_only", "direct":
		m.netCheckNoProxy(ctx, &rep)
	}

	rep.synthesize()
	rep.recordMetrics()
	dumpMetrics(c) // persist <RuntimeDir>/metrics.prom for purewrt-api /metrics; best-effort
	return rep
}

// netCheckProxy runs the proxy/VPN data-path layers.
func (m Manager) netCheckProxy(ctx context.Context, c config.Config, opts NetCheckOpts, rep *NetCheckReport) {
	cli := mihomoapi.Client{Base: localControllerAddr(c), Secret: c.Settings.Secret}
	if !cli.Reachable() {
		rep.addLayer("mihomo", "fail", "external controller unreachable")
		return
	}
	rep.addLayer("mihomo", "ok", "controller reachable")

	proxyClient, err := provider.NewClient(provider.ClientOptions{ProxyURL: config.LocalMihomoProxyURL(), Timeout: opts.Timeout})
	if err != nil {
		rep.addLayer("download", "fail", "build proxy client: "+err.Error())
		return
	}
	rep.Download = timedProbe(ctx, opts.Timeout, proxyClient, fmt.Sprintf(speedDownURL, opts.Bytes), false, 0)
	rep.addLayer("download", throughputStatus(rep.Download), throughputDetail("download via proxy", rep.Download))

	rep.Upload = timedProbe(ctx, opts.Timeout, proxyClient, speedUpURL, true, opts.Bytes/2)
	rep.addLayer("upload", throughputStatus(rep.Upload), throughputDetail("upload via proxy", rep.Upload))

	// foreign-direct is informational (censorship signal), never a fault — so
	// it gets a short fixed timeout (it rides the throttled direct path and
	// would otherwise sit at opts.Timeout, dominating the run's wall-clock).
	rep.ForeignDirect = timedProbe(ctx, foreignDirectTimeout, mustDirect(foreignDirectTimeout), fmt.Sprintf(speedDownURL, 256<<10), false, 0)

	// routing wired (structural): table present + the probe domain's section set
	// actually got populated by dnsmasq.
	rep.checkRouting(c, opts.Domain)

	if opts.PerNode {
		rep.Nodes = perNodeProbe(ctx, cli, opts)
	}
}

// netCheckNoProxy handles zapret-only / direct boxes: skip proxy layers (N/A),
// surface DPI-bypass efficacy via the existing blocking heuristics.
func (m Manager) netCheckNoProxy(ctx context.Context, rep *NetCheckReport) {
	rep.addLayer("proxy", "na", "no proxy section configured")
	bctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	br := checker.BlockingReportRun(bctx, nil, nil)
	rep.Blocking = &br
	switch br.Verdict {
	case "no_blocking_detected":
		rep.addLayer("zapret", "ok", br.Reason)
	case "inconclusive":
		rep.addLayer("zapret", "warn", br.Reason)
	default: // blocked_zone_*
		rep.addLayer("zapret", "fail", br.Reason)
	}
}

func (rep *NetCheckReport) checkRouting(c config.Config, domain string) {
	if _, err := (system.Runner{}).Run("nft", "list", "table", "inet", "purewrt"); err != nil {
		rep.addLayer("routing", "fail", "nft table inet purewrt absent: "+err.Error())
		return
	}
	match := checker.MatchRuleProviders(c, domain)
	if !match.Matched || match.Action != "proxy" {
		rep.addLayer("routing", "ok", "table present (probe domain is catch-all, no per-domain set)")
		return
	}
	sec, ok := sectionByName(c, match.Section)
	if !ok {
		rep.addLayer("routing", "ok", "table present")
		return
	}
	ip := firstIP(rep.DNS)
	if ip == "" {
		rep.addLayer("routing", "warn", "no resolved IP to check set membership")
		return
	}
	set := "dns_" + sec.NFTSet4()
	if in, _ := checker.NFTSetContains(set, ip); in {
		rep.addLayer("routing", "ok", fmt.Sprintf("%s ∈ @%s (section %s wired)", ip, set, sec.Name))
	} else {
		rep.addLayer("routing", "fail", fmt.Sprintf("%s NOT in @%s — dnsmasq not populating section %s", ip, set, sec.Name))
	}
}

// perNodeProbe selects each member of NetCheckProbe in turn and measures real
// throughput through the loopback probe listener, restoring the prior
// selection afterwards. Isolated from live routing.
func perNodeProbe(ctx context.Context, cli mihomoapi.Client, opts NetCheckOpts) []NodeResult {
	proxies, err := cli.Proxies()
	if err != nil {
		return nil
	}
	grp, ok := proxies[netCheckProbeGroup]
	if !ok {
		return nil
	}
	prior := grp.Now
	probeClient, err := provider.NewClient(provider.ClientOptions{ProxyURL: fmt.Sprintf("http://127.0.0.1:%d", config.DefaultNetCheckProbePort), Timeout: opts.Timeout})
	if err != nil {
		return nil
	}
	// small per-node payload to bound the total run.
	nbytes := int64(2 << 20)
	out := []NodeResult{}
	for _, node := range grp.All {
		if err := cli.SelectProxy(netCheckProbeGroup, node); err != nil {
			out = append(out, NodeResult{Node: node, Verdict: "fail"})
			continue
		}
		time.Sleep(150 * time.Millisecond) // let the selection take effect
		down := timedProbe(ctx, opts.Timeout, probeClient, fmt.Sprintf(speedDownURL, nbytes), false, 0)
		up := timedProbe(ctx, opts.Timeout, probeClient, speedUpURL, true, nbytes/4)
		nr := NodeResult{Node: node, DownKbps: down.Kbps, UpKbps: up.Kbps, DelayMS: proxyDelayFor(proxies, node)}
		switch {
		case !down.OK && !up.OK:
			nr.Verdict = "fail"
		case down.Kbps < throttledKbps:
			nr.Verdict = "throttled"
		default:
			nr.Verdict = "ok"
		}
		out = append(out, nr)
	}
	if prior != "" {
		_ = cli.SelectProxy(netCheckProbeGroup, prior)
	}
	return out
}

// ---- verdict synthesis ----

func (rep *NetCheckReport) synthesize() {
	switch rep.Mode {
	case "proxy", "vpn_only":
		switch {
		case rep.layer("mihomo") == "fail":
			rep.set("broken", "mihomo", "mihomo controller unreachable — the proxy daemon is down or its address/secret changed.")
		case rep.Download.OK && rep.Upload.OK && rep.Download.Kbps >= slowKbps:
			rep.set("ok", "", okDiagnosis(rep))
		case !rep.Download.OK && rep.DirectDomestic.OK:
			rep.set("broken", "download", "Nodes answer probes but can't carry data — proxy transport throttled/broken (WAN is up). Try --per-node to find the bad node, or check the node's transport/DPI.")
		case !rep.Download.OK && !rep.DirectDomestic.OK:
			rep.set("broken", "wan", "Both proxy and direct domestic failed — WAN/internet is down (not a purewrt fault).")
		case rep.Download.OK && rep.Download.Kbps < slowKbps:
			rep.set("degraded", "download", fmt.Sprintf("Proxy works but download is slow (%.0f kbps < %d). Likely a throttled node — run --per-node.", rep.Download.Kbps, slowKbps))
		case !rep.Upload.OK:
			rep.set("degraded", "upload", "Download works but upload failed — asymmetric transport issue on the node.")
		case rep.layer("routing") == "fail":
			rep.set("degraded", "routing", "Proxy carries data but the routing chain isn't wired — dnsmasq isn't populating the section nftset (clients won't be TPROXY'd).")
		case rep.layer("dns") == "fail":
			rep.set("degraded", "dns", "Proxy works but DNS resolution failed.")
		default:
			rep.set("ok", "", okDiagnosis(rep))
		}
	case "zapret_only", "direct":
		switch {
		case !rep.DirectDomestic.OK:
			rep.set("broken", "wan", "Domestic direct is unreachable — WAN/internet is down.")
		case rep.layer("zapret") == "fail":
			rep.set("degraded", "zapret", "Censored targets still blocked on direct — zapret isn't defeating DPI. Run `purewrt zapret-check <domain>` or `zapret-autotune` to find a working strategy.")
		case rep.layer("zapret") == "warn":
			rep.set("degraded", "zapret", "Blocking check inconclusive (baseline degraded) — re-run when the network is stable.")
		default:
			rep.set("ok", "", "WAN up and no censorship signal on the tested targets.")
		}
	default:
		rep.set("ok", "", "no egress topology detected")
	}
}

func okDiagnosis(rep *NetCheckReport) string {
	fd := "n/a"
	if rep.ForeignDirect.Bytes > 0 || rep.ForeignDirect.Error != "" {
		if rep.ForeignDirect.OK && rep.ForeignDirect.Kbps >= slowKbps {
			fd = "fast (uncensored env)"
		} else {
			fd = "throttled (proxy is bypassing censorship — expected)"
		}
	}
	return fmt.Sprintf("Healthy: proxy down %.0f / up %.0f kbps; direct-foreign %s.", rep.Download.Kbps, rep.Upload.Kbps, fd)
}

func (rep *NetCheckReport) recordMetrics() {
	metrics.NetCheckDownloadKbps.Set(rep.Download.Kbps)
	metrics.NetCheckUploadKbps.Set(rep.Upload.Kbps)
	metrics.NetCheckDirectDomesticKbps.Set(rep.DirectDomestic.Kbps)
	if rep.Verdict == "ok" {
		metrics.NetCheckVerdict.Set(1)
	} else {
		metrics.NetCheckVerdict.Set(0)
	}
	metrics.NetCheckLastRun.Set(float64(time.Now().Unix()))
	for _, l := range rep.Layers {
		metrics.NetCheckLayerTotal.WithLabelValues(l.Name, l.Status)
	}
	for _, n := range rep.Nodes {
		metrics.NetCheckNodeTotal.WithLabelValues(slugify(n.Node), n.Verdict)
	}
}

// ---- FormatNetCheck (human CLI output) ----

func FormatNetCheck(r NetCheckReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "net-check [mode=%s] verdict=%s\n", r.Mode, strings.ToUpper(r.Verdict))
	if r.Diagnosis != "" {
		fmt.Fprintf(&b, "  → %s\n", r.Diagnosis)
	}
	b.WriteString("Layers:\n")
	for _, l := range r.Layers {
		mark := map[string]string{"ok": "✓", "fail": "✗", "warn": "!", "na": "·"}[l.Status]
		fmt.Fprintf(&b, "  %s %-9s %s\n", mark, l.Name, l.Detail)
	}
	if len(r.Nodes) > 0 {
		b.WriteString("Per-node throughput (worst first):\n")
		sortNodesByThroughput(r.Nodes)
		for _, n := range r.Nodes {
			fmt.Fprintf(&b, "  %-9s down=%-8.0f up=%-8.0f kbps  delay=%dms  %s\n", n.Verdict, n.DownKbps, n.UpKbps, n.DelayMS, n.Node)
		}
	}
	if len(r.Warnings) > 0 {
		b.WriteString("Config warnings:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  ! %s\n", w)
		}
	}
	return b.String()
}

// ---- helpers ----

func (rep *NetCheckReport) addLayer(name, status, detail string) {
	rep.Layers = append(rep.Layers, LayerResult{Name: name, Status: status, Detail: detail})
}

func (rep *NetCheckReport) layer(name string) string {
	for _, l := range rep.Layers {
		if l.Name == name {
			return l.Status
		}
	}
	return ""
}

func (rep *NetCheckReport) set(verdict, broken, diag string) {
	rep.Verdict, rep.BrokenLayer, rep.Diagnosis = verdict, broken, diag
}

func throughputStatus(t checker.ThroughputResult) string {
	switch {
	case !t.OK:
		return "fail"
	case t.Kbps < slowKbps:
		return "warn"
	default:
		return "ok"
	}
}

func throughputDetail(label string, t checker.ThroughputResult) string {
	if !t.OK {
		e := t.Error
		if e == "" {
			e = fmt.Sprintf("http %d", t.HTTPStatus)
		}
		return fmt.Sprintf("%s failed (%.0f kbps, %d B in %.1fs): %s", label, t.Kbps, t.Bytes, t.Seconds, e)
	}
	return fmt.Sprintf("%s %.0f kbps (%d B in %.1fs)", label, t.Kbps, t.Bytes, t.Seconds)
}

func detectMode(c config.Config) string {
	proxySec, zapretSec, vpnMembers := false, false, false
	for _, s := range c.Sections {
		if !s.Enabled {
			continue
		}
		switch s.Action {
		case "proxy":
			proxySec = true
			if len(s.VPNs) > 0 {
				vpnMembers = true
			}
		case "zapret":
			zapretSec = true
		}
	}
	if len(c.EnabledZapretProfiles()) > 0 {
		zapretSec = true
	}
	if proxySec {
		if !hasEnabledProxyProviders(c) && vpnMembers {
			return "vpn_only"
		}
		return "proxy"
	}
	if zapretSec {
		return "zapret_only"
	}
	return "direct"
}

func localControllerAddr(c config.Config) string {
	base := c.Settings.ExternalController
	switch {
	case base == "":
		return "127.0.0.1:9090"
	case strings.HasPrefix(base, "0.0.0.0:"):
		return "127.0.0.1:" + strings.TrimPrefix(base, "0.0.0.0:")
	case strings.HasPrefix(base, "[::]:"):
		return "127.0.0.1:" + strings.TrimPrefix(base, "[::]:")
	default:
		return base
	}
}

func sectionByName(c config.Config, name string) (config.Section, bool) {
	for _, s := range c.Sections {
		if s.Name == name || s.ProxyGroup == name {
			return s, true
		}
	}
	return config.Section{}, false
}

func firstIP(d checker.DNSResult) string {
	if len(d.A) > 0 {
		return d.A[0]
	}
	if len(d.AAAA) > 0 {
		return d.AAAA[0]
	}
	return ""
}

func proxyDelayFor(proxies map[string]mihomoapi.Proxy, node string) int {
	px, ok := proxies[node]
	if !ok {
		return 0
	}
	if px.Delay > 0 {
		return px.Delay
	}
	if n := len(px.History); n > 0 {
		return px.History[n-1].Delay
	}
	return 0
}

// timedProbe runs one throughput probe under its own timeout, cancelling
// cleanly so go vet's lostcancel check stays happy.
func timedProbe(parent context.Context, d time.Duration, client *http.Client, url string, up bool, n int64) checker.ThroughputResult {
	ctx, cancel := context.WithTimeout(parent, d)
	defer cancel()
	return checker.ThroughputProbe(ctx, client, url, up, n)
}

func mustDirect(timeout time.Duration) *http.Client {
	cl, _ := provider.NewClient(provider.ClientOptions{Timeout: timeout})
	return cl
}

// slugify makes a node name scrape-safe for a prometheus label: lowercase,
// emoji/space/punct → '_', collapsed. Node names carry flags + spaces.
func slugify(s string) string {
	var b strings.Builder
	prevUnderscore := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
			prevUnderscore = false
		} else if !prevUnderscore {
			b.WriteByte('_')
			prevUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "node"
	}
	return strings.ToLower(out)
}

// sortNodesByThroughput is used by callers/tests that want a deterministic
// worst-first ordering for display.
func sortNodesByThroughput(ns []NodeResult) {
	sort.SliceStable(ns, func(i, j int) bool { return ns[i].DownKbps < ns[j].DownKbps })
}
