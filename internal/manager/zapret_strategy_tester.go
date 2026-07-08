package manager

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/system"
)

// zapretTestTable is the throwaway nft table the strategy tester creates and
// deletes wholesale on cleanup. zapretTestMark is the fwmark nfqws2 stamps on
// its reinjected fakes (so they're excluded from the queue — no re-queue loop).
// 0x10000000 is the TEST-instance mark (same as blockcheck2's nfqws): the rpcd
// zapret_check_stop kill matches `fwmark=0x10000000` and deliberately spares
// production instances (profile default 0x40000000), so an orphaned tester
// daemon stays killable. Don't switch this to the production mark.
const (
	zapretTestTable = "purewrt_zapret_test"
	zapretTestMark  = "0x10000000"
	zapretTestQNum  = 9909
)

// DefaultZapretTestSites is the canary list used when the served suite
// (config.LoadZapretTestSites) is empty and the caller gives none.
var DefaultZapretTestSites = []string{"redirector.googlevideo.com", "telegram.org", "discord.com", "www.speedtest.net"}

// Test seams (same idea as Manager.mihomoReachable): the defaults are the real
// implementations; tests swap them to drive resolve/probe/spawn/firewall
// outcomes without a live router. zapretBindDelay exists so tests don't pay
// the 1s queue-bind wait.
var (
	zapretResolveHostFn = zapretResolveHost
	zapretProbeSitesFn  = zapretProbeSites
	zapretStartCmd      = func(cmd *exec.Cmd) error { return cmd.Start() }
	zapretFindNFQWS     = Manager.zapretNFQWSBin
	zapretResolveBlobFn = Manager.ResolveBlob
	zapretNewRunner     = func(m Manager) commandRunner {
		return system.Runner{DryRun: m.DryRun, Timeout: 10 * time.Second}
	}
	zapretBindDelay = 1 * time.Second
)

// ZapretStrategyTestOptions drives one strategy probe.
type ZapretStrategyTestOptions struct {
	CmdOpts   string                 // nfqws2 strategy args (validated shell-safe)
	Interface string                 // WAN device to bind probes to
	Sites     []string               // default = served suite, else DefaultZapretTestSites
	Blobs     []config.ZapretBlobRef // resolved to --blob= decls
	Timeout   time.Duration          // whole-run watchdog; 0 -> 60s
	// Download switches the verdict signal from "TLS handshake completed"
	// (time_appconnect>0, fast, default) to "bytes actually flowed" — a small
	// ranged download with a speed floor. Catches strategies that pass the
	// handshake but get throttled or RST afterwards (what Zapret-Manager's
	// download-probe detects), at the cost of a slower probe.
	Download bool
}

type ZapretSiteResult struct {
	Site         string `json:"site"`
	IP           string `json:"ip"`
	Baseline     string `json:"baseline"`      // ok | fail
	WithStrategy string `json:"with_strategy"` // ok | fail
	Verdict       string `json:"verdict"`       // fixed | already-ok | still-blocked | unresolved
	AppconnectMs  int    `json:"appconnect_ms"`
	DownloadBytes int    `json:"download_bytes"` // bytes pulled in download-probe mode (0 in handshake mode)
}

type ZapretStrategyTestResult struct {
	Strategy string             `json:"strategy"`
	Sites    []ZapretSiteResult `json:"sites"`
	Passed   int                `json:"passed"` // sites that ended ok WITH the strategy
	Fixed    int                `json:"fixed"`  // sites the strategy unblocked
	Total    int                `json:"total"`
}

// ZapretStrategyTest loads nfqws2 with one strategy, routes the test sites'
// (direct-forced) traffic through it, and reports per-site verdicts by whether
// the TLS handshake completes (curl time_appconnect > 0). All firewall/daemon
// state is torn down on every exit path.
func (m Manager) ZapretStrategyTest(opt ZapretStrategyTestOptions) (ZapretStrategyTestResult, error) {
	res := ZapretStrategyTestResult{Strategy: strings.TrimSpace(opt.CmdOpts)}
	cmdOpts := strings.Fields(strings.TrimSpace(opt.CmdOpts))
	if len(cmdOpts) == 0 {
		return res, fmt.Errorf("strategy cmd_opts is required")
	}
	if bad := strings.ContainsAny(opt.CmdOpts, ";&|`$()<>\"'\n\r"); bad {
		return res, fmt.Errorf("cmd_opts contains unsupported characters")
	}
	iface := strings.TrimSpace(opt.Interface)
	if iface != "" && strings.ContainsAny(iface, " \t;&|`$()<>\"'\n\r") {
		return res, fmt.Errorf("interface contains unsupported characters")
	}
	sites := opt.Sites
	if len(sites) == 0 {
		sites = config.LoadZapretTestSites()
	}
	if len(sites) == 0 {
		sites = DefaultZapretTestSites
	}
	nfqws := zapretFindNFQWS(m)
	if nfqws == "" {
		return res, fmt.Errorf("nfqws2 binary not found")
	}

	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Resolve sites up front (before touching the firewall).
	type siteIP struct{ site, ip string }
	var resolved []siteIP
	var siteHosts, siteIPs, v4, v6 []string
	for _, s := range sites {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ips, err := zapretResolveHostFn(s)
		if err != nil || len(ips) == 0 {
			res.Sites = append(res.Sites, ZapretSiteResult{Site: s, Verdict: "unresolved"})
			res.Total++
			continue
		}
		ip := ips[0]
		resolved = append(resolved, siteIP{s, ip})
		siteHosts = append(siteHosts, s)
		siteIPs = append(siteIPs, ip)
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	if len(resolved) == 0 {
		return res, nil
	}

	r := zapretNewRunner(m)

	// Baseline: direct curl each site (control), before any desync. Probes are
	// independent curls (no shared firewall state) → run concurrently.
	baseProbe := zapretProbeSitesFn(ctx, iface, siteHosts, siteIPs, opt.Download)
	baseline := map[string]bool{}
	for i, si := range resolved {
		baseline[si.site] = zapretProbeOK(baseProbe[i].ms, baseProbe[i].bytes, opt.Download)
	}

	// Force direct: add site IPs to the bypass sets (skips output_mangle proxy
	// mark). Guaranteed removal.
	var added []string
	for _, si := range resolved {
		if cmd := zapretCheckBypassAddCommand(si.ip); len(cmd) > 0 {
			if _, err := r.Run(cmd[0], cmd[1:]...); err == nil {
				added = append(added, si.ip)
			}
		}
	}
	defer func() {
		for _, ip := range added {
			if cmd := zapretCheckBypassDeleteCommand(ip); len(cmd) > 0 {
				_, _ = r.Run(cmd[0], cmd[1:]...)
			}
		}
	}()

	// Temp nft table: postrouting queues the handshake packets (excluding
	// nfqws's reinjected fakes); output notracks reinjected packets. Deleted
	// wholesale on cleanup.
	udp := strings.Contains(opt.CmdOpts, "--filter-udp")
	if err := m.zapretTestSetupNFT(r, v4, v6, udp); err != nil {
		_, _ = r.Run("nft", "delete", "table", "inet", zapretTestTable)
		return res, err
	}
	defer func() { _, _ = r.Run("nft", "delete", "table", "inet", zapretTestTable) }()

	// Resolve blobs → --blob= decls.
	var blobArgs []string
	for _, b := range opt.Blobs {
		path, err := zapretResolveBlobFn(m, b.File, b.SHA256)
		if err != nil {
			return res, fmt.Errorf("resolve blob %s: %w", b.File, err)
		}
		blobArgs = append(blobArgs, "--blob="+b.Name+":@"+path)
	}

	// Launch nfqws2 on the test queue.
	args := []string{
		"--qnum=" + strconv.Itoa(zapretTestQNum),
		"--user=daemon",
		"--fwmark=" + zapretTestMark,
	}
	args = append(args, m.zapretLuaInitArgs()...)
	args = append(args, blobArgs...)
	args = append(args, cmdOpts...)
	nfq := exec.CommandContext(ctx, nfqws, args...)
	if err := zapretStartCmd(nfq); err != nil {
		return res, fmt.Errorf("start nfqws2: %w", err)
	}
	defer func() {
		if nfq.Process != nil {
			_ = nfq.Process.Kill()
			_, _ = nfq.Process.Wait()
		}
	}()
	time.Sleep(zapretBindDelay) // let nfqws bind the queue

	// Probe each site through the desync (concurrently), then aggregate in order.
	probe := zapretProbeSitesFn(ctx, iface, siteHosts, siteIPs, opt.Download)
	for i, si := range resolved {
		ms, bytes := probe[i].ms, probe[i].bytes
		ok := zapretProbeOK(ms, bytes, opt.Download)
		sr := ZapretSiteResult{Site: si.site, IP: si.ip, AppconnectMs: int(ms * 1000), DownloadBytes: bytes}
		sr.Baseline = boolOK(baseline[si.site])
		sr.WithStrategy = boolOK(ok)
		var passed, fixed bool
		sr.Verdict, passed, fixed = zapretVerdict(baseline[si.site], ok)
		if passed {
			res.Passed++
		}
		if fixed {
			res.Fixed++
		}
		res.Sites = append(res.Sites, sr)
		res.Total++
	}
	return res, nil
}

// ZapretStrategySweepStream tests each candidate in the shared list (optionally
// filtered by ISP and/or service, or narrowed to a single candidate by name)
// and invokes emit with each result AS it completes, so a backgrounded caller
// can surface incremental progress instead of waiting for the whole sweep. When
// name is non-empty only that candidate runs — this is how the LuCI "Test
// selected" button reuses the sweep's bg-job path instead of a synchronous rpc
// call (which times out the XHR on a full nfqws probe). Results are unsorted
// (completion order); rank at display.
func (m Manager) ZapretStrategySweepStream(iface string, sites []string, isp, service, name string, download bool, emit func(ZapretStrategyTestResult)) {
	list := config.LoadZapretCandidates()
	for _, c := range zapretSelectCandidates(list.Candidates, isp, service) {
		if name != "" && c.Name != name {
			continue
		}
		res, _ := m.ZapretStrategyTest(ZapretStrategyTestOptions{
			CmdOpts: c.Params, Interface: iface, Sites: sites, Blobs: c.Blobs, Download: download,
		})
		res.Strategy = c.Name // rank/display by candidate name, not raw args (kept even on error → 0 passed)
		emit(res)
	}
}

// ZapretStrategySweep tests every candidate in the shared list against the
// sites and returns results ranked by sites-fixed (then sites-passed). isp and
// service filter the candidate set (empty = no filter on that axis); service
// uses wildcard semantics (generic candidates always included). name, when set,
// narrows to a single candidate.
// Long-running (each candidate is a full probe) — callers background it.
func (m Manager) ZapretStrategySweep(iface string, sites []string, isp, service, name string, download bool) []ZapretStrategyTestResult {
	var out []ZapretStrategyTestResult
	m.ZapretStrategySweepStream(iface, sites, isp, service, name, download, func(res ZapretStrategyTestResult) {
		out = append(out, res)
	})
	rankStrategyResults(out)
	return out
}

// zapretSelectCandidates returns the candidates to sweep, filtered on two
// orthogonal axes combined with AND: ISP (exact match; empty = any) and service
// (empty = any). Service uses wildcard semantics via serviceMatches so a
// generic/untagged strategy still surfaces in a service-scoped sweep.
func zapretSelectCandidates(cands []config.ZapretCandidate, isp, service string) []config.ZapretCandidate {
	var out []config.ZapretCandidate
	for _, c := range cands {
		if isp != "" && c.ISP != isp {
			continue
		}
		if service != "" && !serviceMatches(c.Service, service) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// serviceMatches reports whether a candidate tagged candService should be
// included when the sweep is scoped to want. Generic/untagged candidates are
// wildcards (included in every service-scoped sweep); otherwise exact match.
func serviceMatches(candService, want string) bool {
	if candService == "" || candService == "generic" {
		return true
	}
	return candService == want
}

// rankStrategyResults sorts sweep results in place, best first: most sites
// unblocked (Fixed), then most sites passing overall (Passed). Stable so equal
// results keep candidate-list order.
func rankStrategyResults(out []ZapretStrategyTestResult) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Fixed != out[j].Fixed {
			return out[i].Fixed > out[j].Fixed
		}
		return out[i].Passed > out[j].Passed
	})
}

// zapretVerdict classifies one site's outcome from its baseline (direct, no
// desync) and with-strategy probe results, and reports whether the site counts
// toward Passed (ok with the strategy) and Fixed (the strategy unblocked a site
// the baseline could not reach).
func zapretVerdict(baselineOK, strategyOK bool) (verdict string, passed, fixed bool) {
	switch {
	case strategyOK && !baselineOK:
		return "fixed", true, true
	case strategyOK:
		return "already-ok", true, false
	default:
		return "still-blocked", false, false
	}
}

// zapretTestSetupNFT builds the throwaway queue table.
func (m Manager) zapretTestSetupNFT(r commandRunner, v4, v6 []string, udp bool) error {
	steps := [][]string{
		{"nft", "add", "table", "inet", zapretTestTable},
		{"nft", "add", "chain", "inet", zapretTestTable, "post", "{", "type", "filter", "hook", "postrouting", "priority", "mangle", ";", "policy", "accept", ";", "}"},
		{"nft", "add", "chain", "inet", zapretTestTable, "out", "{", "type", "filter", "hook", "output", "priority", "mangle", ";", "policy", "accept", ";", "}"},
		{"nft", "add", "rule", "inet", zapretTestTable, "out", "meta", "mark", "and", zapretTestMark, "!=", "0", "notrack"},
	}
	for _, s := range steps {
		if _, err := r.Run(s[0], s[1:]...); err != nil {
			return fmt.Errorf("nft setup: %w", err)
		}
	}
	add := func(fam, set string) error {
		for _, proto := range protoList(udp) {
			rule := fmt.Sprintf("meta mark and %s == 0 %s daddr { %s } meta l4proto %s %s dport 443 ct original packets 1-12 queue num %d bypass",
				zapretTestMark, fam, set, proto, proto, zapretTestQNum)
			if _, err := r.Run("nft", append([]string{"add", "rule", "inet", zapretTestTable, "post"}, strings.Fields(rule)...)...); err != nil {
				return fmt.Errorf("nft queue rule: %w", err)
			}
		}
		return nil
	}
	if len(v4) > 0 {
		if err := add("ip", strings.Join(v4, ", ")); err != nil {
			return err
		}
	}
	if len(v6) > 0 {
		if err := add("ip6", strings.Join(v6, ", ")); err != nil {
			return err
		}
	}
	return nil
}

func protoList(udp bool) []string {
	if udp {
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

// zapretProbeMax bounds concurrent curl probes (matches Zapret-Manager's
// PARALLEL=8) so a large site list doesn't fork hundreds of curls at once.
const zapretProbeMax = 8

type zapretProbeVal struct {
	ms    float64
	bytes int
}

// zapretProbeSites probes hosts[i]/ips[i] concurrently (bounded by
// zapretProbeMax) and returns results index-aligned to the input. Probes are
// independent curls with no shared firewall state, so parallelism is safe and
// cuts a many-site test from N sequential curls to ~ceil(N/8) rounds.
func zapretProbeSites(ctx context.Context, iface string, hosts, ips []string, download bool) []zapretProbeVal {
	out := make([]zapretProbeVal, len(hosts))
	sem := make(chan struct{}, zapretProbeMax)
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			ms, bytes := zapretProbe(ctx, iface, hosts[i], ips[i], download)
			out[i] = zapretProbeVal{ms: ms, bytes: bytes}
		}(i)
	}
	wg.Wait()
	return out
}

// zapretProbe curls one site through the (already-set-up) test path and returns
// curl's time_appconnect (seconds; >0 == TLS handshake completed) and the bytes
// downloaded. Handshake mode issues a HEAD so it stops right after the TLS
// handshake (fast, no body → download_bytes 0); download mode pulls a 64 KiB
// range with a speed floor (--speed-limit/--speed-time) so a throttled/
// RST-after-handshake connection reports 0 bytes — the signal Zapret-Manager
// uses to catch post-handshake blocking.
func zapretProbe(ctx context.Context, iface, host, ip string, download bool) (float64, int) {
	args := []string{"-s", "-o", "/dev/null", "-w", "%{time_appconnect} %{size_download}",
		"--resolve", host + ":443:" + ip, "--connect-timeout", "4", "-A", "Mozilla"}
	if download {
		args = append(args, "-L", "--range", "0-65535",
			"--max-time", "12", "--speed-time", "3", "--speed-limit", "1")
	} else {
		args = append(args, "-I", "--max-time", "10")
	}
	if iface != "" {
		args = append(args, "--interface", iface)
	}
	args = append(args, "https://"+host)
	out, _ := exec.CommandContext(ctx, "curl", args...).Output()
	fields := strings.Fields(strings.TrimSpace(string(out)))
	var ms float64
	var bytes int
	if len(fields) >= 1 {
		ms, _ = strconv.ParseFloat(fields[0], 64)
	}
	if len(fields) >= 2 {
		if b, err := strconv.ParseFloat(fields[1], 64); err == nil {
			bytes = int(b)
		}
	}
	return ms, bytes
}

// zapretProbeOK decides success from a probe: bytes-flowed in download mode,
// TLS-handshake-completed otherwise.
func zapretProbeOK(ms float64, bytes int, download bool) bool {
	if download {
		return bytes > 0
	}
	return ms > 0
}

func (m Manager) zapretNFQWSBin() string {
	c, _ := m.Load()
	if bin := firstZapretNFQWSBin(c); bin != "" {
		return bin
	}
	return firstExisting([]string{
		"/usr/libexec/zapret/nfq2/nfqws2",
		"/usr/libexec/zapret/nfqws2",
		"/opt/zapret2/nfqws2",
	})
}

func (m Manager) zapretLuaInitArgs() []string {
	c, _ := m.Load()
	dir := "/usr/libexec/zapret/lua"
	for _, p := range c.EnabledZapretProfiles() {
		if p.LuaBundleDir != "" {
			dir = p.LuaBundleDir
			break
		}
	}
	var out []string
	for _, s := range []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"} {
		out = append(out, "--lua-init=@"+filepath.Join(dir, s))
	}
	return out
}

// zapretResolveHost resolves a hostname to IP strings (v4 first) via the system
// resolver (dnsmasq → mihomo), matching the client path.
func zapretResolveHost(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var v4, v6 []string
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	return append(v4, v6...), nil
}

func boolOK(b bool) string {
	if b {
		return "ok"
	}
	return "fail"
}
