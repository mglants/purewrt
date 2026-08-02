package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/checker"
	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/mihomoapi"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/proxyguard"
	"github.com/purewrt/purewrt/internal/system"
)

const (
	proxyGuardLatencyURL = "https://cp.cloudflare.com/generate_204"
	proxyGuardSpeedURL   = "https://speed.cloudflare.com/__down?bytes=%d"
	proxyGuardMaxProbes  = 3
	proxyGuardProbeTTL   = time.Hour
	proxyGuardSpeedTier  = 1000 // kbps; stability decides among roughly equal-speed nodes
)

type ProxyGuardOptions struct {
	DryRun bool
}

type ProxyGuardTransition struct {
	Node   string `json:"node"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason,omitempty"`
}

type ProxyGuardReport struct {
	Enabled      bool                   `json:"enabled"`
	DryRun       bool                   `json:"dry_run,omitempty"`
	Skipped      bool                   `json:"skipped,omitempty"`
	Message      string                 `json:"message,omitempty"`
	Probes       int                    `json:"probes"`
	ProbeBytes   int64                  `json:"probe_bytes"`
	Transitions  []ProxyGuardTransition `json:"transitions,omitempty"`
	State        proxyguard.State       `json:"state"`
	UserExcludes map[string]string      `json:"user_excludes,omitempty"`
}

func FormatProxyGuard(rep ProxyGuardReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "proxy-guard enabled=%t probes=%d bytes=%d", rep.Enabled, rep.Probes, rep.ProbeBytes)
	if rep.DryRun {
		b.WriteString(" dry-run")
	}
	if rep.Skipped {
		b.WriteString(" skipped")
	}
	b.WriteByte('\n')
	if rep.Message != "" {
		fmt.Fprintf(&b, "  %s\n", rep.Message)
	}
	for _, tr := range rep.Transitions {
		fmt.Fprintf(&b, "  %s: %s -> %s", tr.Node, tr.From, tr.To)
		if tr.Reason != "" {
			fmt.Fprintf(&b, " (%s)", tr.Reason)
		}
		b.WriteByte('\n')
	}
	names := sortedNodeNames(rep.State.Nodes)
	for _, name := range names {
		n := rep.State.Nodes[name]
		if n == nil {
			continue
		}
		down := "not tested"
		if !n.LastProbe.IsZero() {
			down = fmt.Sprintf("%.0f", n.LastDownKbps)
		}
		fmt.Fprintf(&b, "  %-11s down=%-10s delay=%-5d jitter=%-5d %s\n", n.State, down, n.LastDelayMS, n.JitterMS, name)
	}
	return b.String()
}

// ProxyGuardStatus is read-only and remains useful while disabled: LuCI can
// show the last runtime state until reset/reboot.
func (m Manager) ProxyGuardStatus() ProxyGuardReport {
	c, err := m.Load()
	if err != nil {
		return ProxyGuardReport{Message: err.Error(), State: proxyguard.NewState()}
	}
	s, err := proxyguard.Load(c)
	if err != nil {
		return ProxyGuardReport{Enabled: c.Settings.ProxyGuardEnabled, Message: err.Error(), State: proxyguard.NewState(), UserExcludes: proxyGuardUserExcludes(c)}
	}
	return ProxyGuardReport{Enabled: c.Settings.ProxyGuardEnabled, State: s, UserExcludes: proxyGuardUserExcludes(c)}
}

func (m Manager) ProxyGuardRun(ctx context.Context, opts ProxyGuardOptions) (rep ProxyGuardReport, retErr error) {
	started := time.Now()
	c, err := m.Load()
	if err != nil {
		return ProxyGuardReport{}, err
	}
	rep = ProxyGuardReport{Enabled: c.Settings.ProxyGuardEnabled, DryRun: opts.DryRun, UserExcludes: proxyGuardUserExcludes(c)}
	if !c.Settings.ProxyGuardEnabled {
		rep.Message = "proxy guard is disabled"
		rep.State = proxyguard.NewState()
		return rep, nil
	}
	if !opts.DryRun {
		defer func() {
			recordProxyGuardRunOutcome(rep, retErr, started)
			dumpMetrics(c)
		}()
	}
	lock, err := system.TryAcquire(proxyguard.ProbeLockPath(c))
	if err != nil {
		if errors.Is(err, system.ErrLockBusy) {
			rep.Skipped = true
			rep.Message = "another per-node probe is running"
			rep.State, _ = proxyguard.Load(c)
			return rep, nil
		}
		return rep, err
	}
	defer func() { _ = lock.Close() }()

	_, statErr := os.Stat(proxyguard.Path(c))
	forceRoutingApply := errors.Is(statErr, os.ErrNotExist)
	state, err := proxyguard.Load(c)
	if err != nil {
		// A corrupt runtime file must not strand nodes in a stale quarantine.
		state = proxyguard.NewState()
		forceRoutingApply = true
		rep.Message = "invalid prior runtime state ignored: " + err.Error()
	}
	beforeSig := state.RoutingSignature()
	now := time.Now().UTC()
	cli := mihomoapi.Client{Base: localControllerAddr(c), Secret: c.Settings.Secret}
	proxies, err := cli.Proxies()
	if err != nil {
		return rep, fmt.Errorf("proxy guard: mihomo controller: %w", err)
	}

	memberSet := updateGuardGroups(c, proxies, &state)
	updateGuardNodes(proxies, memberSet, now, &state)
	delays, delayErr := cli.GroupDelayTest(netCheckProbeGroup, proxyGuardLatencyURL, 5000)
	if delayErr == nil {
		updateGuardLatency(proxies, memberSet, delays, c.Settings.ProxyGuardMaxJitterMS, now, &state)
	} else {
		if rep.Message == "" {
			// A controller/endpoint-wide failure is not evidence against every
			// member. Keep prior samples and let real-transfer checks continue.
			rep.Message = "latency sweep failed; prior latency samples retained: " + delayErr.Error()
		}
	}

	active := guardActiveNodes(proxies, state, cli)
	session := newGuardProbeSession(cli, proxies)
	defer session.restore()
	probed := make(map[string]bool)
	probe := func(name string) (checker.ThroughputResult, bool) {
		if rep.Probes >= proxyGuardMaxProbes {
			return checker.ThroughputResult{}, false
		}
		result, err := session.download(ctx, name, int64(c.Settings.ProxyGuardProbeBytes))
		probed[name] = true
		rep.Probes++
		rep.ProbeBytes += result.Bytes
		if err != nil && result.Error == "" {
			result.Error = err.Error()
		}
		return result, true
	}

	fleetInterval := time.Duration(c.Settings.ProxyGuardFleetProbeInterval) * time.Second
	if fleetInterval < 5*time.Minute {
		fleetInterval = 6 * time.Hour
	}
	urgentLimit := proxyGuardMaxProbes
	if len(rollingProbeCandidates(state, now, fleetInterval, probed)) > 0 {
		// Guarantee at least one fleet slot. Without this reservation a busy
		// load-balance pool can consume every tick and inactive members remain
		// unmeasured forever.
		urgentLimit--
	}
	urgentProbe := func(name string) (checker.ThroughputResult, bool) {
		if urgentLimit < proxyGuardMaxProbes && len(rollingProbeCandidates(state, now, fleetInterval, probed)) == 0 {
			// An active/alternative probe may itself have satisfied the only
			// due fleet member. Release the reservation instead of wasting
			// the final slot.
			urgentLimit = proxyGuardMaxProbes
		}
		if rep.Probes >= urgentLimit {
			return checker.ThroughputResult{}, false
		}
		return probe(name)
	}

	// Stagger recovery: one due member per tick, two clean checks required.
	// Recovery is the highest-priority real transfer, but it still leaves the
	// reserved rolling slot intact when an unmeasured fleet member is due.
	for _, name := range sortedNodeNames(state.Nodes) {
		n := state.Nodes[name]
		if n == nil || n.State != proxyguard.Quarantined || now.Before(n.RetryAfter) {
			continue
		}
		result, ok := urgentProbe(name)
		if !ok {
			break
		}
		n.LastProbe = now
		n.LastDownKbps = result.Kbps
		if result.OK && result.Kbps >= float64(c.Settings.ProxyGuardMinDownKbps) && !latencyUnstable(n.LatenciesMS, c.Settings.ProxyGuardMaxJitterMS) {
			n.RecoveryStreak++
			if n.RecoveryStreak >= 2 {
				n.State = proxyguard.Healthy
				n.Reason = ""
				n.BadStreak = 0
				n.RecoveryStreak = 0
				n.RetryAfter = time.Time{}
				rep.Transitions = append(rep.Transitions, ProxyGuardTransition{Node: name, From: proxyguard.Quarantined, To: proxyguard.Healthy, Reason: "two clean recovery probes"})
			} else {
				n.RetryAfter = now.Add(time.Duration(c.Settings.ProxyGuardQuarantineSeconds) * time.Second)
			}
		} else {
			n.RecoveryStreak = 0
			n.RetryAfter = now.Add(time.Duration(c.Settings.ProxyGuardQuarantineSeconds) * time.Second)
		}
		break
	}

	probeInterval := time.Duration(c.Settings.ProxyGuardActiveProbeInterval) * time.Second
	if probeInterval < time.Minute {
		probeInterval = 30 * time.Minute
	}
	for _, name := range active {
		n := state.Nodes[name]
		if n == nil || n.State == proxyguard.Quarantined {
			continue
		}
		if n.BadStreak == 0 && !n.LastProbe.IsZero() && now.Sub(n.LastProbe) < probeInterval {
			continue
		}
		if probed[name] {
			continue
		}
		result, ok := urgentProbe(name)
		if !ok {
			break
		}
		applySpeedResult(n, result, c.Settings.ProxyGuardMinDownKbps, c.Settings.ProxyGuardMaxJitterMS, now)
	}

	// Confirm suspects only when another member of at least one affected
	// group can carry the same transfer. This prevents endpoint-wide trouble
	// from quarantining the pool.
	for _, name := range sortedNodeNames(state.Nodes) {
		n := state.Nodes[name]
		if n == nil || n.State == proxyguard.Quarantined || n.BadStreak < 2 {
			continue
		}
		alternative := passingAlternative(state, name, c.Settings.ProxyGuardMinDownKbps, now)
		if alternative == "" {
			alternative = probeAlternative(state, name, c.Settings.ProxyGuardMinDownKbps, c.Settings.ProxyGuardMaxJitterMS, now, urgentProbe)
		}
		if alternative == "" {
			continue
		}
		from := n.State
		n.State = proxyguard.Quarantined
		n.QuarantinedAt = now
		n.RetryAfter = now.Add(time.Duration(c.Settings.ProxyGuardQuarantineSeconds) * time.Second)
		n.RecoveryStreak = 0
		rep.Transitions = append(rep.Transitions, ProxyGuardTransition{Node: name, From: from, To: n.State, Reason: n.Reason})
	}

	// Fill every remaining slot with the oldest due concrete member. Never-
	// tested nodes sort first, so a new provider cannot sit at down=unknown
	// indefinitely merely because load-balance has not selected it yet.
	for _, name := range rollingProbeCandidates(state, now, fleetInterval, probed) {
		n := state.Nodes[name]
		result, ok := probe(name)
		if !ok {
			break
		}
		applySpeedResult(n, result, c.Settings.ProxyGuardMinDownKbps, c.Settings.ProxyGuardMaxJitterMS, now)
	}

	recomputeLastResorts(&state, c.Settings.ProxyGuardMinMembers)
	state.LastRun = now
	rep.State = state
	afterSig := state.RoutingSignature()
	if opts.DryRun {
		rep.Message = strings.TrimSpace(rep.Message + " dry-run: no state or routing changes written")
		return rep, nil
	}
	if forceRoutingApply || beforeSig != afterSig {
		if err := m.applyProxyGuardConfig(c, state); err != nil {
			return rep, err
		}
	}
	if err := proxyguard.Save(c, state); err != nil {
		return rep, err
	}
	return rep, nil
}

// RecordProxyGuardSkipped records a cron tick that could not acquire the
// global PureWRT operation lock, so staleness and skip-rate alerts can
// distinguish contention from a dead cron daemon.
func (m Manager) RecordProxyGuardSkipped() {
	c, err := m.Load()
	if err != nil || !c.Settings.ProxyGuardEnabled {
		return
	}
	recordProxyGuardRunOutcome(ProxyGuardReport{Enabled: true, Skipped: true}, nil, time.Now())
	dumpMetrics(c)
}

func (m Manager) ProxyGuardReset() (ProxyGuardReport, error) {
	c, err := m.Load()
	if err != nil {
		return ProxyGuardReport{}, err
	}
	empty := proxyguard.NewState()
	if c.Settings.ProxyGuardEnabled {
		if err := m.applyProxyGuardConfig(c, empty); err != nil {
			return ProxyGuardReport{}, err
		}
	}
	if err := proxyguard.Remove(c); err != nil {
		return ProxyGuardReport{}, err
	}
	return ProxyGuardReport{Enabled: c.Settings.ProxyGuardEnabled, Message: "all runtime quarantines cleared", State: empty, UserExcludes: proxyGuardUserExcludes(c)}, nil
}

func proxyGuardUserExcludes(c config.Config) map[string]string {
	managed := make(map[string]bool)
	for _, name := range generator.ProxyGuardManagedGroups(c) {
		managed[name] = true
	}
	out := make(map[string]string)
	if managed["DNSProxy"] {
		out["DNSProxy"] = c.DNS.ProxyExcludeFilter
	}
	for _, s := range c.Sections {
		if !s.Enabled || s.Action != "proxy" {
			continue
		}
		name := s.ProxyGroup
		if managed[name+"_local"] {
			name += "_local"
		}
		if managed[name] {
			out[name] = s.ProxyExcludeFilter
		}
	}
	if managed["MeshExit"] {
		out["MeshExit"] = c.Mesh.ExitExcludeFilter
	}
	return out
}

func updateGuardGroups(c config.Config, proxies map[string]mihomoapi.Proxy, state *proxyguard.State) map[string]bool {
	members := map[string]bool{}
	next := map[string]*proxyguard.GroupState{}
	for _, group := range generator.ProxyGuardManagedGroups(c) {
		shadow, ok := proxies[generator.ProxyGuardCandidateName(group)]
		if !ok {
			continue
		}
		gs := &proxyguard.GroupState{Name: group}
		for _, member := range shadow.All {
			if guardEligibleMember(member, proxies) {
				gs.Members = append(gs.Members, member)
			}
		}
		if old := state.Groups[group]; old != nil {
			gs.LastResorts = append([]string(nil), old.LastResorts...)
		}
		next[group] = gs
		for _, member := range gs.Members {
			members[member] = true
		}
	}
	state.Groups = next
	return members
}

func guardEligibleMember(name string, proxies map[string]mihomoapi.Proxy) bool {
	switch name {
	case "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL":
		return false
	}
	if generator.IsProxyGuardCandidate(name) {
		return false
	}
	// A mixin may put a nested policy group into a managed group. Preserve
	// that user routing construct; only concrete egress members are probed
	// and quarantined. Concrete provider nodes do not expose an `all` list.
	return len(proxies[name].All) == 0
}

func updateGuardNodes(proxies map[string]mihomoapi.Proxy, members map[string]bool, now time.Time, state *proxyguard.State) {
	for name := range state.Nodes {
		if !members[name] {
			delete(state.Nodes, name)
		}
	}
	for name := range members {
		n := state.Nodes[name]
		if n == nil {
			n = &proxyguard.NodeState{Name: name, State: proxyguard.Healthy}
			state.Nodes[name] = n
		}
		px := proxies[name]
		n.Provider = px.ProviderName
		n.Kind = guardNodeKind(name, px.Type)
		n.LastSeen = now
	}
}

func updateGuardLatency(proxies map[string]mihomoapi.Proxy, members map[string]bool, delays map[string]int, maxJitter int, now time.Time, state *proxyguard.State) {
	for name := range members {
		n := state.Nodes[name]
		delay, ok := delays[name]
		if !ok {
			delay = proxyDelayFor(proxies, name)
		}
		n.LastDelayMS = delay
		n.LatenciesMS = append(n.LatenciesMS, delay)
		if len(n.LatenciesMS) > 5 {
			n.LatenciesMS = append([]int(nil), n.LatenciesMS[len(n.LatenciesMS)-5:]...)
		}
		n.JitterMS = latencyJitter(n.LatenciesMS)
		if n.State != proxyguard.Quarantined {
			if latencyUnstable(n.LatenciesMS, maxJitter) {
				n.BadStreak++
				n.State = proxyguard.Suspect
				n.Reason = fmt.Sprintf("unstable latency (jitter %d ms)", n.JitterMS)
			} else if len(n.LatenciesMS) >= 5 && (n.LastProbe.IsZero() || now.Sub(n.LastProbe) > time.Minute) {
				n.BadStreak = 0
				n.State = proxyguard.Healthy
				n.Reason = ""
			}
		}
	}
}

func guardActiveNodes(proxies map[string]mihomoapi.Proxy, state proxyguard.State, cli mihomoapi.Client) []string {
	active := map[string]bool{}
	for group, gs := range state.Groups {
		if p, ok := proxies[group]; ok && containsString(gs.Members, p.Now) {
			active[p.Now] = true
		}
	}
	if snap, err := cli.Connections(); err == nil {
		for _, conn := range snap.Connections {
			for _, gs := range state.Groups {
				for _, member := range gs.Members {
					if containsString(conn.Chains, member) {
						active[member] = true
					}
				}
			}
		}
	}
	out := make([]string, 0, len(active))
	for name := range active {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func applySpeedResult(n *proxyguard.NodeState, result checker.ThroughputResult, minKbps, maxJitter int, now time.Time) {
	n.LastProbe = now
	n.LastDownKbps = result.Kbps
	if !result.OK || result.Kbps < float64(minKbps) {
		n.BadStreak++
		n.State = proxyguard.Suspect
		if !result.OK {
			n.Reason = "download probe failed"
			if result.Error != "" {
				n.Reason += ": " + result.Error
			}
		} else {
			n.Reason = fmt.Sprintf("download %.0f kbps below %d kbps", result.Kbps, minKbps)
		}
		return
	}
	if !latencyUnstable(n.LatenciesMS, maxJitter) {
		n.BadStreak = 0
		n.State = proxyguard.Healthy
		n.Reason = ""
	}
}

func passingAlternative(state proxyguard.State, bad string, minKbps int, now time.Time) string {
	for _, gs := range state.Groups {
		if !containsString(gs.Members, bad) {
			continue
		}
		for _, name := range gs.Members {
			n := state.Nodes[name]
			if name != bad && n != nil && n.State != proxyguard.Quarantined && !n.LastProbe.IsZero() && now.Sub(n.LastProbe) <= proxyGuardProbeTTL && n.LastDownKbps >= float64(minKbps) {
				return name
			}
		}
	}
	return ""
}

func probeAlternative(state proxyguard.State, bad string, minKbps, maxJitter int, now time.Time, probe func(string) (checker.ThroughputResult, bool)) string {
	var candidates []*proxyguard.NodeState
	seen := map[string]bool{}
	for _, gs := range state.Groups {
		if !containsString(gs.Members, bad) {
			continue
		}
		for _, name := range gs.Members {
			n := state.Nodes[name]
			if name != bad && n != nil && n.State != proxyguard.Quarantined && !seen[name] {
				seen[name] = true
				candidates = append(candidates, n)
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		di, dj := candidates[i].LastDelayMS, candidates[j].LastDelayMS
		if di == 0 {
			di = 1 << 30
		}
		if dj == 0 {
			dj = 1 << 30
		}
		return di < dj
	})
	for _, n := range candidates {
		result, ok := probe(n.Name)
		if !ok {
			return ""
		}
		applySpeedResult(n, result, minKbps, maxJitter, now)
		if result.OK && result.Kbps >= float64(minKbps) {
			return n.Name
		}
	}
	return ""
}

func rollingProbeCandidates(state proxyguard.State, now time.Time, interval time.Duration, already map[string]bool) []string {
	var out []string
	for name, n := range state.Nodes {
		if n == nil || n.State == proxyguard.Quarantined || already[name] {
			continue
		}
		if !n.LastProbe.IsZero() && now.Sub(n.LastProbe) < interval {
			continue
		}
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := state.Nodes[out[i]], state.Nodes[out[j]]
		if a.LastProbe.IsZero() != b.LastProbe.IsZero() {
			return a.LastProbe.IsZero()
		}
		if !a.LastProbe.Equal(b.LastProbe) {
			return a.LastProbe.Before(b.LastProbe)
		}
		return out[i] < out[j]
	})
	return out
}

func recomputeLastResorts(state *proxyguard.State, minMembers int) {
	if minMembers < 1 {
		minMembers = 3
	}
	for _, gs := range state.Groups {
		gs.LastResorts = nil
		available := 0
		var quarantined []string
		for _, name := range gs.Members {
			if n := state.Nodes[name]; n != nil && n.State == proxyguard.Quarantined {
				quarantined = append(quarantined, name)
			} else {
				available++
			}
		}
		floor := min(minMembers, len(gs.Members))
		needed := floor - available
		if needed <= 0 {
			continue
		}
		sort.Slice(quarantined, func(i, j int) bool {
			a, b := state.Nodes[quarantined[i]], state.Nodes[quarantined[j]]
			if guardNodeBetter(a, b) {
				return true
			}
			if guardNodeBetter(b, a) {
				return false
			}
			return quarantined[i] < quarantined[j]
		})
		if needed > len(quarantined) {
			needed = len(quarantined)
		}
		gs.LastResorts = append(gs.LastResorts, quarantined[:needed]...)
	}
}

func guardNodeBetter(a, b *proxyguard.NodeState) bool {
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	aTier, bTier := guardSpeedTier(a.LastDownKbps), guardSpeedTier(b.LastDownKbps)
	if aTier != bTier {
		return aTier > bTier
	}
	aJitter, aDelay := guardLatencyRank(a)
	bJitter, bDelay := guardLatencyRank(b)
	if aJitter != bJitter {
		return aJitter < bJitter
	}
	if aDelay != bDelay {
		return aDelay < bDelay
	}
	if a.LastDownKbps != b.LastDownKbps {
		return a.LastDownKbps > b.LastDownKbps
	}
	return false
}

func guardSpeedTier(kbps float64) int64 {
	if kbps <= 0 {
		return 0
	}
	return int64((kbps + proxyGuardSpeedTier/2) / proxyGuardSpeedTier)
}

func guardLatencyRank(n *proxyguard.NodeState) (jitter, delay int) {
	worst := int(^uint(0) >> 1)
	if n == nil || n.LastDelayMS <= 0 {
		return worst, worst
	}
	samples := n.LatenciesMS
	if len(samples) > 5 {
		samples = samples[len(samples)-5:]
	}
	failures := 0
	for _, sample := range samples {
		if sample <= 0 {
			failures++
		}
	}
	// Zero is the mihomo/API failure sentinel, not perfect latency. A window
	// with repeated failures must rank behind a real, stable measurement.
	if failures >= 2 {
		return worst, worst
	}
	return n.JitterMS, n.LastDelayMS
}

func latencyUnstable(samples []int, maxJitter int) bool {
	if len(samples) < 5 {
		return false
	}
	failures := 0
	var good []int
	for _, d := range samples[len(samples)-5:] {
		if d <= 0 {
			failures++
		} else {
			good = append(good, d)
		}
	}
	if failures >= 2 {
		return true
	}
	if len(good) < 3 {
		return false
	}
	sort.Ints(good)
	min, max := good[0], good[len(good)-1]
	median := good[len(good)/2]
	return max-min >= maxJitter && max >= 2*median
}

func latencyJitter(samples []int) int {
	var good []int
	for _, d := range samples {
		if d > 0 {
			good = append(good, d)
		}
	}
	if len(good) < 2 {
		return 0
	}
	sort.Ints(good)
	return good[len(good)-1] - good[0]
}

type guardProbeSession struct {
	cli   mihomoapi.Client
	prior string
}

func newGuardProbeSession(cli mihomoapi.Client, proxies map[string]mihomoapi.Proxy) *guardProbeSession {
	s := &guardProbeSession{cli: cli}
	if group, ok := proxies[netCheckProbeGroup]; ok {
		s.prior = group.Now
	}
	return s
}

func (s *guardProbeSession) download(parent context.Context, node string, nbytes int64) (checker.ThroughputResult, error) {
	if err := s.cli.SelectProxy(netCheckProbeGroup, node); err != nil {
		return checker.ThroughputResult{}, err
	}
	time.Sleep(250 * time.Millisecond)
	client, err := provider.NewClient(provider.ClientOptions{
		ProxyURL: fmt.Sprintf("http://127.0.0.1:%d", config.DefaultNetCheckProbePort),
		Timeout:  15 * time.Second,
	})
	if err != nil {
		return checker.ThroughputResult{}, err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	return checker.ThroughputProbe(ctx, client, fmt.Sprintf(proxyGuardSpeedURL, nbytes), false, 0), nil
}

func (s *guardProbeSession) restore() {
	if s.prior != "" {
		_ = s.cli.SelectProxy(netCheckProbeGroup, s.prior)
	}
}

func (m Manager) applyProxyGuardConfig(c config.Config, state proxyguard.State) error {
	data, err := generator.MihomoWithProxyGuardState(c, &state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.RuntimeDir(), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.RuntimeDir(), "mihomo-guard-*.yaml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	defer func() { _ = os.Remove(tmpPath) }()
	mihomoBin := c.Settings.MihomoBin
	if mihomoBin == "" {
		mihomoBin = "/usr/bin/mihomo"
	}
	if out, err := (system.Runner{}).Run(mihomoBin, "-t", "-d", c.Settings.Workdir, "-f", tmpPath); err != nil {
		return fmt.Errorf("proxy guard config validation failed: %s: %w", strings.TrimSpace(out), err)
	}
	live := c.Settings.MihomoConfig
	if live == "" {
		live = config.DefaultMihomoConfig
	}
	old, oldErr := os.ReadFile(live)
	if err := system.AtomicWrite(live, data, 0644); err != nil {
		return err
	}
	cli := mihomoapi.Client{Base: localControllerAddr(c), Secret: c.Settings.Secret}
	if err := cli.ReloadConfig(live); err != nil {
		if oldErr == nil {
			_ = system.AtomicWrite(live, old, 0644)
			_ = cli.ReloadConfig(live)
		}
		return fmt.Errorf("proxy guard hot reload failed; prior config restored: %w", err)
	}
	return nil
}

func sortedNodeNames(nodes map[string]*proxyguard.NodeState) []string {
	out := make([]string, 0, len(nodes))
	for name := range nodes {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func guardNodeKind(name, typ string) string {
	switch {
	case strings.HasPrefix(name, "vpn_"):
		return "vpn"
	case strings.HasPrefix(name, "friend_"):
		return "friend"
	case typ != "":
		return strings.ToLower(typ)
	default:
		return "proxy"
	}
}

func recordProxyGuardRunOutcome(rep ProxyGuardReport, err error, started time.Time) {
	now := time.Now()
	success := 1.0
	if rep.Skipped {
		success = 0
	} else if err != nil {
		success = 0
	}
	metrics.ProxyGuardLastAttempt.Set(float64(started.Unix()))
	metrics.ProxyGuardLastRunSuccess.Set(success)
	metrics.ProxyGuardLastRunDurationSeconds.Set(now.Sub(started).Seconds())
	if success == 1 {
		metrics.ProxyGuardLastSuccess.Set(float64(now.Unix()))
	}
}
