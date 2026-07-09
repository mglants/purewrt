package manager

// Live zapret runtime status — surfaced by the LuCI Zapret tab so users can see
// "is nfqws2 running?" and "is traffic actually reaching the desync?" without
// SSHing in. nfqws2 has no metrics endpoint, so this assembles three cheap
// external signals: the running nfqws2 processes (/proc walk → qnum→pid), the
// per-section nftables queue counters (packets/bytes actually queued to nfqws),
// and the enabled-config counts. Mirrors MihomoStatus (mihomo_status.go).

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type ZapretInstanceStatus struct {
	Strategy string `json:"strategy"`
	Queue    int    `json:"queue"`
	PID      int    `json:"pid,omitempty"`
	Running  bool   `json:"running"`
}

type ZapretSectionStatus struct {
	Section string `json:"section"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type ZapretStatusResult struct {
	Running           bool                   `json:"running"` // any enabled instance has a live nfqws2
	Instances         []ZapretInstanceStatus `json:"instances"`
	EnabledProfiles   int                    `json:"enabled_profiles"`
	EnabledStrategies int                    `json:"enabled_strategies"`
	RoutedSections    int                    `json:"routed_sections"`
	Sections          []ZapretSectionStatus  `json:"sections"`
	TotalPackets      uint64                 `json:"total_packets"`
	UptimeSeconds     int64                  `json:"uptime_seconds,omitempty"`
	RecentError       string                 `json:"recent_error,omitempty"`
	Error             string                 `json:"error,omitempty"`
}

// zapretProcs / zapretCounters / zapretRecentError are seams so tests can drive
// status without a live router (same idea as mihomoReachable).
var (
	zapretProcs       = defaultZapretProcs
	zapretCounters    = nftCounterStats
	zapretRecentError = defaultZapretRecentError
)

// livePIDs is the set of currently-running nfqws PIDs — recent-error scanning is
// scoped to these so a stale error from a since-restarted instance (still in the
// logread ring buffer) isn't reported as current.
type livePIDs = map[int]bool

// ZapretStatus collects the live nfqws2 state + queued-traffic counters. Never
// fails hard — populates what it can and leaves the rest zero-valued.
func (m Manager) ZapretStatus() ZapretStatusResult {
	c, _ := m.Load()
	out := ZapretStatusResult{EnabledProfiles: len(c.EnabledZapretProfiles())}

	for _, zs := range c.ZapretStrategies {
		if zs.Enabled {
			out.EnabledStrategies++
		}
	}

	procs := zapretProcs() // qnum -> pid
	counters := zapretCounters()
	var oldest time.Time

	// Instances: one per enabled strategy referenced by an enabled zapret
	// section. Dedup by strategy name (a strategy may be listed twice).
	seenStrategy := map[string]bool{}
	for _, sec := range c.Sections {
		if !sec.Enabled || sec.Action != "zapret" {
			continue
		}
		out.RoutedSections++
		// Per-section queued traffic (proxy_ + dns_proxy_, v4+v6).
		var pkts, bytes uint64
		for _, set := range []string{
			"proxy_" + sec.Name + "4", "proxy_" + sec.Name + "6",
			"dns_proxy_" + sec.Name + "4", "dns_proxy_" + sec.Name + "6",
		} {
			if ctr, ok := counters[set]; ok {
				pkts += ctr.Packets
				bytes += ctr.Bytes
			}
		}
		out.Sections = append(out.Sections, ZapretSectionStatus{Section: sec.Name, Packets: pkts, Bytes: bytes})
		out.TotalPackets += pkts

		for i, name := range sec.ZapretStrategies {
			if seenStrategy[name] {
				continue
			}
			zs, ok := c.ZapretStrategyByName(name)
			if !ok {
				continue
			}
			seenStrategy[name] = true
			zs = c.NormalizeZapretStrategyAt(zs, i)
			inst := ZapretInstanceStatus{Strategy: zs.Name, Queue: zs.QueueNum}
			if pid, up := procs[zs.QueueNum]; up && pid > 0 {
				inst.PID = pid
				inst.Running = true
				out.Running = true
				if t, ok := procStartTime(pid); ok && (oldest.IsZero() || t.Before(oldest)) {
					oldest = t
				}
			}
			out.Instances = append(out.Instances, inst)
		}
	}
	if !oldest.IsZero() {
		out.UptimeSeconds = int64(time.Since(oldest).Seconds())
	}
	live := map[int]bool{}
	for _, pid := range procs {
		live[pid] = true
	}
	out.RecentError = zapretRecentError(live)
	return out
}

// defaultZapretProcs walks /proc for running nfqws2 processes and maps each
// one's --qnum to its PID. comm is prefix-matched ("nfqws") then confirmed via
// the cmdline (which also carries --qnum=N).
func defaultZapretProcs() map[int]int {
	out := map[int]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pidStr := e.Name()
		if pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}
		comm, err := os.ReadFile("/proc/" + pidStr + "/comm")
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(comm)), "nfqws") {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + pidStr + "/cmdline")
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		qnum := 0
		for _, arg := range strings.Split(string(cmdline), "\x00") {
			if v, ok := strings.CutPrefix(arg, "--qnum="); ok {
				qnum, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		if qnum > 0 {
			out[qnum] = pid
		}
	}
	return out
}

// defaultZapretRecentError returns the most recent nfqws2 blob/desync error from
// syslog attributable to a currently-running instance, or "" — best-effort.
// Scoping to live PIDs avoids reporting a stale error from a since-restarted
// nfqws that's still lingering in the logread ring buffer. With no live PIDs it
// returns "" (nothing to attribute).
func defaultZapretRecentError(live livePIDs) string {
	if len(live) == 0 {
		return ""
	}
	out, err := exec.Command("logread", "-e", "nfqws").Output()
	if err != nil {
		return ""
	}
	pidTags := make([]string, 0, len(live))
	for pid := range live {
		pidTags = append(pidTags, "nfqws2["+strconv.Itoa(pid)+"]")
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0 && i > len(lines)-300; i-- {
		l := lines[i]
		if !strings.Contains(l, "unavailable") && !strings.Contains(l, "desync ERROR") {
			continue
		}
		for _, tag := range pidTags {
			if strings.Contains(l, tag) {
				return strings.TrimSpace(l)
			}
		}
	}
	return ""
}
