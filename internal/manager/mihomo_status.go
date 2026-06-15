package manager

// Mihomo runtime status snapshot — surfaced by the LuCI Mihomo tab so
// users have a single place to see "is it running?", what version is
// loaded, how many active connections exist, etc. Cheap to compute:
// one pgrep + one HTTP GET to the external controller. No caching —
// the LuCI page polls on user interaction, not on a timer, so the cost
// per call is negligible.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/mihomoapi"
)

// MihomoStatusResult is what /version + /connections + /proc combine
// into. Empty-string fields render as "-" in LuCI; the Running flag is
// the authoritative is-it-alive signal.
type MihomoStatusResult struct {
	Running            bool      `json:"running"`
	PID                int       `json:"pid,omitempty"`
	Version            string    `json:"version,omitempty"`         // mihomo's /version JSON `version` field
	Meta               bool      `json:"meta,omitempty"`            // /version `meta` field — true for Mihomo Meta forks
	StartedAt          time.Time `json:"started_at,omitempty"`      // parsed from /proc/<pid>/stat boot offset
	UptimeSeconds      int64     `json:"uptime_seconds,omitempty"`
	Connections        int       `json:"connections"`               // /connections snapshot length
	DNSMode            string    `json:"dns_mode,omitempty"`        // from UCI, not the runtime — they should match after apply
	ExternalController string    `json:"external_controller,omitempty"`
	MihomoBin          string    `json:"mihomo_bin,omitempty"`      // currently-configured binary path (UCI)
	BinarySource       string    `json:"binary_source,omitempty"`   // "package" | "github" — derived from MihomoBin location
	Error              string    `json:"error,omitempty"`           // top-level error message, e.g. when /version is unreachable
}

// MihomoStatus collects the status from /proc + the external controller.
// Doesn't fail hard when individual signals are missing — populates what
// it can, leaves the rest empty, and stuffs the most-impactful error
// into the Error field so the LuCI page can surface it inline.
func (m Manager) MihomoStatus() MihomoStatusResult {
	c, _ := m.Load()
	out := MihomoStatusResult{
		DNSMode:            c.DNS.EnhancedMode,
		ExternalController: c.Settings.ExternalController,
		MihomoBin:          c.Settings.MihomoBin,
		BinarySource:       classifyMihomoBin(c.Settings.MihomoBin),
	}
	pid := mihomoPID()
	out.Running = pid > 0
	out.PID = pid
	if pid > 0 {
		if t, ok := procStartTime(pid); ok {
			out.StartedAt = t
			out.UptimeSeconds = int64(time.Since(t).Seconds())
		}
	}
	if out.Running {
		cli := mihomoapi.Client{Base: c.Settings.ExternalController, Secret: c.Settings.Secret}
		if v, err := cli.Version(); err == nil {
			out.Version = v.Version
			out.Meta = v.Meta
		} else {
			out.Error = "version: " + err.Error()
		}
		if snap, err := cli.Connections(); err == nil {
			out.Connections = len(snap.Connections)
		}
	}
	return out
}

// mihomoPID locates the running mihomo via /proc walk. Avoids pgrep
// because busybox pgrep matches process names truncated to 15 chars
// (TASK_COMM_LEN). We do the same scan ourselves so the result is
// deterministic regardless of whether the package ships a fuller pgrep.
//
// /proc/<pid>/comm is the kernel's TASK_COMM_LEN-truncated executable
// name — for a GitHub-installed binary named "mihomo-Prerelease-Alpha"
// it ends up as "mihomo-Prerelea". So exact-match on "mihomo" misses
// that case entirely. Strategy: prefix-match comm against "mihomo",
// then confirm via the basename of /proc/<pid>/exe (full path, not
// truncated). The two-step keeps the /proc walk cheap — only candidates
// pay the symlink read.
func mihomoPID() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		commBytes, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commBytes))
		if !strings.HasPrefix(comm, "mihomo") {
			continue
		}
		// Confirm via /proc/<pid>/exe basename so a stray short name
		// like "mihomonia" doesn't match. The symlink read can fail
		// (kernel threads, denied) — fall back to accepting the comm
		// match when it does.
		exe, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil {
			if comm == "mihomo" {
				return pid
			}
			continue
		}
		base := filepath.Base(exe)
		if base == "mihomo" || strings.HasPrefix(base, "mihomo-") || strings.HasPrefix(base, "mihomo.") {
			return pid
		}
	}
	return 0
}

// procStartTime returns the time the given PID's process started, derived
// from the 22nd field of /proc/<pid>/stat (start time in clock ticks
// since boot). Adds the boot time from /proc/stat's `btime` line to
// resolve to wall-clock. Returns ok=false on any parse error — caller
// just renders "-" for uptime in that case.
func procStartTime(pid int) (time.Time, bool) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return time.Time{}, false
	}
	// stat format: pid (comm) state ... but `comm` may contain spaces and
	// parens. Skip past the last ')' to get the rest reliably.
	close := strings.LastIndexByte(string(stat), ')')
	if close < 0 {
		return time.Time{}, false
	}
	rest := strings.Fields(string(stat)[close+1:])
	// rest[0] is `state`, so start time (field 22 in 1-indexed terms,
	// position 21 from `state`) is index 19 of `rest`.
	if len(rest) < 20 {
		return time.Time{}, false
	}
	startTicks, err := strconv.ParseInt(rest[19], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	btime, ok := bootTime()
	if !ok {
		return time.Time{}, false
	}
	hz := clockTicksHz()
	startUnix := btime + startTicks/hz
	return time.Unix(startUnix, 0).UTC(), true
}

func bootTime() (int64, bool) {
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(stat), "\n") {
		if strings.HasPrefix(line, "btime ") {
			n, err := strconv.ParseInt(strings.TrimPrefix(line, "btime "), 10, 64)
			if err != nil {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}

// clockTicksHz returns USER_HZ. Linux/aarch64 is conventionally 100;
// we don't shell out to `getconf CLK_TCK` because OpenWrt's busybox
// often doesn't ship getconf. Hard-code 100 and accept ~1 s drift on
// the rare platform with a different value.
func clockTicksHz() int64 { return 100 }

// classifyMihomoBin reports whether the configured mihomo binary points
// at the package-installed location (/usr/bin/mihomo) or the
// PureWRT-managed GitHub-installed location (<workdir>/mihomo-bin/...).
func classifyMihomoBin(path string) string {
	if path == "" || path == "/usr/bin/mihomo" {
		return "package"
	}
	if strings.Contains(filepath.Clean(path), "/mihomo-bin/") {
		return "github"
	}
	return "custom"
}

// runMihomoServiceCmd is the helper for "restart mihomo" — used by the
// MihomoInstallRelease path. Not in this file's hot path; lives next
// to status because both are mihomo-runtime concerns.
func runMihomoServiceCmd(action string) ([]byte, error) {
	return exec.Command("/etc/init.d/mihomo", action).CombinedOutput()
}
