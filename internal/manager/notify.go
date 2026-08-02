package manager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/notify"
	"github.com/purewrt/purewrt/internal/system"
)

// notifySend is the delivery function — package var so tests can swap it
// for a recorder, matching the codebase's hand-rolled stubbing style.
var notifySend = notify.Send

// notify fires one best-effort notification. Never returns an error —
// notification failure must not affect routing operations; it logs a
// warning and moves on. No-op when notify_url is unset or the event is
// filtered out by notify_on.
func (m Manager) notify(c config.Config, event, detail string) {
	url := c.Settings.NotifyURL
	if url == "" || !notifyEventEnabled(c, event) {
		return
	}
	if err := notifySend(url, c.Settings.NotifyFormat, notify.Event{Event: event, Detail: detail}); err != nil {
		newLog(c).Warn("notify: %s delivery failed: %v", event, err)
	}
}

// Event names: update_failure, sub_expiry, mihomo_revert. An empty
// notify_on list enables all of them.
func notifyEventEnabled(c config.Config, event string) bool {
	return len(c.Settings.NotifyOn) == 0 || slices.Contains(c.Settings.NotifyOn, event)
}

// dumpMetrics merges this short-lived CLI process's latest-state gauges and
// duration observations into a persistent tmpfs registry, then refreshes the
// scrape-ready metrics.prom.
// The lock prevents a net-check and update finishing together from losing
// each other's deltas. Best-effort: metrics must never fail an operation.
func dumpMetrics(c config.Config) {
	runtimeDir := c.RuntimeDir()
	lock, err := system.Acquire(filepath.Join(runtimeDir, "metrics.lock"))
	if err != nil {
		newLog(c).Warn("metrics: acquire persistence lock failed: %v", err)
		return
	}
	defer func() { _ = lock.Close() }()

	statePath := filepath.Join(runtimeDir, "metrics-state.json")
	prior, readErr := os.ReadFile(statePath)
	if readErr != nil && !os.IsNotExist(readErr) {
		newLog(c).Warn("metrics: read persistent state failed: %v", readErr)
	}
	state, rendered, err := metrics.MergePersistent(prior, metrics.Default)
	if err != nil {
		// Runtime state is expendable and may come from an older package
		// version. Recover with current observations instead of leaving the
		// endpoint permanently stale.
		newLog(c).Warn("metrics: prior state ignored: %v", err)
		state, rendered, err = metrics.MergePersistent(nil, metrics.Default)
	}
	if err != nil {
		newLog(c).Warn("metrics: build persistent snapshot failed: %v", err)
		return
	}
	if err := system.AtomicWrite(statePath, state, 0600); err != nil {
		newLog(c).Warn("metrics: persist state to %s failed: %v", statePath, err)
		return
	}
	// State is committed, so these process-local deltas must not be merged a
	// second time if another operation in this same CLI process dumps later.
	metrics.Default.ResetObservations()
	path := filepath.Join(runtimeDir, "metrics.prom")
	if err := system.AtomicWrite(path, []byte(rendered), 0644); err != nil {
		newLog(c).Warn("metrics: dump to %s failed: %v", path, err)
	}
}

// FlushMetrics persists observations made by a standalone CLI command whose
// manager operation does not otherwise own a natural persistence boundary.
// It is intentionally best-effort, like dumpMetrics itself.
func (m Manager) FlushMetrics() {
	c, err := m.Load()
	if err != nil {
		return
	}
	dumpMetrics(c)
}

// notifySubscriptionExpiry sweeps SubscriptionExpiry and notifies per
// needs-attention entry, suppressing repeats for 24 h via a small state
// file under RuntimeDir — the update cron runs every 6 h and must not
// spam four identical "expiring soon" pushes a day.
func (m Manager) notifySubscriptionExpiry(c config.Config) {
	if c.Settings.NotifyURL == "" || !notifyEventEnabled(c, "sub_expiry") {
		return
	}
	statePath := filepath.Join(c.RuntimeDir(), "notify-state.json")
	state := map[string]int64{}
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, &state)
	}
	now := time.Now()
	changed := false
	for _, e := range m.SubscriptionExpiry() {
		if !e.NeedsAttention {
			continue
		}
		key := "sub_expiry:" + e.Name
		if last, ok := state[key]; ok && now.Unix()-last < 24*3600 {
			continue
		}
		detail := fmt.Sprintf("subscription %s needs attention", e.Name)
		if e.ExpireUnix > 0 {
			detail = fmt.Sprintf("subscription %s: %.1f days remaining", e.Name, e.DaysRemaining)
		}
		m.notify(c, "sub_expiry", detail)
		state[key] = now.Unix()
		changed = true
	}
	if changed {
		if b, err := json.Marshal(state); err == nil {
			_ = system.AtomicWrite(statePath, b, 0600)
		}
	}
}
