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

// dumpMetrics persists the in-process metrics registry to
// <RuntimeDir>/metrics.prom. Apply/update observations happen in the
// short-lived CLI process while /metrics is served by the purewrt-api
// daemon — the dump file is the bridge. Best-effort: metrics must never
// fail an apply.
func dumpMetrics(c config.Config) {
	path := filepath.Join(c.RuntimeDir(), "metrics.prom")
	if err := system.AtomicWrite(path, []byte(metrics.Default.Render()), 0644); err != nil {
		newLog(c).Warn("metrics: dump to %s failed: %v", path, err)
	}
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
