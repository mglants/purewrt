package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/notify"
)

// captureNotify swaps notifySend for a recorder for the test's duration.
func captureNotify(t *testing.T) *[]notify.Event {
	t.Helper()
	var got []notify.Event
	orig := notifySend
	notifySend = func(url, format string, ev notify.Event) error {
		got = append(got, ev)
		return nil
	}
	t.Cleanup(func() { notifySend = orig })
	return &got
}

func TestDumpMetricsReplacesLatestStateAndPreservesOtherDomainGauges(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.RuntimeDir = dir
	metrics.Default.ResetObservations()
	defer metrics.Default.ResetObservations()

	metrics.ApplyLastRunSuccess.Set(1)
	metrics.NetCheckLastRun.Set(1234)
	dumpMetrics(c)
	metrics.ApplyLastRunSuccess.Set(0)
	dumpMetrics(c)

	data, err := os.ReadFile(filepath.Join(dir, "metrics.prom"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, `purewrt_apply_last_run_success 0`) {
		t.Fatalf("latest apply state was not replaced across dumps:\n%s", out)
	}
	if !strings.Contains(out, "purewrt_netcheck_last_run_timestamp_seconds 1234") {
		t.Fatalf("unrelated gauge was erased by a later dump:\n%s", out)
	}
	if _, err := os.Stat(MetricsStatePath(c)); err != nil {
		t.Fatalf("persistent state missing: %v", err)
	}
}

func notifyTestConfig(t *testing.T) (Manager, config.Config) {
	t.Helper()
	dir := t.TempDir()
	c := config.Default()
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.NotifyURL = "https://example.com/hook"
	cfgPath := filepath.Join(dir, "purewrt.conf")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	m := Manager{ConfigPath: cfgPath}
	loaded, err := m.Load()
	if err != nil {
		t.Fatal(err)
	}
	return m, loaded
}

func TestNotifyRespectsEventFilter(t *testing.T) {
	got := captureNotify(t)
	m, c := notifyTestConfig(t)
	c.Settings.NotifyOn = []string{"mihomo_revert"}
	m.notify(c, "update_failure", "nope")
	m.notify(c, "mihomo_revert", "yes")
	if len(*got) != 1 || (*got)[0].Event != "mihomo_revert" {
		t.Fatalf("filter failed, got %+v", *got)
	}
}

func TestNotifyDisabledWithoutURL(t *testing.T) {
	got := captureNotify(t)
	m, c := notifyTestConfig(t)
	c.Settings.NotifyURL = ""
	m.notify(c, "update_failure", "x")
	if len(*got) != 0 {
		t.Fatalf("expected no events, got %+v", *got)
	}
}

func TestNotifyEmptyFilterMeansAll(t *testing.T) {
	got := captureNotify(t)
	m, c := notifyTestConfig(t)
	m.notify(c, "update_failure", "x")
	m.notify(c, "sub_expiry", "y")
	if len(*got) != 2 {
		t.Fatalf("expected 2 events, got %+v", *got)
	}
}
