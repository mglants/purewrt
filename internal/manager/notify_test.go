package manager

import (
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
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
