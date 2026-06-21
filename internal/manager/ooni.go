package manager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/system"
)

// OONIPrepare materialises the ooniprobe home before a run: it creates the
// home dir, writes config.json (informed consent + upload flag), and chowns
// both to the dedicated ooni user so the non-root cron run can read/write
// them. The home lives on tmpfs (regenerated each run), so this is cheap and
// idempotent — it deliberately sidesteps the atomic staging pipeline the
// persistent artifacts use. Invoked by the cron wrapper and the LuCI run, as
// root, before `su`-ing to the ooni user for the measurement itself.
func (m Manager) OONIPrepare() error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	c = config.EnsureDefaults(c)
	c = ResolveOONIUser(c)
	o := c.OONISettings()
	if !c.OONI.Enabled {
		return fmt.Errorf("ooni: not enabled")
	}
	if !m.OONIInstalled() {
		return fmt.Errorf("ooni: ooniprobe binary not installed")
	}
	if err := os.MkdirAll(o.Home, 0o755); err != nil {
		return fmt.Errorf("ooni: create home %s: %w", o.Home, err)
	}
	cfgPath := filepath.Join(o.Home, "config.json")
	if err := system.WriteFile(cfgPath, generator.OONIConfigJSON(c), 0o644); err != nil {
		return fmt.Errorf("ooni: write %s: %w", cfgPath, err)
	}
	// Hand the home (and its contents) to the ooni user when resolved; a
	// failed chown is non-fatal (the run may still work if perms allow).
	if c.OONI.UID > 0 {
		_ = os.Chown(o.Home, c.OONI.UID, c.OONI.UID)
		_ = os.Chown(cfgPath, c.OONI.UID, c.OONI.UID)
	}
	return nil
}

// OONIStatus returns a small status map for the LuCI panel.
func (m Manager) OONIStatus() map[string]any {
	c, err := m.Load()
	if err != nil {
		c = config.Default()
	}
	c = config.EnsureDefaults(c)
	c = ResolveOONIUser(c)
	o := c.OONISettings()
	return map[string]any{
		"installed": m.OONIInstalled(),
		"enabled":   c.OONI.Enabled,
		"upload":    o.Upload,
		"schedule":  o.Schedule,
		"proxy":     o.Proxy,
		"home":      o.Home,
		"user":      o.User,
		"uid":       c.OONI.UID,
		// running reflects ANY ooniprobe measurement in flight — cron,
		// on-demand, or external — not just the rpcd bg-job, so the LuCI
		// panel doesn't show "Idle" while a scheduled run is active.
		"running": ooniRunning(),
	}
}

// ooniRunning scans /proc for a live `ooniprobe ... run` process.
func ooniRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		cmd := strings.ReplaceAll(string(b), "\x00", " ")
		if strings.Contains(cmd, "ooniprobe") && strings.Contains(cmd, " run") {
			return true
		}
	}
	return false
}
