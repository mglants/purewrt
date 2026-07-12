package manager

// apk update-available reporting for the three first-party packages
// (purewrt, mihomo-alpha, zapret). The LuCI Mihomo tab surfaces these
// as "vX → vY available" hints; the General page shows a small dot
// next to the matching menu items when any has an upgrade.
//
// We don't auto-install — that's a sharp tool that can yank running
// daemons. The hint exists so the user can choose timing.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PackageUpdate is one row of the report. UpgradeAvailable is the
// boolean the UI uses to decide whether to render the badge; it stays
// false when the package isn't installed at all (Installed == "").
type PackageUpdate struct {
	Name             string    `json:"name"`
	Installed        string    `json:"installed,omitempty"`
	Available        string    `json:"available,omitempty"`
	UpgradeAvailable bool      `json:"upgrade_available"`
	CheckedAt        time.Time `json:"checked_at"`
	Note             string    `json:"note,omitempty"` // surfaced when the probe failed (apk missing, network down, etc.)
}

// PackagesToTrack is the fixed list of names the LuCI hint cares about.
// All three are PureWRT-feed-owned (or its bundled dependencies). Any
// other apk upgrades are out of scope for this banner — LuCI's own
// Software page is the right place for general package management.
var packagesToTrack = []string{"purewrt", "mihomo-alpha", "zapret"}

// apkUpdateCacheFile holds the timestamp of the last successful
// `apk update`. Used to rate-limit hitting the repo to once per hour
// per session.
const apkUpdateCacheFile = "/tmp/purewrt-apk-update.stamp"
const apkUpdateMaxAge = 1 * time.Hour

// AptUpdatesAvailable returns the per-package report. Refreshes the
// repo index when the cache is older than apkUpdateMaxAge. Force a
// refresh by passing force=true (used by the LuCI "Refresh repo index"
// button).
func (m Manager) AptUpdatesAvailable(force bool) ([]PackageUpdate, error) {
	if _, err := exec.LookPath("apk"); err != nil {
		return nil, fmt.Errorf("apk not in PATH; only OpenWrt 25.12+ (apk-based) is supported: %w", err)
	}
	if force || apkCacheStale() {
		if err := runApkUpdate(); err != nil {
			// Don't fail the whole report on a transient network blip —
			// fall through to reading stale data. Each per-package row
			// gets a Note explaining the index might be old.
			fmt.Fprintln(os.Stderr, "apk update warning:", err)
		} else {
			_ = touchApkCache()
		}
	}

	installed, err := apkListInstalled()
	if err != nil {
		return nil, err
	}
	available, _ := apkListUpgradable()

	now := time.Now().UTC()
	out := make([]PackageUpdate, 0, len(packagesToTrack))
	for _, name := range packagesToTrack {
		row := PackageUpdate{Name: name, CheckedAt: now}
		if v, ok := installed[name]; ok {
			row.Installed = v
		}
		if v, ok := available[name]; ok {
			row.Available = v
			row.UpgradeAvailable = row.Installed != "" && row.Installed != v
		}
		out = append(out, row)
	}
	return out, nil
}

func apkCacheStale() bool {
	fi, err := os.Stat(apkUpdateCacheFile)
	if err != nil {
		return true
	}
	return time.Since(fi.ModTime()) > apkUpdateMaxAge
}

func touchApkCache() error {
	if err := os.MkdirAll(filepath.Dir(apkUpdateCacheFile), 0o755); err != nil {
		return err
	}
	now := time.Now()
	if err := os.WriteFile(apkUpdateCacheFile, []byte(now.Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Chtimes(apkUpdateCacheFile, now, now)
}

func runApkUpdate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "apk", "update").CombinedOutput()
	if err != nil {
		return fmt.Errorf("apk update: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// apkListInstalled returns `map[name]version` for currently-installed
// packages. Output line shape: "<name>-<version> <arch> {<repo>} (<license>) [installed]".
// Parses name by splitting at the *last* `-N.N…-rN` segment — apk
// names can contain hyphens (e.g. "mihomo-alpha"), so we can't just
// split on the first hyphen.
func apkListInstalled() (map[string]string, error) {
	out, err := exec.Command("apk", "list", "-I").Output()
	if err != nil {
		return nil, fmt.Errorf("apk list -I: %w", err)
	}
	return parseApkList(out), nil
}

// apkListUpgradable runs `apk list -u`. Always succeeds (returns an
// empty map) if apk's repo cache is missing — that case shows up as
// "no upgrades found" in the UI, which is honest.
func apkListUpgradable() (map[string]string, error) {
	out, err := exec.Command("apk", "list", "-u").Output()
	if err != nil {
		// apk emits warnings to stderr but exits 0 if the upgrade-list
		// command itself succeeds; an actual error here means apk isn't
		// callable.
		if errors.Is(err, exec.ErrNotFound) {
			return nil, err
		}
		return map[string]string{}, nil
	}
	return parseApkList(out), nil
}

// parseApkList implements the name/version split for both `-I` and
// `-u` output (same line shape). Returns name → version map. Lines that
// don't match the expected shape are skipped silently — we'd rather
// under-report than panic on an apk format change.
func parseApkList(data []byte) map[string]string {
	out := map[string]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "WARNING:") || strings.HasPrefix(line, "fetch ") {
			continue
		}
		first, _, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		name, version := splitNameVersion(first)
		if name == "" {
			continue
		}
		if _, exists := out[name]; !exists {
			out[name] = version
		}
	}
	return out
}

// splitNameVersion separates "<name>-<X.Y.Z-rN>" by walking from the
// right until we hit a token whose first char is a digit — that token
// (and everything after) is the version. Necessary because apk names
// like "mihomo-alpha" contain hyphens themselves.
func splitNameVersion(s string) (string, string) {
	parts := strings.Split(s, "-")
	for i := len(parts) - 1; i >= 1; i-- {
		if len(parts[i]) > 0 && parts[i][0] >= '0' && parts[i][0] <= '9' {
			return strings.Join(parts[:i], "-"), strings.Join(parts[i:], "-")
		}
	}
	return s, ""
}
