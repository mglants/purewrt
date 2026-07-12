package manager

// Real binary install from upstream GitHub releases. Replaces the
// previous "record-only" mihomo-download behaviour for users who'd
// rather pull straight from MetaCubeX/mihomo than wait for the
// purewrt-feed apk to catch up. Two channels: alpha (Prerelease-Alpha
// rolling tag) and stable (latest semver-tagged release).
//
// Safety properties:
//   - Never overwrites /usr/bin/mihomo (apk-managed; touching it
//     corrupts the apk install database). Installs to
//     <workdir>/mihomo-bin/mihomo-<tag>, then flips Settings.MihomoBin
//     in UCI so the init script picks up the new path.
//   - Atomic place via system.AtomicWrite — no half-written binary.
//   - SHA256 verification before extraction. Abort on mismatch.
//   - Restart only after the binary is in place + UCI committed. If
//     the new binary fails to start, the user reverts by clearing the
//     UCI override (see MihomoRevertToPackage below).

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mihomoapi"
)

// MihomoChannelResolve maps the channel name to the API URL. Empty
// channel falls back to the configured default (alpha) — matches the
// historic behaviour of MihomoCheckUpdate.
func mihomoChannelAPI(c config.Config, channel string) (string, error) {
	switch channel {
	case "", "alpha":
		api := c.Settings.MihomoReleaseAPI
		if api == "" {
			api = mihomoapi.DefaultAlphaAPI
		}
		return api, nil
	case "stable":
		api := c.Settings.MihomoStableReleaseAPI
		if api == "" {
			api = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
		}
		return api, nil
	default:
		return "", fmt.Errorf("unsupported mihomo channel %q; expected alpha or stable", channel)
	}
}

// MihomoCheckUpdateChannel is the channel-aware variant of
// MihomoCheckUpdate. Kept as a separate method (rather than changing
// the existing signature) so other callers — particularly the original
// rpcd `mihomo_check_update` method that the diagnostics page used to
// expose — keep working unmodified. The Mihomo tab uses this one.
func (m Manager) MihomoCheckUpdateChannel(channel string) (mihomoapi.UpdateInfo, error) {
	c, err := m.Load()
	if err != nil {
		return mihomoapi.UpdateInfo{}, err
	}
	api, err := mihomoChannelAPI(c, channel)
	if err != nil {
		return mihomoapi.UpdateInfo{}, err
	}
	// Same download tactics as providers: bootstrap DoH client, optional
	// update-via-proxy, single retry through the local mihomo proxy.
	// GitHub's API is the most-blocked endpoint PureWRT talks to.
	primary, fallback := updaterClients(c, 30*time.Second)
	info, err := (mihomoapi.Updater{APIURL: api, HTTPClient: primary}).Check(c.Settings.MihomoVersion, c.Settings.MihomoArch)
	if err != nil && fallback != nil {
		info, err = (mihomoapi.Updater{APIURL: api, HTTPClient: fallback}).Check(c.Settings.MihomoVersion, c.Settings.MihomoArch)
	}
	if err != nil {
		return info, err
	}
	// Updater.Check hard-codes Channel="alpha" in the returned struct.
	// Override here so the LuCI page sees the right value.
	if channel != "" {
		info.Channel = channel
	}
	return info, nil
}

// MihomoAutoUpdateResult reports what the auto-update cron did this
// tick. Same fields as a hand-triggered install, plus enough hints to
// distinguish "did nothing because disabled" from "did nothing because
// up to date" in the log line.
type MihomoAutoUpdateResult struct {
	Enabled        bool   `json:"enabled"`
	Channel        string `json:"channel"`
	CurrentVersion string `json:"current_version,omitempty"`
	LatestVersion  string `json:"latest_version,omitempty"`
	Action         string `json:"action"` // "disabled" | "up-to-date" | "installed" | "install-failed" | "auto-reverted"
	Error          string `json:"error,omitempty"`
}

// MihomoAutoUpdate is the cron entry point. Honors
// Settings.MihomoAutoUpdateEnabled (off → silent no-op), checks the
// current channel, and only invokes MihomoInstallRelease when the
// asset-derived version differs from what's installed. The downstream
// install path already auto-reverts on warmup fail; this method just
// surfaces that outcome in the report so cron logs are useful.
func (m Manager) MihomoAutoUpdate() (MihomoAutoUpdateResult, error) {
	c, err := m.Load()
	if err != nil {
		return MihomoAutoUpdateResult{}, err
	}
	channel := c.Settings.MihomoChannel
	if channel == "" {
		channel = "alpha"
	}
	res := MihomoAutoUpdateResult{Channel: channel, CurrentVersion: c.Settings.MihomoVersion}
	if !c.Settings.MihomoAutoUpdateEnabled {
		res.Action = "disabled"
		return res, nil
	}
	res.Enabled = true
	info, err := m.MihomoCheckUpdateChannel(channel)
	if err != nil {
		res.Action = "install-failed"
		res.Error = "check: " + err.Error()
		return res, fmt.Errorf("check: %w", err)
	}
	res.LatestVersion = info.Version
	if !info.UpdateAvailable {
		res.Action = "up-to-date"
		return res, nil
	}
	installRes, err := m.MihomoInstallRelease(channel)
	if err != nil {
		res.Action = "install-failed"
		res.Error = err.Error()
		return res, err
	}
	if installRes.AutoReverted {
		res.Action = "auto-reverted"
		if installRes.RevertError != "" {
			res.Error = installRes.RevertError
		}
		return res, nil
	}
	res.Action = "installed"
	return res, nil
}

// MihomoInstallReleaseResult is the success report from a completed
// install. Surfaced into the rpcd async job's status output and into
// the LuCI page's progress display.
type MihomoInstallReleaseResult struct {
	Channel       string `json:"channel"`
	Version       string `json:"version"`
	InstalledPath string `json:"installed_path"`
	AssetName     string `json:"asset_name"`
	BytesWritten  int64  `json:"bytes_written"`
	RestartedAt   string `json:"restarted_at"`
	WarmedUp      bool   `json:"warmed_up"`     // true if /version responded within the post-restart wait
	AutoReverted  bool   `json:"auto_reverted"` // set when warmup failed and we fell back to the package binary
	RevertError   string `json:"revert_error,omitempty"`
}

// MihomoInstallRelease performs the full download → verify → install →
// UCI flip → service restart sequence. Synchronous; the rpcd layer
// wraps it with start_bg_job for the async dance LuCI uses.
//
// The path chosen for the new binary lives under <workdir>/mihomo-bin/
// so the apk-managed /usr/bin/mihomo stays untouched. The init script
// reads Settings.MihomoBin from UCI on every restart, so flipping that
// option is the entire switch-over.
func (m Manager) MihomoInstallRelease(channel string) (MihomoInstallReleaseResult, error) {
	res := MihomoInstallReleaseResult{Channel: channel}
	c, err := m.Load()
	if err != nil {
		return res, err
	}
	info, err := m.MihomoCheckUpdateChannel(channel)
	if err != nil {
		return res, fmt.Errorf("check release: %w", err)
	}
	if info.URL == "" {
		return res, fmt.Errorf("release %s has no downloadable asset for arch %s", info.Version, info.Arch)
	}
	res.Version = info.Version
	res.AssetName = info.AssetName

	workdir := c.Settings.Workdir
	if workdir == "" {
		workdir = config.DefaultWorkdir
	}
	destDir := filepath.Join(workdir, "mihomo-bin")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return res, fmt.Errorf("mkdir mihomo-bin: %w", err)
	}
	destPath := filepath.Join(destDir, "mihomo-"+sanitizeTag(info.Version))
	res.InstalledPath = destPath

	// Reuse mihomoapi.Updater.DownloadAndInstall — it handles the
	// download, SHA256 verify, and atomic place via system.AtomicWrite.
	// Pass destPath directly so it lands in our managed dir, not the
	// /usr/bin location. Same tactics as provider downloads: bootstrap
	// client (+ optional update-via-proxy), then one retry through the
	// local mihomo proxy — the binary is hosted on GitHub, the
	// most-blocked endpoint PureWRT fetches from. Wide timeout: the
	// asset is ~44 MB and slow uplinks need minutes, not 30 s.
	primary, fallback := updaterClients(c, 5*time.Minute)
	err = (mihomoapi.Updater{HTTPClient: primary}).DownloadAndInstall(info, destPath)
	if err != nil && fallback != nil {
		err = (mihomoapi.Updater{HTTPClient: fallback}).DownloadAndInstall(info, destPath)
	}
	if err != nil {
		// Wipe any half-written file. AtomicWrite shouldn't leave one
		// behind but extractBinary can fail mid-gunzip.
		_ = os.Remove(destPath)
		return res, fmt.Errorf("download+install: %w", err)
	}
	if fi, err := os.Stat(destPath); err == nil {
		res.BytesWritten = fi.Size()
	}

	// Update UCI: MihomoBin now points at the new binary, and the
	// existing tracking fields (MihomoVersion, MihomoAssetURL,
	// MihomoSHA256URL) record provenance. Backup the UCI file first so
	// `purewrt config-restore` can undo this in one gesture.
	c.Settings.MihomoBin = destPath
	c.Settings.MihomoVersion = info.Version
	c.Settings.MihomoAssetURL = info.URL
	c.Settings.MihomoSHA256URL = info.SHA256URL
	if m.ConfigPath == "" {
		m.ConfigPath = uciPurewrtPath
	}
	_, _ = config.Backup(m.ConfigPath)
	if err := config.Save(m.ConfigPath, c); err != nil {
		return res, fmt.Errorf("uci save: %w", err)
	}

	// Restart the service and wait for it to come up. 10 s budget is
	// usually enough for mihomo to bind its sockets and respond to
	// /version. If it doesn't respond within that window we treat the
	// release as broken and auto-revert to the apk-managed binary —
	// otherwise a bad upstream release would brick the proxy until the
	// user noticed and reverted manually. Better to fail loud and
	// undo than fail silent.
	if out, err := runMihomoServiceCmd("restart"); err != nil {
		return res, fmt.Errorf("/etc/init.d/mihomo restart: %w (%s)", err, string(out))
	}
	res.RestartedAt = time.Now().UTC().Format(time.RFC3339)
	res.WarmedUp = waitForMihomoReady(c, 10*time.Second)
	if !res.WarmedUp {
		if err := m.MihomoRevertToPackage(); err != nil {
			res.RevertError = err.Error()
			m.notify(c, "mihomo_revert", fmt.Sprintf("mihomo %s failed warmup AND revert failed: %s — proxy may be down", res.Version, res.RevertError))
		} else {
			res.AutoReverted = true
			m.notify(c, "mihomo_revert", fmt.Sprintf("mihomo %s failed warmup; auto-reverted to the package binary", res.Version))
		}
	}
	return res, nil
}

// MihomoRevertToPackage clears the Settings.MihomoBin UCI override,
// restarts the service, and wipes the GitHub-staged binaries from
// <workdir>/mihomo-bin/ to free disk space (a single install is ~44 MB
// uncompressed, real cost on a flash-backed router). The init script
// then resolves the default /usr/bin/mihomo (apk-managed). If a user
// later wants to switch back to GitHub they re-run install — cheaper
// than carrying dead bytes around on every box that reverted once.
//
// Ordering matters: restart first (so the running process detaches
// from the old inode), then remove the directory. Removing while the
// binary is mapped would still succeed on Linux (rename/unlink doesn't
// touch in-use inodes) but the disk space wouldn't reclaim until the
// kernel released the mapping — restarting first makes the reclaim
// immediate.
func (m Manager) MihomoRevertToPackage() error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	workdir := c.Settings.Workdir
	if workdir == "" {
		workdir = config.DefaultWorkdir
	}
	binDir := filepath.Join(workdir, "mihomo-bin")

	c.Settings.MihomoBin = "/usr/bin/mihomo"
	if m.ConfigPath == "" {
		m.ConfigPath = uciPurewrtPath
	}
	_, _ = config.Backup(m.ConfigPath)
	if err := config.Save(m.ConfigPath, c); err != nil {
		return err
	}
	if out, err := runMihomoServiceCmd("restart"); err != nil {
		return fmt.Errorf("/etc/init.d/mihomo restart: %w (%s)", err, string(out))
	}
	// Best-effort cleanup — a failure here doesn't unwind the revert,
	// the service is already running on the package binary. Surface
	// the error so the CLI can log it for diagnosis but don't return
	// it; otherwise callers would see a "revert failed" when revert
	// itself actually succeeded.
	if err := os.RemoveAll(binDir); err != nil {
		fmt.Fprintf(os.Stderr, "mihomo-revert-package: warning: failed to remove %s: %v\n", binDir, err)
	}
	return nil
}

// sanitizeTag strips characters that would create a problem-shaped
// filename. Mihomo's tags are clean (alpha-c59c99a0, v1.18.10) but we
// defensively replace anything outside [A-Za-z0-9._-] with `_` so a
// future tag with weird characters doesn't crash the install.
func sanitizeTag(tag string) string {
	out := make([]byte, 0, len(tag))
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '.' || c == '-' || c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// waitForMihomoReady polls /version up to `timeout` and returns true
// once it responds. Used by MihomoInstallRelease to distinguish
// "service started and is serving" from "service started but
// initialisation is still in progress".
func waitForMihomoReady(c config.Config, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	cli := mihomoapi.Client{Base: c.Settings.ExternalController, Secret: c.Settings.Secret}
	for time.Now().Before(deadline) {
		if _, err := cli.Version(); err == nil {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}
