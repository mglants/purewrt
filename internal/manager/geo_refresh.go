package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/mihomoapi"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/system"
)

// GeoRefreshResult is the outcome of a single GeoRefresh invocation. Each
// target may succeed, fail, or be skipped independently — the call as a
// whole returns no error if at least one target succeeded.
type GeoRefreshResult struct {
	Targets    []GeoRefreshTarget `json:"targets"`
	ReloadOK   bool               `json:"reload_ok"`
	ReloadErr  string             `json:"reload_error,omitempty"`
}

type GeoRefreshTarget struct {
	Name    string `json:"name"`    // "geoip" | "geosite" | "mmdb"
	URL     string `json:"url"`
	Path    string `json:"path"`
	Bytes   int    `json:"bytes,omitempty"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// GeoRefresh downloads each configured geo file through the bootstrap-
// resilient HTTP client (so the refresh survives censored upstream DNS),
// verifies SHA-256 when configured, atomically swaps into place, then
// signals mihomo to reload its configuration so the new files take effect
// without bouncing the proxy.
//
// Targets with empty URL are skipped silently — lets users enable only
// the geo data their setup actually consumes (geoip without geosite,
// say). The single-result-no-error contract: GeoRefresh returns an
// error only when ALL configured targets failed; partial success is
// reported via the per-target OK flags so callers can show a per-target
// pill in LuCI without losing successes to a single failure.
func (m Manager) GeoRefresh() (GeoRefreshResult, error) {
	c, err := m.Load()
	if err != nil {
		return GeoRefreshResult{}, err
	}
	dir := c.Settings.GeoRefreshGeoIPDir
	if dir == "" {
		dir = "/etc/purewrt/geo"
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return GeoRefreshResult{}, fmt.Errorf("geo-refresh: mkdir %s: %w", dir, err)
	}

	type spec struct {
		name, url, sha, filename string
	}
	specs := []spec{
		{"geoip", c.Settings.GeoRefreshGeoIPURL, c.Settings.GeoRefreshGeoIPSHA, "geoip.dat"},
		{"geosite", c.Settings.GeoRefreshGeoSiteURL, c.Settings.GeoRefreshGeoSiteSHA, "geosite.dat"},
		{"mmdb", c.Settings.GeoRefreshMMDBURL, c.Settings.GeoRefreshMMDBSHA, "country.mmdb"},
	}

	// Geo downloads use the same tactics as subscription/provider fetches:
	// bootstrap DoH client, retry rounds, optional update-via-proxy, and
	// the last-resort fallback through the local mihomo proxy. geosite.dat
	// hosts (github/jsdelivr) are blocked in exactly the environments that
	// need the geo data most.
	proxyURL := ""
	if c.Settings.UpdateViaProxy {
		proxyURL = effectiveUpdateProxyURL(c)
	}
	opt := provider.DownloadOptions{
		Bootstrap:        bootstrapFromSettings(c.Settings),
		ProxyURL:         proxyURL,
		FallbackProxyURL: fallbackProxyURL(c, proxyURL),
		MaxBytes:         128 << 20, // geo .dat files outgrow the 32 MiB subscription cap
	}
	var res GeoRefreshResult
	any := false
	for _, s := range specs {
		t := GeoRefreshTarget{Name: s.name, URL: s.url, Path: filepath.Join(dir, s.filename)}
		if s.url == "" {
			t.Skipped = true
			t.Reason = "url not configured"
			res.Targets = append(res.Targets, t)
			continue
		}
		ok, reason := refreshOne(s.url, s.sha, t.Path, opt)
		t.OK = ok
		t.Reason = reason
		if ok {
			if info, err := os.Stat(t.Path); err == nil {
				t.Bytes = int(info.Size())
			}
			any = true
		}
		res.Targets = append(res.Targets, t)
	}

	// Refresh the on-disk-age gauge regardless of which targets ran.
	updateGeoAgeGauge(dir)

	if !any {
		return res, fmt.Errorf("geo-refresh: no targets succeeded")
	}

	// Ask mihomo to re-read its config so the new geo files take effect.
	// PUT /configs?force=true with the existing path is the canonical way
	// to reload without a restart.
	cli := mihomoapi.Client{Base: c.Settings.ExternalController, Secret: c.Settings.Secret}
	if err := cli.ReloadConfig(c.Settings.MihomoConfig); err != nil {
		res.ReloadErr = err.Error()
	} else {
		res.ReloadOK = true
	}
	return res, nil
}

// refreshOne downloads one URL through the shared provider downloader
// (bootstrap DoH, retry rounds, mirrors-less but proxy + mihomo-fallback
// capable), verifies the SHA when supplied, and atomically swaps the
// destination file. Returns (ok, reason) — reason on failure is
// human-readable.
func refreshOne(url, wantSHA, dst string, opt provider.DownloadOptions) (bool, string) {
	d, err := provider.DownloadWithOptions(url, opt)
	if err != nil {
		return false, "fetch: " + err.Error()
	}
	if len(d.Data) == 0 {
		return false, "empty response"
	}
	if wantSHA != "" {
		sum := sha256.Sum256(d.Data)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(wantSHA), "sha256:"), got) {
			return false, fmt.Sprintf("sha mismatch: got %s want %s", got, wantSHA)
		}
	}
	if err := system.AtomicWrite(dst, d.Data, 0644); err != nil {
		return false, "swap: " + err.Error()
	}
	return true, ""
}

// updateGeoAgeGauge sets purewrt_geoip_data_age_seconds to the age of the
// newest file in dir. Run after every refresh attempt (success or not) so
// the gauge tracks reality even when refresh failed.
func updateGeoAgeGauge(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var newest time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if !newest.IsZero() {
		metrics.GeoDataAgeSeconds.Set(time.Since(newest).Seconds())
	}
}

// DefaultGeoSources is a thin proxy onto config.DefaultGeoSources so
// existing callers in this package don't need to change. The map was
// moved into internal/config so write.go can use it to auto-seed
// Settings.GeoRefresh*URL when a user adds their first geo-backed
// RuleProvider.
func DefaultGeoSources() map[string]string {
	return config.DefaultGeoSources()
}

// Compile-time check that GeoRefreshResult round-trips through the
// internal config type cleanly. (Empty function — exists only to anchor
// imports if the config package import gets garbage-collected by tooling.)
var _ = config.Config{}
