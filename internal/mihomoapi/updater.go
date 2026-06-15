package mihomoapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/system"
)

const DefaultAlphaAPI = "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/Prerelease-Alpha"

type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}
type Release struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	PublishedAt time.Time      `json:"published_at"`
	Assets      []ReleaseAsset `json:"assets"`
}
type UpdateInfo struct {
	Channel, Version, AssetName, URL, SHA256URL string
	// TagName is the raw GitHub release tag (e.g. "Prerelease-Alpha"
	// for the rolling alpha, "v1.18.10" for stable). For alpha it's
	// useless as a version identifier because it never changes — the
	// real per-release identifier lives in the asset filename and is
	// surfaced via the Version field above.
	TagName                                     string
	Size                                        int64
	Arch                                        string
	PublishedAt                                 time.Time
	CurrentVersion                              string
	UpdateAvailable                             bool
}

type Updater struct {
	APIURL     string
	HTTPClient *http.Client
}

func (u Updater) Check(currentVersion, archHint string) (UpdateInfo, error) {
	api := u.APIURL
	if api == "" {
		api = DefaultAlphaAPI
	}
	cli := u.HTTPClient
	if cli == nil {
		cli = &http.Client{Timeout: 30 * time.Second}
	}
	req, _ := http.NewRequest("GET", api, nil)
	req.Header.Set("User-Agent", "PureWRT mihomo updater")
	resp, err := cli.Do(req)
	if err != nil {
		return UpdateInfo{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return UpdateInfo{}, fmt.Errorf("release check failed: %s", resp.Status)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return UpdateInfo{}, err
	}
	asset, checksum := selectAsset(rel.Assets, archHint)
	if asset.Name == "" {
		return UpdateInfo{}, fmt.Errorf("no mihomo linux asset found for arch %s", effectiveArch(archHint))
	}
	arch := effectiveArch(archHint)
	// Prefer the asset-derived version over the tag — for alpha the
	// tag is "Prerelease-Alpha" forever, so comparing against it can
	// never detect an update. The asset name embeds the actual commit
	// hash / semver so it's the right identity to compare.
	version := parseAssetVersion(asset.Name, arch)
	if version == "" {
		version = rel.TagName
	}
	return UpdateInfo{Channel: "alpha", Version: version, TagName: rel.TagName, AssetName: asset.Name, URL: asset.BrowserDownloadURL, SHA256URL: checksum.BrowserDownloadURL, Size: asset.Size, Arch: arch, PublishedAt: rel.PublishedAt, CurrentVersion: currentVersion, UpdateAvailable: currentVersion == "" || currentVersion != version}, nil
}

// parseAssetVersion extracts the version segment from a mihomo asset
// filename. The format is "mihomo-<os>-<arch>-<version>.<ext>" — e.g.
// "mihomo-linux-arm64-alpha-d08c885.gz" → "alpha-d08c885", or
// "mihomo-linux-amd64-v1.18.10.gz" → "v1.18.10". Strips known archive
// extensions (.gz / .tar.gz / .tgz). Returns "" if the filename doesn't
// fit the expected shape — callers fall back to the release tag in
// that case.
func parseAssetVersion(name, arch string) string {
	lower := strings.ToLower(name)
	for _, ext := range []string{".tar.gz", ".tgz", ".gz"} {
		if strings.HasSuffix(lower, ext) {
			name = name[:len(name)-len(ext)]
			lower = lower[:len(lower)-len(ext)]
			break
		}
	}
	// Strip the "-compatible" marker that some MIPS variants carry —
	// it's a build flag, not part of the version. We've already
	// preferred non-compatible assets in selectAsset, but if that's
	// the only one available we still need to extract a clean version.
	name = strings.TrimSuffix(name, "-compatible")
	lower = strings.TrimSuffix(lower, "-compatible")

	prefix := "mihomo-linux-" + strings.ToLower(arch) + "-"
	if !strings.HasPrefix(lower, prefix) {
		return ""
	}
	return name[len(prefix):]
}

func (u Updater) DownloadAndInstall(info UpdateInfo, dest string) error {
	if dest == "" {
		dest = "/usr/bin/mihomo"
	}
	cli := u.HTTPClient
	if cli == nil {
		cli = &http.Client{Timeout: 120 * time.Second}
	}
	data, err := download(cli, info.URL)
	if err != nil {
		return err
	}
	if info.SHA256URL != "" {
		sumData, err := download(cli, info.SHA256URL)
		if err == nil {
			if err := verifySHA256(data, string(sumData), info.AssetName); err != nil {
				return err
			}
		}
	}
	bin, err := extractBinary(data, info.AssetName)
	if err != nil {
		return err
	}
	if err := system.AtomicWrite(dest, bin, 0755); err != nil {
		return err
	}
	meta, _ := json.MarshalIndent(info, "", "  ")
	return system.AtomicWrite(filepath.Dir(dest)+"/.mihomo-purewrt-version.json", append(meta, '\n'), 0644)
}

func selectAsset(assets []ReleaseAsset, archHint string) (ReleaseAsset, ReleaseAsset) {
	arch := effectiveArch(archHint)
	var best, checksum ReleaseAsset
	for _, a := range assets {
		n := strings.ToLower(a.Name)
		if strings.Contains(n, "sha256") || strings.HasSuffix(n, ".sha") || strings.HasSuffix(n, ".txt") {
			if checksum.Name == "" {
				checksum = a
			}
			continue
		}
		if !strings.Contains(n, "linux") {
			continue
		}
		if !strings.Contains(n, arch) {
			continue
		}
		// Prefer the gzipped tarball/binary over .rpm / .deb — those
		// are distro-package formats, useless for OpenWrt where we
		// drop the binary into a managed dir. extractBinary expects
		// .gz / .tar.gz / .tgz — anything else fails downstream.
		if !isInstallableAsset(n) {
			continue
		}
		if strings.Contains(n, "compatible") && best.Name != "" {
			continue
		}
		best = a
	}
	if best.Name != "" {
		for _, a := range assets {
			n := strings.ToLower(a.Name)
			if strings.Contains(n, "sha256") && (strings.Contains(n, strings.ToLower(best.Name)) || checksum.Name == "") {
				checksum = a
			}
		}
	}
	return best, checksum
}
// isInstallableAsset filters to the asset shapes extractBinary can
// process. Mihomo releases include .rpm/.deb (distro packages) and
// .zip (Windows) alongside the OpenWrt-relevant .gz / .tar.gz / .tgz
// — keep only the latter so the asset selector doesn't pick a format
// that'd fail on extraction.
func isInstallableAsset(lowerName string) bool {
	return strings.HasSuffix(lowerName, ".gz") ||
		strings.HasSuffix(lowerName, ".tar.gz") ||
		strings.HasSuffix(lowerName, ".tgz")
}

func effectiveArch(h string) string {
	if h != "" {
		return strings.ToLower(h)
	}
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "arm":
		return "armv7"
	case "mipsle":
		return "mipsle"
	default:
		return runtime.GOARCH
	}
}
func download(cli *http.Client, u string) ([]byte, error) {
	resp, err := cli.Get(u)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download failed: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 128<<20))
}
func verifySHA256(data []byte, sums, asset string) error {
	h := sha256.Sum256(data)
	got := hex.EncodeToString(h[:])
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if strings.EqualFold(f[0], got) && (len(f) == 1 || strings.Contains(line, asset)) {
			return nil
		}
	}
	if strings.Contains(strings.ToLower(sums), got) {
		return nil
	}
	return fmt.Errorf("sha256 mismatch for %s", asset)
}
func extractBinary(data []byte, name string) ([]byte, error) {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".gz") && !strings.HasSuffix(lower, ".tar.gz") {
		zr, err := gzip.NewReader(strings.NewReader(string(data)))
		if err != nil {
			zr, err = gzip.NewReader(bytesReader(data))
			if err != nil {
				return nil, err
			}
		}
		defer func() { _ = zr.Close() }()
		return io.ReadAll(zr)
	}
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		zr, err := gzip.NewReader(bytesReader(data))
		if err != nil {
			return nil, err
		}
		defer func() { _ = zr.Close() }()
		tr := tar.NewReader(zr)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			base := filepath.Base(h.Name)
			if strings.Contains(strings.ToLower(base), "mihomo") && h.Typeflag == tar.TypeReg {
				return io.ReadAll(tr)
			}
		}
		return nil, fmt.Errorf("mihomo binary not found in archive")
	}
	return data, nil
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

var _ = os.FileMode(0)
