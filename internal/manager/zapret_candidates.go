package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/system"
)

// FetchZapretCandidates downloads <default_lists_base_url>/zapret_candidates.json
// through the same bootstrap-resilient path as DefaultListsCatalog and writes
// it atomically to config.ZapretCandidatesPath (the override LoadZapretCandidates
// prefers). Mirrors the native-list catalog fetch so candidates update from
// purewrt-lists exactly like the rule lists.
func (m Manager) FetchZapretCandidates() error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	data, err := m.fetchFromLists(c, "zapret_candidates.json", 1<<20)
	if err != nil {
		return err
	}
	// Validate it parses + is non-empty before persisting (don't clobber a good
	// override / the embed with garbage).
	var l config.ZapretCandidateList
	if err := json.Unmarshal(data, &l); err != nil || len(l.Candidates) == 0 {
		return fmt.Errorf("fetched zapret_candidates.json is empty or invalid")
	}
	if err := os.MkdirAll(filepath.Dir(config.ZapretCandidatesPath), 0o755); err != nil {
		return err
	}
	return system.AtomicWrite(config.ZapretCandidatesPath, data, 0o644)
}

// FetchZapretTestSites downloads <default_lists_base_url>/zapret_test_sites.json
// and writes it atomically to config.ZapretTestSitesPath, so the strategy
// tester's probe-target suite stays current from purewrt-lists (like the
// candidate list). Mirrors FetchZapretCandidates.
func (m Manager) FetchZapretTestSites() error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	data, err := m.fetchFromLists(c, "zapret_test_sites.json", 1<<20)
	if err != nil {
		return err
	}
	var l config.ZapretTestSiteList
	if err := json.Unmarshal(data, &l); err != nil || len(l.Sites) == 0 {
		return fmt.Errorf("fetched zapret_test_sites.json is empty or invalid")
	}
	if err := os.MkdirAll(filepath.Dir(config.ZapretTestSitesPath), 0o755); err != nil {
		return err
	}
	return system.AtomicWrite(config.ZapretTestSitesPath, data, 0o644)
}

// FetchDPISuite downloads the hyperion-cs/dpi-checkers suite, extracts its host
// list, and caches it (as our {"sites":[]} shape) to config.DPISuitePath.
// Returns the host list.
func (m Manager) FetchDPISuite() ([]string, error) {
	c, err := m.Load()
	if err != nil {
		return nil, err
	}
	data, err := m.fetchURL(c, config.DPISuiteURL, 1<<20)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse dpi-checkers suite: %w", err)
	}
	var hosts []string
	seen := map[string]bool{}
	for _, e := range entries {
		h := strings.TrimSpace(e.Host)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("dpi-checkers suite has no hosts")
	}
	out, _ := json.MarshalIndent(config.ZapretTestSiteList{Sites: hosts}, "", "  ")
	if err := os.MkdirAll(filepath.Dir(config.DPISuitePath), 0o755); err != nil {
		return nil, err
	}
	if err := system.AtomicWrite(config.DPISuitePath, out, 0o644); err != nil {
		return nil, err
	}
	return hosts, nil
}

// DPISuiteSites returns the DPI-checkers probe hosts, using the cache when
// present and fetching (+caching) on a cold cache.
func (m Manager) DPISuiteSites() ([]string, error) {
	if s := config.LoadDPISuite(); len(s) > 0 {
		return s, nil
	}
	return m.FetchDPISuite()
}

// EnsureZapretBlobs makes every file-backed blob the enabled zapret instances
// will emit present on disk — shipped decoys resolve in place, non-shipped ones
// are fetched from purewrt-lists into the /etc cache. Called before generation
// so the generator's canonical --blob paths point at real files. A blob that
// can't be resolved fails loudly (better than emitting a dangling --blob that
// silently breaks the whole nfqws2 daemon at launch).
func (m Manager) EnsureZapretBlobs(c config.Config) error {
	var errs []string
	for _, file := range generator.ZapretRequiredBlobFiles(c) {
		if _, err := m.ResolveBlob(file, ""); err != nil {
			errs = append(errs, fmt.Sprintf("%q: %v", file, err))
		}
	}
	if len(errs) > 0 {
		// Keep trying the rest before failing so one bad blob reports every
		// missing file at once instead of one per apply attempt.
		return fmt.Errorf("zapret blobs unresolved: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ResolveBlob returns a filesystem path for a candidate's blob .bin, resolving:
//  1. a copy shipped by the zapret package (used in place, no fetch);
//  2. a previously-fetched copy under config.ZapretBlobCacheDir;
//  3. a fresh fetch of <base>/blobs/<file> → cached, sha256-verified when given.
func (m Manager) ResolveBlob(file, sha256hex string) (string, error) {
	file = filepath.Base(strings.TrimSpace(file)) // no path traversal
	if file == "" || file == "." {
		return "", fmt.Errorf("blob file is empty")
	}
	for _, d := range config.ZapretFakeDirs {
		p := filepath.Join(d, file)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	cache := filepath.Join(config.ZapretBlobCacheDir, file)
	if data, err := os.ReadFile(cache); err == nil {
		if sha256hex == "" || blobSum(data) == strings.ToLower(sha256hex) {
			return cache, nil
		}
	}
	c, err := m.Load()
	if err != nil {
		return "", err
	}
	data, err := m.fetchFromLists(c, "blobs/"+file, 4<<20)
	if err != nil {
		return "", fmt.Errorf("fetch blob %s: %w", file, err)
	}
	// A zero-byte fake is never valid nfqws2 input (and usually means the CDN
	// served an empty error body) — don't cache it as a good blob.
	if len(data) == 0 {
		return "", fmt.Errorf("blob %s fetched empty", file)
	}
	if sha256hex != "" && blobSum(data) != strings.ToLower(sha256hex) {
		return "", fmt.Errorf("blob %s sha256 mismatch", file)
	}
	if err := os.MkdirAll(config.ZapretBlobCacheDir, 0o755); err != nil {
		return "", err
	}
	if err := system.AtomicWrite(cache, data, 0o644); err != nil {
		return "", err
	}
	return cache, nil
}

// fetchFromLists downloads <default_lists_base_url>/<rel> with the same
// bootstrap-resilient options DefaultListsCatalog uses.
func (m Manager) fetchFromLists(c config.Config, rel string, maxBytes int64) ([]byte, error) {
	base := strings.TrimSpace(c.Settings.DefaultListsBaseURL)
	if base == "" {
		return nil, fmt.Errorf("default_lists_base_url is not set")
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return m.fetchURL(c, base+rel, maxBytes)
}

// fetchURL downloads an absolute URL with the same bootstrap-resilient options
// as fetchFromLists (for upstreams that aren't under default_lists_base_url,
// e.g. the DPI-checkers suite).
func (m Manager) fetchURL(c config.Config, url string, maxBytes int64) ([]byte, error) {
	proxyURL := ""
	if c.Settings.UpdateViaProxy {
		proxyURL = effectiveUpdateProxyURL(c)
	}
	d, err := provider.DownloadWithOptions(url, provider.DownloadOptions{
		Bootstrap:        bootstrapFromSettings(c.Settings),
		ProxyURL:         proxyURL,
		FallbackProxyURL: fallbackProxyURL(c, proxyURL),
		MaxBytes:         maxBytes,
	})
	if err != nil {
		return nil, err
	}
	return d.Data, nil
}

func blobSum(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}
