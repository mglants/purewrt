package ipdb

// IP-database download/refresh logic. Public-domain TSV from iptoasn.com;
// fetched at user request via `purewrt ipdb-update` or the LuCI button,
// never on background timer (we don't want a router making outbound HTTPS
// requests unprompted).

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// UpdateResult reports the outcome of one ipdb-update invocation. The
// JSON shape doubles as the rpcd reply body so LuCI can render the
// post-download status block directly.
type UpdateResult struct {
	URL          string    `json:"url"`
	SavedPath    string    `json:"saved_path"`
	BytesWritten int64     `json:"bytes_written"`
	ETag         string    `json:"etag,omitempty"`
	NotModified  bool      `json:"not_modified,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
	EntryCount   int       `json:"entry_count,omitempty"`
}

// Update downloads the iptoasn dataset to gzPath, using the cached ETag
// in <gzPath>.etag for conditional-GET so re-running on an already-fresh
// DB is essentially free (one HEAD-equivalent request, no body download).
//
// client selects the HTTP client — callers pass the bootstrap-resilient
// (and optionally proxied) client so the fetch shares the same tactics
// as provider downloads; nil falls back to a plain 5-minute client.
//
// Atomically swaps via .tmp + rename so a mid-download crash leaves the
// previous version intact.
func Update(ctx context.Context, gzPath string, client *http.Client) (UpdateResult, error) {
	res := UpdateResult{
		URL:       SourceURL,
		SavedPath: gzPath,
		UpdatedAt: time.Now().UTC(),
	}
	if err := os.MkdirAll(filepath.Dir(gzPath), 0o755); err != nil {
		return res, fmt.Errorf("ensure dir: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, SourceURL, nil)
	if err != nil {
		return res, err
	}
	// Identify ourselves so iptoasn's logs / abuse-handling can attribute
	// traffic back to PureWRT rather than seeing anonymous curl spam.
	req.Header.Set("User-Agent", "purewrt-ipdb/1 (+https://github.com/purewrt)")

	if prev, err := os.ReadFile(etagPath(gzPath)); err == nil {
		etag := strings.TrimSpace(string(prev))
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
	}

	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, fmt.Errorf("GET %s: %w", SourceURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		res.NotModified = true
		res.ETag = strings.TrimSpace(resp.Header.Get("ETag"))
		// Still report current entry count so the status block looks the
		// same as after a fresh download.
		if db, err := Load(gzPath); err == nil {
			res.EntryCount = db.Count()
		}
		if fi, err := os.Stat(gzPath); err == nil {
			res.BytesWritten = fi.Size()
		}
		return res, nil
	}
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("GET %s: HTTP %s", SourceURL, resp.Status)
	}

	tmp := gzPath + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return res, fmt.Errorf("create tmp: %w", err)
	}
	written, copyErr := io.Copy(out, resp.Body)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return res, fmt.Errorf("download body: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return res, fmt.Errorf("close tmp: %w", closeErr)
	}
	if err := os.Rename(tmp, gzPath); err != nil {
		_ = os.Remove(tmp)
		return res, fmt.Errorf("rename into place: %w", err)
	}
	res.BytesWritten = written

	// A successful combined download supersedes the legacy v4-only file —
	// remove it so GZPath stops resolving to stale data and the flash
	// space is reclaimed.
	if filepath.Base(gzPath) == combinedName {
		legacy := filepath.Join(filepath.Dir(gzPath), legacyName)
		_ = os.Remove(legacy)
		_ = os.Remove(legacy + ".etag")
	}

	if etag := strings.TrimSpace(resp.Header.Get("ETag")); etag != "" {
		// Best-effort — failure to persist the ETag means the next update
		// downloads the whole body again, no functional harm.
		_ = os.WriteFile(etagPath(gzPath), []byte(etag), 0o644)
		res.ETag = etag
	}

	if db, err := Load(gzPath); err == nil {
		res.EntryCount = db.Count()
	}
	return res, nil
}

// Status describes the on-disk DB state without loading it — used by the
// LuCI banner and the `ipdb-status` CLI subcommand to decide between
// "installed (N days old)", "not installed", and "stale".
type Status struct {
	Installed    bool      `json:"installed"`
	Path         string    `json:"path"`
	SizeBytes    int64     `json:"size_bytes,omitempty"`
	LastModified time.Time `json:"last_modified,omitempty"`
	AgeDays      int       `json:"age_days,omitempty"`
	EntryCount   int       `json:"entry_count,omitempty"`
}

// CheckStatus is cheap — stat + read of the ETag side-file. It does NOT
// fully load the database to count entries unless `loadCount` is true,
// because the LuCI banner refreshes every page load and a 100ms load on
// each refresh adds up.
func CheckStatus(gzPath string, loadCount bool) Status {
	st := Status{Path: gzPath}
	fi, err := os.Stat(gzPath)
	if err != nil {
		return st
	}
	st.Installed = true
	st.SizeBytes = fi.Size()
	st.LastModified = fi.ModTime().UTC()
	st.AgeDays = int(time.Since(fi.ModTime()).Hours() / 24)
	if loadCount {
		if db, err := Load(gzPath); err == nil {
			st.EntryCount = db.Count()
		}
	}
	return st
}

// etagPath returns the sidecar file path used to remember the last
// download's ETag for conditional-GET. Co-located with the data file so
// nuking the workdir wipes both at once.
func etagPath(gzPath string) string {
	return gzPath + ".etag"
}
