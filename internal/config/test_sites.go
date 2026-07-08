package config

import (
	_ "embed"
	"encoding/json"
	"os"
)

// embeddedZapretTestSites is the built-in default probe-target list — the
// canaries the strategy tester hits when the user gives none. The purewrt-lists
// fetch writes an updated copy to ZapretTestSitesPath which overrides this, so
// the suite stays current (like the candidate list) without a code change.
//
//go:embed zapret_test_sites.json
var embeddedZapretTestSites []byte

// ZapretTestSitesPath is the on-disk override the purewrt-lists fetch writes
// (and users may hand-edit). Takes precedence over the embedded baseline.
const ZapretTestSitesPath = "/etc/purewrt/zapret_test_sites.json"

// DPISuiteURL is hyperion-cs/dpi-checkers' maintained RU TCP 16-20 suite — a
// CDN-diverse set of SNI-DPI probe hosts. Fetched + cached (as our {"sites":[]}
// shape) to DPISuitePath, then usable as an alternate probe target set.
const (
	DPISuiteURL  = "https://raw.githubusercontent.com/hyperion-cs/dpi-checkers/refs/heads/main/ru/tcp-16-20/suite.v2.json"
	DPISuitePath = "/etc/purewrt/zapret_dpi_suite.json"
)

// LoadDPISuite returns the cached DPI-checkers host list, or nil if never
// fetched (the manager fetches on demand).
func LoadDPISuite() []string {
	if data, err := os.ReadFile(DPISuitePath); err == nil {
		var l ZapretTestSiteList
		if json.Unmarshal(data, &l) == nil && len(l.Sites) > 0 {
			return l.Sites
		}
	}
	return nil
}

// ZapretTestSiteList is the zapret_test_sites.json root.
type ZapretTestSiteList struct {
	Sites []string `json:"sites"`
}

// LoadZapretTestSites resolves the probe-target list: the on-disk override at
// ZapretTestSitesPath if present and non-empty, else the embedded baseline.
// Never fails — a missing or malformed override falls back to the embed.
func LoadZapretTestSites() []string {
	if data, err := os.ReadFile(ZapretTestSitesPath); err == nil {
		var l ZapretTestSiteList
		if json.Unmarshal(data, &l) == nil && len(l.Sites) > 0 {
			return l.Sites
		}
	}
	var l ZapretTestSiteList
	_ = json.Unmarshal(embeddedZapretTestSites, &l)
	return l.Sites
}
