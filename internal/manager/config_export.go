package manager

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/system"
)

// ExportConfig renders the full config as portable UCI text — the same
// shape as /etc/config/purewrt, directly usable on another router. By
// default secrets are redacted (exports get pasted into issues and chats);
// includeSecrets opts into a byte-faithful dump for personal backups.
//
// Redaction lives here rather than in internal/config because it reuses
// provider.RedactURL and config must not import provider.
func (m Manager) ExportConfig(includeSecrets bool) (string, error) {
	c, err := m.Load()
	if err != nil {
		return "", err
	}
	if !includeSecrets {
		c = redactConfig(c)
	}
	return string(config.Serialize(c)), nil
}

// redactConfig strips credentials from a copy of the config: the mihomo
// controller secret, subscription/provider URLs (tokens live in the query
// string — RedactURL truncates at `?`), mirrors, and HWIDs.
func redactConfig(c config.Config) config.Config {
	if c.Settings.Secret != "" {
		c.Settings.Secret = "REDACTED"
	}
	subs := make([]config.Subscription, len(c.Subscriptions))
	copy(subs, c.Subscriptions)
	for i := range subs {
		subs[i].URL = provider.RedactURL(subs[i].URL)
		subs[i].HWID = ""
	}
	c.Subscriptions = subs
	pps := make([]config.ProxyProvider, len(c.ProxyProviders))
	copy(pps, c.ProxyProviders)
	for i := range pps {
		pps[i].URL = provider.RedactURL(pps[i].URL)
		pps[i].Mirrors = redactList(pps[i].Mirrors)
		pps[i].HWID = ""
	}
	c.ProxyProviders = pps
	rps := make([]config.RuleProvider, len(c.RuleProviders))
	copy(rps, c.RuleProviders)
	for i := range rps {
		rps[i].URL = provider.RedactURL(rps[i].URL)
		rps[i].Mirrors = redactList(rps[i].Mirrors)
	}
	c.RuleProviders = rps
	return c
}

func redactList(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = provider.RedactURL(v)
	}
	return out
}

// ImportConfigResult is the JSON reply shape for the CLI and rpcd.
type ImportConfigResult struct {
	OK       bool     `json:"ok"`
	Applied  bool     `json:"applied"` // always false — import never auto-applies
	Backup   string   `json:"backup,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ImportConfig validates the candidate config and, only if it passes,
// backs up the live file and atomically replaces it. It never applies —
// the caller decides when to `purewrt apply` so a bad import can be
// reviewed (or reverted from the .purewrt.bak) before touching routing.
func (m Manager) ImportConfig(data []byte) (ImportConfigResult, error) {
	res := ImportConfigResult{}
	if strings.TrimSpace(string(data)) == "" {
		return res, fmt.Errorf("import: empty config")
	}
	c, _ := m.Load()
	stagingDir := c.RuntimeDir()
	staged := filepath.Join(stagingDir, "import-staged.conf")
	if err := system.AtomicWrite(staged, data, 0600); err != nil {
		return res, fmt.Errorf("import: stage: %w", err)
	}
	stagedMgr := Manager{ConfigPath: staged}
	if _, err := config.Load(staged); err != nil {
		return res, fmt.Errorf("import: parse: %w", err)
	}
	if err := stagedMgr.Validate(); err != nil {
		return res, fmt.Errorf("import: validation failed: %w", err)
	}
	res.Warnings = stagedMgr.DoctorWarnings()
	if strings.Contains(string(data), "?...") {
		res.Warnings = append(res.Warnings, "imported config contains redacted URLs (\"?...\") — re-enter subscription/provider tokens before updating")
	}
	backup, err := config.Backup(m.ConfigPath)
	if err != nil {
		return res, fmt.Errorf("import: backup live config: %w", err)
	}
	res.Backup = backup
	if err := system.AtomicWrite(m.ConfigPath, data, 0600); err != nil {
		return res, fmt.Errorf("import: write: %w", err)
	}
	res.OK = true
	return res, nil
}
