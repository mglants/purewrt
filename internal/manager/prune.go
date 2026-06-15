package manager

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/logging"
	"github.com/purewrt/purewrt/internal/provider"
)

// PruneOrphans loads the current config and removes provider files on disk that
// no longer correspond to any configured provider/subscription. With dryRun it
// only reports what it would remove. Used by the `prune-orphans` CLI.
func (m Manager) PruneOrphans(dryRun bool) ([]string, error) {
	c, err := m.Load()
	if err != nil {
		return nil, err
	}
	c = config.EnsureDefaults(c)
	return m.PruneOrphanProviderFiles(c, dryRun), nil
}

// PruneOrphanProviderFiles reconciles the purewrt-owned provider directories
// against the configured providers/subscriptions and removes orphans —
// rule-provider rulesets, proxy-provider/subscription files, their .meta.json
// sidecars, and per-provider artifact-cache directories. Returns the sorted
// list of removed (or, when dryRun, would-remove) absolute paths.
//
// Mirrors generator.PromoteDNSMasqFragments: build the expected set from
// config, glob the owned dir, remove anything not expected. Idempotent; a
// missing dir is a no-op. Only the three known purewrt-owned dirs are scanned,
// so a custom rp.Path pointing elsewhere is never touched.
func (m Manager) PruneOrphanProviderFiles(c config.Config, dryRun bool) []string {
	log := newLog(c)
	workdir := c.Settings.Workdir
	if workdir == "" {
		workdir = config.DefaultWorkdir
	}

	// rulesets/: keep each rule provider's file + its .meta.json sidecar.
	// Disabled providers are kept too — they're still in config.
	rulesets := map[string]struct{}{}
	for _, rp := range c.RuleProviders {
		if rp.Path == "" {
			continue
		}
		base := filepath.Base(rp.Path)
		rulesets[base] = struct{}{}
		rulesets[base+".meta.json"] = struct{}{}
	}

	// providers/: keep proxy-provider files AND each subscription's own
	// <name>.yaml (subscriptions write their provider file there), + sidecars.
	providers := map[string]struct{}{}
	for _, pp := range c.ProxyProviders {
		if pp.Path == "" {
			continue
		}
		base := filepath.Base(pp.Path)
		providers[base] = struct{}{}
		providers[base+".meta.json"] = struct{}{}
	}
	for _, s := range c.Subscriptions {
		if s.Name == "" {
			continue
		}
		providers[s.Name+".yaml"] = struct{}{}
		providers[s.Name+".yaml.meta.json"] = struct{}{}
	}

	// cache/rules/: per-provider directories named by the sanitized provider
	// name. Reuse provider.ArtifactPath so the sanitization stays in one place.
	cacheDirs := map[string]struct{}{}
	for _, rp := range c.RuleProviders {
		dir := filepath.Base(filepath.Dir(provider.ArtifactPath(workdir, rp.Name, "x")))
		cacheDirs[dir] = struct{}{}
	}

	var removed []string
	removed = append(removed, pruneDirByBasename(filepath.Join(workdir, "rulesets"), rulesets, false, dryRun, log)...)
	removed = append(removed, pruneDirByBasename(filepath.Join(workdir, "providers"), providers, false, dryRun, log)...)
	removed = append(removed, pruneDirByBasename(filepath.Join(workdir, "cache", "rules"), cacheDirs, true, dryRun, log)...)
	sort.Strings(removed)
	return removed
}

// pruneDirByBasename removes top-level entries of dir whose basename isn't in
// expected. removeAll uses os.RemoveAll (for the per-provider cache dirs);
// otherwise os.Remove (files). A non-existent dir yields no removals.
func pruneDirByBasename(dir string, expected map[string]struct{}, removeAll, dryRun bool, log logging.Logger) []string {
	matches, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return nil
	}
	var removed []string
	for _, path := range matches {
		if _, ok := expected[filepath.Base(path)]; ok {
			continue
		}
		removed = append(removed, path)
		if dryRun {
			log.Debug("prune: would remove orphan %s", path)
			continue
		}
		var rmErr error
		if removeAll {
			rmErr = os.RemoveAll(path)
		} else {
			rmErr = os.Remove(path)
		}
		if rmErr != nil {
			log.Info("prune: failed to remove orphan %s: %v", path, rmErr)
			continue
		}
		log.Debug("prune: removed orphan %s", path)
	}
	return removed
}
