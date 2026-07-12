package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/logging"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/mihomoapi"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/rules"
	"github.com/purewrt/purewrt/internal/system"
)

// Paths the manager invokes during apply/disable. Centralised here so a
// distro repackaging PureWRT (e.g. with non-default init script names) has
// one place to override, and so the apply pipeline doesn't sprinkle the
// same /etc/init.d/* path through eight call sites.
const (
	uciPurewrtPath = "/etc/config/purewrt"
	initFirewall   = "/etc/init.d/firewall"
	initDnsmasq    = "/etc/init.d/dnsmasq"
	initMihomo     = "/etc/init.d/mihomo"
	initMwan3      = "/etc/init.d/mwan3"
	initEasytier   = "/etc/init.d/purewrt-easytier"
	libexecPeerDNS = "/usr/libexec/purewrt-peerdns"
)

type Manager struct {
	ConfigPath string
	DryRun     bool

	// mihomoReachable / mihomoReload are seams for tests; nil means use the
	// real external-controller calls (defaultMihomoReachable / defaultMihomoReload).
	// They drive the hot-reload-instead-of-restart path in reloadOrRestartMihomo.
	mihomoReachable func(config.Config) bool
	mihomoReload    func(config.Config) error
}

type commandRunner interface {
	Run(name string, args ...string) (string, error)
	RunWithTimeout(t time.Duration, name string, args ...string) (string, error)
}

// serviceRestartTimeout is the budget for daemon restart/reload commands.
// `/etc/init.d/dnsmasq restart` on a router with a large nftset config can take
// well over the 20s default; using the default caused a restart-timeout →
// rollback → retry loop (the rollback re-runs the same slow restart and the
// generation fingerprint never commits, so update-if-needed re-applies every
// run). See runServiceRestart and AGENTS.md.
const serviceRestartTimeout = 120 * time.Second

type UpdateResult struct {
	Changed bool
}

// newLog is a one-liner alias for the common pattern
// `newLog(c)` —
// previously repeated in 20+ apply/update functions across this package.
// Keeps callsites readable without changing behaviour (logging.Logger is
// a value type, construction is cheap, so we don't try to cache it on
// Manager — just stop re-typing the same two struct field accesses).
func newLog(c config.Config) logging.Logger {
	return logging.NewWithFormat(c.Settings.LogLevel, c.Settings.LogFormat)
}

func (m Manager) Load() (config.Config, error) {
	if m.ConfigPath == "" {
		m.ConfigPath = uciPurewrtPath
	}
	return config.Load(m.ConfigPath)
}
func (m Manager) Analyze(url string) (provider.Analysis, error) {
	d, err := provider.DownloadWithOptions(url, m.downloadOptionsForURL(url))
	if err != nil {
		return provider.Analysis{}, err
	}
	return provider.AnalyzeContent(url, d.Data), nil
}

func (m Manager) Import(url, name, mode, preset string) (provider.ImportPlan, error) {
	c, err := m.Load()
	if err != nil {
		return provider.ImportPlan{}, err
	}
	a, err := m.Analyze(url)
	if err != nil {
		return provider.ImportPlan{}, err
	}
	plan := provider.PlanImportWithOptions(c, url, name, mode, preset, a, provider.ImportOptions{LowResource: c.LowResource()})
	c = config.EnsureDefaults(c)
	c = config.UpsertSubscription(c, config.Subscription{Name: plan.SubscriptionName, Enabled: true, URL: url, Mode: modeOrDefault(mode), PresetIfNoRules: presetOrDefault(preset), AutoApply: true, Interval: 86400})
	for _, pp := range plan.ProxyProviders {
		c = config.UpsertProxyProvider(c, pp)
	}
	for _, rp := range plan.RuleProviders {
		c = config.UpsertRuleProvider(c, rp)
	}
	for _, sec := range plan.SectionGroups {
		c = config.UpsertSectionProxyGroup(c, sec)
	}
	for _, f := range plan.Files {
		if f.Path == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(f.Path), 0700); err != nil {
			return provider.ImportPlan{}, err
		}
		if err := system.AtomicWrite(f.Path, f.Data, 0600); err != nil {
			return provider.ImportPlan{}, err
		}
	}
	if m.ConfigPath == "" {
		m.ConfigPath = uciPurewrtPath
	}
	_, _ = config.Backup(m.ConfigPath) // best-effort; Backup warns on failure
	if err := config.Save(m.ConfigPath, c); err != nil {
		return plan, err
	}
	if c.Settings.Enabled || hasEnabledProxyProviders(c) {
		if err := generator.WriteAllToWithOptions(c, generator.DefaultGeneratedPaths(c), generator.WriteOptions{SkipFingerprint: true}); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

func (m Manager) downloadOptionsForURL(raw string) provider.DownloadOptions {
	c, err := m.Load()
	if err != nil {
		return provider.DownloadOptions{}
	}
	updateProxyURL := ""
	if c.Settings.UpdateViaProxy && !isBootstrapDownload(c, raw) {
		updateProxyURL = effectiveUpdateProxyURL(c)
	}
	bootstrap := bootstrapFromSettings(c.Settings)
	fallback := fallbackProxyURL(c, updateProxyURL)
	for _, s := range c.Subscriptions {
		if s.URL == raw {
			return provider.DownloadOptions{IncludeHWID: true, HWID: s.HWID, DeviceName: s.DeviceName, UserAgent: s.UserAgent, Headers: s.Headers, ProxyURL: updateProxyURL, Bootstrap: bootstrap, Mirrors: s.Mirrors, FallbackProxyURL: fallback, PinSHA256: s.PinSHA256, SuppressHWID: c.Settings.SuppressHWID || s.SuppressHWID}
		}
	}
	for _, p := range c.ProxyProviders {
		if p.URL == raw {
			return provider.DownloadOptions{IncludeHWID: true, HWID: p.HWID, DeviceName: p.DeviceName, UserAgent: p.UserAgent, Headers: p.Headers, ProxyURL: updateProxyURL, Bootstrap: bootstrap, Mirrors: p.Mirrors, FallbackProxyURL: fallback, PinSHA256: p.PinSHA256, SuppressHWID: c.Settings.SuppressHWID || p.SuppressHWID}
		}
	}
	for _, p := range c.RuleProviders {
		if p.URL == raw {
			return provider.DownloadOptions{ProxyURL: updateProxyURL, Bootstrap: bootstrap, Mirrors: p.Mirrors, FallbackProxyURL: fallback, PinSHA256: p.PinSHA256}
		}
	}
	// No matching subscription/provider yet (typical during the very first
	// `purewrt import` call before the URL is persisted). Default the UA to
	// the same value `UpdateDetailed` uses so the panel returns the same
	// content type both passes. Without this, panels that gate the response
	// format on UA (e.g. base64 for generic curl / Clash YAML for
	// "mihomo*") return base64 on the import-time analyze and Clash YAML
	// on the update-time re-analyze, producing two redundant proxy
	// providers (one type=http with raw bytes, one type=file with decoded
	// proxies) where only one should exist.
	return provider.DownloadOptions{ProxyURL: updateProxyURL, Bootstrap: bootstrap, FallbackProxyURL: fallback}
}

// effectiveUpdateProxyURL resolves the proxy used for provider downloads
// when update_via_proxy is on: the user's update_proxy_url when set,
// otherwise the local mihomo proxy that the generated config always opens
// (mixed-port). An empty URL therefore means "use the local mihomo proxy"
// — previously it silently disabled proxying despite the enabled flag.
func effectiveUpdateProxyURL(c config.Config) string {
	if v := strings.TrimSpace(c.Settings.UpdateProxyURL); v != "" {
		return v
	}
	return config.LocalMihomoProxyURL()
}

// updaterClients builds the HTTP clients for GitHub release fetches
// (mihomo updater) with the same tactics as provider downloads: primary =
// bootstrap DoH + optional update-via-proxy; fallback = routed through
// the local mihomo proxy for a single retry after the primary fails.
// fallback is nil when disabled or identical to the primary. timeout is
// caller-chosen (release-index checks are small, binary downloads big).
func updaterClients(c config.Config, timeout time.Duration) (primary, fallback *http.Client) {
	proxyURL := ""
	if c.Settings.UpdateViaProxy {
		proxyURL = effectiveUpdateProxyURL(c)
	}
	bc := bootstrapFromSettings(c.Settings)
	primary, _ = provider.ClientFromBootstrapTimeout(bc, proxyURL, "", timeout)
	if fb := fallbackProxyURL(c, proxyURL); fb != "" {
		fallback, _ = provider.ClientFromBootstrapTimeout(bc, fb, "", timeout)
	}
	return primary, fallback
}

// fallbackProxyURL returns the local mihomo mixed-port URL to use as a
// last-ditch fetch path after direct attempts fail. Empty when the user
// disabled the fallback or when the direct path is already proxied.
func fallbackProxyURL(c config.Config, primaryProxy string) string {
	if !c.Settings.BootstrapProxyFallback {
		return ""
	}
	candidate := effectiveUpdateProxyURL(c)
	if candidate == primaryProxy {
		return ""
	}
	return candidate
}

// pickHeader returns the fresh value if non-empty, otherwise the prior one.
// Used to retain ETag / Last-Modified across a 304 (where the server may
// omit them entirely) or transient gaps.
func pickHeader(fresh, prior string) string {
	if fresh != "" {
		return fresh
	}
	return prior
}

// bootstrapFromSettings projects the bootstrap-relevant fields of Settings
// onto the small struct that the provider package consumes. Lives here so
// the provider package never has to import config.
func bootstrapFromSettings(s config.Settings) provider.BootstrapConfig {
	timeout := time.Duration(s.BootstrapDoHTimeoutMs) * time.Millisecond
	resolvers := s.BootstrapDoHResolvers
	if len(resolvers) == 0 {
		resolvers = config.DefaultBootstrapDoHResolvers()
	}
	return provider.BootstrapConfig{
		DoHEnabled:     s.BootstrapDoHEnabled,
		DoHResolvers:   resolvers,
		DoHTimeout:     timeout,
		TLSFingerprint: s.BootstrapTLSFingerprint,
		TOFUPath:       s.BootstrapTOFUPath,
		TOFUTTL:        time.Duration(s.BootstrapTOFUTTLSec) * time.Second,
		Warn:           logging.New(s.LogLevel).Warn,
	}
}

func isBootstrapDownload(c config.Config, raw string) bool {
	for _, p := range c.ProxyProviders {
		if p.URL == raw {
			return true
		}
	}
	return false
}

func modeOrDefault(v string) string {
	if v == "" {
		return "auto"
	}
	return v
}
func presetOrDefault(v string) string {
	if v == "" {
		return "minimal"
	}
	return v
}
func (m Manager) Generate() error {
	return m.GenerateWithOptions(false)
}

func (m Manager) GenerateWithOptions(force bool) error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	c = config.EnsureDefaults(c)
	c = ResolveZapretProfileInterfaces(c)
	c = ResolveOONIUser(c)
	log := newLog(c)
	defer log.DebugTimer("generate: total")()
	log.Info("generate: start")
	defer log.Info("generate: complete")
	if err := m.EnsureZapretBlobs(c); err != nil {
		return err
	}
	if force {
		return generator.WriteAllForce(c)
	}
	return generator.WriteAll(c)
}

func (m Manager) GenerateCacheStatus() (string, error) {
	c, err := m.Load()
	if err != nil {
		return "", err
	}
	c = config.EnsureDefaults(c)
	// Resolve zapret network=auto/mwan3_members interfaces exactly as Generate
	// and applyPrepare do — otherwise this read-only status hashes the raw
	// config while generate/apply hash the resolved one, and the zapret +
	// openwrt_bundle groups report a permanent (phantom) cache miss.
	c = ResolveZapretProfileInterfaces(c)
	c = ResolveOONIUser(c)
	return generator.CacheStatus(c), nil
}

func (m Manager) CacheClean() error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	workdir := c.Settings.Workdir
	if workdir == "" {
		workdir = config.DefaultWorkdir
	}
	return os.RemoveAll(filepath.Join(workdir, "cache", "rules"))
}

func (m Manager) Update() error {
	_, err := m.UpdateDetailedWithOptions(false)
	return err
}

func (m Manager) UpdateWithOptions(force bool) error {
	_, err := m.UpdateDetailedWithOptions(force)
	return err
}

func (m Manager) UpdateRuleProvider(name string) (UpdateResult, error) {
	c, err := m.Load()
	if err != nil {
		return UpdateResult{}, err
	}
	log := newLog(c)
	defer log.DebugTimer("update-rule-provider: %s", name)()
	log.Info("update-rule-provider: %s start", name)
	now := time.Now().UTC()
	updateProxyURL := ""
	if c.Settings.UpdateViaProxy {
		updateProxyURL = effectiveUpdateProxyURL(c)
	}
	found := false
	var selected []config.RuleProvider
	for _, rp := range c.RuleProviders {
		if rp.Name == name {
			found = true
			selected = append(selected, rp)
			break
		}
	}
	if !found {
		return UpdateResult{}, fmt.Errorf("rule provider %q not found", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ruleProviderUpdateBudget)
	defer cancel()
	changed, failures, err := m.updateRuleProvidersAsync(ctx, selected, now, updateProxyURL, bootstrapFromSettings(c.Settings), fallbackProxyURL(c, updateProxyURL), c.Settings.UpdateConcurrency, true)
	if err != nil {
		log.Error("update-rule-provider: %s failed: %v", name, err)
		return UpdateResult{}, err
	}
	if len(failures) > 0 {
		log.Error("update-rule-provider: %s failed: %s", name, strings.Join(failures, "; "))
		return UpdateResult{Changed: changed}, fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	if changed || hasEnabledProxyProviders(c) {
		log.Info("update-rule-provider: %s regenerating outputs changed=%v", name, changed)
		if err := generator.WriteAllToWithOptions(c, generator.DefaultGeneratedPaths(c), generator.WriteOptions{SkipFingerprint: true}); err != nil {
			return UpdateResult{}, err
		}
	}
	log.Info("update-rule-provider: %s complete changed=%v", name, changed)
	return UpdateResult{Changed: changed}, nil
}

func (m Manager) UpdateProxyProvider(name string) (UpdateResult, error) {
	c, err := m.Load()
	if err != nil {
		return UpdateResult{}, err
	}
	log := newLog(c)
	defer log.DebugTimer("update-proxy-provider: %s", name)()
	log.Info("update-proxy-provider: %s start", name)
	found := false
	changed := false
	now := time.Now().UTC()
	updateProxyURL := ""
	if c.Settings.UpdateViaProxy {
		updateProxyURL = effectiveUpdateProxyURL(c)
	}
	for _, pp := range c.ProxyProviders {
		if pp.Name != name {
			continue
		}
		found = true
		if pp.URL == "" || pp.Path == "" {
			return UpdateResult{}, fmt.Errorf("proxy provider %q needs URL and path", name)
		}
		log.InfoFields("proxy-provider download start", "provider", pp.Name, "url", provider.RedactURL(pp.URL))
		priorMeta, _ := provider.ReadMetadata(pp.Path)
		d, err := provider.DownloadWithOptions(pp.URL, provider.DownloadOptions{IncludeHWID: true, HWID: pp.HWID, DeviceName: pp.DeviceName, UserAgent: pp.UserAgent, Headers: pp.Headers, ProxyURL: updateProxyURL, Bootstrap: bootstrapFromSettings(c.Settings), PriorETag: priorMeta.ETag, PriorLastModified: priorMeta.LastModified, Mirrors: pp.Mirrors, FallbackProxyURL: fallbackProxyURL(c, updateProxyURL), PinSHA256: pp.PinSHA256, SuppressHWID: c.Settings.SuppressHWID || pp.SuppressHWID})
		meta := provider.Metadata{URLRedacted: d.URLRedacted, LastUpdate: now, SubExpire: d.SubscriptionInfo.Expire, SubUsedBytes: d.SubscriptionInfo.UploadBytes + d.SubscriptionInfo.DownloadBytes, SubTotalBytes: d.SubscriptionInfo.TotalBytes}
		if err != nil {
			meta.ErrorMessage = err.Error()
			_ = provider.WriteMetadata(pp.Path, meta)
			log.ErrorFields("proxy-provider download failed", "provider", pp.Name, "error", err.Error())
			return UpdateResult{}, err
		}
		meta.LastSuccess = now
		meta.ETag = pickHeader(d.ETag, priorMeta.ETag)
		meta.LastModified = pickHeader(d.LastModified, priorMeta.LastModified)
		if d.NotModified {
			meta.Checksum = priorMeta.Checksum
			log.Info("proxy-provider: %s not modified (304)", pp.Name)
		} else {
			meta.Checksum = d.Checksum
			if d.Checksum != existingChecksum(pp.Path) {
				if err := system.AtomicWrite(pp.Path, d.Data, 0600); err != nil {
					return UpdateResult{}, err
				}
				changed = true
				log.Info("proxy-provider: %s changed checksum=%s bytes=%d", pp.Name, shortChecksum(d.Checksum), len(d.Data))
			} else {
				log.Info("proxy-provider: %s unchanged checksum=%s", pp.Name, shortChecksum(d.Checksum))
			}
		}
		if err := provider.WriteMetadata(pp.Path, meta); err != nil {
			return UpdateResult{}, err
		}
		break
	}
	if !found {
		return UpdateResult{}, fmt.Errorf("proxy provider %q not found", name)
	}
	if changed || hasEnabledProxyProviders(c) {
		log.Info("update-proxy-provider: %s regenerating outputs changed=%v", name, changed)
		if err := generator.WriteAllToWithOptions(c, generator.DefaultGeneratedPaths(c), generator.WriteOptions{SkipFingerprint: true}); err != nil {
			return UpdateResult{}, err
		}
	}
	log.Info("update-proxy-provider: %s complete changed=%v", name, changed)
	return UpdateResult{Changed: changed}, nil
}

func (m Manager) UpdateDetailed() (UpdateResult, error) {
	return m.UpdateDetailedWithOptions(false)
}

func (m Manager) UpdateDetailedWithOptions(force bool) (UpdateResult, error) {
	c, err := m.Load()
	if err != nil {
		return UpdateResult{}, err
	}
	log := newLog(c)
	defer log.DebugTimer("update: total")()
	log.Info("update: start subscriptions=%d proxy_providers=%d rule_providers=%d force=%v", len(c.Subscriptions), len(c.ProxyProviders), len(c.RuleProviders), force)
	changed := false
	// failures collects per-item network/parse failures so we can keep
	// processing remaining subscriptions/providers (existing on-disk
	// providers + config still apply) but still return a non-zero error
	// at the end so the init-script retry loop fires for transient
	// conditions like DNS unavailability right after a reboot.
	var failures []string
	for _, s := range c.Subscriptions {
		if !s.Enabled || !s.AutoApply || s.URL == "" {
			log.Debug("subscription: %s skipped enabled=%v auto_apply=%v url_present=%v", s.Name, s.Enabled, s.AutoApply, s.URL != "")
			continue
		}
		log.Info("subscription: %s analyze start", s.Name)
		log.Debug("subscription: %s parsing downloaded profile", s.Name)
		a, err := m.Analyze(s.URL)
		if err != nil {
			log.Error("subscription: %s analyze failed: %v", s.Name, err)
			failures = append(failures, fmt.Sprintf("subscription %s: %v", s.Name, err))
			continue
		}
		plan := provider.PlanImportWithOptions(c, s.URL, s.Name, s.Mode, s.PresetIfNoRules, a, provider.ImportOptions{LowResource: c.LowResource(), ImportRulesOnLowResource: s.ImportRulesOnLowResource})
		log.Debug("subscription: %s parsed type=%s rules=%d proxy_nodes=%d", s.Name, a.Type, a.Rules, a.ProxyNodes)
		log.Info("subscription: %s import planned proxy_providers=%d rule_providers=%d section_groups=%d files=%d", s.Name, len(plan.ProxyProviders), len(plan.RuleProviders), len(plan.SectionGroups), len(plan.Files))
		c = config.UpsertSubscription(c, config.Subscription{Name: plan.SubscriptionName, Enabled: true, URL: s.URL, Mode: modeOrDefault(s.Mode), PresetIfNoRules: presetOrDefault(s.PresetIfNoRules), ImportRulesOnLowResource: s.ImportRulesOnLowResource, AutoApply: true, Interval: s.Interval, HWID: s.HWID, DeviceName: s.DeviceName, UserAgent: s.UserAgent, Headers: s.Headers})
		for _, pp := range plan.ProxyProviders {
			c = config.UpsertProxyProvider(c, pp)
		}
		for _, rp := range plan.RuleProviders {
			c = config.UpsertRuleProvider(c, rp)
		}
		for _, sec := range plan.SectionGroups {
			c = config.UpsertSectionProxyGroup(c, sec)
		}
		for _, f := range plan.Files {
			if f.Path == "" {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(f.Path), 0700); err != nil {
				return UpdateResult{}, err
			}
			if err := system.AtomicWrite(f.Path, f.Data, 0600); err != nil {
				return UpdateResult{}, err
			}
			log.Debug("subscription: %s wrote imported file path=%s bytes=%d", s.Name, f.Path, len(f.Data))
		}
		changed = true
	}
	if changed {
		c = config.EnsureDefaults(c)
		if m.ConfigPath == "" {
			m.ConfigPath = uciPurewrtPath
		}
		_, _ = config.Backup(m.ConfigPath) // best-effort; Backup warns on failure
		if err := config.Save(m.ConfigPath, c); err != nil {
			return UpdateResult{}, err
		}
	}
	now := time.Now().UTC()
	updateProxyURL := ""
	if c.Settings.UpdateViaProxy {
		updateProxyURL = effectiveUpdateProxyURL(c)
	}
	for _, pp := range c.ProxyProviders {
		if !pp.Enabled || pp.URL == "" || pp.Path == "" {
			log.Debug("proxy-provider: %s skipped enabled=%v url_present=%v path_present=%v", pp.Name, pp.Enabled, pp.URL != "", pp.Path != "")
			continue
		}
		if !force && !shouldUpdate(now, pp.Path, pp.Interval) {
			log.Debug("proxy-provider: %s skipped interval not due path=%s", pp.Name, pp.Path)
			continue
		}
		log.Info("proxy-provider: %s download start", pp.Name)
		priorMeta, _ := provider.ReadMetadata(pp.Path)
		d, err := provider.DownloadWithOptions(pp.URL, provider.DownloadOptions{IncludeHWID: true, HWID: pp.HWID, DeviceName: pp.DeviceName, UserAgent: pp.UserAgent, Headers: pp.Headers, ProxyURL: updateProxyURL, Bootstrap: bootstrapFromSettings(c.Settings), PriorETag: priorMeta.ETag, PriorLastModified: priorMeta.LastModified, Mirrors: pp.Mirrors, FallbackProxyURL: fallbackProxyURL(c, updateProxyURL), PinSHA256: pp.PinSHA256, SuppressHWID: c.Settings.SuppressHWID || pp.SuppressHWID})
		meta := provider.Metadata{URLRedacted: d.URLRedacted, LastUpdate: now, LastSuccess: now, Checksum: d.Checksum, ETag: pickHeader(d.ETag, priorMeta.ETag), LastModified: pickHeader(d.LastModified, priorMeta.LastModified), SubExpire: d.SubscriptionInfo.Expire, SubUsedBytes: d.SubscriptionInfo.UploadBytes + d.SubscriptionInfo.DownloadBytes, SubTotalBytes: d.SubscriptionInfo.TotalBytes}
		if d.NotModified {
			meta.Checksum = priorMeta.Checksum
		}
		if err != nil {
			meta.ErrorMessage = err.Error()
			_ = provider.WriteMetadata(pp.Path, meta)
			log.Error("proxy-provider: %s download failed: %v", pp.Name, err)
			failures = append(failures, fmt.Sprintf("proxy-provider %s: %v", pp.Name, err))
			continue
		}
		if d.NotModified {
			if err := provider.WriteMetadata(pp.Path, meta); err != nil {
				return UpdateResult{}, err
			}
			log.Info("proxy-provider: %s not modified (304)", pp.Name)
			continue
		}
		if d.Checksum == existingChecksum(pp.Path) {
			if err := provider.WriteMetadata(pp.Path, meta); err != nil {
				return UpdateResult{}, err
			}
			log.Info("proxy-provider: %s unchanged checksum=%s", pp.Name, shortChecksum(d.Checksum))
			continue
		}
		if err := system.AtomicWrite(pp.Path, d.Data, 0600); err != nil {
			return UpdateResult{}, err
		}
		if err := provider.WriteMetadata(pp.Path, meta); err != nil {
			return UpdateResult{}, err
		}
		log.Info("proxy-provider: %s changed checksum=%s bytes=%d", pp.Name, shortChecksum(d.Checksum), len(d.Data))
		changed = true
	}
	rpCtx, rpCancel := context.WithTimeout(context.Background(), ruleProviderUpdateBudget)
	defer rpCancel()
	rpChanged, rpFailures, err := m.updateRuleProvidersAsync(rpCtx, c.RuleProviders, now, updateProxyURL, bootstrapFromSettings(c.Settings), fallbackProxyURL(c, updateProxyURL), c.Settings.UpdateConcurrency, force)
	if err != nil {
		// Hard error (e.g., disk write failure for ALL providers); abort.
		return UpdateResult{}, err
	}
	if rpChanged {
		changed = true
	}
	failures = append(failures, rpFailures...)
	if changed || hasEnabledProxyProviders(c) {
		log.Info("update: regenerating outputs changed=%v", changed)
		if err := generator.WriteAllToWithOptions(c, generator.DefaultGeneratedPaths(c), generator.WriteOptions{Force: force, SkipFingerprint: true}); err != nil {
			return UpdateResult{}, err
		}
	}
	log.Info("update: complete changed=%v failures=%d", changed, len(failures))
	// Expiry sweep, failure push and metrics dump are all best-effort;
	// none affects the update result or exit code.
	m.notifySubscriptionExpiry(c)
	dumpMetrics(c)
	if len(failures) > 0 {
		m.notify(c, "update_failure", fmt.Sprintf("%d provider(s) failed: %s", len(failures), strings.Join(failures, "; ")))
		// Return Changed=<whatever-succeeded> AND a non-nil error. The
		// caller (cmd/purewrt/main.go::update-if-needed) propagates the
		// non-zero exit so the shell-level retry loop in init.d/purewrt
		// fires. Apply runs separately at boot via `apply --force`, so
		// existing on-disk providers + config are still serving traffic
		// while we wait for the retry to succeed. Wrapping ErrPartialUpdate
		// lets the CLI exit 3 instead of 1 so operators can tell
		// "soft-continue, retry will heal" from a hard failure.
		return UpdateResult{Changed: changed}, fmt.Errorf("update: %d provider(s) failed: %s: %w", len(failures), strings.Join(failures, "; "), ErrPartialUpdate)
	}
	return UpdateResult{Changed: changed}, nil
}

// ErrPartialUpdate marks soft-continue update failures: one or more
// providers failed, but everything that succeeded is already on disk and
// the previous artifacts keep serving traffic. Callers map this to a
// distinct exit code (3) so the init-script retry loop and operators can
// tell "retry will heal" apart from "the operation never ran".
var ErrPartialUpdate = errors.New("partial update failure")

type ruleProviderDownloadResult struct {
	rp      config.RuleProvider
	data    provider.DownloadResult
	meta    provider.Metadata
	changed bool
	err     error
}

// ruleProviderUpdateBudget bounds the whole rule-provider fan-out. One wedged
// download (a mirror that accepts the connection and never responds through
// every fallback) must not stall `purewrt update` indefinitely — cron re-runs
// would pile up coalesced behind the operation lock.
const ruleProviderUpdateBudget = 10 * time.Minute

func (m Manager) updateRuleProvidersAsync(ctx context.Context, ruleProviders []config.RuleProvider, now time.Time, updateProxyURL string, bootstrap provider.BootstrapConfig, fallbackProxy string, concurrency int, force bool) (bool, []string, error) {
	log := logging.New(m.logLevel())
	c, _ := m.Load()
	// Materialize geo-backed providers first — they don't need the
	// HTTP fetch dance, they read directly from the local v2ray dat
	// that the geo-refresh cron populates. Tracking the changed flag
	// + failures inline so the downstream loop returns one combined
	// result.
	geoChanged := false
	var geoFailures []string
	var urlJobs []config.RuleProvider
	// Self-heal: a geo provider can't materialize without its source .dat, and
	// nothing else guarantees the .dat is present (geo-refresh is otherwise
	// manual). Without this, a freshly-added geoip/geosite provider fails every
	// update (→ partial-failure exit 3 → retry loop) until the user manually
	// refreshes. If any enabled geo provider's .dat is missing, fetch geo data
	// once now (best-effort) so the materialize below succeeds. No-op once the
	// .dat exists, so steady-state updates pay nothing.
	if geoProvidersNeedData(c, ruleProviders) {
		log.Info("rule-provider: geo data missing for an enabled geo provider; running geo-refresh once")
		if _, err := m.GeoRefresh(); err != nil {
			log.Warn("rule-provider: geo-refresh failed: %v — geo providers may not materialize this run", err)
		}
	}
	for _, rp := range ruleProviders {
		if !rp.Enabled {
			log.Debug("rule-provider: %s skipped enabled=false", rp.Name)
			continue
		}
		if provider.IsGeoFormat(rp.Format) {
			changed, err := m.materializeGeoProvider(c, rp, log)
			if err != nil {
				geoFailures = append(geoFailures, fmt.Sprintf("rule-provider %s: %v", rp.Name, err))
				continue
			}
			if changed {
				geoChanged = true
			}
			continue
		}
		if rp.URL == "" || rp.Path == "" {
			log.Debug("rule-provider: %s skipped url_present=%v path_present=%v", rp.Name, rp.URL != "", rp.Path != "")
			continue
		}
		if !force && !shouldUpdate(now, rp.Path, rp.Interval) {
			log.Debug("rule-provider: %s skipped interval not due path=%s", rp.Name, rp.Path)
			continue
		}
		urlJobs = append(urlJobs, rp)
	}
	jobs := urlJobs
	if len(jobs) == 0 {
		log.Info("rule-provider: no jobs queued")
		return false, nil, nil
	}
	if concurrency <= 0 {
		concurrency = 2
	}
	if concurrency > 8 {
		concurrency = 8
	}
	log.Info("rule-provider: jobs queued=%d concurrency=%d force=%v", len(jobs), concurrency, force)
	results := make(chan ruleProviderDownloadResult, len(jobs))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, rp := range jobs {
		wg.Add(1)
		go func() {
			defer log.DebugTimer("rule-provider: %s download", rp.Name)()
			defer wg.Done()
			// Honour cancellation while queued and before starting the
			// download — once the budget/caller cancels, remaining jobs
			// report a soft failure instead of firing new fetches.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results <- ruleProviderDownloadResult{rp: rp, meta: provider.Metadata{ErrorMessage: ctx.Err().Error()}, err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			if err := ctx.Err(); err != nil {
				results <- ruleProviderDownloadResult{rp: rp, meta: provider.Metadata{ErrorMessage: err.Error()}, err: err}
				return
			}
			log.Info("rule-provider: %s download start", rp.Name)
			priorMeta, _ := provider.ReadMetadata(rp.Path)
			d, err := provider.DownloadWithOptions(rp.URL, provider.DownloadOptions{UserAgent: rp.UserAgent, Headers: rp.Headers, ProxyURL: updateProxyURL, Bootstrap: bootstrap, PriorETag: priorMeta.ETag, PriorLastModified: priorMeta.LastModified, Mirrors: rp.Mirrors, FallbackProxyURL: fallbackProxy, PinSHA256: rp.PinSHA256})
			meta := provider.Metadata{URLRedacted: d.URLRedacted, LastUpdate: now, SubExpire: d.SubscriptionInfo.Expire, SubUsedBytes: d.SubscriptionInfo.UploadBytes + d.SubscriptionInfo.DownloadBytes, SubTotalBytes: d.SubscriptionInfo.TotalBytes}
			if err != nil {
				meta.ErrorMessage = err.Error()
				log.Error("rule-provider: %s download failed: %v", rp.Name, err)
				results <- ruleProviderDownloadResult{rp: rp, meta: meta, err: err}
				return
			}
			meta.LastSuccess = now
			meta.ETag = pickHeader(d.ETag, priorMeta.ETag)
			meta.LastModified = pickHeader(d.LastModified, priorMeta.LastModified)
			if d.NotModified {
				meta.Checksum = priorMeta.Checksum
				meta.EntryCount = priorMeta.EntryCount
				log.Info("rule-provider: %s not modified (304) entries=%d", rp.Name, meta.EntryCount)
				results <- ruleProviderDownloadResult{rp: rp, data: d, meta: meta, changed: false}
				return
			}
			changed := d.Checksum != existingChecksum(rp.Path)
			meta.Checksum = d.Checksum
			if !changed {
				meta.EntryCount = priorMeta.EntryCount
				log.Info("rule-provider: %s unchanged checksum=%s entries=%d", rp.Name, shortChecksum(d.Checksum), meta.EntryCount)
				results <- ruleProviderDownloadResult{rp: rp, data: d, meta: meta, changed: false}
				return
			}
			analysis := provider.AnalyzeContent(rp.URL, d.Data)
			meta.EntryCount = analysis.Rules
			log.Debug("rule-provider: %s parsed type=%s rules=%d", rp.Name, analysis.Type, analysis.Rules)
			log.Info("rule-provider: %s changed checksum=%s entries=%d bytes=%d", rp.Name, shortChecksum(d.Checksum), meta.EntryCount, len(d.Data))
			results <- ruleProviderDownloadResult{rp: rp, data: d, meta: meta, changed: true}
		}()
	}
	wg.Wait()
	close(results)
	changed := false
	// Per-provider failures are soft — log + record but keep processing
	// the other results. Caller aggregates these into the update-level
	// failure list so the init-script retry loop can re-run later.
	var failures []string
	for res := range results {
		if res.err != nil {
			_ = provider.WriteMetadata(res.rp.Path, res.meta)
			failures = append(failures, fmt.Sprintf("rule-provider %s: %v", res.rp.Name, res.err))
			continue
		}
		if res.changed {
			if err := system.AtomicWrite(res.rp.Path, res.data.Data, 0600); err != nil {
				failures = append(failures, fmt.Sprintf("rule-provider %s: write failed: %v", res.rp.Name, err))
				continue
			}
			// MRS providers are now consumed via the streaming walker in
			// internal/generator/stream.go::streamMRSData — that path
			// bypasses the artifact cache entirely, so writing a 4.8 MB
			// pre-materialised artifact for the big MRS files is pure
			// disk + I/O waste. Skip for MRS; keep for text/native where
			// the cache still feeds the artifact-cache-hit path.
			if m.artifactCacheEnabled() && m.shouldWriteArtifact(res.rp, len(res.data.Data)) && !strings.EqualFold(res.rp.Format, "mrs") {
				artifactMeta, err := provider.EnsureArtifact(m.artifactWorkdir(), res.rp.Name, res.rp.Format, res.meta.Checksum, res.data.Data)
				if err != nil {
					failures = append(failures, fmt.Sprintf("rule-provider %s: artifact failed: %v", res.rp.Name, err))
					continue
				}
				if res.meta.EntryCount == 0 {
					res.meta.EntryCount = artifactMeta.EntryCount
				}
				log.Debug("rule-provider: %s artifact ensured entries=%d", res.rp.Name, artifactMeta.EntryCount)
			}
			changed = true
		}
		if err := provider.WriteMetadata(res.rp.Path, res.meta); err != nil {
			failures = append(failures, fmt.Sprintf("rule-provider %s: metadata write failed: %v", res.rp.Name, err))
			continue
		}
		log.Debug("rule-provider: %s metadata written", res.rp.Name)
	}
	if m.artifactCacheEnabled() {
		_ = m.cleanupArtifactCache()
	}
	if geoChanged {
		changed = true
	}
	if len(geoFailures) > 0 {
		failures = append(geoFailures, failures...)
	}
	return changed, failures, nil
}

// materializeGeoProvider extracts the geo target (geosite category or
// geoip country) into the same text-format rule file path that URL-
// backed text providers use. The rest of the system reads from
// rp.Path uniformly, so this keeps stream.go / nftset emission /
// dnsmasq directive emission unchanged. Returns (changed, error)
// where changed is true when the on-disk content differs from the
// previous write.
// geoProvidersNeedData reports whether any enabled geo-format rule provider's
// source v2ray .dat (geoip.dat / geosite.dat) is absent from the geo dir, in
// which case materializeGeoProvider would fail. Drives the one-time geo-refresh
// in updateRuleProvidersAsync.
func geoProvidersNeedData(c config.Config, ruleProviders []config.RuleProvider) bool {
	dir := c.Settings.GeoRefreshGeoIPDir
	if dir == "" {
		dir = "/etc/purewrt/geo"
	}
	for _, rp := range ruleProviders {
		if !rp.Enabled || !provider.IsGeoFormat(rp.Format) {
			continue
		}
		var dat string
		switch rp.Format {
		case "geosite":
			dat = filepath.Join(dir, "geosite.dat")
		case "geoip":
			dat = filepath.Join(dir, "geoip.dat")
		default:
			continue
		}
		if _, err := os.Stat(dat); err != nil {
			return true
		}
	}
	return false
}

func (m Manager) materializeGeoProvider(c config.Config, rp config.RuleProvider, log logging.Logger) (bool, error) {
	prov, err := provider.ParseGeoProvider(c, rp)
	if err != nil {
		return false, err
	}
	body := serializeRulesText(prov.Rules)
	prior, _ := os.ReadFile(rp.Path)
	changed := !bytes.Equal(prior, body)
	if err := system.AtomicWrite(rp.Path, body, 0o600); err != nil {
		return false, fmt.Errorf("write %s: %w", rp.Path, err)
	}
	sum := sha256.Sum256(body)
	meta := provider.Metadata{LastUpdate: time.Now(), LastSuccess: time.Now(), Checksum: fmt.Sprintf("%x", sum), EntryCount: len(prov.Rules)}
	if err := provider.WriteMetadata(rp.Path, meta); err != nil {
		return false, fmt.Errorf("write metadata: %w", err)
	}
	for _, w := range prov.Warnings {
		log.Info("rule-provider: %s %s", rp.Name, w)
	}
	log.Info("rule-provider: %s %s/%s entries=%d changed=%v", rp.Name, rp.Format, rp.GeoTarget, len(prov.Rules), changed)
	return changed, nil
}

// serializeRulesText writes one rule per line in the same syntax the
// text parser accepts on the read side (rules.ParseText). The
// roundtrip is dumb-equal for the three rule types we emit; future
// rule types would extend this.
func serializeRulesText(rs []rules.Rule) []byte {
	var b bytes.Buffer
	for _, r := range rs {
		switch r.Type {
		case rules.Domain:
			fmt.Fprintf(&b, "DOMAIN,%s\n", r.Value)
		case rules.DomainSuffix:
			fmt.Fprintf(&b, "DOMAIN-SUFFIX,%s\n", r.Value)
		case rules.DomainKeyword:
			fmt.Fprintf(&b, "DOMAIN-KEYWORD,%s\n", r.Value)
		case rules.IPCIDR:
			fmt.Fprintf(&b, "IP-CIDR,%s,no-resolve\n", r.Value)
		case rules.IPCIDR6:
			fmt.Fprintf(&b, "IP-CIDR6,%s,no-resolve\n", r.Value)
		}
	}
	return b.Bytes()
}

func (m Manager) shouldWriteArtifact(_ config.RuleProvider, size int) bool {
	c, err := m.Load()
	if err != nil {
		return true
	}
	if c.LowResource() {
		return false
	}
	maxBytes := c.Settings.ArtifactCacheMaxBytes
	if maxBytes > 0 && int64(size) > maxBytes {
		return false
	}
	return true
}

func (m Manager) artifactWorkdir() string {
	c, err := m.Load()
	if err != nil {
		return config.DefaultWorkdir
	}
	return c.CacheDir()
}

func (m Manager) artifactCacheEnabled() bool {
	c, err := m.Load()
	if err != nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(c.Settings.ArtifactCacheMode)) {
	case "off", "disabled", "0", "false":
		return false
	case "on", "enabled", "1", "true":
		return true
	default:
		return !strings.EqualFold(c.Settings.CacheMode, "off")
	}
}

func (m Manager) cleanupArtifactCache() error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	// Live map: one entry per configured provider (enabled or not — a
	// disabled provider may be re-enabled and its artifact is still valid),
	// so superseded checksums and removed providers get pruned instead of
	// accumulating on flash below the byte cap forever.
	live := make(map[string]string, len(c.RuleProviders))
	for _, rp := range c.RuleProviders {
		live[rp.Name] = provider.ArtifactChecksum(rp.Path)
	}
	_, err = provider.CleanupArtifacts(c.CacheDir(), provider.CacheLimits{MaxBytes: c.Settings.ArtifactCacheMaxBytes, MaxEntries: c.Settings.ArtifactCacheMaxEntries, Live: live})
	return err
}

func (m Manager) logLevel() string {
	c, err := m.Load()
	if err != nil {
		return "warn"
	}
	return c.Settings.LogLevel
}

func shortChecksum(v string) string {
	if len(v) <= 12 {
		return v
	}
	return v[:12]
}

func existingChecksum(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

func shouldUpdate(now time.Time, path string, interval int) bool {
	if interval <= 0 || path == "" {
		return true
	}
	st, err := os.Stat(path)
	if err != nil {
		return true
	}
	return now.Sub(st.ModTime()) >= time.Duration(interval)*time.Second
}

func hasEnabledProxyProviders(c config.Config) bool {
	for _, p := range c.ProxyProviders {
		if p.Enabled {
			return true
		}
	}
	return false
}
func (m Manager) Validate() error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	if err := validateConfigHardening(c); err != nil {
		return err
	}
	if c.Settings.FakeIP {
		return fmt.Errorf("fake-ip is not default-safe; disable or use advanced mode")
	}
	if strings.Contains(string(generator.NFTables(c)), "meta mark set "+c.Settings.FwMark+" ") {
		return fmt.Errorf("nft rules overwrite marks instead of OR")
	}
	if err := validateZapretProfileMarks(c); err != nil {
		return err
	}
	return nil
}

var (
	safeIdentRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
	safeNFTIdentRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	safeIfaceRE     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	safeProviderRE  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	unsafePathParts = regexp.MustCompile(`(^|/)\.\.(/|$)`)
)

// mihomoReservedGroupNames are proxy-group names the generated mihomo.yaml
// cannot use: mihomo's built-in proxies/groups plus the groups PureWRT itself
// always emits (DNSProxy, NetCheckProbe). A section proxy_group colliding with
// any of these fails mihomo config validation after apply.
var mihomoReservedGroupNames = map[string]bool{
	"GLOBAL": true, "DIRECT": true, "REJECT": true, "REJECT-DROP": true,
	"PASS": true, "COMPATIBLE": true, "DNSProxy": true, "NetCheckProbe": true,
}

func validateConfigHardening(c config.Config) error {
	if err := validateHexField("fwmark", c.Settings.FwMark, true); err != nil {
		return err
	}
	if err := validateHexField("fwmark_mask", c.Settings.FwMarkMask, true); err != nil {
		return err
	}
	if err := validateNumericRange("route_table", c.Settings.RouteTable, 1, 4294967295); err != nil {
		return err
	}
	if err := validateNumericRange("ip_rule_priority", c.Settings.IPRulePriority, 0, 32767); err != nil {
		return err
	}
	if c.Settings.UpdateConcurrency < 0 || c.Settings.UpdateConcurrency > 8 {
		return fmt.Errorf("update_concurrency must be between 0 and 8")
	}
	for _, listen := range []struct{ name, value string }{{"dns_listen", c.Settings.DNSListen}, {"dns.listen", c.DNS.Listen}} {
		if listen.value != "" {
			if err := validateHostPort(listen.name, listen.value); err != nil {
				return err
			}
		}
	}
	for _, addr := range c.Settings.APIListen {
		if err := validateHostPort("api_listen", addr); err != nil {
			return err
		}
	}
	groupOwner := map[string]string{}
	for _, s := range c.Sections {
		if !safeIdentRE.MatchString(s.Name) {
			return fmt.Errorf("section %q has unsafe name", s.Name)
		}
		if s.Enabled && s.Action == "proxy" {
			if mihomoReservedGroupNames[s.ProxyGroup] {
				return fmt.Errorf("section %q proxy_group %q is a reserved mihomo/PureWRT group name; choose another", s.Name, s.ProxyGroup)
			}
			if prev := groupOwner[s.ProxyGroup]; prev != "" {
				return fmt.Errorf("section %q proxy_group %q duplicates section %q — mihomo group names must be unique", s.Name, s.ProxyGroup, prev)
			}
			groupOwner[s.ProxyGroup] = s.Name
		}
		if !safeNFTIdentRE.MatchString(s.NFTSet4()) || !safeNFTIdentRE.MatchString(s.NFTSet6()) {
			return fmt.Errorf("section %q generates unsafe nft set name", s.Name)
		}
		if !knownValue(s.Action, "proxy", "direct", "reject", "zapret") {
			return fmt.Errorf("section %q has unsupported action %q", s.Name, s.Action)
		}
		if s.UDPMode != "" && !knownValue(s.UDPMode, "proxy", "direct", "reject", "block_quic", "block", "off") {
			return fmt.Errorf("section %q has unsupported udp_mode %q", s.Name, s.UDPMode)
		}
		if s.Enabled && s.Action == "proxy" {
			if err := validatePort("section "+s.Name+" tproxy_port", s.TPROXYPort, 1, 65535); err != nil {
				return err
			}
		}
		if s.Enabled && s.Action == "zapret" && len(s.ZapretStrategies) == 0 {
			return fmt.Errorf("section %q action zapret requires at least one zapret_strategy", s.Name)
		}
		// Cross-action zapret bleed: zapret NFQUEUE only makes sense for
		// traffic that exits unchanged on the WAN. If a section's action
		// pushes traffic through a TPROXY listener (proxy/vpn), nfqws2 will
		// see the OUTER tunnelled flow and either no-op (already encrypted
		// by the proxy outbound) or, worse, desync the encrypted wrapper —
		// which breaks the proxy itself. Reject the misconfig at validate
		// time so the user sees a clear error instead of mysterious
		// connection resets after apply.
		if s.Enabled && len(s.ZapretStrategies) > 0 && s.Action == "proxy" {
			return fmt.Errorf("section %q has action=%q AND zapret_strategies set — zapret only applies to direct traffic; either drop the strategies or change the section's action to direct/zapret", s.Name, s.Action)
		}
	}
	for _, rp := range c.RuleProviders {
		if err := validateProviderSafety("rule provider", rp.Name, rp.Path); err != nil {
			return err
		}
	}
	providerSeen := map[string]bool{}
	for _, pp := range c.ProxyProviders {
		if err := validateProviderSafety("proxy provider", pp.Name, pp.Path); err != nil {
			return err
		}
		// mihomo hard-rejects a proxy-provider named "default" (its internal
		// provider holding all static proxies) — fail here with a clear
		// message instead of the post-apply rollback loop.
		if pp.Name == "default" {
			return fmt.Errorf("proxy provider name %q is reserved by mihomo; rename the provider (e.g. \"main\")", pp.Name)
		}
		if providerSeen[pp.Name] {
			return fmt.Errorf("duplicate proxy provider name %q — provider names must be unique", pp.Name)
		}
		providerSeen[pp.Name] = true
	}
	for _, v := range c.VPNs {
		if !safeProviderRE.MatchString(v.Name) {
			return fmt.Errorf("vpn %q has unsafe name", v.Name)
		}
		if v.Interface != "" && !safeIfaceRE.MatchString(v.Interface) {
			return fmt.Errorf("vpn %q has unsafe interface %q", v.Name, v.Interface)
		}
	}
	for _, p := range c.EnabledZapretProfiles() {
		if !safeProviderRE.MatchString(p.Name) {
			return fmt.Errorf("zapret profile %q has unsafe name", p.Name)
		}
		for _, iface := range p.Interfaces {
			if iface != "" && !safeIfaceRE.MatchString(iface) {
				return fmt.Errorf("zapret profile %q has unsafe interface %q", p.Name, iface)
			}
		}
		if err := validateHexField("zapret profile "+p.Name+" fwmark", p.FwMark, true); err != nil {
			return err
		}
	}
	if err := validateZapretStrategies(c); err != nil {
		return err
	}
	return nil
}

func validateZapretStrategies(c config.Config) error {
	profiles := map[string]bool{}
	for _, p := range c.EnabledZapretProfiles() {
		profiles[p.Name] = true
	}
	strategies := map[string]config.ZapretStrategy{}
	queues := map[int]string{}
	for i, raw := range c.ZapretStrategies {
		zs := c.NormalizeZapretStrategyAt(raw, i)
		if !zs.Enabled {
			continue
		}
		if !safeProviderRE.MatchString(zs.Name) {
			return fmt.Errorf("zapret strategy %q has unsafe name", zs.Name)
		}
		if !profiles[zs.Profile] {
			return fmt.Errorf("zapret strategy %q references missing profile %q", zs.Name, zs.Profile)
		}
		if err := validatePort("zapret strategy "+zs.Name+" queue_num", zs.QueueNum, 0, 65535); err != nil {
			return err
		}
		if prev := queues[zs.QueueNum]; prev != "" {
			return fmt.Errorf("zapret strategy %q duplicates queue_num %d used by %q", zs.Name, zs.QueueNum, prev)
		}
		queues[zs.QueueNum] = zs.Name
		for _, proto := range zs.Protocols {
			if !knownValue(strings.ToLower(strings.TrimSpace(proto)), "tcp", "udp") {
				return fmt.Errorf("zapret strategy %q has unsupported protocol %q", zs.Name, proto)
			}
		}
		if protocolListHas(zs.Protocols, "tcp") {
			if err := validatePortList("zapret strategy "+zs.Name+" tcp_ports", zs.TCPPorts); err != nil {
				return err
			}
		}
		if protocolListHas(zs.Protocols, "udp") {
			if err := validatePortList("zapret strategy "+zs.Name+" udp_ports", zs.UDPPorts); err != nil {
				return err
			}
		}
		strategies[zs.Name] = zs
	}
	for _, sec := range c.Sections {
		if !sec.Enabled || sec.Action != "zapret" {
			continue
		}
		for _, name := range sec.ZapretStrategies {
			if _, ok := strategies[name]; !ok {
				return fmt.Errorf("section %q references missing zapret strategy %q", sec.Name, name)
			}
		}
	}
	return nil
}

func protocolListHas(v []string, want string) bool {
	for _, x := range v {
		if strings.EqualFold(strings.TrimSpace(x), want) {
			return true
		}
	}
	return false
}

func validatePortList(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return fmt.Errorf("%s has empty port item", name)
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return fmt.Errorf("%s has invalid port range %q", name, part)
		}
		for _, b := range bounds {
			n, err := strconv.Atoi(strings.TrimSpace(b))
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("%s has invalid port %q", name, b)
			}
		}
	}
	return nil
}

func validateHexField(name, value string, required bool) error {
	if strings.TrimSpace(value) == "" && !required {
		return nil
	}
	if _, ok := parseHexMark(value); !ok {
		return fmt.Errorf("%s has invalid hex value %q", name, value)
	}
	return nil
}

func validateNumericRange(name, value string, min, max uint64) error {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil || n < min || n > max {
		return fmt.Errorf("%s must be numeric in range %d-%d", name, min, max)
	}
	return nil
}

func validatePort(name string, value, min, max int) error {
	if value < min || value > max {
		return fmt.Errorf("%s must be in range %d-%d", name, min, max)
	}
	return nil
}

func validateHostPort(name, value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return fmt.Errorf("%s must be host:port", name)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%s has invalid port", name)
	}
	return nil
}

func validateProviderSafety(kind, name, path string) error {
	if !safeProviderRE.MatchString(name) {
		return fmt.Errorf("%s %q has unsafe name", kind, name)
	}
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\x00\n\r") || unsafePathParts.MatchString(path) {
		return fmt.Errorf("%s %q has unsafe path", kind, name)
	}
	return nil
}

func knownValue(v string, allowed ...string) bool {
	return slices.Contains(allowed, v)
}

func validateZapretProfileMarks(c config.Config) error {
	pureMark, pureMarkOK := parseHexMark(c.Settings.FwMark)
	pureMask, pureMaskOK := parseHexMark(c.Settings.FwMarkMask)
	for _, p := range c.EnabledZapretProfiles() {
		zapretMark, ok := parseHexMark(p.FwMark)
		if !ok || zapretMark == 0 {
			return fmt.Errorf("zapret profile %q has invalid fwmark %q", p.Name, p.FwMark)
		}
		if pureMarkOK && pureMaskOK && pureMask != 0 && zapretMark&pureMask == pureMark&pureMask {
			return fmt.Errorf("zapret profile %q fwmark %s overlaps PureWRT fwmark %s/%s", p.Name, p.FwMark, c.Settings.FwMark, c.Settings.FwMarkMask)
		}
		// VPNs no longer carry an fwmark (routed via mihomo, not kernel marks),
		// so there's no VPN↔zapret mark overlap to check.
	}
	return nil
}

func parseHexMark(v string) (uint64, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "0x")
	v = strings.TrimPrefix(v, "0X")
	if v == "" {
		return 0, false
	}
	var n uint64
	for _, r := range v {
		n <<= 4
		switch {
		case r >= '0' && r <= '9':
			n |= uint64(r - '0')
		case r >= 'a' && r <= 'f':
			n |= uint64(r-'a') + 10
		case r >= 'A' && r <= 'F':
			n |= uint64(r-'A') + 10
		default:
			return 0, false
		}
	}
	return n, true
}

func (m Manager) Apply() error {
	return m.ApplyWithOptions(false)
}

func (m Manager) ApplyWithOptions(force bool) error {
	applyStart := time.Now()
	c, backup, staged, gen, cleanup, err := m.applyPrepare(force)
	if err != nil {
		metrics.ApplyTotal.WithLabelValues("prepare_error")
		return err
	}
	// Observe duration for every completed attempt (outcome lives in
	// ApplyTotal) and persist the registry for purewrt-api's /metrics —
	// observations happen in this CLI process, scrapes in the daemon.
	defer func() {
		metrics.ApplyDurationMS.Observe(float64(time.Since(applyStart).Milliseconds()))
		dumpMetrics(c)
	}()
	log := newLog(c)
	defer log.DebugTimer("apply: total")()
	log.Warn("apply: start")
	defer cleanup()
	r := system.Runner{DryRun: m.DryRun}
	if err := m.applyWithRunner(c, backup, staged, gen, r); err != nil {
		log.Error("apply: failed: %v", err)
		metrics.ApplyTotal.WithLabelValues("error")
		return err
	}
	log.Info("apply: complete")
	metrics.ApplyTotal.WithLabelValues("ok")
	// Reconcile provider dirs against config now that the apply committed:
	// remove rulesets/providers/cache files for providers that no longer
	// exist (deleted in the UI, dropped by a wizard reset, etc.). Runs only
	// on a successful apply; config is already persisted so c is authoritative.
	if removed := m.PruneOrphanProviderFiles(c, false); len(removed) > 0 {
		log.Info("apply: pruned %d orphan provider file(s)", len(removed))
	}
	// Snapshot a couple of static gauges on every successful apply so the
	// /metrics endpoint reflects the post-apply state without needing a
	// dedicated background sampler.
	metrics.ZapretStrategiesActive.Set(float64(countEnabledZapretStrategies(c)))
	if minSecs, ok := minSubscriptionSecondsToExpiry(c); ok {
		metrics.SubscriptionMinSecondsToExpiry.Set(minSecs)
	}
	return nil
}

func countEnabledZapretStrategies(c config.Config) int {
	n := 0
	for _, zs := range c.ZapretStrategies {
		if zs.Enabled {
			n++
		}
	}
	return n
}

// minSubscriptionSecondsToExpiry returns the earliest subscription expiry
// (in seconds from now; negative = expired) across all enabled subscriptions
// for which we have metadata. Returns ok=false when no subscription has a
// non-zero SubExpire — saves the metric from getting set to an arbitrary
// large positive value.
func minSubscriptionSecondsToExpiry(c config.Config) (float64, bool) {
	var min float64
	have := false
	now := time.Now()
	for _, s := range c.Subscriptions {
		if !s.Enabled || s.URL == "" {
			continue
		}
		path := filepath.Join(c.Settings.Workdir, "providers", s.Name+".yaml")
		meta, err := provider.ReadMetadata(path)
		if err != nil || meta.SubExpire.IsZero() {
			continue
		}
		secs := meta.SubExpire.Sub(now).Seconds()
		if !have || secs < min {
			min = secs
			have = true
		}
	}
	return min, have
}

func (m Manager) applyPrepare(force bool) (config.Config, system.BackupSet, generator.GeneratedPaths, generator.GenerationResult, func(), error) {
	c, err := m.Load()
	if err != nil {
		return c, nil, generator.GeneratedPaths{}, generator.GenerationResult{}, func() {}, err
	}
	c = ResolveZapretProfileInterfaces(c)
	c = ResolveOONIUser(c)
	log := newLog(c)
	defer log.DebugTimer("apply: prepare")()
	log.Info("apply: validating config")
	if err := m.Validate(); err != nil {
		return c, nil, generator.GeneratedPaths{}, generator.GenerationResult{}, func() {}, err
	}
	if c.Settings.BootstrapDoHEnabled && c.Settings.BootstrapHealthGate {
		log.Info("apply: bootstrap-health gate probing %d DoH endpoint(s)", len(c.Settings.BootstrapDoHResolvers))
		r := m.ResolversProbe("")
		if !r.Anywhere {
			return c, nil, generator.GeneratedPaths{}, generator.GenerationResult{}, func() {}, fmt.Errorf("bootstrap-health gate: all %d DoH resolvers failed to answer for %q — check zapret, add a user-provided endpoint to bootstrap_doh_resolver, or set bootstrap_health_gate '0' to skip this gate", len(r.Entries), r.Canary)
		}
		if !r.OK {
			log.Warn("apply: bootstrap-health gate: only %d/%d resolvers answered for %q — bootstrap path is degraded but proceeding", countOK(r.Entries), len(r.Entries), r.Canary)
		}
	}
	log.Info("apply: creating temporary backups max_bytes=%d", applyBackupMaxBytes(c))
	backup, backupCleanup, err := m.applyBackup(c)
	if err != nil {
		return c, nil, generator.GeneratedPaths{}, generator.GenerationResult{}, func() {}, err
	}
	if err := m.EnsureZapretBlobs(c); err != nil {
		backupCleanup()
		return c, backup, generator.GeneratedPaths{}, generator.GenerationResult{}, func() {}, err
	}
	log.Info("apply: generating staged outputs")
	staged, gen, cleanup, err := m.applyStagedGenerate(c, force)
	if err != nil {
		backupCleanup()
		return c, backup, generator.GeneratedPaths{}, generator.GenerationResult{}, func() {}, err
	}
	combinedCleanup := func() {
		cleanup()
		backupCleanup()
	}
	return c, backup, staged, gen, combinedCleanup, nil
}

func (m Manager) applyBackup(c config.Config) (system.BackupSet, func(), error) {
	log := newLog(c)
	paths := generator.DefaultGeneratedPaths(c)
	maxBytes := applyBackupMaxBytes(c)
	baseDir := filepath.Join(c.RuntimeDir(), "apply-backups")
	log.Debug("apply: temp backup paths max_bytes=%d mihomo=%s dnsmasq=%s dnsmasq_dir=%s nft=%s nftsets=%s firewall=%s", maxBytes, paths.MihomoConfig, paths.DNSMasqFile, paths.DNSMasqFragmentDir, paths.NFTFile, paths.NFTSetsFile, paths.FirewallFile)
	res, err := system.BackupFilesTempWithLimit(baseDir, maxBytes, paths.MihomoConfig, paths.DNSMasqFile, paths.NFTFile, paths.NFTSetsFile, paths.FirewallFile)
	if err != nil {
		return nil, func() {}, err
	}
	for _, skipped := range res.Skipped {
		log.Info("apply: temp backup skipped large file path=%s max_bytes=%d", skipped, maxBytes)
	}
	return res.Set, res.Cleanup, nil
}

func applyBackupMaxBytes(c config.Config) int64 {
	if c.Settings.ApplyBackupMaxBytes > 0 {
		return c.Settings.ApplyBackupMaxBytes
	}
	switch c.ResourceProfile() {
	case "low":
		return 128 * 1024
	case "high":
		return 4 * 1024 * 1024
	default:
		return 512 * 1024
	}
}

// sweepStaleStageDirs removes .purewrt-stage-* leftovers under stageBase.
// The normal `defer cleanup()` never runs when an apply dies mid-flight
// (SIGKILL, watchdog, power loss), and the leaks accumulate until reboot
// (or forever when GeneratedDir points at persistent storage). Only dirs
// older than an hour go — a younger one may be a concurrent apply that is
// still staging. Best-effort: a sweep failure must not block the apply.
func sweepStaleStageDirs(c config.Config, stageBase string) {
	entries, err := os.ReadDir(stageBase)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-time.Hour)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), ".purewrt-stage-") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(stageBase, e.Name())); err == nil {
			newLog(c).Info("apply: swept stale stage dir path=%s", filepath.Join(stageBase, e.Name()))
		}
	}
}

func (m Manager) applyStagedGenerate(c config.Config, force bool) (generator.GeneratedPaths, generator.GenerationResult, func(), error) {
	stageBase := c.Settings.GeneratedDir
	if stageBase == "" {
		runtimeDir := c.Settings.RuntimeDir
		if runtimeDir == "" {
			runtimeDir = config.DefaultRuntimeDir
		}
		stageBase = filepath.Join(runtimeDir, "generated")
	}
	// On a fresh boot the runtime dir lives on tmpfs and gets wiped, so the
	// first apply pass finds stageBase missing and `os.MkdirTemp` returns
	// an ENOENT (surfaced as "stat <stageBase>: no such file or directory"
	// in the logs). Create the dir explicitly here so we no longer rely on
	// the now-removed `prepare_runtime` shell helper to make it first.
	if err := os.MkdirAll(stageBase, 0755); err != nil {
		return generator.GeneratedPaths{}, generator.GenerationResult{}, func() {}, err
	}
	sweepStaleStageDirs(c, stageBase)
	stageDir, err := os.MkdirTemp(stageBase, ".purewrt-stage-*")
	if err != nil {
		return generator.GeneratedPaths{}, generator.GenerationResult{}, func() {}, err
	}
	newLog(c).Info("apply: stage dir created path=%s", stageDir)
	cleanup := func() { _ = os.RemoveAll(stageDir) }
	staged := generator.StagedGeneratedPaths(c, stageDir)
	gen, err := generator.WriteAllToResult(c, staged, generator.WriteOptions{Force: force, CheckPaths: generator.DefaultGeneratedPaths(c), SkipFingerprint: true})
	if err != nil {
		cleanup()
		return generator.GeneratedPaths{}, generator.GenerationResult{}, func() {}, err
	}
	return staged, gen, cleanup, nil
}

func (m Manager) applyWithRunner(c config.Config, backup system.BackupSet, staged generator.GeneratedPaths, gen generator.GenerationResult, r commandRunner) error {
	return m.applyWithRunnerPaths(c, backup, staged, generator.DefaultGeneratedPaths(c), gen, r)
}

func (m Manager) applyWithRunnerPaths(c config.Config, backup system.BackupSet, staged, live generator.GeneratedPaths, args ...any) error {
	gen := generator.GenerationResult{DirtyGroups: generator.GenerationGroups{}.All()}
	var r commandRunner
	if len(args) == 1 {
		r, _ = args[0].(commandRunner)
	} else if len(args) == 2 {
		gen, _ = args[0].(generator.GenerationResult)
		r, _ = args[1].(commandRunner)
	}
	if r == nil {
		return fmt.Errorf("apply runner missing")
	}
	log := newLog(c)
	if !gen.DirtyGroups.Any() {
		log.Info("apply: no dirty generation groups reason=%s; skipping reloads", gen.Reason)
		m.touchLastApplied(c)
		return nil
	}
	if err := m.applyValidateStaged(c, staged, gen.DirtyGroups, r); err != nil {
		return m.applyRollback(c, backup, r, err)
	}
	log.Info("apply: promoting staged outputs to live paths groups=%+v", gen.DirtyGroups)
	if err := m.applyPromote(staged, live, gen.DirtyGroups); err != nil {
		return m.applyRollback(c, backup, r, err)
	}
	if err := m.applyNFT(c, live, gen.DirtyGroups, r); err != nil {
		return m.applyRollback(c, backup, r, err)
	}
	if err := m.applyUCIDNSFirewall(c, live, gen.DirtyGroups, r); err != nil {
		return m.applyRollback(c, backup, r, err)
	}
	if err := m.applyPolicyRules(c, gen.DirtyGroups, r); err != nil {
		return m.applyRollback(c, backup, r, err)
	}
	if err := m.applyServiceRestarts(c, gen.DirtyGroups, r); err != nil {
		return m.applyRollback(c, backup, r, err)
	}
	if err := m.applyNetworkInterfaces(c, gen.DirtyGroups, r); err != nil {
		return m.applyRollback(c, backup, r, err)
	}
	if err := generator.CommitGenerationFingerprint(c); err != nil {
		return m.applyRollback(c, backup, r, err)
	}
	m.touchLastApplied(c)
	return nil
}

// touchLastApplied refreshes <RuntimeDir>/.last_applied, the marker the
// rpcd config_state method compares against /etc/config/purewrt's mtime to
// drive the LuCI "config has unapplied changes" banner. The rpcd wrapper
// also writes it for LuCI-initiated applies, but CLI paths (cron
// update-if-needed, boot apply) only pass through here — without this the
// banner sticks after any cron update that rewrites UCI. Content is unix
// seconds because config_state does a shell -gt on it. Best-effort: a
// marker write failure must not fail an otherwise committed apply.
func (m Manager) touchLastApplied(c config.Config) {
	if m.DryRun {
		return
	}
	dir := c.RuntimeDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10) + "\n"
	_ = os.WriteFile(filepath.Join(dir, ".last_applied"), []byte(ts), 0644)
}

// applyNetworkInterfaces enforces the IPv6-WAN state in /etc/config/network.
// When IPv6 routing is off in PureWRT we also bring down upstream v6
// interfaces so the kernel never gets a public v6 address (so client apps
// don't form v6 connection attempts at the LAN-side that we'd then have to
// blackhole). When IPv6 is back on we delete the disable flag so OpenWrt's
// netifd brings them up again.
//
// The target interface list is resolved in this order:
//  1. c.Settings.IPv6WANInterfaces if non-empty (user-set override list —
//     supports multi-WAN setups with several v6 uplinks)
//  2. Every network.* section with proto=dhcpv6 (covers PPPoE+v6,
//     6in4/6rd tunnels named anything, and multi-WAN deployments)
//  3. "wan6" (OpenWrt convention) as final single-element fallback
//
// We commit + reload the network only when at least one interface's
// on-disk state actually differs from what we want, since
// `/etc/init.d/network reload` is heavier than the rest of apply (briefly
// tears down + brings up interfaces) and can momentarily disrupt the LAN
// if run unnecessarily.
func (m Manager) applyNetworkInterfaces(c config.Config, groups generator.GenerationGroups, r commandRunner) error {
	if !groups.OpenWrtBundle {
		return nil
	}
	log := newLog(c)
	targets := resolveIPv6WANInterfaces(c, r)
	if len(targets) == 0 {
		log.Debug("apply: no v6 WAN interface found in /etc/config/network; skipping wan6 disable management")
		return nil
	}
	want := ""
	if !c.IPv6Routed() {
		want = "1"
	}
	mutated := false
	for _, target := range targets {
		// First confirm the section exists at all — `uci -q get
		// network.<name>` returns the section type (e.g. "interface"). An
		// error here means the section is missing (stale override), so
		// skip without trying to synthesize one.
		if _, err := r.Run("uci", "-q", "get", "network."+target); err != nil {
			log.Debug("apply: network.%s not present; skipping", target)
			continue
		}
		// Now read the .disabled option separately. uci -q get returns
		// exit-1 with empty stdout when the option isn't set — treat that
		// as the implicit "" (enabled) value, not as a section-missing
		// error. The earlier combined check conflated the two cases and
		// silently no-op'd whenever .disabled wasn't already present.
		got, _ := r.Run("uci", "-q", "get", "network."+target+".disabled")
		got = strings.TrimSpace(got)
		if got == want {
			log.Debug("apply: network.%s.disabled already=%q, no change", target, got)
			continue
		}
		if want == "1" {
			if err := m.runApplyCommand(r, "uci", "set", "network."+target+".disabled=1"); err != nil {
				return err
			}
			log.Info("apply: disabling network.%s (IPv6 routing off)", target)
		} else {
			if err := m.runApplyCommand(r, "uci", "-q", "delete", "network."+target+".disabled"); err != nil {
				if !isNotFoundErr(err) && !isUCIQuietDeleteMissingErr(err) {
					return err
				}
			}
			log.Info("apply: enabling network.%s (IPv6 routing back on)", target)
		}
		mutated = true
	}
	if !mutated {
		return nil
	}
	if err := m.runApplyCommand(r, "uci", "commit", "network"); err != nil {
		return err
	}
	if err := m.runApplyCommand(r, "/etc/init.d/network", "reload"); err != nil {
		return err
	}
	return nil
}

// resolveIPv6WANInterfaces returns the /etc/config/network section names to
// toggle when IPv6 routing flips. See applyNetworkInterfaces for the
// precedence rules. Falls back to ["wan6"] when uci show network can't run
// (test envs without uci) so the legacy hard-coded behavior is preserved.
func resolveIPv6WANInterfaces(c config.Config, r commandRunner) []string {
	if len(c.Settings.IPv6WANInterfaces) > 0 {
		out := make([]string, 0, len(c.Settings.IPv6WANInterfaces))
		seen := map[string]bool{}
		for _, name := range c.Settings.IPv6WANInterfaces {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
		return out
	}
	out, err := r.Run("uci", "show", "network")
	if err != nil {
		return []string{"wan6"}
	}
	// Parse lines like `network.wan6.proto='dhcpv6'`. We want the section
	// name (between the two dots) for every proto=dhcpv6 match.
	var found []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(line, ".proto='dhcpv6'") && !strings.HasSuffix(line, ".proto=dhcpv6") {
			continue
		}
		rest := strings.TrimPrefix(line, "network.")
		dot := strings.Index(rest, ".")
		if dot <= 0 {
			continue
		}
		name := rest[:dot]
		// Skip anonymous sections (e.g. @interface[0]) — they don't have
		// a stable name we can target with `uci set`.
		if strings.HasPrefix(name, "@") || seen[name] {
			continue
		}
		seen[name] = true
		found = append(found, name)
	}
	if len(found) == 0 {
		return []string{"wan6"}
	}
	return found
}

func (m Manager) applyValidateStaged(c config.Config, staged generator.GeneratedPaths, groups generator.GenerationGroups, r commandRunner) error {
	log := newLog(c)
	if !m.DryRun {
		if groups.Mihomo {
			log.Info("apply: validating staged mihomo config")
			if out, err := r.Run(c.Settings.MihomoBin, "-t", "-d", c.Settings.Workdir, "-f", staged.MihomoConfig); err != nil {
				return fmt.Errorf("mihomo config validation failed: %w: %s", err, out)
			}
			log.Info("apply: mihomo validation ok")
		}
		if groups.OpenWrtBundle {
			log.Info("apply: validating staged nft rules")
			if out, err := r.Run("nft", "-c", "-f", staged.NFTFile); err != nil {
				return fmt.Errorf("nft -c -f %s failed: %w: %s", staged.NFTFile, err, out)
			}
			log.Info("apply: nft validation ok")
		}
	}
	return nil
}

func (m Manager) applyPromote(staged, live generator.GeneratedPaths, groups generator.GenerationGroups) error {
	return generator.PromoteGeneratedPathsForGroups(staged, live, groups)
}

func (m Manager) runApplyCommand(r commandRunner, name string, args ...string) error {
	log := logging.New(m.logLevel())
	defer log.DebugTimer("command: %s %s", name, strings.Join(args, " "))()
	out, err := r.Run(name, args...)
	if err != nil {
		log.Error("command failed: %s %s", name, strings.Join(args, " "))
		return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, out)
	}
	return nil
}

func (m Manager) applyNFT(c config.Config, live generator.GeneratedPaths, groups generator.GenerationGroups, r commandRunner) error {
	log := logging.New(m.logLevel())
	if !groups.OpenWrtBundle {
		// Drift check: the fingerprint says nothing changed and we'd
		// normally skip the `nft -f` reload — but the live ruleset can
		// be cleared from under us by external events (a buggy fw4
		// reload, a manual `nft delete table`, or a reboot where the
		// boot apply silently no-op'd because of the same fingerprint
		// optimisation). When that happens the on-disk nft file is
		// fine and the fingerprint is correct, but the kernel has
		// nothing loaded. Probe `nft list table inet purewrt` cheaply
		// and force a reload if it's gone.
		if _, probeErr := r.Run("nft", "list", "table", "inet", "purewrt"); probeErr == nil {
			log.Debug("apply: nft reload skipped openwrt_bundle unchanged, table present")
			return nil
		}
		log.Warn("apply: live nft table missing despite cache-hit; forcing reload")
	}
	// The atomic table replace below wipes the dynamic dns_* sets (the IPs
	// dnsmasq resolved from domains). dnsmasq only re-adds an IP on a *fresh*
	// client query, so cached-client domains would silently fall direct until
	// their DNS TTL expires. Snapshot the live members first and re-inject them
	// after the reload. Best-effort: a snapshot/restore failure must never abort
	// the apply (worst case is the pre-existing behaviour — empty sets).
	snap := m.snapshotDynamicDNSSets(c, r)
	log.Info("apply: loading nft main path=%s", live.NFTFile)
	if err := m.runApplyCommand(r, "nft", "-f", live.NFTFile); err != nil {
		return err
	}
	log.Info("apply: loading nft sets path=%s", live.NFTSetsFile)
	if err := m.runApplyCommand(r, "nft", "-f", live.NFTSetsFile); err != nil {
		return err
	}
	if n := m.restoreDynamicDNSSets(snap, r); n > 0 {
		log.Info("apply: restored %d dynamic dns-set members across reload", n)
	}
	return nil
}

// snapshotDynamicDNSSets reads the current members of each dynamic dns_* set for
// the (new) config. Keyed by set name; a removed section's set is not in the
// list so it is never read. Absent/empty sets (newly added section, first boot,
// missing table) yield nothing. Best-effort — any read error is skipped.
func (m Manager) snapshotDynamicDNSSets(c config.Config, r commandRunner) map[string][]string {
	snap := map[string][]string{}
	for _, set := range generator.DynamicDNSSetNames(c) {
		out, err := r.Run("nft", "list", "set", "inet", "purewrt", set)
		if err != nil {
			continue
		}
		if ips := parseNFTSetElements(out); len(ips) > 0 {
			snap[set] = ips
		}
	}
	return snap
}

// restoreDynamicDNSSets re-adds snapshotted members into their original sets
// (which the just-loaded NFTFile recreated, so they exist). Chunked to keep the
// element argument well under ARG_MAX on large sets. Best-effort: a failed add
// is logged and skipped, never aborting the apply. Returns the count attempted.
func (m Manager) restoreDynamicDNSSets(snap map[string][]string, r commandRunner) int {
	log := logging.New(m.logLevel())
	const chunk = 500
	total := 0
	for set, ips := range snap {
		for i := 0; i < len(ips); i += chunk {
			batch := ips[i:min(i+chunk, len(ips))]
			if _, err := r.Run("nft", "add", "element", "inet", "purewrt", set, "{ "+strings.Join(batch, ", ")+" }"); err != nil {
				log.Warn("apply: restore dns-set %s batch failed (best-effort): %v", set, err)
				continue
			}
			total += len(batch)
		}
	}
	return total
}

// parseNFTSetElements extracts the plain addresses from `nft list set` output.
// Dynamic dns_* sets are ipv4_addr/ipv6_addr (single addresses, no intervals);
// elements look like `elements = { 1.2.3.4 expires 2h29m, 5.6.7.8 }` — take the
// first field of each comma-separated entry and drop expires/timeout tokens.
func parseNFTSetElements(out string) []string {
	_, rest, found := strings.Cut(out, "elements = {")
	if !found {
		return nil
	}
	if before, _, ok := strings.Cut(rest, "}"); ok {
		rest = before
	}
	var ips []string
	for _, part := range strings.Split(rest, ",") {
		if f := strings.Fields(part); len(f) > 0 {
			ips = append(ips, f[0])
		}
	}
	return ips
}

// FlushDynamicDNSSets empties every dynamic dns_* set (diagnostics action — the
// sets repopulate from dnsmasq on the next client query). Tolerates a missing
// set/table (returns the set names it cleared). Used by the `flush-dns-sets`
// CLI subcommand / LuCI diagnostics button.
func (m Manager) FlushDynamicDNSSets() ([]string, error) {
	c, err := m.Load()
	if err != nil {
		return nil, err
	}
	r := system.Runner{DryRun: m.DryRun}
	var flushed []string
	for _, set := range generator.DynamicDNSSetNames(c) {
		if _, err := r.Run("nft", "flush", "set", "inet", "purewrt", set); err == nil {
			flushed = append(flushed, set)
		}
	}
	return flushed, nil
}

// purewrtFirewallSectionNames extracts the named firewall sections PureWRT owns
// (prefix "purewrt_") from `uci show firewall` output — the `firewall.<name>=<type>`
// header lines, ignoring `firewall.<name>.<opt>=` option lines.
func purewrtFirewallSectionNames(uciShow string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(uciShow, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		const pfx = "firewall."
		if !strings.HasPrefix(key, pfx) {
			continue
		}
		name := key[len(pfx):]
		if strings.Contains(name, ".") {
			continue // option line, not a section header
		}
		if strings.HasPrefix(name, "purewrt_") && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// deletePurewrtFirewallSections removes every purewrt_* firewall section (best
// effort) so the generated rule set can be reconciled. Returns how many were
// removed. Caller commits + reloads.
func (m Manager) deletePurewrtFirewallSections(r commandRunner) int {
	out, err := r.Run("uci", "show", "firewall")
	if err != nil {
		return 0
	}
	names := purewrtFirewallSectionNames(out)
	for _, name := range names {
		_, _ = r.Run("uci", "-q", "delete", "firewall."+name)
	}
	return len(names)
}

func (m Manager) applyUCIDNSFirewall(c config.Config, live generator.GeneratedPaths, groups generator.GenerationGroups, r commandRunner) error {
	log := newLog(c)
	if groups.Firewall && len(generator.FirewallRules(c)) > 0 {
		log.Info("apply: importing PureWRT firewall rules path=%s", live.FirewallFile)
		// Reconcile: drop every prior purewrt_* section (handles de-selected
		// zones / renamed rules) then import the freshly generated set.
		m.deletePurewrtFirewallSections(r)
		if err := m.runApplyCommand(r, "uci", "-m", "-f", live.FirewallFile, "import", "firewall"); err != nil {
			return err
		}
		if err := m.runApplyCommand(r, "uci", "commit", "firewall"); err != nil {
			return err
		}
		if err := m.runApplyCommand(r, initFirewall, "reload"); err != nil {
			return err
		}
		log.Info("apply: firewall reload complete")
	} else if groups.Firewall {
		// No rules to install (no LAN source zones) — clear any leftovers.
		if m.deletePurewrtFirewallSections(r) > 0 {
			_ = m.runApplyCommand(r, "uci", "commit", "firewall")
			_ = m.runApplyCommand(r, initFirewall, "reload")
		}
		log.Debug("apply: no PureWRT firewall rules to install")
	} else {
		log.Debug("apply: firewall UCI unchanged, skipping firewall reload")
	}
	if groups.OpenWrtBundle && c.DNS.Enabled && c.DNS.UpstreamMode == "mihomo" {
		log.Info("apply: DNS upstream mode=mihomo, applying dnsmasq upstream UCI")
		for _, cmd := range generator.DNSUCIApplyCommands(c) {
			if err := m.runApplyCommand(r, cmd[0], cmd[1:]...); err != nil {
				return err
			}
		}
		if err := m.runApplyCommand(r, libexecPeerDNS, "apply"); err != nil {
			return err
		}
		log.Info("apply: peerdns apply complete")
	} else if groups.OpenWrtBundle {
		log.Debug("apply: DNS upstream mode=%s, skipping peerdns apply", c.DNS.UpstreamMode)
	} else {
		log.Debug("apply: DNS UCI unchanged, skipping peerdns apply")
	}
	// Toggle dnsmasq filter-aaaa based on effective IPv6 state. Lives in the
	// OpenWrtBundle gate because the subsequent dnsmasq restart already
	// fires on that group; running here keeps the commit + restart in the
	// same apply phase. `delete` may exit 1 when the option isn't set —
	// the isNotFoundErr/isUCIQuietDeleteMissingErr guard below swallows that
	// to keep apply idempotent.
	if groups.OpenWrtBundle {
		for _, cmd := range generator.DNSMasqIPv6FilterCommands(c) {
			if cmd[1] == "-q" && cmd[2] == "delete" {
				if err := m.runApplyCommand(r, cmd[0], cmd[1:]...); err != nil {
					if !isNotFoundErr(err) && !isUCIQuietDeleteMissingErr(err) {
						return err
					}
				}
				continue
			}
			if err := m.runApplyCommand(r, cmd[0], cmd[1:]...); err != nil {
				return err
			}
		}
		if c.IPv6Routed() {
			log.Debug("apply: dnsmasq filter-aaaa disabled (IPv6 routed)")
		} else {
			log.Info("apply: dnsmasq filter-aaaa enabled (IPv6 routing off)")
		}
	}
	return nil
}

func (m Manager) applyPolicyRules(c config.Config, groups generator.GenerationGroups, r commandRunner) error {
	log := newLog(c)
	if !groups.Policy {
		// Same drift-check pattern as applyNFT: if the fingerprint says
		// the policy bundle is unchanged but the live ip rule table no
		// longer carries our fwmark rule (wiped by a reboot or external
		// `ip rule del`), reinstall. `ip rule show` is a single fast
		// netlink read; grep for `fwmark <mark>/<mask>` to be specific
		// rather than misfiring on unrelated rules.
		marker := "fwmark " + c.Settings.FwMark + "/" + c.Settings.FwMarkMask
		if out, probeErr := r.Run("ip", "rule", "show"); probeErr == nil && strings.Contains(out, marker) {
			log.Debug("apply: policy rules unchanged, skipping (live rule present)")
			return nil
		}
		log.Warn("apply: live policy rule missing despite cache-hit; forcing install")
	}
	log.Info("apply: applying policy rules")
	for _, parts := range generator.PolicyCommandArgs(c) {
		if len(parts) > 0 {
			if err := m.runApplyCommand(r, parts[0], parts[1:]...); err != nil {
				if isPolicyDelete(parts) && isNotFoundErr(err) {
					log.Debug("apply: old policy rule absent, continuing")
					continue
				}
				return err
			}
		}
	}
	return nil
}

func (m Manager) applyServiceRestarts(c config.Config, groups generator.GenerationGroups, r commandRunner) error {
	log := newLog(c)
	if groups.OpenWrtBundle {
		// dnsmasq's `reload` only sends SIGHUP, which re-reads /etc/hosts
		// and leases but NOT the conf-dir where we drop the nftset
		// fragments. After a fragment change (or at boot, where dnsmasq
		// comes up before us with an empty conf-dir), only a full restart
		// makes the directives take effect. The fingerprint gate above
		// ensures this only fires when the OpenWrt bundle actually
		// changed, so DNS doesn't blip on every apply.
		if err := m.runServiceRestart(c, r, initDnsmasq, "restart"); err != nil {
			return err
		}
		log.Info("apply: dnsmasq restart complete")
	} else {
		log.Debug("apply: dnsmasq restart skipped openwrt_bundle unchanged")
	}
	if groups.Mihomo {
		if err := m.reloadOrRestartMihomo(c, r); err != nil {
			return err
		}
	} else {
		log.Debug("apply: mihomo reload skipped mihomo group unchanged")
	}
	if groups.Mwan3 && c.Mwan3.Mode == "integrated" && c.Mwan3.IntegratedRules {
		if err := m.runServiceRestart(c, r, initMwan3, "reload"); err != nil {
			return err
		}
		log.Info("apply: mwan3 reload complete")
	} else if groups.Mwan3 {
		log.Debug("apply: mwan3 reload skipped mode=%s integrated_rules=%v", c.Mwan3.Mode, c.Mwan3.IntegratedRules)
	} else {
		log.Debug("apply: mwan3 reload skipped mwan3 group unchanged")
	}
	// Friend-mesh overlay daemon. Best-effort like the companion package it
	// belongs to: a missing init script (easytier not installed) or a failed
	// restart must not roll back the whole apply — mihomo/firewall state is
	// already correct, the overlay just stays down until the package appears.
	if groups.Mesh {
		if _, err := os.Stat(initEasytier); err != nil {
			log.Debug("apply: easytier restart skipped (init script missing)")
		} else if c.MeshActive() {
			if err := m.runServiceRestart(c, r, initEasytier, "enable"); err != nil {
				log.Warn("apply: easytier enable failed: %v", err)
			}
			if err := m.runServiceRestart(c, r, initEasytier, "restart"); err != nil {
				log.Warn("apply: easytier restart failed: %v", err)
			} else {
				log.Info("apply: easytier restart complete")
			}
		} else {
			_ = m.runServiceRestart(c, r, initEasytier, "stop")
			_ = m.runServiceRestart(c, r, initEasytier, "disable")
			log.Info("apply: easytier stopped (mesh inactive)")
		}
	}
	return nil
}

func (m Manager) applyRollback(c config.Config, backup system.BackupSet, r commandRunner, cause error) error {
	if !c.Settings.RollbackOnFail {
		return cause
	}
	log := newLog(c)
	log.Warn("rollback: starting cause=%v", cause)
	if restoreErr := m.restoreAndReload(c, backup, r); restoreErr != nil {
		log.Error("rollback: failed: %v", restoreErr)
		return fmt.Errorf("%w; rollback failed: %v", cause, restoreErr)
	}
	log.Info("rollback: complete")
	return cause
}

func isPolicyDelete(parts []string) bool {
	return len(parts) >= 3 && parts[0] == "ip" && parts[1] == "rule" && parts[2] == "del" || len(parts) >= 4 && parts[0] == "ip" && parts[1] == "-6" && parts[2] == "rule" && parts[3] == "del"
}

// isNotFoundErr classifies stderr from shelled-out commands (`ip rule del`,
// `uci delete`, nft) — there is no Go error type to errors.Is against here.
// String matching is safe because busybox, iproute2 and uci emit fixed,
// unlocalized English messages ("No such file or directory", "Entry not
// found", "does not exist").
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "not found") || strings.Contains(s, "no such") || strings.Contains(s, "does not exist")
}

func isUCIQuietDeleteMissingErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "uci -q delete") && strings.Contains(s, "exit status 1")
}

// isTimeoutErr matches the message system.Runner emits when a command exceeds
// its deadline (system/exec.go). A daemon restart that times out has almost
// certainly still come up (it's slow, not broken), so the apply treats it as
// best-effort rather than a rollback trigger — see runServiceRestart.
func isTimeoutErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "timed out after")
}

func defaultMihomoReachable(c config.Config) bool {
	return mihomoapi.Client{Base: c.Settings.ExternalController, Secret: c.Settings.Secret}.Reachable()
}

func defaultMihomoReload(c config.Config) error {
	return mihomoapi.Client{Base: c.Settings.ExternalController, Secret: c.Settings.Secret}.ReloadConfig(c.Settings.MihomoConfig)
}

// reloadOrRestartMihomo applies a changed mihomo config without dropping live
// proxy connections when possible. A full `/etc/init.d/mihomo restart` resets
// every proxied flow; mihomo's external-controller hot reload (PUT
// /configs?force=true) swaps the rule/proxy/dns tree in place and keeps
// established connections alive. We prefer the hot reload and fall back to a
// cold restart only when it can't work:
//   - controller unreachable  → mihomo is down: cold start.
//   - controller moved / secret changed → the probe at the *configured*
//     address+secret fails (old daemon answers the old address/secret), so we
//     correctly restart to pick up the new control channel.
//   - reload returns an error → restart.
//
// Apply never changes the mihomo *binary* (that's the separate install path),
// so a config apply is always safe to hot-reload when the controller answers.
func (m Manager) reloadOrRestartMihomo(c config.Config, r commandRunner) error {
	log := newLog(c)
	reachable := m.mihomoReachable
	if reachable == nil {
		reachable = defaultMihomoReachable
	}
	reload := m.mihomoReload
	if reload == nil {
		reload = defaultMihomoReload
	}
	if reachable(c) {
		if err := reload(c); err == nil {
			log.Info("apply: mihomo hot-reloaded (PUT /configs); live connections preserved")
			return nil
		} else {
			log.Warn("apply: mihomo hot-reload failed (%v); falling back to restart", err)
		}
	} else {
		log.Debug("apply: mihomo controller unreachable; cold restart")
	}
	if err := m.runServiceRestart(c, r, initMihomo, "restart"); err != nil {
		return err
	}
	log.Info("apply: mihomo restart complete")
	return nil
}

// runServiceRestart runs a daemon restart/reload with a generous timeout. A
// timeout is tolerated (logged, treated as success) because the config is
// already validated, promoted, and loaded into the kernel before we reach the
// restart step — a slow daemon must not roll the whole apply back and spin the
// update-if-needed loop. A genuine non-zero exit (e.g. a bad init script) is
// still returned so the caller rolls back.
func (m Manager) runServiceRestart(c config.Config, r commandRunner, name string, args ...string) error {
	log := newLog(c)
	if _, err := r.RunWithTimeout(serviceRestartTimeout, name, args...); err != nil {
		joined := name + " " + strings.Join(args, " ")
		if isTimeoutErr(err) {
			log.Warn("apply: %s timed out after %s; continuing (daemon restarts are best-effort, it is likely still starting)", joined, serviceRestartTimeout)
			return nil
		}
		log.Error("command failed: %s", joined)
		return fmt.Errorf("%s failed: %w", joined, err)
	}
	return nil
}

func (m Manager) restoreAndReload(c config.Config, backup system.BackupSet, r commandRunner) error {
	log := newLog(c)
	var errs []string
	if err := backup.Restore(); err != nil {
		errs = append(errs, err.Error())
	} else {
		log.Info("rollback: backups restored")
	}
	run := func(name string, args ...string) {
		out, err := r.Run(name, args...)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s %s failed: %v: %s", name, strings.Join(args, " "), err, out))
		}
	}
	// Service restarts during rollback get the same generous timeout as the
	// forward path (dnsmasq with a large nftset config is slow); a timeout is
	// tolerated so the rollback itself can't hang. A hard failure is recorded.
	runService := func(name string, args ...string) {
		if _, err := r.RunWithTimeout(serviceRestartTimeout, name, args...); err != nil && !isTimeoutErr(err) {
			errs = append(errs, fmt.Sprintf("%s %s failed: %v", name, strings.Join(args, " "), err))
		}
	}
	paths := generator.DefaultGeneratedPaths(c)
	run("nft", "-f", paths.NFTFile)
	run("nft", "-f", paths.NFTSetsFile)
	if len(generator.FirewallRules(c)) > 0 {
		m.deletePurewrtFirewallSections(r)
		run("uci", "-m", "-f", paths.FirewallFile, "import", "firewall")
		run("uci", "commit", "firewall")
		run(initFirewall, "reload")
	}
	// See applyServiceRestarts — reload-via-SIGHUP doesn't pick up the
	// nftset fragments. Use restart so the rollback genuinely restores
	// dnsmasq state.
	runService(initDnsmasq, "restart")
	// Prefer hot-reload of the restored config (keeps connections) and fall
	// back to a cold restart — same logic as the forward apply path.
	if err := m.reloadOrRestartMihomo(c, r); err != nil {
		errs = append(errs, err.Error())
	}
	if c.Mwan3.Mode == "integrated" && c.Mwan3.IntegratedRules {
		runService(initMwan3, "reload")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (m Manager) Disable() error {
	c, _ := m.Load()
	log := newLog(c)
	defer log.DebugTimer("disable: total")()
	log.Warn("disable: start")
	r := system.Runner{DryRun: m.DryRun}
	var errs []string
	if out, err := r.Run("nft", "delete", "table", "inet", "purewrt"); err != nil && !strings.Contains(out, "No such") {
		errs = append(errs, out)
	} else {
		log.Info("disable: nft table removed or absent")
	}
	paths := generator.DefaultGeneratedPaths(c)
	_ = os.Remove(paths.DNSMasqFile)
	_ = os.Remove(paths.NFTFile)
	_ = os.Remove(paths.NFTSetsFile)
	if paths.DNSMasqFragmentDir != "" {
		matches, _ := filepath.Glob(filepath.Join(paths.DNSMasqFragmentDir, "purewrt-*.dnsmasq"))
		for _, path := range matches {
			_ = os.Remove(path)
		}
	}
	_ = os.Remove("/etc/config/purewrt-firewall.generated")
	log.Info("disable: generated files removed")
	for _, cmd := range generator.DNSUCIDisableCommands(c) {
		_, _ = r.Run(cmd[0], cmd[1:]...)
	}
	_, _ = r.Run(libexecPeerDNS, "restore")
	m.deletePurewrtFirewallSections(r)
	_, _ = r.Run("uci", "commit", "firewall")
	_, _ = r.Run(initFirewall, "reload")
	log.Info("disable: DNS/firewall state restored")
	if out, err := r.Run("ip", "rule", "del", "priority", c.Settings.IPRulePriority); err != nil {
		errs = append(errs, out)
	}
	if out, err := r.Run("ip", "-6", "rule", "del", "priority", c.Settings.IPRulePriority); err != nil {
		errs = append(errs, out)
	}
	if len(errs) > 0 {
		log.Error("disable: completed with warnings=%d", len(errs))
		return fmt.Errorf("disable completed with warnings: %s", strings.Join(errs, "; "))
	}
	log.Info("disable: complete")
	return nil
}
func (m Manager) Status() string {
	c, _ := m.Load()
	var b strings.Builder
	fmt.Fprintf(&b, "PureWRT enabled: %v\nmihomo config: %s\nsections: %d\nproxy providers: %d\nrule providers: %d\nmwan3 mode: %s\n",
		c.Settings.Enabled, c.Settings.MihomoConfig, len(c.Sections), len(c.ProxyProviders), len(c.RuleProviders), c.Mwan3.Mode)
	if lines := subscriptionExpiryLines(c); len(lines) > 0 {
		b.WriteString("subscriptions:\n")
		for _, l := range lines {
			fmt.Fprintf(&b, "  %s\n", l)
		}
	}
	return b.String()
}
