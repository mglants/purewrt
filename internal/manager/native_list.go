package manager

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/provider"
)

var nativeListNameSanitize = regexp.MustCompile(`[^a-z0-9_]+`)

// AddNativeList upserts a parse_mode=native_import rule provider for a
// pre-built nftset-builder list at url, bound to section. It only persists
// the provider (idempotent by derived name) — the caller fetches + applies.
// Returns the provider name. native_import imports the list verbatim on the
// router (no parse/validate/dedup), so this is the lightweight default-list
// path used by the wizard and the `add-native-list` CLI.
func (m Manager) AddNativeList(url, section string, priority int) (string, error) {
	url = strings.TrimSpace(url)
	section = strings.TrimSpace(section)
	if url == "" || section == "" {
		return "", fmt.Errorf("add-native-list: url and section are required")
	}
	c, err := m.Load()
	if err != nil {
		return "", err
	}
	name := nativeListName(url)

	// Resolve the section's action + the effective priority. An explicit
	// catalog priority (>0) wins; otherwise inherit an existing section's
	// priority; otherwise fall back to the UCI section default (100).
	sec, sectionExists := c.SectionByName(section)
	action := "proxy"
	if sectionExists && sec.Action != "" {
		action = sec.Action
	} else if !sectionExists {
		// New section: derive the action from conventional names so a list
		// mapped to "direct"/"reject" routes correctly without a proxy port.
		switch section {
		case "direct", "reject":
			action = section
		}
	}
	effPriority := priority
	if effPriority <= 0 {
		if sectionExists {
			effPriority = sec.Priority
		}
		if effPriority <= 0 {
			effPriority = 100
		}
	}

	// Create the section if it doesn't exist yet (like subscription import),
	// seeding the new section's precedence from the rule provider's priority.
	if !sectionExists {
		c = ensureNativeSection(c, section, action, effPriority)
	}

	workdir := c.Settings.Workdir
	if workdir == "" {
		workdir = config.DefaultWorkdir
	}
	rp := config.RuleProvider{
		Name:        name,
		Enabled:     true,
		Format:      "text",
		ParseMode:   "native_import",
		URL:         url,
		Section:     section,
		RouteAction: action,
		Priority:    effPriority,
		Interval:    86400,
		Path:        filepath.Join(workdir, "rulesets", name+".native"),
		Category:    "default",
		SourceKind:  "native_import",
	}
	replaced := false
	for i := range c.RuleProviders {
		if c.RuleProviders[i].Name == name {
			// Preserve enabled state intent but refresh the binding.
			rp.Enabled = true
			c.RuleProviders[i] = rp
			replaced = true
			break
		}
	}
	if !replaced {
		c.RuleProviders = append(c.RuleProviders, rp)
	}
	path := defaultConfigPath(&m)
	_, _ = config.Backup(path)
	if err := config.Save(path, c); err != nil {
		return "", err
	}
	return name, nil
}

// ensureNativeSection appends a complete routing section for a native list
// when one doesn't already exist, mirroring the shape of Default()'s sections
// so it passes apply-validation. Proxy sections get a freshly-allocated
// TPROXY port; direct/reject sections need none. The section's Priority is
// seeded from the rule provider's effective priority.
func ensureNativeSection(c config.Config, name, action string, priority int) config.Config {
	s := config.Section{
		Name:           name,
		Enabled:        true,
		Action:         action,
		ProxyGroup:     config.TitleASCII(name),
		ProxyGroupType: "url-test",
		ProxyStrategy:  "sticky-sessions",
		IPv4Enabled:    true,
		IPv6Enabled:    true,
		UDPMode:        "proxy",
		Priority:       priority,
	}
	if action == "proxy" {
		s.TPROXYPort = c.NextTPROXYPort()
	}
	c.Sections = append(c.Sections, s)
	return c
}

// DefaultListsCatalog fetches <default_lists_base_url>/catalog.json through
// the bootstrap-resilient download path (DoH + update-via-proxy + local
// mihomo fallback), so the wizard's list picker works even when the
// release host's DNS is censored.
func (m Manager) DefaultListsCatalog() ([]byte, error) {
	c, err := m.Load()
	if err != nil {
		return nil, err
	}
	base := strings.TrimSpace(c.Settings.DefaultListsBaseURL)
	if base == "" {
		return nil, fmt.Errorf("default_lists_base_url is not set")
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	proxyURL := ""
	if c.Settings.UpdateViaProxy {
		proxyURL = effectiveUpdateProxyURL(c)
	}
	d, err := provider.DownloadWithOptions(base+"catalog.json", provider.DownloadOptions{
		Bootstrap:        bootstrapFromSettings(c.Settings),
		ProxyURL:         proxyURL,
		FallbackProxyURL: fallbackProxyURL(c, proxyURL),
		MaxBytes:         1 << 20,
	})
	if err != nil {
		return nil, fmt.Errorf("fetch catalog: %w", err)
	}
	return d.Data, nil
}

// nativeListName derives a stable provider name from a list URL, e.g.
// ".../common.native" → "native_common". Keeps re-adds idempotent.
func nativeListName(url string) string {
	base := url
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".native")
	base = strings.TrimSuffix(base, ".lst")
	base = nativeListNameSanitize.ReplaceAllString(strings.ToLower(base), "_")
	base = strings.Trim(base, "_")
	if base == "" {
		base = "list"
	}
	return "native_" + base
}
