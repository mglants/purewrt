package provider

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

type ImportPlan struct {
	SubscriptionName string
	Mode             string
	PresetIfNoRules  string
	CreatedSections  []string
	SectionGroups    []config.Section
	ProxyProviders   []config.ProxyProvider
	RuleProviders    []config.RuleProvider
	Files            []MaterializedFile
	Warnings         []string
	Summary          Analysis
}

type ImportOptions struct {
	LowResource              bool
	ImportRulesOnLowResource bool
}

func PlanImport(c config.Config, rawURL, name, mode, preset string, a Analysis) ImportPlan {
	return PlanImportWithOptions(c, rawURL, name, mode, preset, a, ImportOptions{})
}

func PlanImportWithOptions(c config.Config, rawURL, name, mode, preset string, a Analysis, opt ImportOptions) ImportPlan {
	if mode == "" {
		mode = "auto"
	}
	if preset == "" {
		preset = "minimal"
	}
	if name == "" {
		name = deriveName(rawURL)
	}
	p := ImportPlan{SubscriptionName: SafeName(name), Mode: mode, PresetIfNoRules: preset, Summary: a}
	if opt.LowResource && !opt.ImportRulesOnLowResource && (mode == "auto" || mode == "rules_only") {
		mode = "proxy_only"
		p.Mode = mode
		p.Warnings = append(p.Warnings, "low-resource profile: subscription rule-providers were skipped; enable advanced import rules override to include them")
	}
	seenSections := map[string]bool{}
	for _, sec := range c.Sections {
		seenSections[sec.Name] = true
	}
	for _, sec := range []string{"common", "media", "ai", "direct", "reject"} {
		if !seenSections[sec] {
			p.CreatedSections = append(p.CreatedSections, sec)
		}
	}
	if strings.EqualFold(a.Type, "Mihomo/Clash YAML profile") && (mode == "auto" || mode == "proxy_only" || mode == "rules_only") {
		if d, ok := DecomposeYAMLProfile(rawURL, p.SubscriptionName, a.Raw); ok {
			if (mode == "auto" || mode == "proxy_only") && d.ProxyProvider.Name != "" {
				p.ProxyProviders = append(p.ProxyProviders, d.ProxyProvider)
			}
			if mode == "auto" || mode == "rules_only" {
				p.RuleProviders = append(p.RuleProviders, d.RuleProviders...)
			}
			p.Files = append(p.Files, d.Files...)
			p.SectionGroups = append(p.SectionGroups, d.SectionGroups...)
			p.Warnings = append(p.Warnings, d.Warnings...)
			p.Warnings = append(p.Warnings, a.Warnings...)
			return p
		}
	}
	if (mode == "auto" || mode == "proxy_only") && (a.ProxyNodes > 0 || a.ProxyProviders > 0 || strings.Contains(strings.ToLower(a.Type), "proxy")) {
		ppName := dedupeProviderName("main", c.ProxyProviders)
		p.ProxyProviders = append(p.ProxyProviders, config.ProxyProvider{Name: ppName, Enabled: true, Type: "http", URL: rawURL, Interval: 86400, Path: filepath.Join(config.DefaultWorkdir, "providers", ppName+".yaml"), HealthCheck: true, HealthCheckURL: "https://cp.cloudflare.com/generate_204", HealthCheckInterval: 300, HWID: "", DeviceName: ""})
	}
	if mode == "auto" || mode == "rules_only" {
		if a.RuleProviders > 0 || a.Rules > 0 {
			rpName := dedupeRuleProviderName(p.SubscriptionName+"_rules", c.RuleProviders)
			section := "common"
			if len(a.SuggestedSections) > 0 && strings.Contains(a.SuggestedSections[0], " -> ") {
				parts := strings.Split(a.SuggestedSections[0], " -> ")
				section = SafeUCIName(parts[len(parts)-1])
			}
			cls := ClassifyRuleProvider(rpName, rawURL, guessBehavior(a), guessFormat(a), a.Raw)
			if cls.Section != "" {
				section = SafeUCIName(cls.Section)
			}
			p.RuleProviders = append(p.RuleProviders, config.RuleProvider{Name: rpName, Enabled: true, Behavior: guessBehavior(a), Format: guessFormat(a), URL: rawURL, Interval: 86400, Path: filepath.Join(config.DefaultWorkdir, "rulesets", rpName+".txt"), Section: section, Category: cls.Category, SourceKind: cls.SourceKind, RouteAction: cls.RouteAction, Priority: cls.Priority, SourceSubscription: p.SubscriptionName, DetectedCategory: cls.Category})
		} else if preset == "minimal" {
			p.Warnings = append(p.Warnings, "No routing rules found; Minimal preset keeps only user/manual rules")
		} else if preset == "balanced" {
			p.Warnings = append(p.Warnings, "Balanced preset requested; built-in pack catalog is intentionally not hardcoded without explicit user-selected sources")
		}
	}
	p.Warnings = append(p.Warnings, a.Warnings...)
	return p
}

func (p ImportPlan) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Import summary:\nSubscription: %s\nType: %s\nProxy nodes: %d\nProxy providers: %d\nRule providers: %d\nRules: %d\n", p.SubscriptionName, p.Summary.Type, p.Summary.ProxyNodes, len(p.ProxyProviders), len(p.RuleProviders), p.Summary.Rules)
	fmt.Fprintf(&b, "Created sections: %s\n", strings.Join(p.CreatedSections, ", "))
	if len(p.SectionGroups) > 0 {
		parts := make([]string, 0, len(p.SectionGroups))
		for _, s := range p.SectionGroups {
			parts = append(parts, fmt.Sprintf("%s: %s filter=%s exclude=%s strategy=%s url=%s interval=%d", s.Name, s.ProxyGroupType, s.ProxyFilter, s.ProxyExcludeFilter, s.ProxyStrategy, s.ProxyHealthCheckURL, s.ProxyHealthCheckInterval))
		}
		fmt.Fprintf(&b, "Section group updates: %s\n", strings.Join(parts, "; "))
	}
	fmt.Fprintf(&b, "OpenWrt export: %s\nMihomo-only: %s\n", strings.Join(p.Summary.OpenWrtExport, ", "), strings.Join(p.Summary.MihomoOnly, ", "))
	if len(p.Warnings) > 0 {
		fmt.Fprintf(&b, "Warnings:\n  %s\n", strings.Join(p.Warnings, "\n  "))
	}
	b.WriteString("Status: Ready to apply\n")
	return b.String()
}

func deriveName(raw string) string {
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" {
		base := strings.Trim(strings.ReplaceAll(u.Host, ".", "_"), "_")
		if base != "" {
			return base
		}
	}
	return "main_auto"
}

func dedupeProviderName(base string, existing []config.ProxyProvider) string {
	seen := map[string]bool{}
	for _, p := range existing {
		seen[p.Name] = true
	}
	name := base
	for i := 2; seen[name]; i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	return name
}

func dedupeRuleProviderName(base string, existing []config.RuleProvider) string {
	seen := map[string]bool{}
	for _, p := range existing {
		seen[p.Name] = true
	}
	name := SafeName(base)
	for i := 2; seen[name]; i++ {
		name = fmt.Sprintf("%s_%d", SafeName(base), i)
	}
	return name
}

func guessBehavior(a Analysis) string {
	if strings.Contains(strings.ToLower(a.Type), "cidr") {
		return "ipcidr"
	}
	return "domain"
}

func guessFormat(a Analysis) string {
	// Only `mrs` and `text` are first-class rule-provider formats — the
	// rule-provider parser layer only branches on those two. YAML-shaped
	// sources fall through to text: the line-oriented parser can't read
	// `payload:` lists anyway, and labelling them as text keeps the UI
	// (which offers only text + mrs) consistent. Subscriptions whose
	// content is a *whole* Clash YAML profile are handled by
	// profile_decompose.go via rules.ParseYAMLProfile before this guess
	// is consulted, so that path is unaffected.
	if strings.Contains(strings.ToLower(a.Type), "mrs") {
		return "mrs"
	}
	return "text"
}
