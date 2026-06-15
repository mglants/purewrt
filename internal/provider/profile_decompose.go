package provider

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/rules"
	"gopkg.in/yaml.v3"
)

type MaterializedFile struct {
	Path string
	Data []byte
}

type ProfileDecomposition struct {
	ProxyProvider config.ProxyProvider
	RuleProviders []config.RuleProvider
	SectionGroups []config.Section
	Files         []MaterializedFile
	Warnings      []string
}

func DecomposeYAMLProfile(rawURL, subName string, data []byte) (ProfileDecomposition, bool) {
	prof, err := rules.ParseYAMLProfile(data)
	if err != nil || (len(prof.Proxies) == 0 && len(prof.RuleProviders) == 0 && len(prof.Rules) == 0) {
		return ProfileDecomposition{}, false
	}
	d := ProfileDecomposition{}
	base := SafeName(subName)
	if base == "" {
		base = "profile"
	}
	if len(prof.Proxies) > 0 {
		name := base + "_nodes"
		path := filepath.Join(config.DefaultWorkdir, "providers", name+".yaml")
		d.ProxyProvider = config.ProxyProvider{Name: name, Enabled: true, Type: "file", Path: path, HealthCheck: true, HealthCheckURL: "https://cp.cloudflare.com/generate_204", HealthCheckInterval: 300}
		b, _ := yaml.Marshal(map[string]any{"proxies": prof.Proxies})
		d.Files = append(d.Files, MaterializedFile{Path: path, Data: b})
	}
	d.SectionGroups = extractSectionGroupHints(prof)
	sectionPriority := sectionPrioritiesFromRules(prof.Rules, prof.ProxyGroups)
	for i := range d.SectionGroups {
		if prio := sectionPriority[d.SectionGroups[i].Name]; prio > 0 {
			d.SectionGroups[i].Priority = prio
		}
	}
	rulePriority := ruleProviderPrioritiesFromRules(prof.Rules)
	keys := make([]string, 0, len(prof.RuleProviders))
	for k := range prof.RuleProviders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range keys {
		raw, ok := prof.RuleProviders[name].(map[string]any)
		if !ok {
			if m, ok := prof.RuleProviders[name].(map[any]any); ok {
				raw = mapAnyToString(m)
			} else {
				continue
			}
		}
		rpName := SafeName(name)
		section := SafeUCIName(rules.SectionForName(name))
		targetSection := ""
		targetRouteAction := ""
		if targetSection = sectionForRuleProviderTarget(name, prof.Rules, prof.ProxyGroups); targetSection != "" {
			section = SafeUCIName(targetSection)
			targetRouteAction = routeActionForSection(targetSection)
		}
		cls := ClassifyRuleProvider(name, stringVal(raw, "url", ""), stringVal(raw, "behavior", "domain"), stringVal(raw, "format", "text"), nil)
		rp := config.RuleProvider{Name: rpName, Enabled: true, Behavior: stringVal(raw, "behavior", "domain"), Format: stringVal(raw, "format", "text"), Interval: intVal(raw, "interval", 86400), Section: section, Category: cls.Category, SourceKind: cls.SourceKind, RouteAction: cls.RouteAction, Priority: cls.Priority, SourceSubscription: base, DetectedCategory: cls.Category}
		if prio := rulePriority[name]; prio > 0 {
			rp.Priority = prio
		}
		if targetSection == "" && cls.Section != "" {
			rp.Section = SafeUCIName(cls.Section)
		}
		if targetRouteAction != "" {
			rp.RouteAction = targetRouteAction
		}
		typ := strings.ToLower(stringVal(raw, "type", ""))
		payload, hasPayload := raw["payload"]
		if typ == "inline" || hasPayload {
			rp.Format = "text"
			rp.Path = filepath.Join(config.DefaultWorkdir, "rulesets", rpName+".list")
			d.Files = append(d.Files, MaterializedFile{Path: rp.Path, Data: []byte(payloadLines(payload))})
		} else {
			rp.URL = stringVal(raw, "url", "")
			if rp.URL == "" {
				d.Warnings = append(d.Warnings, fmt.Sprintf("rule-provider %s has no url or inline payload; skipped", name))
				continue
			}
			if rp.Format == "" {
				rp.Format = formatFromPathOrURL(stringVal(raw, "path", rp.URL))
			}
			ext := rp.Format
			if ext == "" {
				ext = "txt"
			}
			rp.Path = filepath.Join(config.DefaultWorkdir, "rulesets", rpName+"."+ext)
		}
		d.RuleProviders = append(d.RuleProviders, rp)
	}
	if strings.Contains(strings.ToLower(string(data)), "tun:\n") {
		d.Warnings = append(d.Warnings, "TUN settings detected and ignored; PureWRT default mode uses OpenWrt TPROXY/nftsets")
	}
	if strings.Contains(strings.ToLower(string(data)), "enhanced-mode: fake-ip") {
		d.Warnings = append(d.Warnings, "fake-ip DNS detected and ignored by default; PureWRT defaults to real-IP mode")
	}
	_ = rawURL
	return d, true
}

func extractSectionGroupHints(prof rules.ClashProfile) []config.Section {
	byTarget := ruleTargetsByGroup(prof.Rules)
	seen := map[string]bool{}
	out := []config.Section{}
	for _, raw := range prof.ProxyGroups {
		name := stringVal(raw, "name", "")
		section, proxyGroup := sectionAndGroupForProxyGroup(name)
		knownGroup := sectionForProxyGroup(name) != ""
		if section == "" {
			section = SafeUCIName(sectionForRuleTarget(name, byTarget))
			proxyGroup = groupNameForSection(section)
		} else if !knownGroup && sectionForRuleTarget(name, byTarget) == "" {
			continue
		}
		if section == "" || seen[section] {
			continue
		}
		groupType := normalizeGroupType(stringVal(raw, "type", ""))
		strategy := normalizeGroupStrategy(stringVal(raw, "strategy", ""))
		filter := stringVal(raw, "filter", "")
		excludeFilter := stringVal(raw, "exclude-filter", "")
		healthURL := stringVal(raw, "url", "")
		healthInterval := intVal(raw, "interval", 0)
		if groupType == "" && strategy == "" && filter == "" && excludeFilter == "" && healthURL == "" && healthInterval == 0 {
			continue
		}
		out = append(out, config.Section{Name: SafeUCIName(section), Action: "proxy", ProxyGroup: proxyGroup, ProxyGroupType: groupType, ProxyFilter: filter, ProxyExcludeFilter: excludeFilter, ProxyStrategy: strategy, ProxyHealthCheckURL: healthURL, ProxyHealthCheckInterval: healthInterval})
		seen[section] = true
	}
	return out
}

func ruleProviderPrioritiesFromRules(rulesIn []string) map[string]int {
	out := map[string]int{}
	for idx, line := range rulesIn {
		provider, _, ok := ruleSetTarget(line)
		if !ok || provider == "" || out[provider] != 0 {
			continue
		}
		out[provider] = (idx + 1) * 10
	}
	return out
}

func sectionPrioritiesFromRules(rulesIn []string, proxyGroups []map[string]any) map[string]int {
	out := map[string]int{}
	for idx, line := range rulesIn {
		_, action, ok := ruleSetTarget(line)
		if !ok {
			continue
		}
		section := SafeUCIName(sectionForRuleAction(action, proxyGroups))
		if section == "" || section == "direct" || section == "reject" || out[section] != 0 {
			continue
		}
		out[section] = (idx + 1) * 10
	}
	return out
}

func sectionForRuleProviderTarget(providerName string, rulesIn []string, proxyGroups []map[string]any) string {
	for _, line := range rulesIn {
		provider, action, ok := ruleSetTarget(line)
		if !ok || provider != providerName {
			continue
		}
		return SafeUCIName(sectionForRuleAction(action, proxyGroups))
	}
	return ""
}

func ruleSetTarget(line string) (string, string, bool) {
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return "", "", false
	}
	for i := 0; i < len(parts)-2; i++ {
		if !strings.Contains(strings.ToUpper(parts[i]), "RULE-SET") {
			continue
		}
		provider := strings.Trim(strings.TrimSpace(parts[i+1]), "()")
		if provider == "" {
			continue
		}
		action := strings.Trim(strings.TrimSpace(parts[len(parts)-1]), "()")
		if action == "" {
			continue
		}
		return provider, action, true
	}
	return "", "", false
}

func sectionForRuleAction(action string, proxyGroups []map[string]any) string {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "DIRECT":
		return "direct"
	case "REJECT", "REJECT-DROP":
		return "reject"
	}
	for _, raw := range proxyGroups {
		name := stringVal(raw, "name", "")
		if name != action {
			continue
		}
		sec, _ := sectionAndGroupForProxyGroup(name)
		return sec
	}
	if sec := sectionForProxyGroup(action); sec != "" {
		return sec
	}
	return "common"
}

func routeActionForSection(section string) string {
	switch section {
	case "direct":
		return "direct"
	case "reject":
		return "reject"
	default:
		return "proxy"
	}
}

func ruleTargetsByGroup(rulesIn []string) map[string]string {
	out := map[string]string{}
	for _, line := range rulesIn {
		provider, group, ok := ruleSetTarget(line)
		if !ok || provider == "" || group == "" {
			continue
		}
		out[group] = SafeUCIName(rules.SectionForName(provider))
	}
	return out
}

func sectionAndGroupForProxyGroup(name string) (string, string) {
	if sec := sectionForProxyGroup(name); sec != "" {
		return sec, groupNameForSection(sec)
	}
	sec := SafeUCIName(name)
	if sec == "" {
		return "", ""
	}
	switch sec {
	case "direct", "reject":
		return sec, groupNameForSection(sec)
	default:
		return sec, name
	}
}

func sectionForRuleTarget(group string, byTarget map[string]string) string {
	if sec := byTarget[group]; sec != "" {
		return sec
	}
	return ""
}

func sectionForProxyGroup(name string) string {
	hay := strings.ToLower(name)
	switch {
	case containsAnyText(hay, "youtube", "video", "media", "▶"):
		return "media"
	case containsAnyText(hay, "ai", "openai", "chatgpt", "gemini", "claude", "✨"):
		return "ai"
	case containsAnyText(hay, "telegram", "discord", "➤", "💬", "common", "proxy", "blocked", "unavailable", "🚫"):
		return "common"
	default:
		return ""
	}
}

func groupNameForSection(section string) string {
	switch section {
	case "media":
		return "Media"
	case "ai":
		return "AI"
	case "common":
		return "Common"
	default:
		return config.TitleASCII(section)
	}
}

func normalizeGroupType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "select", "url-test", "load-balance":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return ""
	}
}

func normalizeGroupStrategy(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "sticky-sessions", "consistent-hashing", "round-robin":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return ""
	}
}

func containsAnyText(s string, vals ...string) bool {
	for _, v := range vals {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

func mapAnyToString(in map[any]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[fmt.Sprint(k)] = v
	}
	return out
}

func stringVal(m map[string]any, key, def string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return def
}

func intVal(m map[string]any, key string, def int) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return def
}

func payloadLines(v any) string {
	var lines []string
	switch p := v.(type) {
	case []any:
		for _, x := range p {
			lines = append(lines, fmt.Sprint(x))
		}
	case []string:
		lines = append(lines, p...)
	case nil:
	default:
		lines = append(lines, fmt.Sprint(p))
	}
	return strings.Join(lines, "\n") + "\n"
}

func formatFromPathOrURL(v string) string {
	// MRS is the only non-text rule-provider format the parser supports.
	// .yaml / .yml URLs map to "text" because the rule-provider parser
	// has never understood the `payload:` list — labelling them text is
	// honest about what gets parsed downstream.
	if strings.HasSuffix(strings.ToLower(v), ".mrs") {
		return "mrs"
	}
	return "text"
}
