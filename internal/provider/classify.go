package provider

import "strings"

type RuleClassification struct {
	Category    string
	Section     string
	RouteAction string
	SourceKind  string
	Priority    int
	Reason      string
}

func ClassifyRuleProvider(name, rawURL, behavior, format string, data []byte) RuleClassification {
	hay := strings.ToLower(strings.Join([]string{name, rawURL, behavior, format, string(data[:min(len(data), 4096)])}, " "))
	c := RuleClassification{Category: "common", Section: "common", RouteAction: "proxy", SourceKind: sourceKind(format, rawURL), Priority: 60, Reason: "default proxy routing"}

	if containsAny(hay, "reject", "block", "ads", "adguard", "ban", "banned", "malware", "phishing", "quic") {
		c.Category, c.Section, c.RouteAction, c.Priority, c.Reason = "reject", "reject", "reject", 2, "blocking/reject ruleset"
		return c
	}
	if containsAny(hay, "private", "lan", "local", "iran", "ir", "geoip-ir", "geosite-ir", "category-ir", "cn", "china", "geoip-cn", "geosite-cn", "category-cn", "ru", "russia", "geoip-ru", "geosite-ru", "category-ru", "inside") {
		c.Category, c.Section, c.RouteAction, c.Priority, c.Reason = "direct", "direct", "direct", 1, "local/country/private direct ruleset"
		return c
	}
	if containsAny(hay, "youtube", "googlevideo", "netflix", "spotify", "tiktok", "disney", "hbo", "media") {
		c.Category, c.Section, c.Priority, c.Reason = "media", "media", 10, "media ruleset"
		return c
	}
	if containsAny(hay, "openai", "chatgpt", "anthropic", "gemini", "copilot", "category-ai") {
		c.Category, c.Section, c.Priority, c.Reason = "ai", "ai", 20, "AI ruleset"
		return c
	}
	return c
}

func sourceKind(format, rawURL string) string {
	// First-class rule-provider source kinds. "geosite" and "geoip" mean
	// "extract from the locally downloaded v2ray dat file" (see
	// internal/geodb) rather than fetching from a URL — the URL field
	// stays empty for these and the data path is the geo refresh cron.
	switch strings.ToLower(format) {
	case "mrs":
		return "mrs"
	case "text":
		return "text"
	case "geosite":
		return "geosite"
	case "geoip":
		return "geoip"
	}
	if strings.HasSuffix(strings.ToLower(rawURL), ".mrs") {
		return "mrs"
	}
	return "unknown"
}

func containsAny(s string, vals ...string) bool {
	for _, v := range vals {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}
