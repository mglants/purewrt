package provider

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/purewrt/purewrt/internal/rules"
)

type Analysis struct {
	Type                                                                string
	ProxyNodes, ProxyProviders, RuleProviders, Rules                    int
	SuggestedSections, OpenWrtExport, MihomoOnly, Unsupported, Warnings []string
	// ProxyNodeNames lists the inline proxy node names from a Clash/Mihomo
	// profile (capped). These become the generated proxy provider's nodes, so
	// the wizard can preview which servers a section's filter/exclude selects
	// before applying. Empty for subscriptions whose nodes come only from an
	// external proxy-provider (resolved by mihomo at runtime).
	ProxyNodeNames []string
	Raw            []byte
}

// maxPreviewProxyNames caps the node-name list carried in a preview so a
// subscription with thousands of nodes doesn't bloat the rpc payload.
const maxPreviewProxyNames = 500

func AnalyzeContent(url string, data []byte) Analysis {
	a := Analysis{Raw: data}
	txt := string(data)
	if !utf8.Valid(data) {
		if len(data) > 4 {
			a.Type = "MRS ruleset"
			a.RuleProviders = 1
			if info, err := rules.AnalyzeMRS(data); err == nil {
				a.Rules = info.Count
				a.OpenWrtExport = []string{fmt.Sprintf("rules: %d", info.Count)}
				a.MihomoOnly = []string{"rules: 0"}
			} else {
				a.Warnings = append(a.Warnings, "Binary MRS detected but could not be decoded: "+err.Error())
			}
		}
		return a
	}
	if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(txt)); err == nil && strings.Contains(string(dec), "://") {
		txt = string(dec)
		data = dec
		a.Warnings = append(a.Warnings, "Base64 proxy subscription decoded")
	}
	low := strings.ToLower(txt)
	switch {
	case strings.Contains(low, "proxies:") || strings.Contains(low, "proxy-providers:") || strings.Contains(low, "rule-providers:") || strings.Contains(low, "rules:"):
		prof, _ := rules.ParseYAMLProfile(data)
		a.Type = "Mihomo/Clash YAML profile"
		a.ProxyNodes = len(prof.Proxies)
		for _, p := range prof.Proxies {
			if name, ok := p["name"].(string); ok && name != "" {
				a.ProxyNodeNames = append(a.ProxyNodeNames, name)
				if len(a.ProxyNodeNames) >= maxPreviewProxyNames {
					break
				}
			}
		}
		a.ProxyProviders = len(prof.ProxyProviders)
		a.RuleProviders = len(prof.RuleProviders)
		a.Rules = len(prof.Rules)
		for name := range prof.RuleProviders {
			sec := rules.SectionForName(name)
			a.SuggestedSections = append(a.SuggestedSections, fmt.Sprintf("%s -> %s", name, sec))
		}
	case strings.Contains(low, "vmess://") || strings.Contains(low, "trojan://") || strings.Contains(low, "vless://") || strings.Contains(low, "ss://") || strings.Contains(low, "hysteria2://"):
		a.Type = "Proxy URI subscription"
		a.ProxyNodes = countProxyURIs(txt)
	case strings.Contains(low, "domain-suffix") || strings.Contains(low, "ip-cidr") || strings.Contains(low, "domain,"):
		p := rules.ParseText("inline", data)
		a.Type = "Classical rule list"
		a.Rules = len(p.Rules)
		a.RuleProviders = 1
		ow, mo := rules.SplitOpenWrt(p.Rules)
		a.OpenWrtExport = []string{fmt.Sprintf("rules: %d", len(ow))}
		a.MihomoOnly = []string{fmt.Sprintf("rules: %d", len(mo))}
	default:
		p := rules.ParseText("inline", data)
		a.Rules = len(p.Rules)
		if a.Rules > 0 {
			a.Type = "Domain/CIDR list"
			a.RuleProviders = 1
			a.OpenWrtExport = []string{fmt.Sprintf("rules: %d", len(p.Rules))}
		} else {
			a.Type = "Unknown"
			a.Warnings = append(a.Warnings, "Unsupported or empty subscription")
		}
	}
	if len(a.SuggestedSections) == 0 {
		a.SuggestedSections = []string{"common"}
	}
	return a
}
func countProxyURIs(s string) int {
	n := 0
	for _, line := range strings.Fields(s) {
		if strings.Contains(line, "://") {
			n++
		}
	}
	return n
}
