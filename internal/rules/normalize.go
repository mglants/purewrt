package rules

import (
	"net"
	"strings"
)

func NormalizeDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "+.")
	v = strings.TrimPrefix(v, ".")
	return strings.TrimSuffix(v, ".")
}
func ClassifyValue(v string) Rule {
	v = strings.TrimSpace(v)
	if _, n, err := net.ParseCIDR(v); err == nil {
		if strings.Contains(n.IP.String(), ":") {
			return Rule{Type: IPCIDR6, Value: n.String(), SupportedOpenWrt: true, SupportedMihomo: true}
		}
		return Rule{Type: IPCIDR, Value: n.String(), SupportedOpenWrt: true, SupportedMihomo: true}
	}
	// Bare IP literal (no /N) — promote to /32 or /128 so the manual
	// rules file accepts entries like `74.125.131.19` directly, the same
	// way a user expects from reading the documentation. Without this,
	// IsValidDomain's char rules accept all-numeric labels and the line
	// gets misclassified as a DomainSuffix (which mihomo would only
	// match against hostnames, never IPs).
	if ip := net.ParseIP(v); ip != nil {
		if ip.To4() != nil {
			return Rule{Type: IPCIDR, Value: ip.To4().String() + "/32", SupportedOpenWrt: true, SupportedMihomo: true}
		}
		return Rule{Type: IPCIDR6, Value: ip.String() + "/128", SupportedOpenWrt: true, SupportedMihomo: true}
	}
	if !IsValidDomain(v) {
		return Rule{Type: DomainSuffix, Value: NormalizeDomain(v), SupportedOpenWrt: false, SupportedMihomo: false}
	}
	return Rule{Type: DomainSuffix, Value: NormalizeDomain(v), SupportedOpenWrt: true, SupportedMihomo: true}
}

func IsValidDomain(v string) bool {
	v = NormalizeDomain(v)
	if v == "" || len(v) > 253 || strings.Contains(v, "*") || strings.Contains(v, "..") {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	labels := strings.Split(v, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}
func Dedup(rs []Rule) []Rule {
	seen := map[string]bool{}
	out := make([]Rule, 0, len(rs))
	for _, r := range rs {
		k := string(r.Type) + "|" + r.Value
		if !seen[k] && r.Value != "" {
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}
