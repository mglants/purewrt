package rules

import (
	"bufio"
	"strings"
)

func ParseText(name string, data []byte) Provider {
	p := Provider{Name: name, Format: "text", Action: "proxy"}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Strip inline comments so entries can carry provenance metadata
		// — used by the LuCI manual-rule picker which appends e.g.
		// "149.154.167.41  # AS62041 TELEGRAM" when the user adds an IP
		// while the optional ipdb is installed. Neither IPs/CIDRs nor
		// DOMAIN values ever legitimately contain `#`, so dropping
		// everything from the first `#` is safe. Same treatment for
		// `//` so users can pick whichever comment style they prefer.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		} else if i := strings.Index(line, "\t#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, " //"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		} else if i := strings.Index(line, "\t//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, "+")
		if r, ok := parseLogicalRule(line); ok {
			r.SourceProvider = name
			r.SourceLine = lineNo
			p.Rules = append(p.Rules, r)
			continue
		}
		parts := strings.Split(line, ",")
		var r Rule
		switch strings.ToUpper(parts[0]) {
		case "DOMAIN":
			if len(parts) > 1 && IsValidDomain(parts[1]) {
				r = Rule{Type: Domain, Value: NormalizeDomain(parts[1]), SupportedOpenWrt: true, SupportedMihomo: true}
			}
		case "DOMAIN-SUFFIX":
			if len(parts) > 1 && IsValidDomain(parts[1]) {
				r = Rule{Type: DomainSuffix, Value: NormalizeDomain(parts[1]), SupportedOpenWrt: true, SupportedMihomo: true}
			}
		case "DOMAIN-KEYWORD":
			if len(parts) > 1 && IsValidDomain(parts[1]) {
				r = Rule{Type: DomainKeyword, Value: NormalizeDomain(parts[1]), SupportedOpenWrt: false, SupportedMihomo: true}
			}
		case "IP-CIDR":
			if len(parts) > 1 {
				r = Rule{Type: IPCIDR, Value: strings.TrimSpace(parts[1]), NoResolve: strings.Contains(strings.ToLower(line), "no-resolve"), SupportedOpenWrt: true, SupportedMihomo: true}
			}
		case "IP-CIDR6":
			if len(parts) > 1 {
				r = Rule{Type: IPCIDR6, Value: strings.TrimSpace(parts[1]), NoResolve: strings.Contains(strings.ToLower(line), "no-resolve"), SupportedOpenWrt: true, SupportedMihomo: true}
			}
		case "GEOSITE":
			if len(parts) > 1 {
				r = Rule{Type: GeoSite, Value: strings.ToLower(strings.TrimSpace(parts[1])), SupportedOpenWrt: false, SupportedMihomo: true}
			}
		case "GEOIP":
			if len(parts) > 1 {
				r = Rule{Type: GeoIP, Value: strings.ToLower(strings.TrimSpace(parts[1])), SupportedOpenWrt: false, SupportedMihomo: true}
			}
		case "DST-PORT":
			if len(parts) > 1 {
				r = Rule{Type: Native, Value: "th dport " + strings.TrimSpace(parts[1]), SupportedOpenWrt: true, SupportedMihomo: true}
			}
		case "SRC-PORT":
			if len(parts) > 1 {
				r = Rule{Type: Native, Value: "th sport " + strings.TrimSpace(parts[1]), SupportedOpenWrt: true, SupportedMihomo: true}
			}
		case "NETWORK":
			if len(parts) > 1 && isNativeNetwork(parts[1]) {
				r = Rule{Type: Native, Value: "meta l4proto " + strings.ToLower(strings.TrimSpace(parts[1])), SupportedOpenWrt: true, SupportedMihomo: true}
			}
		default:
			r = ClassifyValue(line)
		}
		r.SourceProvider = name
		r.SourceLine = lineNo
		p.Rules = append(p.Rules, r)
	}
	p.Rules = Dedup(p.Rules)
	return p
}

func parseLogicalRule(line string) (Rule, bool) {
	trimmed := strings.TrimSpace(line)
	upper := strings.ToUpper(trimmed)
	if strings.HasPrefix(upper, "AND,") {
		if expr, ok := parseNativeAND(trimmed); ok {
			return Rule{Type: Native, Value: expr, SupportedOpenWrt: true, SupportedMihomo: true}, true
		}
		return Rule{Type: Logical, Value: trimmed, SupportedOpenWrt: false, SupportedMihomo: true}, true
	}
	if strings.HasPrefix(upper, "OR,") || strings.HasPrefix(upper, "NOT,") {
		return Rule{Type: Logical, Value: trimmed, SupportedOpenWrt: false, SupportedMihomo: true}, true
	}
	return Rule{}, false
}

func parseNativeAND(line string) (string, bool) {
	conds := splitLogicalConditions(line)
	if len(conds) == 0 {
		return "", false
	}
	var out []string
	for _, cond := range conds {
		parts := strings.SplitN(cond, ",", 2)
		if len(parts) != 2 {
			return "", false
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		switch key {
		case "ip-cidr":
			out = append(out, "ip daddr "+val)
		case "ip-cidr6":
			out = append(out, "ip6 daddr "+val)
		case "src-ip-cidr":
			out = append(out, "ip saddr "+val)
		case "src-ip-cidr6":
			out = append(out, "ip6 saddr "+val)
		case "network":
			if !isNativeNetwork(val) {
				return "", false
			}
			out = append(out, "meta l4proto "+strings.ToLower(val))
		case "dst-port":
			out = append(out, "th dport "+val)
		case "src-port":
			out = append(out, "th sport "+val)
		default:
			return "", false
		}
	}
	return strings.Join(out, " "), true
}

func splitLogicalConditions(line string) []string {
	start := strings.Index(line, "(")
	end := strings.LastIndex(line, ")")
	if start < 0 || end <= start {
		return nil
	}
	body := line[start+1 : end]
	var out []string
	depth := 0
	condStart := -1
	for i, r := range body {
		switch r {
		case '(':
			if depth == 0 {
				condStart = i + 1
			}
			depth++
		case ')':
			depth--
			if depth == 0 && condStart >= 0 {
				out = append(out, strings.TrimSpace(body[condStart:i]))
				condStart = -1
			}
		}
	}
	return out
}

func isNativeNetwork(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "tcp" || v == "udp"
}
