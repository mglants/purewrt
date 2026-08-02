package generator

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/proxyguard"
)

const proxyGuardCandidatePrefix = "PureWRTGuardCandidate_"

// ProxyGuardCandidateName is stable across runs and deliberately detached
// from user-visible group names. ProxyGroups filters this reserved prefix.
func ProxyGuardCandidateName(group string) string {
	sum := sha256.Sum256([]byte(group))
	return fmt.Sprintf("%s%x", proxyGuardCandidatePrefix, sum[:6])
}

func IsProxyGuardCandidate(name string) bool {
	return strings.HasPrefix(name, proxyGuardCandidatePrefix)
}

func managedProxyGuardGroups(c config.Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	add("DNSProxy")
	friends := meshFriends(c)
	for _, sec := range c.Sections {
		if !sec.Enabled || sec.Action != "proxy" {
			continue
		}
		if len(friends) > 0 {
			add(sec.ProxyGroup + "_local")
		} else {
			add(sec.ProxyGroup)
		}
	}
	if len(friends) > 0 {
		add("Friends")
	}
	enabledProviders := make([]config.ProxyProvider, 0, len(c.ProxyProviders))
	for _, p := range c.ProxyProviders {
		if p.Enabled {
			enabledProviders = append(enabledProviders, p)
		}
	}
	if meshExitViable(c, enabledProviders) {
		add("MeshExit")
	}
	return out
}

// ProxyGuardManagedGroups exposes the concrete generated groups whose direct
// egress members are eligible for runtime quarantine.
func ProxyGuardManagedGroups(c config.Config) []string {
	return managedProxyGuardGroups(c)
}

// applyProxyGuardOverlay runs after the user mixin. It never writes UCI and
// never edits the user's stored filter. For mihomo's single effective
// exclude-filter field, it preserves the exact user expression as the first
// backtick-delimited clause and appends one generated exact-name clause.
func applyProxyGuardOverlay(data []byte, c config.Config, state *proxyguard.State) ([]byte, error) {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("decode mihomo yaml: %w", err)
	}
	rawGroups, ok := root["proxy-groups"].([]any)
	if !ok {
		return nil, fmt.Errorf("proxy-groups is missing or not an array")
	}
	byName := map[string]map[string]any{}
	for _, raw := range rawGroups {
		if g, ok := raw.(map[string]any); ok {
			if name, _ := g["name"].(string); name != "" {
				byName[name] = g
			}
		}
	}
	if state == nil {
		empty := proxyguard.NewState()
		state = &empty
	}

	for _, name := range managedProxyGuardGroups(c) {
		group := byName[name]
		if group == nil {
			// A mixin may intentionally replace the entire proxy-groups list.
			// Skip missing managed groups; never synthesize routing the user
			// removed.
			continue
		}
		shadow := cloneStringMap(group)
		shadow["name"] = ProxyGuardCandidateName(name)
		shadow["type"] = "select"
		shadow["hidden"] = true
		delete(shadow, "strategy")
		delete(shadow, "url")
		delete(shadow, "interval")
		delete(shadow, "tolerance")
		delete(shadow, "timeout")
		delete(shadow, "max-failed-times")
		rawGroups = append(rawGroups, shadow)

		gs := state.Groups[name]
		if gs == nil || len(gs.Members) == 0 {
			continue
		}
		excluded := map[string]bool{}
		retained := map[string]bool{}
		for _, member := range gs.LastResorts {
			retained[member] = true
		}
		for _, member := range gs.Members {
			if retained[member] {
				continue
			}
			if node := state.Nodes[member]; node != nil && node.State == proxyguard.Quarantined {
				excluded[member] = true
			}
		}
		if len(excluded) == 0 {
			continue
		}
		if proxies, ok := group["proxies"].([]any); ok {
			kept := proxies[:0]
			for _, p := range proxies {
				name, _ := p.(string)
				if !excluded[name] {
					kept = append(kept, p)
				}
			}
			group["proxies"] = kept
		}
		userFilter, _ := group["exclude-filter"].(string)
		guardFilter := exactNamesRegex(excluded)
		if userFilter == "" {
			group["exclude-filter"] = guardFilter
		} else {
			group["exclude-filter"] = userFilter + "`" + guardFilter
		}
	}
	root["proxy-groups"] = rawGroups
	return yaml.Marshal(root)
}

func cloneStringMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch x := v.(type) {
		case []any:
			out[k] = append([]any(nil), x...)
		case map[string]any:
			out[k] = cloneStringMap(x)
		default:
			out[k] = v
		}
	}
	return out
}

func exactNamesRegex(names map[string]bool) string {
	items := make([]string, 0, len(names))
	for name := range names {
		escaped := regexp.QuoteMeta(name)
		// Backtick is mihomo's multiple-regex separator. Hex-escape it so a
		// node name cannot create an extra clause.
		escaped = strings.ReplaceAll(escaped, "`", `\x60`)
		items = append(items, escaped)
	}
	sort.Strings(items)
	return "^(?:" + strings.Join(items, "|") + ")$"
}
