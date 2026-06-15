package provider

import (
	"fmt"
	"path/filepath"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/geodb"
	"github.com/purewrt/purewrt/internal/rules"
)

// ParseRuleProvider has two formats: mrs (mihomo's binary) and text
// (everything else). The "text" branch handles bare FQDNs, IPs, CIDRs,
// and classical rule expressions (`DOMAIN-SUFFIX,foo` / `IP-CIDR,…`) via
// `rules.ParseText`'s auto-classify + line-oriented parser.
//
// YAML rule-provider files (a top-level `payload:` list) are *not*
// supported at this layer — `ParseText` doesn't understand the YAML
// envelope, so labelling such files `format=text` produces empty rules.
// That's intentional: we'd rather be honest than parse half the format.
// Whole Clash *config profiles* are a different layer entirely
// (rules.ParseYAMLProfile, used during subscription decomposition).
func ParseRuleProvider(name, format string, data []byte) (rules.Provider, error) {
	if format == "mrs" {
		return rules.ParseMRS(name, data)
	}
	p := rules.ParseText(name, data)
	p.Section = rules.SectionForName(name)
	return p, nil
}

func ParseRuleProviderForGeneration(name, format string, data []byte) (rules.Provider, error) {
	if format == "mrs" {
		return rules.ParseMRSWithOptions(name, data, rules.MRSParseOptions{SortDomains: false})
	}
	return ParseRuleProvider(name, format, data)
}

// ParseGeoProvider materialises a rules.Provider from the locally
// downloaded v2ray geo dat — the geosite category or geoip country
// named by rp.GeoTarget. The dat files live at
// <Settings.GeoRefreshGeoIPDir>/{geosite,geoip}.dat and are populated
// by the existing `geo-refresh` cron / CLI.
//
// Returned Provider follows the same shape as ParseRuleProvider so the
// existing generator/stream.go pipeline expands it into nftset +
// nftables sets just like a URL-backed mrs/text provider. The
// skippedRegex count surfaces in the Warnings slice — `update-rule-
// provider` logs it; the LuCI page shows it as a passing note.
func ParseGeoProvider(c config.Config, rp config.RuleProvider) (rules.Provider, error) {
	if rp.GeoTarget == "" {
		return rules.Provider{}, fmt.Errorf("geo rule provider %q has empty geo_target", rp.Name)
	}
	dir := c.Settings.GeoRefreshGeoIPDir
	if dir == "" {
		dir = "/etc/purewrt/geo"
	}
	provider := rules.Provider{
		Name:     rp.Name,
		Behavior: rp.Behavior,
		Format:   rp.Format,
		Section:  rp.Section,
		Action:   rp.RouteAction,
	}
	switch rp.Format {
	case "geosite":
		rls, skipped, err := geodb.ExtractGeoSiteRules(filepath.Join(dir, "geosite.dat"), rp.GeoTarget)
		if err != nil {
			return rules.Provider{}, fmt.Errorf("geosite/%s: %w", rp.GeoTarget, err)
		}
		provider.Rules = rls
		if skipped > 0 {
			provider.Warnings = append(provider.Warnings, fmt.Sprintf("skipped %d regex entries (unsupported by nftset path)", skipped))
		}
	case "geoip":
		rls, err := geodb.ExtractGeoIPRules(filepath.Join(dir, "geoip.dat"), rp.GeoTarget)
		if err != nil {
			return rules.Provider{}, fmt.Errorf("geoip/%s: %w", rp.GeoTarget, err)
		}
		provider.Rules = rls
	default:
		return rules.Provider{}, fmt.Errorf("ParseGeoProvider: format %q is not a geo format", rp.Format)
	}
	return provider, nil
}

// IsGeoFormat reports whether a rule provider's Format string indicates
// the geo (local v2ray dat) source path instead of a URL fetch.
func IsGeoFormat(format string) bool {
	return format == "geosite" || format == "geoip"
}
