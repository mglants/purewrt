package checker

import (
	"errors"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/rules"
)

type RuleProviderMatch struct {
	Provider string
	Rule     rules.Rule
	Section  string
	Action   string
	Matched  bool
}

// matchInfo carries the provenance of a single (domain, rule) entry as it
// sits in the index. We keep the full source rule so callers that surface
// "matched rule: domain_suffix,netflix.com" (purewrt-check) still get
// accurate output.
type matchInfo struct {
	provider string
	section  string
	action   string
	rule     rules.Rule
}

type keywordEntry struct {
	kw   string
	info matchInfo
}

// mrsDomainSetEntry holds a non-materialising MRS DomainSet alongside the
// provider's match metadata. The rule field in info is left zero — the
// concrete rules.Rule is synthesised at match time from the matched
// suffix returned by DomainSet.Lookup.
type mrsDomainSetEntry struct {
	set  rules.DomainSet
	info matchInfo
}

func (e *mrsDomainSetEntry) toMatch(suffix string) RuleProviderMatch {
	return RuleProviderMatch{
		Provider: e.info.provider,
		Rule: rules.Rule{
			Type:             rules.DomainSuffix,
			Value:            suffix,
			SourceProvider:   e.info.provider,
			SupportedOpenWrt: true,
			SupportedMihomo:  true,
		},
		Section: e.info.section,
		Action:  e.info.action,
		Matched: true,
	}
}

// RuleProviderIndex is a lazy, priority-ordered domain match index over the
// enabled rule providers. Providers are sorted by Priority up front but
// parsed on demand — Match parses the next-highest-priority provider only
// when the partial index built so far doesn't claim the domain, and stops
// the moment it finds a hit.
//
// Why lazy: blocked-refilter-domains alone has ~81 k entries and ~572 KB
// of zstd-compressed binary that has to be decoded and reified into Go
// strings (and then sorted, by upstream's ParseMRS default). For
// purewrt-check with chatgpt.com — which matches the tiny priority-30
// `ai` MRS — we used to eagerly parse every provider anyway, paying the
// full multi-second cost for nothing. Lazy parsing keeps the small
// per-call overhead for hits in early providers, and only pays the big
// cost when no higher-priority provider claims the domain.
//
// Priority handling: a key already present in the map is never overwritten
// as later (lower-priority) providers are parsed in, so mihomo's
// "first match wins" semantics are preserved without per-entry priorities.
//
// Concurrency: Match mutates internal state and is not safe for concurrent
// callers. Build a separate index per goroutine if you need parallelism.
// cidrRuleEntry holds one IP-CIDR rule from a rule provider with the
// provider's match metadata. Used for the IP-lookup path — when the user
// (or purewrt-check) passes an IPv4/IPv6 instead of a domain, we walk
// these in priority order looking for containment.
type cidrRuleEntry struct {
	pfx  netip.Prefix
	info matchInfo
}

type RuleProviderIndex struct {
	pending      []config.RuleProvider // remaining unparsed, sorted asc by priority
	cfg          config.Config
	domainExact  map[string]matchInfo
	domainSuffix map[string]matchInfo
	domainSets   []mrsDomainSetEntry // MRS-format domain providers, priority-ordered
	keywords     []keywordEntry
	// cidrs collects every IP-CIDR rule from providers we've parsed so far.
	// Walked linearly by MatchIP — fine for ~hundreds-of-thousands of
	// entries in practice (each lookup is one-shot per user query, not
	// per-packet), and avoids the complexity of a prefix-trie when the
	// hot path doesn't need it.
	cidrs    []cidrRuleEntry
	fallback RuleProviderMatch
}

// NewRuleProviderIndex prepares the priority-ordered list of providers but
// does not read or parse any of them — that happens lazily inside Match.
func NewRuleProviderIndex(c config.Config) *RuleProviderIndex {
	enabled := make([]config.RuleProvider, 0, len(c.RuleProviders))
	for _, rp := range c.RuleProviders {
		if !rp.Enabled || rp.Path == "" {
			continue
		}
		enabled = append(enabled, rp)
	}
	sort.SliceStable(enabled, func(i, j int) bool {
		return enabled[i].Priority < enabled[j].Priority
	})
	return &RuleProviderIndex{
		pending:      enabled,
		cfg:          c,
		domainExact:  make(map[string]matchInfo, 256),
		domainSuffix: make(map[string]matchInfo, 4096),
		// No-match fallback: PureWRT routes through proxies only when an
		// nftset claims the destination. When nothing matches, traffic
		// goes out WAN via the default route — "direct", not "proxy". Set
		// Matched=false (zero value) so callers know this is the no-match
		// branch and can decide whether to keep their own metadata.
		fallback:     RuleProviderMatch{Section: "default", Action: "direct"},
	}
}

func (info matchInfo) toMatch() RuleProviderMatch {
	return RuleProviderMatch{Provider: info.provider, Rule: info.rule, Section: info.section, Action: info.action, Matched: true}
}

// lookup checks the currently-parsed maps without triggering any new
// provider parses. Returns the match and whether one was found.
func (idx *RuleProviderIndex) lookup(domain string) (RuleProviderMatch, bool) {
	if info, ok := idx.domainExact[domain]; ok {
		return info.toMatch(), true
	}
	if info, ok := idx.domainSuffix[domain]; ok {
		return info.toMatch(), true
	}
	d := domain
	for i := strings.IndexByte(d, '.'); i >= 0; i = strings.IndexByte(d, '.') {
		d = d[i+1:]
		if d == "" {
			break
		}
		if info, ok := idx.domainSuffix[d]; ok {
			return info.toMatch(), true
		}
	}
	// MRS DomainSets are walked in priority order. They're checked after
	// the hash-map fast path because text-format providers usually carry
	// hand-curated exceptions that should override binary lists at the
	// same priority slot; lazy parsing in parseNext guarantees a true
	// priority-ordered match across MRS+text mixes.
	for i := range idx.domainSets {
		if suffix, ok := idx.domainSets[i].set.Lookup(domain); ok {
			return idx.domainSets[i].toMatch(suffix), true
		}
	}
	return RuleProviderMatch{}, false
}

// parseNext reads and folds the next pending provider into the index.
// Returns false when no more providers remain.
func (idx *RuleProviderIndex) parseNext() bool {
	if len(idx.pending) == 0 {
		return false
	}
	rp := idx.pending[0]
	idx.pending = idx.pending[1:]
	action := ""
	if sec, ok := idx.cfg.SectionByName(rp.Section); ok && sec.Action != "" {
		action = sec.Action
	}
	data, err := os.ReadFile(rp.Path)
	if err != nil {
		return true
	}
	if strings.EqualFold(rp.Format, "mrs") {
		set, err := rules.ParseMRSDomainSet(rp.Name, data)
		if err == nil {
			idx.domainSets = append(idx.domainSets, mrsDomainSetEntry{
				set:  set,
				info: matchInfo{provider: rp.Name, section: rp.Section, action: action},
			})
			return true
		}
		if !errors.Is(err, rules.ErrNotDomainBehavior) {
			return true
		}
		// IPCIDR MRS file — pull the prefixes out via the full ParseMRS
		// (which materialises rules into rules.Rule entries) and fold
		// them into the cidrs slice for IP-lookup queries.
		parsedMRS, err := rules.ParseMRS(rp.Name, data)
		if err == nil {
			info := matchInfo{provider: rp.Name, section: rp.Section, action: action}
			for _, r := range parsedMRS.Rules {
				if r.Type != rules.IPCIDR && r.Type != rules.IPCIDR6 {
					continue
				}
				if pfx, err := netip.ParsePrefix(r.Value); err == nil {
					ri := info
					ri.rule = r
					idx.cidrs = append(idx.cidrs, cidrRuleEntry{pfx: pfx, info: ri})
				}
			}
		}
		return true
	}
	parsed := rules.ParseText(rp.Name, data)
	for _, r := range parsed.Rules {
		info := matchInfo{provider: rp.Name, section: rp.Section, action: action, rule: r}
		switch r.Type {
		case rules.Domain:
			if _, ok := idx.domainExact[r.Value]; !ok {
				idx.domainExact[r.Value] = info
			}
		case rules.DomainSuffix:
			if _, ok := idx.domainSuffix[r.Value]; !ok {
				idx.domainSuffix[r.Value] = info
			}
		case rules.DomainKeyword:
			idx.keywords = append(idx.keywords, keywordEntry{kw: r.Value, info: info})
		case rules.IPCIDR, rules.IPCIDR6:
			if pfx, err := netip.ParsePrefix(r.Value); err == nil {
				idx.cidrs = append(idx.cidrs, cidrRuleEntry{pfx: pfx, info: info})
			}
		}
	}
	return true
}

// Match returns the highest-priority rule that claims domain, or the
// fallback common+proxy default. Lazily parses pending providers in
// priority order until it finds a hit (or runs out of providers).
func (idx *RuleProviderIndex) Match(domain string) RuleProviderMatch {
	d := rules.NormalizeDomain(domain)
	if m, ok := idx.lookup(d); ok {
		return m
	}
	for idx.parseNext() {
		if m, ok := idx.lookup(d); ok {
			return m
		}
	}
	// Keyword rules can't be addressed by hash lookup; scan the
	// accumulated list now that every provider is parsed.
	for _, k := range idx.keywords {
		if strings.Contains(domain, k.kw) {
			return k.info.toMatch()
		}
	}
	return idx.fallback
}

// MatchIP returns the highest-priority rule provider that lists ip in its
// IPCIDR set, or the fallback when none claim it. Forces all pending
// providers to be parsed before checking — CIDR matches don't admit a
// short-circuit (we can't tell from the partial index whether a
// higher-priority unparsed provider would cover the IP), so this is more
// expensive than Match for domains. Still cheap enough for a one-shot
// user query.
func (idx *RuleProviderIndex) MatchIP(addr netip.Addr) RuleProviderMatch {
	for idx.parseNext() {
	}
	for _, c := range idx.cidrs {
		if c.pfx.Contains(addr) {
			return RuleProviderMatch{
				Provider: c.info.provider,
				Rule:     c.info.rule,
				Section:  c.info.section,
				Action:   c.info.action,
				Matched:  true,
			}
		}
	}
	return idx.fallback
}

// MatchRuleProviders is the single-query convenience wrapper. Detects
// whether the input is a literal IP (IPv4 or IPv6) and dispatches to the
// IP-CIDR matcher; otherwise treats it as a domain and uses the existing
// suffix/exact/keyword index. Each call builds a fresh index — fine for
// one-shot tools like purewrt-check; batch callers should build the
// index once with NewRuleProviderIndex.
//
// Iteration order is priority-sorted (lower number first) to match mihomo;
// MRS format is dispatched to ParseMRS instead of ParseText so binary
// rulesets like category-ai-!cn match the same domains they would inside
// mihomo's own engine.
func MatchRuleProviders(c config.Config, query string) RuleProviderMatch {
	idx := NewRuleProviderIndex(c)
	if addr, err := netip.ParseAddr(strings.TrimSpace(query)); err == nil {
		return idx.MatchIP(addr)
	}
	return idx.Match(query)
}
