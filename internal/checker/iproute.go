package checker

import (
	"net/netip"
	"sort"

	"github.com/purewrt/purewrt/internal/config"
)

// IPRoute is the GROUND-TRUTH route for a destination IP — decided by which
// nftables prerouting dest set the IP falls in, mirroring the generator's
// precedence (see internal/generator/nftables.go prerouting chain). This is
// what the kernel actually does, independent of domain rules: an IP can be
// routed via a section's IP/CIDR set even when the domain matches no rule (so
// the domain-rule verdict would say "direct").
type IPRoute struct {
	Set     string // matched set (proxy_common4, direct4, bypass4, …); "" when no set matched
	Section string // section name, or "bypass"/"reject"/"direct", or "" (default route)
	Action  string // proxy | direct | reject | bypass | default
}

// ipSetContains is the membership check ClassifyIP uses; a package var so tests
// can stub the nft lookup.
var ipSetContains = func(set, ip string) bool {
	ok, _ := NFTSetContains(set, ip)
	return ok
}

// ClassifyIP returns the effective route for ip by testing nftables dest-set
// membership in prerouting order: bypass/exclude → global reject → global
// direct → per-section (by ascending priority) → default. Static and dynamic
// (dns_) variants of each set are both checked. Returns Action "default" when
// the IP is in no set (kernel-direct catch-all) or the address is unparseable.
func ClassifyIP(c config.Config, ip string) IPRoute {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return IPRoute{Action: "default"}
	}
	suf := "4"
	if addr.Is6() {
		suf = "6"
	}
	setContains := ipSetContains // seam for tests
	inEither := func(base string) bool {
		return setContains(base, ip) || setContains("dns_"+base, ip)
	}
	// 1. Excluded / bypass (returned early in prerouting → routes direct).
	if inEither("bypass"+suf) {
		return IPRoute{Set: "bypass" + suf, Section: "bypass", Action: "bypass"}
	}
	if setContains("proxy_server_bypass"+suf, ip) {
		return IPRoute{Set: "proxy_server_bypass" + suf, Section: "bypass", Action: "bypass"}
	}
	// 2. Global reject / direct aggregates (emitted before the per-section pass).
	if inEither("reject" + suf) {
		return IPRoute{Set: "reject" + suf, Section: "reject", Action: "reject"}
	}
	if inEither("direct" + suf) {
		return IPRoute{Set: "direct" + suf, Section: "direct", Action: "direct"}
	}
	// 3. Per-section destination sets, in the same ascending-priority order the
	//    generator emits them (first match wins).
	secs := append([]config.Section(nil), c.Sections...)
	sort.SliceStable(secs, func(i, j int) bool { return secs[i].Priority < secs[j].Priority })
	for _, s := range secs {
		if !s.Enabled {
			continue
		}
		set := s.NFTSet4()
		if addr.Is6() {
			set = s.NFTSet6()
		}
		if set == "" {
			continue
		}
		if inEither(set) {
			return IPRoute{Set: set, Section: s.Name, Action: s.Action}
		}
	}
	return IPRoute{Action: "default"}
}
