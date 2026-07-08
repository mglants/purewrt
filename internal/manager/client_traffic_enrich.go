package manager

// Enrichment state for ClientTraffic: ASN/ipdb lookup holder, hostname
// mapping (DNS/SNI-derived), nftset membership snapshots, and the
// packetEnrichers bundle attached to rejection events.

import (
	"context"
	"encoding/json"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/purewrt/purewrt/internal/ipdb"
)

// asnHolder lets the ASN database load in the background, off the capture's
// critical path. ipdb.Load on the ~700k-row combined dataset is CPU/alloc
// heavy; run concurrently with the nftset refresh at session start it has
// intermittently stalled long enough to delay the very first emit, so the
// LuCI Client Traffic page showed nothing ("not capturing sometimes"). We now
// start conntrack + pcap immediately and swap the DB in once it finishes;
// early flows simply lack ASN/country enrichment. Lookup is nil-safe until
// the DB is ready.
type asnHolder struct{ p atomic.Pointer[ipdb.DB] }

func (h *asnHolder) set(db *ipdb.DB) { h.p.Store(db) }
func (h *asnHolder) Lookup(a netip.Addr) ipdb.Lookup {
	if db := h.p.Load(); db != nil {
		return db.Lookup(a)
	}
	return ipdb.Lookup{}
}

// --- hostname enrichment shared state -------------------------------------

type hostnameMap struct {
	mu sync.Mutex
	m  map[string][]string // dstIP -> []hostname (most-recent-last)
}

func (h *hostnameMap) add(ip, host string) {
	if ip == "" || host == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, existing := range h.m[ip] {
		if existing == host {
			return
		}
	}
	h.m[ip] = append(h.m[ip], host)
	if len(h.m[ip]) > 5 {
		h.m[ip] = h.m[ip][len(h.m[ip])-5:]
	}
}

func (h *hostnameMap) get(ip string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.m[ip]
	if len(hs) == 0 {
		return ""
	}
	return hs[len(hs)-1]
}

// --- nftset enrichment ---------------------------------------------------
//
// Snapshots the PureWRT nft table once at session start and refreshes every
// ~10s in a background goroutine. Lookups by destination IP return the set
// memberships, which we attach to FlowSummary so the UI can show e.g. "this
// destination is currently in proxy_common" — answering the question
// "is the section's proxy failing, or is the ISP just blocking the dest?"

type nftsetEnricher struct {
	mu sync.RWMutex
	// Exact-match lookups. Populated by sets that use literal element
	// addresses (the dns_* timeout-bearing sets dnsmasq feeds into).
	ipToSets map[string][]string
	// Prefix-match lookups. Populated by interval sets — proxy_<section>4
	// holds CIDR ranges like 149.154.160.0/20 (Telegram), and an arbitrary
	// dest IP inside that range needs a containment test, not equality.
	// Sorted ascending by prefix start so we can binary-search by IP.
	cidrs []cidrEntry
}

type cidrEntry struct {
	pfx  netip.Prefix
	name string
}

func newNftsetEnricher() *nftsetEnricher {
	return &nftsetEnricher{ipToSets: map[string][]string{}}
}

func (n *nftsetEnricher) refresh() error {
	// Step 1: enumerate set names via list-table — that gives us the
	// schema (set names + flags) but, importantly, does NOT include
	// elements for interval-flagged sets. nft chooses to summarise those
	// in list-table output, only emitting the full element list for
	// list-set <name>.
	out, err := exec.Command("nft", "-j", "list", "table", "inet", "purewrt").Output()
	if err != nil {
		return err
	}
	var doc struct {
		Nftables []struct {
			Set *struct {
				Name  string   `json:"name"`
				Flags []string `json:"flags"`
			} `json:"set,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return err
	}
	nextIPs := map[string][]string{}
	var nextCIDRs []cidrEntry
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		setName := normaliseSetName(item.Set.Name)
		if setName == "" {
			continue
		}
		// Step 2: pull the full element list for this set. ~14 sets × ~50 ms
		// each = a one-off cost paid every refresh tick (10 s), well within
		// budget. Errors are logged but non-fatal — a flaky set shouldn't
		// kill enrichment for the others.
		setOut, err := exec.Command("nft", "-j", "list", "set", "inet", "purewrt", item.Set.Name).Output()
		if err != nil {
			continue
		}
		var setDoc struct {
			Nftables []struct {
				Set *struct {
					Elem []json.RawMessage `json:"elem"`
				} `json:"set,omitempty"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(setOut, &setDoc); err != nil {
			continue
		}
		for _, sItem := range setDoc.Nftables {
			if sItem.Set == nil {
				continue
			}
			for _, raw := range sItem.Set.Elem {
				if pfx, ok := parseNftPrefix(raw); ok {
					nextCIDRs = append(nextCIDRs, cidrEntry{pfx: pfx, name: setName})
					continue
				}
				ip := parseNftElem(raw)
				if ip == "" {
					continue
				}
				// Some sets emit literal "X.X.X.X/N" as a bare string for
				// /32-equivalent entries; treat those as CIDRs too.
				if strings.ContainsAny(ip, "/-") {
					if pfx, ok := parsePrefixOrRange(ip); ok {
						nextCIDRs = append(nextCIDRs, cidrEntry{pfx: pfx, name: setName})
					}
					continue
				}
				already := false
				for _, s := range nextIPs[ip] {
					if s == setName {
						already = true
						break
					}
				}
				if !already {
					nextIPs[ip] = append(nextIPs[ip], setName)
				}
			}
		}
	}
	n.mu.Lock()
	n.ipToSets = nextIPs
	n.cidrs = nextCIDRs
	n.mu.Unlock()
	return nil
}

// parseNftPrefix handles the third element shape — interval/CIDR entries
// from nft -j look like {"prefix": {"addr": "1.0.0.0", "len": 24}}. Returns
// false for the other two shapes (bare string / {elem:{val:...}}), which
// the caller falls back to via parseNftElem.
func parseNftPrefix(raw json.RawMessage) (netip.Prefix, bool) {
	var obj struct {
		Prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return netip.Prefix{}, false
	}
	if obj.Prefix.Addr == "" {
		return netip.Prefix{}, false
	}
	addr, err := netip.ParseAddr(obj.Prefix.Addr)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, obj.Prefix.Len), true
}

// parsePrefixOrRange handles both nft element formats for interval entries:
//   - "1.2.3.0/24"        → single Prefix
//   - "1.2.3.0-1.2.3.255"  → degenerate range; we collapse to a single /N
//     when the range is a whole subnet, otherwise drop (rare in practice;
//     iptoasn-style arbitrary ranges aren't what PureWRT generates).
func parsePrefixOrRange(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p, true
	}
	// "start-end" form: try parsing both endpoints; only collapse when the
	// range happens to be CIDR-aligned (common for the 1-IP "/32" case).
	if i := strings.Index(s, "-"); i > 0 {
		start, err := netip.ParseAddr(s[:i])
		if err != nil {
			return netip.Prefix{}, false
		}
		end, err := netip.ParseAddr(s[i+1:])
		if err != nil {
			return netip.Prefix{}, false
		}
		if start == end {
			return netip.PrefixFrom(start, 32), true
		}
		// Drop multi-IP non-CIDR ranges — a /20 etc. would have arrived as
		// "X/N" already, so this branch is just exotic outliers.
		return netip.Prefix{}, false
	}
	return netip.Prefix{}, false
}

// parseNftElem handles the two element shapes nft -j emits: a bare string
// like "1.2.3.4" for entries without metadata, and {"elem":{"val":"1.2.3.4",
// "timeout":..,"expires":..}} for sets with timeouts.
func parseNftElem(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj struct {
		Elem struct {
			Val string `json:"val"`
		} `json:"elem"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Elem.Val
	}
	return ""
}

// normaliseSetName strips the trailing 4/6 family suffix but keeps the
// dns_ prefix when present — so the user can distinguish:
//   - "proxy_media"      → IP entered the set from a static CIDR rule
//   - "dns_proxy_media"  → dnsmasq resolved a domain to this IP (TTL-bound)
//
// Both can be present for the same IP (CIDR matches + a domain happened to
// resolve to a covered address). Showing them separately tells the user
// WHY this destination is currently routed where it is — a domain match is
// a much stronger "the user is actually going to this hostname" signal
// than a CIDR coincidence.
//
// Returns "" for bypass-class sets — those describe the router's WAN-side
// infrastructure rather than client-destination classification, so they're
// noise in the per-flow display.
func normaliseSetName(s string) string {
	if l := len(s); l > 0 && (s[l-1] == '4' || s[l-1] == '6') {
		s = s[:l-1]
	}
	switch s {
	case "bypass", "proxy_server_bypass", "dns_bypass", "dns_proxy_server_bypass":
		return ""
	}
	return s
}

func (n *nftsetEnricher) get(ip string) []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var out []string
	// Exact-match dns_* entries first.
	if v, ok := n.ipToSets[ip]; ok {
		out = append(out, v...)
	}
	// Then walk the CIDR list and append every set whose range contains
	// this IP. Linear scan over ~hundreds-to-thousands of prefixes is
	// fine — the lookup is per-flow and per-tick, not per-packet.
	if len(n.cidrs) > 0 {
		if addr, err := netip.ParseAddr(ip); err == nil {
			for _, c := range n.cidrs {
				if c.pfx.Contains(addr) {
					if !contains(out, c.name) {
						out = append(out, c.name)
					}
				}
			}
		}
	}
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// runRefreshLoop refreshes the snapshot every interval until ctx is cancelled.
// First refresh happens immediately so the very first conntrack tick can use
// the enrichment.
func (n *nftsetEnricher) runRefreshLoop(ctx context.Context, interval time.Duration) {
	_ = n.refresh()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = n.refresh()
		}
	}
}

// packetEnrichers bundles everything a packet-level parser needs to
// attach hostname / nftset / ASN / QUIC-retry context to its emitted
// events. One field per data source, passed by pointer so a single nil-safe
// nftsets/asndb keeps the snapshot path working when the user hasn't
// installed the IP database.
type packetEnrichers struct {
	hostnames *hostnameMap
	nftsets   *nftsetEnricher
	asndb     *asnHolder
	quic      *quicRetryTracker
}

// enrich looks up ip in every available source and fills the rejectEnrichment
// struct embedded into rejection events. Safe to call with a nil receiver
// (no-op) so callers don't need to gate per field.
func (e *packetEnrichers) enrich(ip string) rejectEnrichment {
	var r rejectEnrichment
	if e == nil || ip == "" {
		return r
	}
	if e.hostnames != nil {
		r.Hostname = e.hostnames.get(ip)
	}
	if e.nftsets != nil {
		r.Nftsets = e.nftsets.get(ip)
	}
	if e.asndb != nil {
		if addr, err := netip.ParseAddr(ip); err == nil {
			lk := e.asndb.Lookup(addr)
			r.ASN, r.ASOrg, r.Country = lk.ASN, lk.ASOrg, lk.Country
		}
	}
	return r
}
