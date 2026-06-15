// Package ipdb provides offline IP → ASN / country / org enrichment for
// PureWRT diagnostics (IPv4 and IPv6). The data source is iptoasn.com — a
// public-domain dataset derived from the global routing table — distributed
// as a single gzipped TSV that we download into /etc/purewrt/ipdb/ on demand.
//
// Why not reuse mihomo's geoip.metadb: that's a MetaCubeX-flavoured MMDB
// loaded into mihomo's process. Reading it from outside would mean
// implementing the MMDB reader and the metadb extensions, AND working
// around the fact that mihomo holds an exclusive read lock most of the
// time. iptoasn's TSV is simpler, smaller, license-clean, and gives us
// the three fields we actually want (ASN, country, AS org) in one record.
//
// Format of each TSV row:
//   range_start	range_end	as_number	country_code	as_description
//   1.0.0.0       1.0.0.255    13335        US             CLOUDFLARENET
package ipdb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// SourceURL is the upstream — public domain, no key or license needed.
// The combined dataset carries both IPv4 and IPv6 ranges in one file.
const SourceURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

const (
	combinedName = "ip2asn-combined.tsv.gz"
	legacyName   = "ip2asn-v4.tsv.gz"
)

// GZPath returns the absolute path to the gzipped TSV under the user's
// configured PureWRT workdir. Callers should pass c.Settings.Workdir
// (typically "/etc/purewrt") rather than hardcoding paths — installs that
// override Workdir for non-standard layouts get the right location for free.
//
// Migration: installs that downloaded the old v4-only dataset keep working
// — when the combined file is absent but the legacy one exists, the legacy
// path is returned so status/enrichment stay alive until the next
// `ipdb-update` replaces it.
//
// The DB is kept gzipped on disk (~12 MB compressed vs ~45 MB raw) so the
// flash budget on small OpenWrt targets isn't blown for an optional
// enrichment dataset. Decompression happens in-memory on Load.
func GZPath(workdir string) string {
	dir := ipdbDir(workdir)
	combined := filepath.Join(dir, combinedName)
	if _, err := os.Stat(combined); err == nil {
		return combined
	}
	legacy := filepath.Join(dir, legacyName)
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return combined
}

// DownloadPath is the target for Update — always the combined dataset,
// regardless of which file GZPath currently resolves to.
func DownloadPath(workdir string) string {
	return filepath.Join(ipdbDir(workdir), combinedName)
}

func ipdbDir(workdir string) string {
	if workdir == "" {
		workdir = "/etc/purewrt"
	}
	return filepath.Join(workdir, "ipdb")
}

// Lookup is what callers get back per IP. ASN==0 means "not announced in
// the global routing table" — could be RFC1918, bogon, or just unrouted.
// Callers should treat ASN==0 as "no useful info" rather than "AS zero."
type Lookup struct {
	ASN     uint32 `json:"asn,omitempty"`
	ASOrg   string `json:"as_org,omitempty"`
	Country string `json:"country,omitempty"`
}

// DB is an in-memory snapshot of the iptoasn dataset, both families
// sorted by start address so Lookup can binary-search.
type DB struct {
	entries  []entry
	entries6 []entry6
}

// entry is the unmarshalled in-memory form of one TSV row. Using uint32
// instead of net.IP keeps the binary representation tight (~80 bytes per
// entry vs ~200), which matters: ~500K entries × 200B = 100MB; × 80B = 40MB.
type entry struct {
	startIP, endIP uint32
	asn            uint32
	cc             string
	org            string
}

// entry6 mirrors entry for IPv6 ranges using 16-byte big-endian addresses.
// The v6 table is ~2 orders of magnitude smaller than v4 (~100K ranges),
// so the wider keys cost only a few MB.
type entry6 struct {
	startIP, endIP [16]byte
	asn            uint32
	cc             string
	org            string
}

// Load parses the gzipped TSV at path into an in-memory DB. Errors only on
// IO or hard format problems — individual unparseable rows are skipped
// silently so a single malformed line doesn't break the whole load.
func Load(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("gunzip %s: %w", path, err)
		}
		defer gz.Close()
		r = gz
	}
	return parseTSV(r)
}

func parseTSV(r io.Reader) (*DB, error) {
	scanner := bufio.NewScanner(r)
	// iptoasn rows are short but make the buffer generous to handle any
	// AS-description outliers (some AS names can include addresses).
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	out := make([]entry, 0, 500_000)
	var out6 []entry6
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.SplitN(line, "\t", 5)
		if len(fields) < 5 {
			continue
		}
		asn64, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		cc := strings.TrimSpace(fields[3])
		org := strings.TrimSpace(fields[4])
		if start, ok := parseIPv4(fields[0]); ok {
			end, ok := parseIPv4(fields[1])
			if !ok {
				continue
			}
			out = append(out, entry{startIP: start, endIP: end, asn: uint32(asn64), cc: cc, org: org})
			continue
		}
		// Combined dataset rows: v6 ranges use the same columns with
		// full-form addresses. Both endpoints must be v6 or the row is
		// malformed and skipped.
		start6, ok := parseIPv6(fields[0])
		if !ok {
			continue
		}
		end6, ok := parseIPv6(fields[1])
		if !ok {
			continue
		}
		out6 = append(out6, entry6{startIP: start6, endIP: end6, asn: uint32(asn64), cc: cc, org: org})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// iptoasn data is already sorted by start address, but defend against
	// future format changes — sort.Slice is O(n log n) ~= 100ms on 500K
	// already-sorted entries (insertion-sort fast path doesn't apply, but
	// it's still cheap enough to do once per load).
	sort.Slice(out, func(i, j int) bool { return out[i].startIP < out[j].startIP })
	sort.Slice(out6, func(i, j int) bool { return bytes.Compare(out6[i].startIP[:], out6[j].startIP[:]) < 0 })
	return &DB{entries: out, entries6: out6}, nil
}

// parseIPv4 turns a dotted-quad string into a 32-bit BE integer. Returns
// false for IPv6 or malformed input — callers skip the row.
func parseIPv4(s string) (uint32, bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, false
	}
	p4 := ip.To4()
	if p4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(p4), true
}

// parseIPv6 turns an IPv6 string into its 16-byte BE form. Returns false
// for IPv4 (including v4-mapped) or malformed input.
func parseIPv6(s string) ([16]byte, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return [16]byte{}, false
	}
	return addr.As16(), true
}

// Lookup finds the entry containing ip and returns its ASN/CC/org. Zero
// Lookup{} is returned for IPs outside any known range, IPv6, or invalid
// input — callers can treat that case the same as "DB not installed."
func (db *DB) Lookup(ip netip.Addr) Lookup {
	if db == nil || len(db.entries) == 0 {
		return Lookup{}
	}
	if !ip.Is4() && !ip.Is4In6() {
		return db.lookup6(ip)
	}
	v4 := ip.Unmap().As4()
	needle := binary.BigEndian.Uint32(v4[:])
	// Binary-search for the rightmost entry whose startIP <= needle.
	i := sort.Search(len(db.entries), func(i int) bool {
		return db.entries[i].startIP > needle
	})
	if i == 0 {
		return Lookup{}
	}
	e := db.entries[i-1]
	if needle > e.endIP {
		return Lookup{} // gap between ranges
	}
	if e.asn == 0 {
		// "Not routed" entries in iptoasn are intentional placeholders; we
		// treat them as "no info" so the UI doesn't render "AS 0".
		return Lookup{}
	}
	return Lookup{ASN: e.asn, Country: e.cc, ASOrg: e.org}
}

// lookup6 mirrors the v4 binary search over the IPv6 table. Empty table
// (legacy v4-only dataset still on disk) returns the zero Lookup, same as
// "DB not installed" — no error surface for dual-stack-on-old-data.
func (db *DB) lookup6(ip netip.Addr) Lookup {
	if len(db.entries6) == 0 || !ip.Is6() {
		return Lookup{}
	}
	needle := ip.As16()
	i := sort.Search(len(db.entries6), func(i int) bool {
		return bytes.Compare(db.entries6[i].startIP[:], needle[:]) > 0
	})
	if i == 0 {
		return Lookup{}
	}
	e := db.entries6[i-1]
	if bytes.Compare(needle[:], e.endIP[:]) > 0 {
		return Lookup{} // gap between ranges
	}
	if e.asn == 0 {
		return Lookup{}
	}
	return Lookup{ASN: e.asn, Country: e.cc, ASOrg: e.org}
}

// Count returns the number of usable entries — exposed so the
// `ipdb-status` CLI can show "loaded N ranges" as a freshness sanity check.
func (db *DB) Count() int {
	if db == nil {
		return 0
	}
	return len(db.entries) + len(db.entries6)
}

// ASInfo summarises one Autonomous System for the "add entire AS to
// manual" feature. Prefixes are the CIDR decomposition of every
// start-end range the database lists for the ASN — iptoasn stores ranges
// natively, not CIDRs, so we decompose them at lookup time so callers
// (LuCI manual picker, scripts) get the CIDR list they actually need to
// write into a rule provider.
type ASInfo struct {
	ASN      uint32   `json:"asn"`
	ASOrg    string   `json:"as_org,omitempty"`
	Country  string   `json:"country,omitempty"`
	Prefixes []string `json:"prefixes"`
	Ranges   int      `json:"ranges"`
}

// PrefixesForASN walks the database for every range claimed by asn and
// returns the union as a list of CIDR strings, sorted by prefix start.
// Empty result if the ASN isn't in the database or the database isn't
// loaded — caller can treat both the same.
func (db *DB) PrefixesForASN(asn uint32) ASInfo {
	info := ASInfo{ASN: asn}
	if db == nil || asn == 0 {
		return info
	}
	for _, e := range db.entries {
		if e.asn != asn {
			continue
		}
		info.Ranges++
		if info.ASOrg == "" {
			info.ASOrg = e.org
		}
		if info.Country == "" {
			info.Country = e.cc
		}
		// Decompose start..end into CIDRs. Each iteration carves the
		// largest aligned prefix that doesn't overshoot end.
		start, end := e.startIP, e.endIP
		for start <= end {
			plen := 32
			for plen > 0 {
				newPlen := plen - 1
				blockSize := uint64(1) << uint(32-newPlen)
				if uint64(start)%blockSize != 0 {
					break
				}
				if uint64(start)+blockSize-1 > uint64(end) {
					break
				}
				plen = newPlen
			}
			info.Prefixes = append(info.Prefixes, cidrString(start, plen))
			step := uint64(1) << uint(32-plen)
			next := uint64(start) + step
			if next > 0xffffffff {
				break
			}
			start = uint32(next)
		}
	}
	for _, e := range db.entries6 {
		if e.asn != asn {
			continue
		}
		info.Ranges++
		if info.ASOrg == "" {
			info.ASOrg = e.org
		}
		if info.Country == "" {
			info.Country = e.cc
		}
		info.Prefixes = append(info.Prefixes, rangeToPrefixes6(e.startIP, e.endIP)...)
	}
	return info
}

// rangeToPrefixes6 decomposes an inclusive IPv6 range into CIDRs using
// netip — same greedy largest-aligned-block walk as the v4 loop, with the
// 128-bit arithmetic done on [16]byte via helpers.
func rangeToPrefixes6(start, end [16]byte) []string {
	var out []string
	cur := start
	for bytes.Compare(cur[:], end[:]) <= 0 {
		plen := 128
		for plen > 0 {
			newPlen := plen - 1
			if !aligned6(cur, newPlen) {
				break
			}
			last := lastInBlock6(cur, newPlen)
			if bytes.Compare(last[:], end[:]) > 0 {
				break
			}
			plen = newPlen
		}
		addr := netip.AddrFrom16(cur)
		out = append(out, netip.PrefixFrom(addr, plen).String())
		last := lastInBlock6(cur, plen)
		next, overflow := inc6(last)
		if overflow {
			break
		}
		cur = next
	}
	return out
}

// aligned6 reports whether addr is the first address of a /plen block —
// i.e. all host bits below plen are zero.
func aligned6(addr [16]byte, plen int) bool {
	for i := plen; i < 128; i++ {
		if addr[i/8]&(1<<(7-i%8)) != 0 {
			return false
		}
	}
	return true
}

// lastInBlock6 returns the last address of the /plen block starting at addr.
func lastInBlock6(addr [16]byte, plen int) [16]byte {
	out := addr
	for i := plen; i < 128; i++ {
		out[i/8] |= 1 << (7 - i%8)
	}
	return out
}

// inc6 adds one to a 16-byte BE address; overflow=true past all-ones.
func inc6(addr [16]byte) ([16]byte, bool) {
	for i := 15; i >= 0; i-- {
		addr[i]++
		if addr[i] != 0 {
			return addr, false
		}
	}
	return addr, true
}

// cidrString formats a uint32 BE IPv4 + prefix length as dotted-quad/N.
// Local helper to avoid the netip allocation cost when we just want the
// JSON string representation.
func cidrString(ip uint32, plen int) string {
	return fmt.Sprintf("%d.%d.%d.%d/%d",
		byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), plen)
}
