// Package geodb parses v2ray-format geosite.dat / geoip.dat files (the
// binary protobuf-encoded "dat" format that MetaCubeX/meta-rules-dat
// publishes). The parser is hand-rolled wire-format — no protobuf
// dependency — because we only read two field shapes:
//
//   GeoSiteList { repeated GeoSite entry = 1; }
//   GeoSite     { string country_code = 1; repeated Domain domain = 2; }
//   Domain      { Type type = 1; string value = 2; }
//                 // Type: 0=Plain, 1=Regex, 2=Domain (suffix), 3=Full (exact)
//
//   GeoIPList   { repeated GeoIP entry = 1; }
//   GeoIP       { string country_code = 1; repeated CIDR cidr = 2; }
//   CIDR        { bytes ip = 1; uint32 prefix = 2; }
//
// Public API:
//   - ListGeoSiteEntries / ListGeoIPEntries: sorted unique entry names
//     (the LuCI category browser uses these).
//   - ExtractGeoSiteRules: PureWRT rules.Rule list for one category.
//     Skips Regex entries (can't expand to nftset) but returns a count
//     so the caller can log them.
//   - ExtractGeoIPRules: rules.Rule list of IP-CIDR / IP-CIDR6 for one
//     country code.
//
// All reads are capped at maxDatBytes against hostile or truncated
// inputs (matches geo_refresh.go's download cap).
package geodb

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/purewrt/purewrt/internal/rules"
)

const maxDatBytes = 128 << 20 // 128 MiB — same brake as geo_refresh.refreshOne

// Domain.Type enum values per v2ray's spec.
const (
	domTypePlain  = 0 // keyword
	domTypeRegex  = 1 // skip (mihomo-only)
	domTypeDomain = 2 // suffix
	domTypeFull   = 3 // exact
)

// readFile loads the dat file with the safety cap. Returns os.ErrNotExist
// transparently so callers can render a clear "run geo-refresh first"
// hint rather than a confusing wrapped error.
func readFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxDatBytes {
		return nil, fmt.Errorf("geodb: %s exceeds %d byte cap (got %d)", path, maxDatBytes, fi.Size())
	}
	return os.ReadFile(path)
}

// readVarint reads a base-128 varint from buf starting at off. Returns
// (value, next offset, error). Errors only when the buffer is short.
func readVarint(buf []byte, off int) (uint64, int, error) {
	var v uint64
	var shift uint
	for {
		if off >= len(buf) {
			return 0, off, errors.New("geodb: varint truncated")
		}
		b := buf[off]
		off++
		v |= uint64(b&0x7F) << shift
		if b < 0x80 {
			return v, off, nil
		}
		shift += 7
		if shift > 63 {
			return 0, off, errors.New("geodb: varint overflow")
		}
	}
}

// readBytesField reads a length-delimited field (wire-type 2). The tag
// has already been consumed by the caller. Returns the inner bytes
// without copying.
func readBytesField(buf []byte, off int) ([]byte, int, error) {
	n, next, err := readVarint(buf, off)
	if err != nil {
		return nil, off, err
	}
	end := next + int(n)
	if end < next || end > len(buf) {
		return nil, off, fmt.Errorf("geodb: length-delimited field overruns buffer (want %d, have %d)", n, len(buf)-next)
	}
	return buf[next:end], end, nil
}

// skipField consumes one tagged field at off based on its wire type.
// Used to skip protobuf fields we don't care about (e.g. attribute
// records in Domain, reverse_match in GeoIP).
func skipField(buf []byte, off int, wire uint64) (int, error) {
	switch wire {
	case 0: // varint
		_, next, err := readVarint(buf, off)
		return next, err
	case 1: // 64-bit fixed
		if off+8 > len(buf) {
			return off, errors.New("geodb: fixed64 truncated")
		}
		return off + 8, nil
	case 2: // length-delimited
		n, next, err := readVarint(buf, off)
		if err != nil {
			return off, err
		}
		end := next + int(n)
		if end < next || end > len(buf) {
			return off, errors.New("geodb: length-delimited skip overruns buffer")
		}
		return end, nil
	case 5: // 32-bit fixed
		if off+4 > len(buf) {
			return off, errors.New("geodb: fixed32 truncated")
		}
		return off + 4, nil
	default:
		return off, fmt.Errorf("geodb: unsupported wire type %d", wire)
	}
}

// scanEntries walks a top-level GeoSiteList / GeoIPList. The format is
// just repeated field 1 (tag byte 0x0A) records — each one is a
// length-delimited Entry message. For each record cb gets the bytes
// of the inner message; cb decides what to do with it.
func scanEntries(buf []byte, cb func(payload []byte) error) error {
	off := 0
	for off < len(buf) {
		tag, next, err := readVarint(buf, off)
		if err != nil {
			return err
		}
		field := tag >> 3
		wire := tag & 0x07
		if field == 1 && wire == 2 {
			payload, after, err := readBytesField(buf, next)
			if err != nil {
				return err
			}
			if err := cb(payload); err != nil {
				return err
			}
			off = after
			continue
		}
		// Unknown top-level field — skip it for forward compat.
		off, err = skipField(buf, next, wire)
		if err != nil {
			return err
		}
	}
	return nil
}

// entryName extracts country_code (field 1, string) from an Entry
// message — that's the only field we need from an Entry to satisfy
// "list categories". Returns "" if the field is absent.
func entryName(payload []byte) (string, error) {
	off := 0
	for off < len(payload) {
		tag, next, err := readVarint(payload, off)
		if err != nil {
			return "", err
		}
		field := tag >> 3
		wire := tag & 0x07
		if field == 1 && wire == 2 {
			b, _, err := readBytesField(payload, next)
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
		off, err = skipField(payload, next, wire)
		if err != nil {
			return "", err
		}
	}
	return "", nil
}

// listEntries shares the scan loop between GeoSite and GeoIP — the
// top-level shape and entry-name field number are identical.
func listEntries(path string) ([]string, error) {
	buf, err := readFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	if err := scanEntries(buf, func(payload []byte) error {
		name, err := entryName(payload)
		if err != nil || name == "" {
			return err
		}
		seen[strings.ToLower(name)] = struct{}{}
		return nil
	}); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// ListGeoSiteEntries returns sorted unique category names from a
// geosite.dat file (lowercased — v2ray itself is case-insensitive on
// category names).
func ListGeoSiteEntries(path string) ([]string, error) { return listEntries(path) }

// ListGeoIPEntries returns sorted unique country codes from a
// geoip.dat file (lowercased — same convention).
func ListGeoIPEntries(path string) ([]string, error) { return listEntries(path) }

// ExtractGeoSiteRules walks geosite.dat, finds the GeoSite entry whose
// country_code matches the requested category (case-insensitive), and
// returns the domain rules in PureWRT's rules.Rule shape:
//
//   v2ray Plain  → rules.DomainKeyword
//   v2ray Domain → rules.DomainSuffix
//   v2ray Full   → rules.Domain
//   v2ray Regex  → skipped (counted in skippedRegex)
//
// Returns os.ErrNotExist if the dat file is missing; a clear error if
// the category isn't in the file.
func ExtractGeoSiteRules(path, category string) (out []rules.Rule, skippedRegex int, err error) {
	buf, err := readFile(path)
	if err != nil {
		return nil, 0, err
	}
	want := strings.ToLower(strings.TrimSpace(category))
	if want == "" {
		return nil, 0, errors.New("geodb: empty category")
	}
	found := false
	err = scanEntries(buf, func(payload []byte) error {
		name, perr := entryName(payload)
		if perr != nil {
			return perr
		}
		if strings.ToLower(name) != want {
			return nil
		}
		found = true
		// Re-walk the entry, this time collecting domain records.
		off := 0
		for off < len(payload) {
			tag, next, terr := readVarint(payload, off)
			if terr != nil {
				return terr
			}
			field := tag >> 3
			wire := tag & 0x07
			if field == 2 && wire == 2 {
				dom, after, derr := readBytesField(payload, next)
				if derr != nil {
					return derr
				}
				rule, isRegex, perr := parseDomain(dom)
				if perr != nil {
					return perr
				}
				switch {
				case isRegex:
					skippedRegex++
				case rule.Value != "":
					out = append(out, rule)
				}
				off = after
				continue
			}
			off, terr = skipField(payload, next, wire)
			if terr != nil {
				return terr
			}
		}
		return nil
	})
	if err != nil {
		return nil, skippedRegex, err
	}
	if !found {
		return nil, 0, fmt.Errorf("geodb: category %q not found in %s", category, path)
	}
	return out, skippedRegex, nil
}

// parseDomain reads one Domain message — fields are { Type type = 1;
// string value = 2; }. Returns the rule, an isRegex flag (so the caller
// can keep an accurate skip count), or an error.
func parseDomain(payload []byte) (rules.Rule, bool, error) {
	var dtype uint64
	var value string
	off := 0
	for off < len(payload) {
		tag, next, err := readVarint(payload, off)
		if err != nil {
			return rules.Rule{}, false, err
		}
		field := tag >> 3
		wire := tag & 0x07
		switch {
		case field == 1 && wire == 0:
			t, after, err := readVarint(payload, next)
			if err != nil {
				return rules.Rule{}, false, err
			}
			dtype = t
			off = after
		case field == 2 && wire == 2:
			b, after, err := readBytesField(payload, next)
			if err != nil {
				return rules.Rule{}, false, err
			}
			value = string(b)
			off = after
		default:
			off, err = skipField(payload, next, wire)
			if err != nil {
				return rules.Rule{}, false, err
			}
		}
	}
	if value == "" {
		return rules.Rule{}, false, nil
	}
	switch dtype {
	case domTypePlain:
		return rules.Rule{Type: rules.DomainKeyword, Value: value, SupportedMihomo: true, SupportedOpenWrt: true}, false, nil
	case domTypeDomain:
		return rules.Rule{Type: rules.DomainSuffix, Value: value, SupportedMihomo: true, SupportedOpenWrt: true}, false, nil
	case domTypeFull:
		return rules.Rule{Type: rules.Domain, Value: value, SupportedMihomo: true, SupportedOpenWrt: true}, false, nil
	case domTypeRegex:
		return rules.Rule{}, true, nil
	default:
		// Unknown type — treat as regex/unsupported rather than guessing.
		return rules.Rule{}, true, nil
	}
}

// ExtractGeoIPRules walks geoip.dat, finds the GeoIP entry whose
// country_code matches (case-insensitive), and returns IP-CIDR /
// IP-CIDR6 rules. v4 addresses (4-byte ip) → rules.IPCIDR, v6 (16-byte)
// → rules.IPCIDR6.
func ExtractGeoIPRules(path, country string) (out []rules.Rule, err error) {
	buf, rerr := readFile(path)
	if rerr != nil {
		return nil, rerr
	}
	want := strings.ToLower(strings.TrimSpace(country))
	if want == "" {
		return nil, errors.New("geodb: empty country code")
	}
	found := false
	err = scanEntries(buf, func(payload []byte) error {
		name, perr := entryName(payload)
		if perr != nil {
			return perr
		}
		if strings.ToLower(name) != want {
			return nil
		}
		found = true
		off := 0
		for off < len(payload) {
			tag, next, terr := readVarint(payload, off)
			if terr != nil {
				return terr
			}
			field := tag >> 3
			wire := tag & 0x07
			if field == 2 && wire == 2 {
				cidr, after, cerr := readBytesField(payload, next)
				if cerr != nil {
					return cerr
				}
				r, perr := parseCIDR(cidr)
				if perr != nil {
					return perr
				}
				if r.Value != "" {
					out = append(out, r)
				}
				off = after
				continue
			}
			off, terr = skipField(payload, next, wire)
			if terr != nil {
				return terr
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("geodb: country %q not found in %s", country, path)
	}
	return out, nil
}

// parseCIDR reads one CIDR message: { bytes ip = 1; uint32 prefix = 2; }
func parseCIDR(payload []byte) (rules.Rule, error) {
	var ipBytes []byte
	var prefix uint64
	off := 0
	for off < len(payload) {
		tag, next, err := readVarint(payload, off)
		if err != nil {
			return rules.Rule{}, err
		}
		field := tag >> 3
		wire := tag & 0x07
		switch {
		case field == 1 && wire == 2:
			b, after, err := readBytesField(payload, next)
			if err != nil {
				return rules.Rule{}, err
			}
			ipBytes = b
			off = after
		case field == 2 && wire == 0:
			p, after, err := readVarint(payload, next)
			if err != nil {
				return rules.Rule{}, err
			}
			prefix = p
			off = after
		default:
			off, err = skipField(payload, next, wire)
			if err != nil {
				return rules.Rule{}, err
			}
		}
	}
	if len(ipBytes) == 0 {
		return rules.Rule{}, nil
	}
	var ip net.IP
	var ruleType rules.Type
	switch len(ipBytes) {
	case 4:
		ip = net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
		ruleType = rules.IPCIDR
	case 16:
		ip = make(net.IP, 16)
		copy(ip, ipBytes)
		ruleType = rules.IPCIDR6
	default:
		return rules.Rule{}, fmt.Errorf("geodb: unexpected IP length %d", len(ipBytes))
	}
	return rules.Rule{
		Type:             ruleType,
		Value:            ip.String() + "/" + strconv.FormatUint(prefix, 10),
		NoResolve:        true,
		SupportedMihomo:  true,
		SupportedOpenWrt: true,
	}, nil
}

