package geodb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/rules"
)

// buildVarint emits a base-128 protobuf varint. Helper for fixture
// construction; the parser has its own readVarint that we exercise via
// the public API.
func buildVarint(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
			continue
		}
		out = append(out, b)
		return out
	}
}

// tagBytes builds the tag prefix byte for a field with given number and
// wire type. (field<<3 | wire), then varint-encoded — but for fields <16
// and wires <8 it fits in a single byte.
func tagBytes(field, wire uint64) []byte {
	return buildVarint((field << 3) | wire)
}

// lenDelim wraps a payload with its length-delimited tag (wire type 2).
func lenDelim(field uint64, payload []byte) []byte {
	out := tagBytes(field, 2)
	out = append(out, buildVarint(uint64(len(payload)))...)
	return append(out, payload...)
}

// varintField builds a tag(field,0) + value pair.
func varintField(field, value uint64) []byte {
	out := tagBytes(field, 0)
	return append(out, buildVarint(value)...)
}

// buildDomain encodes one Domain message: type + value.
func buildDomain(t uint64, value string) []byte {
	out := varintField(1, t)
	out = append(out, lenDelim(2, []byte(value))...)
	return out
}

// buildGeoSiteEntry encodes one GeoSite message: country_code + N domains.
func buildGeoSiteEntry(name string, domains [][]byte) []byte {
	out := lenDelim(1, []byte(name))
	for _, d := range domains {
		out = append(out, lenDelim(2, d)...)
	}
	return out
}

// buildCIDR encodes one CIDR message: ip bytes + prefix.
func buildCIDR(ip []byte, prefix uint64) []byte {
	out := lenDelim(1, ip)
	out = append(out, varintField(2, prefix)...)
	return out
}

func buildGeoIPEntry(name string, cidrs [][]byte) []byte {
	out := lenDelim(1, []byte(name))
	for _, c := range cidrs {
		out = append(out, lenDelim(2, c)...)
	}
	return out
}

// writeTempDat dumps payload to a tmp file in t.TempDir() so each test
// case gets a real file path to exercise the os.Open path.
func writeTempDat(t *testing.T, name string, payload []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestListGeoSiteEntries_sortedUnique(t *testing.T) {
	t.Parallel()
	// Three entries — out of order, with a duplicate that should de-dup.
	var blob []byte
	blob = append(blob, lenDelim(1, buildGeoSiteEntry("YOUTUBE", nil))...)    // mixed case
	blob = append(blob, lenDelim(1, buildGeoSiteEntry("telegram", nil))...)
	blob = append(blob, lenDelim(1, buildGeoSiteEntry("youtube", nil))...)    // duplicate (lowercased)
	blob = append(blob, lenDelim(1, buildGeoSiteEntry("category-ads", nil))...)

	path := writeTempDat(t, "geosite.dat", blob)
	got, err := ListGeoSiteEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"category-ads", "telegram", "youtube"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Fatalf("got[%d] = %q, want %q (full: %v)", i, got[i], v, got)
		}
	}
}

func TestExtractGeoSiteRules_typesAndSkipRegex(t *testing.T) {
	t.Parallel()
	youtube := buildGeoSiteEntry("youtube", [][]byte{
		buildDomain(domTypePlain, "yt"),                // → keyword
		buildDomain(domTypeDomain, "youtube.com"),      // → suffix
		buildDomain(domTypeFull, "www.youtube.com"),    // → exact
		buildDomain(domTypeRegex, ".*\\.youtube\\..*"), // skipped
	})
	other := buildGeoSiteEntry("other", [][]byte{
		buildDomain(domTypeDomain, "example.com"),
	})
	blob := append(lenDelim(1, youtube), lenDelim(1, other)...)
	path := writeTempDat(t, "geosite.dat", blob)

	got, skipped, err := ExtractGeoSiteRules(path, "youtube")
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Fatalf("skipped regex = %d, want 1", skipped)
	}
	want := []struct {
		t rules.Type
		v string
	}{
		{rules.DomainKeyword, "yt"},
		{rules.DomainSuffix, "youtube.com"},
		{rules.Domain, "www.youtube.com"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d (%+v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Type != w.t || got[i].Value != w.v {
			t.Fatalf("rule[%d] = %+v, want type=%s value=%s", i, got[i], w.t, w.v)
		}
		if !got[i].SupportedOpenWrt {
			t.Fatalf("rule[%d] should be openwrt-supported: %+v", i, got[i])
		}
	}
}

func TestExtractGeoSiteRules_caseInsensitive(t *testing.T) {
	t.Parallel()
	blob := lenDelim(1, buildGeoSiteEntry("YouTube", [][]byte{
		buildDomain(domTypeDomain, "youtube.com"),
	}))
	path := writeTempDat(t, "geosite.dat", blob)

	got, _, err := ExtractGeoSiteRules(path, "youtube")
	if err != nil {
		t.Fatalf("lowercase lookup: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(got))
	}
}

func TestExtractGeoSiteRules_missingCategory(t *testing.T) {
	t.Parallel()
	blob := lenDelim(1, buildGeoSiteEntry("youtube", nil))
	path := writeTempDat(t, "geosite.dat", blob)

	_, _, err := ExtractGeoSiteRules(path, "telegram")
	if err == nil {
		t.Fatal("expected an error for missing category, got nil")
	}
}

func TestExtractGeoSiteRules_missingFile(t *testing.T) {
	t.Parallel()
	_, _, err := ExtractGeoSiteRules("/nonexistent/geosite.dat", "youtube")
	if err == nil {
		t.Fatal("expected an error for missing file, got nil")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("error should be os.IsNotExist-compatible, got %T: %v", err, err)
	}
}

func TestExtractGeoIPRules_v4andV6(t *testing.T) {
	t.Parallel()
	// 1.1.1.0/24 (v4) + 2001:db8::/32 (v6)
	v4 := buildCIDR([]byte{1, 1, 1, 0}, 24)
	v6 := buildCIDR([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 32)
	cn := buildGeoIPEntry("cn", [][]byte{v4, v6})
	blob := lenDelim(1, cn)
	path := writeTempDat(t, "geoip.dat", blob)

	got, err := ExtractGeoIPRules(path, "cn")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2 (%+v)", len(got), got)
	}
	if got[0].Type != rules.IPCIDR || got[0].Value != "1.1.1.0/24" {
		t.Fatalf("v4 rule = %+v, want type=ip_cidr value=1.1.1.0/24", got[0])
	}
	if got[1].Type != rules.IPCIDR6 || got[1].Value != "2001:db8::/32" {
		t.Fatalf("v6 rule = %+v, want type=ip_cidr6 value=2001:db8::/32", got[1])
	}
}

func TestScanEntries_truncatedInput(t *testing.T) {
	t.Parallel()
	// A tag claiming 1000-byte length-delimited content, but the body is empty.
	blob := append(tagBytes(1, 2), buildVarint(1000)...)
	path := writeTempDat(t, "geosite.dat", blob)

	_, err := ListGeoSiteEntries(path)
	if err == nil {
		t.Fatal("expected error on truncated input, got nil")
	}
}
