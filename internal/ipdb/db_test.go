package ipdb

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic TSV mimicking iptoasn's layout, including a "Not routed" gap
// entry that should yield Lookup{} on lookup (not "AS 0 None").
const testTSV = "" +
	"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
	"1.0.4.0\t1.0.7.255\t38803\tAU\tWPL-AS-AP Wirefreebroadband\n" +
	"\n" + // blank — should be skipped
	"# header comment\n" +
	"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n" +
	"malformed line with too few fields\n" +
	"192.0.2.0\t192.0.2.255\t0\tNone\tNot routed\n" +
	// Combined-dataset IPv6 rows, interleaved as iptoasn ships them.
	"2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n" +
	"2606:4700::\t2606:4700::ffff\t13335\tUS\tCLOUDFLARENET\n" +
	"2001:db8::\t2001:db8::ffff\t0\tNone\tNot routed\n"

func mustDB(t *testing.T, body string) *DB {
	t.Helper()
	db, err := parseTSV(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseTSV: %v", err)
	}
	return db
}

func TestLookup_KnownASN(t *testing.T) {
	db := mustDB(t, testTSV)
	tests := []struct {
		ip       string
		wantASN  uint32
		wantCC   string
		wantOrg  string
	}{
		{"1.0.0.50", 13335, "US", "CLOUDFLARENET"},
		{"1.0.0.255", 13335, "US", "CLOUDFLARENET"},
		{"1.0.4.10", 38803, "AU", "WPL-AS-AP Wirefreebroadband"},
		{"8.8.8.8", 15169, "US", "GOOGLE"},
	}
	for _, tc := range tests {
		addr := netip.MustParseAddr(tc.ip)
		got := db.Lookup(addr)
		if got.ASN != tc.wantASN || got.Country != tc.wantCC || got.ASOrg != tc.wantOrg {
			t.Errorf("Lookup(%s) = %+v; want ASN=%d cc=%s org=%s", tc.ip, got, tc.wantASN, tc.wantCC, tc.wantOrg)
		}
	}
}

func TestLookup_NotRoutedReturnsEmpty(t *testing.T) {
	// 1.0.1.0–1.0.3.255 is the iptoasn "Not routed" gap. Lookups inside
	// should return zero Lookup{}, not "AS 0".
	db := mustDB(t, testTSV)
	for _, ip := range []string{"1.0.1.5", "1.0.2.99", "1.0.3.255", "192.0.2.42"} {
		got := db.Lookup(netip.MustParseAddr(ip))
		if got.ASN != 0 || got.ASOrg != "" || got.Country != "" {
			t.Errorf("Lookup(%s) = %+v; want empty (not-routed gap)", ip, got)
		}
	}
}

func TestLookup_GapBetweenRanges(t *testing.T) {
	db := mustDB(t, testTSV)
	// 1.0.8.x is between the two seeded ranges with no covering entry.
	for _, ip := range []string{"1.0.8.0", "5.5.5.5", "200.200.200.200"} {
		got := db.Lookup(netip.MustParseAddr(ip))
		if got.ASN != 0 {
			t.Errorf("Lookup(%s) expected empty, got %+v", ip, got)
		}
	}
}

func TestLookup_IPv6(t *testing.T) {
	db := mustDB(t, testTSV)
	cases := []struct {
		ip      string
		wantASN uint32
	}{
		{"2606:4700::5", 13335},                              // inside CF range
		{"2606:4700::ffff", 13335},                           // range end boundary
		{"2606:4700::", 13335},                               // range start boundary
		{"2001:4860:4860::8888", 15169},                      // inside Google /32
		{"2001:db8::1", 0},                                   // not-routed range → empty
		{"2606:4700:1::1", 0},                                // gap just past CF range end
		{"fd00::1", 0},                                       // ULA, no coverage
		{"2001:4860:ffff:ffff:ffff:ffff:ffff:ffff", 15169},   // Google end boundary
	}
	for _, tc := range cases {
		got := db.Lookup(netip.MustParseAddr(tc.ip))
		if got.ASN != tc.wantASN {
			t.Errorf("Lookup(%s).ASN = %d; want %d", tc.ip, got.ASN, tc.wantASN)
		}
	}
}

func TestLookup_IPv6OnLegacyV4Data(t *testing.T) {
	// Legacy v4-only file still on disk: v6 lookups must return empty,
	// not error or misclassify.
	db := mustDB(t, "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n")
	if got := db.Lookup(netip.MustParseAddr("2606:4700::5")); got.ASN != 0 {
		t.Errorf("v6 on v4-only data should be empty; got %+v", got)
	}
}

func TestPrefixesForASN_IPv6(t *testing.T) {
	db := mustDB(t, testTSV)
	info := db.PrefixesForASN(15169)
	// v4: 8.8.8.0/24; v6: 2001:4860::/32 (clean aligned range).
	var has4, has6 bool
	for _, p := range info.Prefixes {
		if p == "8.8.8.0/24" {
			has4 = true
		}
		if p == "2001:4860::/32" {
			has6 = true
		}
	}
	if !has4 || !has6 {
		t.Fatalf("expected both 8.8.8.0/24 and 2001:4860::/32, got %v", info.Prefixes)
	}
}

func TestGZPathLegacyFallback(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "ipdb")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Nothing on disk → combined (download target default).
	if got := GZPath(dir); got != filepath.Join(sub, combinedName) {
		t.Fatalf("empty dir: got %s", got)
	}
	// Only legacy present → legacy.
	if err := os.WriteFile(filepath.Join(sub, legacyName), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := GZPath(dir); got != filepath.Join(sub, legacyName) {
		t.Fatalf("legacy only: got %s", got)
	}
	// Combined appears → combined wins.
	if err := os.WriteFile(filepath.Join(sub, combinedName), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := GZPath(dir); got != filepath.Join(sub, combinedName) {
		t.Fatalf("combined present: got %s", got)
	}
}

func TestLookup_NilDBSafe(t *testing.T) {
	var db *DB
	got := db.Lookup(netip.MustParseAddr("1.1.1.1"))
	if got.ASN != 0 {
		t.Errorf("nil DB lookup should be empty; got %+v", got)
	}
}

func TestPrefixesForASN(t *testing.T) {
	// 1.0.0.0–1.0.0.255 is a single /24, 1.0.4.0–1.0.7.255 is a single /22
	// — verify the decomposer collapses each clean range to one CIDR and
	// produces the right org/cc metadata.
	db := mustDB(t, testTSV)
	info := db.PrefixesForASN(13335)
	if info.ASOrg != "CLOUDFLARENET" || info.Country != "US" {
		t.Errorf("CF: %+v", info)
	}
	// v4 /24 plus the v6 range 2606:4700::–::ffff decomposed to one /112.
	want := []string{"1.0.0.0/24", "2606:4700::/112"}
	if len(info.Prefixes) != 2 || info.Prefixes[0] != want[0] || info.Prefixes[1] != want[1] {
		t.Errorf("CF prefixes: %v, want %v", info.Prefixes, want)
	}

	info = db.PrefixesForASN(38803)
	if len(info.Prefixes) != 1 || info.Prefixes[0] != "1.0.4.0/22" {
		t.Errorf("WPL: got %v want [1.0.4.0/22]", info.Prefixes)
	}

	// Unknown ASN → empty.
	if got := db.PrefixesForASN(99999); len(got.Prefixes) != 0 {
		t.Errorf("unknown asn returned prefixes: %v", got.Prefixes)
	}
}

func TestPrefixesForASN_MultiCIDRDecomposition(t *testing.T) {
	// 10.0.0.5–10.0.0.10 is a deliberately CIDR-unaligned range. Correct
	// decomposition: 10.0.0.5/32, 10.0.0.6/31, 10.0.0.8/31, 10.0.0.10/32.
	tsv := "10.0.0.5\t10.0.0.10\t64500\tUS\tTESTNET\n"
	db := mustDB(t, tsv)
	info := db.PrefixesForASN(64500)
	want := []string{"10.0.0.5/32", "10.0.0.6/31", "10.0.0.8/31", "10.0.0.10/32"}
	if len(info.Prefixes) != len(want) {
		t.Fatalf("got %v, want %v", info.Prefixes, want)
	}
	for i, p := range want {
		if info.Prefixes[i] != p {
			t.Errorf("[%d] got %q want %q", i, info.Prefixes[i], p)
		}
	}
}

func TestCount(t *testing.T) {
	db := mustDB(t, testTSV)
	// 5 v4 + 3 v6 entries (Not routed entries DO count as ranges in the
	// table — the filter happens at Lookup time so the lookup can
	// distinguish "gap" from "in a not-routed range").
	if got := db.Count(); got != 8 {
		t.Errorf("Count = %d; want 8", got)
	}
}
