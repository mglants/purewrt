package rules

import (
	"errors"
	"os"
	"testing"
)

func TestParseMRSNativeDomain(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mrs/youtube.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	p, err := ParseMRS("youtube", data)
	if err != nil {
		t.Fatalf("ParseMRS domain failed: %v", err)
	}
	if p.Behavior != "domain" || len(p.Rules) == 0 {
		t.Fatalf("unexpected domain MRS provider: behavior=%q rules=%d", p.Behavior, len(p.Rules))
	}
	found := false
	for _, r := range p.Rules {
		if r.Type != DomainSuffix || !r.SupportedOpenWrt || !r.SupportedMihomo {
			t.Fatalf("unexpected decoded domain rule: %+v", r)
		}
		if r.Value == "youtube.com" || r.Value == "googlevideo.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected common youtube/googlevideo domain in %d rules", len(p.Rules))
	}
}

func TestAnalyzeMRSNativeDomainFastCount(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mrs/youtube.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	info, err := AnalyzeMRS(data)
	if err != nil {
		t.Fatalf("AnalyzeMRS failed: %v", err)
	}
	if !info.Native || info.Behavior != "domain" || info.Count <= 0 {
		t.Fatalf("unexpected MRS info: %+v", info)
	}
}

func TestParseMRSNativeIPCIDR(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mrs/telegram-ips.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	p, err := ParseMRS("telegram-ips", data)
	if err != nil {
		t.Fatalf("ParseMRS ipcidr failed: %v", err)
	}
	if p.Behavior != "ipcidr" || len(p.Rules) == 0 {
		t.Fatalf("unexpected ipcidr MRS provider: behavior=%q rules=%d", p.Behavior, len(p.Rules))
	}
	for _, r := range p.Rules {
		if r.Type != IPCIDR && r.Type != IPCIDR6 {
			t.Fatalf("unexpected decoded cidr rule: %+v", r)
		}
	}
}

func TestAnalyzeMRSNativeIPCIDRFastCount(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mrs/telegram-ips.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	info, err := AnalyzeMRS(data)
	if err != nil {
		t.Fatalf("AnalyzeMRS failed: %v", err)
	}
	if !info.Native || info.Behavior != "ipcidr" || info.Count <= 0 {
		t.Fatalf("unexpected MRS info: %+v", info)
	}
}

func TestDomainSetLookupYouTubeFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mrs/youtube.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	ds, err := ParseMRSDomainSet("youtube", data)
	if err != nil {
		t.Fatalf("ParseMRSDomainSet failed: %v", err)
	}
	if ds.Name() != "youtube" {
		t.Fatalf("DomainSet.Name = %q, want %q", ds.Name(), "youtube")
	}
	p, err := ParseMRSWithOptions("youtube", data, MRSParseOptions{SortDomains: false})
	if err != nil {
		t.Fatalf("ParseMRS failed: %v", err)
	}
	// Every materialised rule must be findable via DomainSet.Lookup. The
	// returned suffix may be a shorter shadowing entry (e.g., querying
	// "ads.youtube.com" can return "youtube.com" because that rule
	// already shadows the longer one); we just need the returned suffix
	// to itself be a DomainSuffix match for the query.
	values := make(map[string]struct{}, len(p.Rules))
	for _, r := range p.Rules {
		values[r.Value] = struct{}{}
	}
	for i, r := range p.Rules {
		got, ok := ds.Lookup(r.Value)
		if !ok {
			t.Fatalf("Lookup(%q) miss; expected hit (rule %d)", r.Value, i)
		}
		if _, present := values[got]; !present {
			t.Fatalf("Lookup(%q) suffix=%q not present in materialised rule set", r.Value, got)
		}
		if got != r.Value && !(len(got) < len(r.Value) && r.Value[len(r.Value)-len(got)-1] == '.' && r.Value[len(r.Value)-len(got):] == got) {
			t.Fatalf("Lookup(%q) suffix=%q is not a DomainSuffix of the query", r.Value, got)
		}
	}
	// Subdomain matching: a stored suffix X must also match subdomains.
	subdomainCases := []struct {
		query   string
		wantHit bool
	}{
		{"www.youtube.com", true},
		{"www.googlevideo.com", true},
		{"youtube.com", true},
		{"googlevideo.com", true},
	}
	for _, tc := range subdomainCases {
		got, ok := ds.Lookup(tc.query)
		if ok != tc.wantHit {
			t.Fatalf("Lookup(%q) ok=%v, want %v (got=%q)", tc.query, ok, tc.wantHit, got)
		}
	}
	// Known misses: domains that should not be in any YouTube provider.
	for _, miss := range []string{"example.com", "apple.com", "fooyoutube.com", "youtube.com.evil.tld"} {
		if _, ok := ds.Lookup(miss); ok {
			t.Fatalf("Lookup(%q) unexpected hit", miss)
		}
	}
}

func TestDomainSetLookupIPCIDRRejected(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mrs/telegram-ips.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	if _, err := ParseMRSDomainSet("telegram-ips", data); !errors.Is(err, ErrNotDomainBehavior) {
		t.Fatalf("ParseMRSDomainSet ipcidr err=%v, want ErrNotDomainBehavior", err)
	}
}

func TestDomainSetLookupEmptyDomain(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mrs/youtube.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	ds, err := ParseMRSDomainSet("youtube", data)
	if err != nil {
		t.Fatalf("ParseMRSDomainSet failed: %v", err)
	}
	for _, q := range []string{"", "."} {
		if got, ok := ds.Lookup(q); ok {
			t.Fatalf("Lookup(%q) hit=%q, want miss", q, got)
		}
	}
}

func TestDomainSetLookupTrailingDot(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mrs/youtube.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	ds, err := ParseMRSDomainSet("youtube", data)
	if err != nil {
		t.Fatalf("ParseMRSDomainSet failed: %v", err)
	}
	// Lookup must normalise a trailing root-dot the same way mihomo does.
	got, ok := ds.Lookup("www.youtube.com.")
	if !ok {
		t.Fatalf("Lookup(%q) miss; expected hit", "www.youtube.com.")
	}
	if got != "youtube.com" {
		t.Fatalf("Lookup(%q) suffix=%q, want %q", "www.youtube.com.", got, "youtube.com")
	}
}

func TestStreamMRSMatchesUnsortedGenerationParse(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mrs/youtube.mrs")
	if err != nil {
		t.Skipf("mrs fixture not available: %v", err)
	}
	parsed, err := ParseMRSWithOptions("youtube", data, MRSParseOptions{SortDomains: false})
	if err != nil {
		t.Fatal(err)
	}
	var streamed []string
	if err := StreamMRS(data, MRSStreamHandlers{Domain: func(v []byte) error {
		// Domain bytes are valid only during the call — copy via string().
		streamed = append(streamed, string(v))
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	if len(streamed) == 0 || len(streamed) != len(parsed.Rules) {
		t.Fatalf("streamed domains=%d parsed rules=%d", len(streamed), len(parsed.Rules))
	}
	for i, r := range parsed.Rules {
		if r.Value != streamed[i] {
			t.Fatalf("streamed order differs at %d: got %q want %q", i, streamed[i], r.Value)
		}
	}
}
