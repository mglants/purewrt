package rules

import "testing"

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		" Example.COM. ": "example.com",
		"+.Example.COM":  "example.com",
		".example.com":   "example.com",
	}
	for in, want := range tests {
		if got := NormalizeDomain(in); got != want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in          string
		wantType    Type
		wantValue   string
		wantOpenWRT bool
	}{
		{in: "192.168.1.1/24", wantType: IPCIDR, wantValue: "192.168.1.0/24", wantOpenWRT: true},
		{in: "2001:db8::1/64", wantType: IPCIDR6, wantValue: "2001:db8::/64", wantOpenWRT: true},
		{in: "+.Example.COM", wantType: DomainSuffix, wantValue: "example.com", wantOpenWRT: true},
		{in: "*.example.com", wantType: DomainSuffix, wantValue: "*.example.com", wantOpenWRT: false},
		// Bare IP literals — previously routed to DomainSuffix (broken: all-
		// numeric labels passed IsValidDomain). Now promoted to /32 or /128
		// so a manual rules file with `74.125.131.19` per line works as
		// the docs and placeholder text claim.
		{in: "74.125.131.19", wantType: IPCIDR, wantValue: "74.125.131.19/32", wantOpenWRT: true},
		{in: "2001:db8::1", wantType: IPCIDR6, wantValue: "2001:db8::1/128", wantOpenWRT: true},
	}
	for _, tt := range tests {
		got := ClassifyValue(tt.in)
		if got.Type != tt.wantType || got.Value != tt.wantValue || got.SupportedOpenWrt != tt.wantOpenWRT {
			t.Fatalf("ClassifyValue(%q) = %+v", tt.in, got)
		}
	}
}

func TestDedupPreservesOrderAndSkipsEmpty(t *testing.T) {
	t.Parallel()

	got := Dedup([]Rule{
		{Type: DomainSuffix, Value: "a.example"},
		{Type: DomainSuffix, Value: ""},
		{Type: DomainSuffix, Value: "a.example"},
		{Type: IPCIDR, Value: "10.0.0.0/8"},
	})
	if len(got) != 2 || got[0].Value != "a.example" || got[1].Value != "10.0.0.0/8" {
		t.Fatalf("Dedup = %+v", got)
	}
}

func TestSplitOpenWrt(t *testing.T) {
	t.Parallel()

	openwrt, mihomoOnly := SplitOpenWrt([]Rule{
		{Value: "native", SupportedOpenWrt: true, SupportedMihomo: true},
		{Value: "mihomo", SupportedOpenWrt: false, SupportedMihomo: true},
		{Value: "unsupported", SupportedOpenWrt: false, SupportedMihomo: false},
	})
	if len(openwrt) != 1 || openwrt[0].Value != "native" {
		t.Fatalf("openwrt = %+v", openwrt)
	}
	if len(mihomoOnly) != 1 || mihomoOnly[0].Value != "mihomo" {
		t.Fatalf("mihomoOnly = %+v", mihomoOnly)
	}
}
