package provider

import "testing"

// TestFormatGuessersAreYAMLFree pins the behaviour after the format
// simplification: the UI offers only `text` and `mrs`, so neither the
// subscription-analysis path (guessFormat) nor the per-file extension
// detector (formatFromPathOrURL) is allowed to mint a `format=yaml`
// rule provider that the UI can't render. yaml-shaped sources collapse
// to `text` — the parser already handled them as text (silently),
// this just makes the UCI label match reality.
func TestFormatGuessersAreYAMLFree(t *testing.T) {
	t.Parallel()
	if got := guessFormat(Analysis{Type: "Clash YAML rule-provider"}); got != "text" {
		t.Errorf("guessFormat(yaml) = %q, want text", got)
	}
	if got := guessFormat(Analysis{Type: "mihomo MRS rule-set"}); got != "mrs" {
		t.Errorf("guessFormat(mrs) = %q, want mrs", got)
	}
	if got := guessFormat(Analysis{Type: "plain text list"}); got != "text" {
		t.Errorf("guessFormat(text) = %q, want text", got)
	}
	for _, url := range []string{"https://example.com/rules.yaml", "https://example.com/rules.YML"} {
		if got := formatFromPathOrURL(url); got != "text" {
			t.Errorf("formatFromPathOrURL(%q) = %q, want text", url, got)
		}
	}
	if got := formatFromPathOrURL("https://example.com/rules.mrs"); got != "mrs" {
		t.Errorf("formatFromPathOrURL(mrs) = %q, want mrs", got)
	}
	if got := formatFromPathOrURL("https://example.com/rules.txt"); got != "text" {
		t.Errorf("formatFromPathOrURL(txt) = %q, want text", got)
	}
}

// TestSourceKindOnlyMRSAndText pins the sourceKind classification to the
// surviving format universe. yaml/cidr/classical formats no longer exist
// at the UCI level, so the switch arm collapsing is correct.
func TestSourceKindOnlyMRSAndText(t *testing.T) {
	t.Parallel()
	cases := map[[2]string]string{
		{"mrs", ""}:                "mrs",
		{"text", ""}:               "text",
		{"", "https://x/foo.mrs"}:  "mrs",
		{"", "https://x/foo.txt"}:  "unknown",
		{"yaml", ""}:               "unknown", // was "clash_yaml", now dead
		{"cidr", ""}:               "unknown", // was "text", now dead
	}
	for k, want := range cases {
		if got := sourceKind(k[0], k[1]); got != want {
			t.Errorf("sourceKind(%q, %q) = %q, want %q", k[0], k[1], got, want)
		}
	}
}

func TestClassifyRuleProvider(t *testing.T) {
	tests := []struct {
		name        string
		wantAction  string
		wantSection string
		wantPrio    int
	}{
		{name: "geosite-ru", wantAction: "direct", wantSection: "direct", wantPrio: 1},
		{name: "geoip-private", wantAction: "direct", wantSection: "direct", wantPrio: 1},
		{name: "reject-ads", wantAction: "reject", wantSection: "reject", wantPrio: 2},
		{name: "youtube", wantAction: "proxy", wantSection: "media", wantPrio: 10},
		{name: "openai", wantAction: "proxy", wantSection: "ai", wantPrio: 20},
		{name: "telegram", wantAction: "proxy", wantSection: "common", wantPrio: 60},
	}
	for _, tt := range tests {
		got := ClassifyRuleProvider(tt.name, "", "domain", "mrs", nil)
		if got.RouteAction != tt.wantAction || got.Section != tt.wantSection || got.Priority != tt.wantPrio {
			t.Fatalf("%s classified as action=%s section=%s priority=%d, want action=%s section=%s priority=%d", tt.name, got.RouteAction, got.Section, got.Priority, tt.wantAction, tt.wantSection, tt.wantPrio)
		}
	}
}
