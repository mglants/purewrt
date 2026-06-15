package rules

import "testing"

func TestParseText(t *testing.T) {
	p := ParseText("ai", []byte("DOMAIN-SUFFIX,chatgpt.com\nIP-CIDR,1.1.1.0/24,no-resolve\nPROCESS-NAME,curl\n"))
	if len(p.Rules) != 3 {
		t.Fatalf("rules=%d", len(p.Rules))
	}
	if p.Rules[2].SupportedOpenWrt || p.Rules[2].SupportedMihomo {
		t.Fatal("process-name must not be imported on router")
	}
}

// Inline `#` and `//` comments are stripped so manual-rule files can
// carry provenance metadata appended by the LuCI picker
// (e.g. "149.154.167.41  # AS62041 TELEGRAM"). Full-line comments still
// produce no rules.
func TestParseText_InlineComments(t *testing.T) {
	in := "# header — Telegram\n" +
		"149.154.167.41  # AS62041 TELEGRAM\n" +
		"1.0.0.0/24\t# AS13335 CLOUDFLARENET\n" +
		"example.com // AS15169 GOOGLE\n" +
		"// full-line comment, ignored\n" +
		"#another full line\n"
	p := ParseText("manual", []byte(in))
	if len(p.Rules) != 3 {
		t.Fatalf("expected 3 rules; got %d (%+v)", len(p.Rules), p.Rules)
	}
	// Bare IPs get a /32 appended by normalisation — but the comment text
	// must NOT leak into the parsed value.
	if p.Rules[0].Value != "149.154.167.41/32" {
		t.Errorf("rule[0] value=%q (comment leaked into parsed value)", p.Rules[0].Value)
	}
	if p.Rules[1].Value != "1.0.0.0/24" {
		t.Errorf("rule[1] value=%q", p.Rules[1].Value)
	}
	if p.Rules[2].Value != "example.com" {
		t.Errorf("rule[2] value=%q", p.Rules[2].Value)
	}
}

func TestParseLogicalRules(t *testing.T) {
	p := ParseText("game", []byte("or,((domain,example.com),(domain,example.org))\nnot,((geoip,private))\n"))
	if len(p.Rules) != 2 {
		t.Fatalf("rules=%d", len(p.Rules))
	}
	for _, r := range p.Rules {
		if r.Type != Logical || r.SupportedOpenWrt || !r.SupportedMihomo {
			t.Fatalf("unexpected logical rule: %+v", r)
		}
	}
}

func TestParseGeoSiteGeoIPRules(t *testing.T) {
	p := ParseText("geo", []byte("GEOSITE,openai\nGEOIP,telegram,no-resolve\n"))
	if len(p.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(p.Rules))
	}
	if p.Rules[0].Type != GeoSite || p.Rules[0].Value != "openai" || p.Rules[0].SupportedOpenWrt || !p.Rules[0].SupportedMihomo {
		t.Fatalf("unexpected geosite rule: %#v", p.Rules[0])
	}
	if p.Rules[1].Type != GeoIP || p.Rules[1].Value != "telegram" || p.Rules[1].SupportedOpenWrt || !p.Rules[1].SupportedMihomo {
		t.Fatalf("unexpected geoip rule: %#v", p.Rules[1])
	}
}

func TestParseNativeANDRule(t *testing.T) {
	p := ParseText("game", []byte("and,((ip-cidr,138.128.136.0/21),(network,udp),(dst-port,50000-50100))\n"))
	if len(p.Rules) != 1 {
		t.Fatalf("rules=%d", len(p.Rules))
	}
	r := p.Rules[0]
	if r.Type != Native || !r.SupportedOpenWrt || !r.SupportedMihomo {
		t.Fatalf("unexpected native rule: %+v", r)
	}
	want := "ip daddr 138.128.136.0/21 meta l4proto udp th dport 50000-50100"
	if r.Value != want {
		t.Fatalf("value=%q want %q", r.Value, want)
	}
}

func TestParseNativeSimpleRules(t *testing.T) {
	p := ParseText("ports", []byte("DST-PORT,443\nSRC-PORT,1000-2000\nNETWORK,udp\n"))
	if len(p.Rules) != 3 {
		t.Fatalf("rules=%d", len(p.Rules))
	}
	for _, r := range p.Rules {
		if r.Type != Native || !r.SupportedOpenWrt || !r.SupportedMihomo {
			t.Fatalf("unexpected native rule: %+v", r)
		}
	}
}

func TestUnsupportedLogicalRulePreservesValue(t *testing.T) {
	p := ParseText("game", []byte("and,((process-name,curl),(network,udp))\n"))
	if len(p.Rules) != 1 {
		t.Fatalf("rules=%d", len(p.Rules))
	}
	r := p.Rules[0]
	if r.Type != Logical || r.SupportedOpenWrt || !r.SupportedMihomo {
		t.Fatalf("unexpected logical rule: %+v", r)
	}
	want := "and,((process-name,curl),(network,udp))"
	if r.Value != want {
		t.Fatalf("value=%q want %q", r.Value, want)
	}
}

func TestParseInvalidUnknownRuleIsNotExported(t *testing.T) {
	p := ParseText("bad", []byte("payload:\n- process-name,com.example.app\n"))
	for _, r := range p.Rules {
		if r.SupportedOpenWrt || r.SupportedMihomo {
			t.Fatalf("invalid unknown rule should not be exported: %+v", r)
		}
	}
}
