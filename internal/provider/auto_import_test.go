package provider

import "testing"

func TestAnalyzeYAML(t *testing.T) {
	a := AnalyzeContent("", []byte("proxies:\n- name: n1\n  type: ss\nrules:\n- DOMAIN-SUFFIX,chatgpt.com,AI\n"))
	if a.ProxyNodes != 1 || a.Rules != 1 {
		t.Fatalf("bad analysis: %+v", a)
	}
}

// Inline proxy node names are surfaced so the wizard can preview which servers
// a section's filter/exclude selects before applying.
func TestAnalyzeYAMLProxyNodeNames(t *testing.T) {
	a := AnalyzeContent("", []byte("proxies:\n- name: 🇱🇻 vpn-lv\n  type: vless\n- name: 🇩🇪 vpn-de\n  type: vless\n"))
	if len(a.ProxyNodeNames) != 2 || a.ProxyNodeNames[0] != "🇱🇻 vpn-lv" || a.ProxyNodeNames[1] != "🇩🇪 vpn-de" {
		t.Fatalf("proxy node names not extracted: %+v", a.ProxyNodeNames)
	}
}
