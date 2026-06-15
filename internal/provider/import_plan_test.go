package provider

import (
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestPlanImportDedupesProvider(t *testing.T) {
	c := config.Default()
	c.ProxyProviders = []config.ProxyProvider{{Name: "main"}}
	plan := PlanImport(c, "https://example.com/sub", "", "auto", "minimal", Analysis{Type: "Proxy URI subscription", ProxyNodes: 2})
	if len(plan.ProxyProviders) != 1 || plan.ProxyProviders[0].Name != "main_2" {
		t.Fatalf("unexpected provider plan: %+v", plan.ProxyProviders)
	}
}

func TestPlanImportDeepYAMLProfile(t *testing.T) {
	data := []byte(`proxies:
  - name: node-a
    type: vless
    server: 192.0.2.1
    port: 443
proxy-groups:
  - name: ▶️ YouTube
    type: load-balance
    filter: "♾️"
    exclude-filter: "🇷🇺"
    strategy: sticky-sessions
    url: https://cp.cloudflare.com/generate_204
    interval: 300
  - name: ✨ AI
    type: load-balance
    filter: "♾️"
    exclude-filter: "🇷🇺|YTRU|NoGemini"
    strategy: sticky-sessions
  - name: 🚫 Недоступные сайты
    type: load-balance
    filter: "♾️"
    exclude-filter: "🇷🇺"
    strategy: sticky-sessions
rule-providers:
  youtube:
    type: http
    behavior: domain
    format: mrs
    url: https://example.com/youtube.mrs
    interval: 86400
  ru-inline:
    type: inline
    behavior: classical
    payload:
      - DOMAIN-SUFFIX,example.ru
rules:
  - RULE-SET,youtube,Media
`)
	a := AnalyzeContent("https://example.com/profile.yaml", data)
	plan := PlanImport(config.Default(), "https://example.com/profile.yaml", "remna", "auto", "minimal", a)
	if len(plan.ProxyProviders) != 1 || plan.ProxyProviders[0].Type != "file" {
		t.Fatalf("expected local file proxy provider, got %+v", plan.ProxyProviders)
	}
	if len(plan.RuleProviders) != 2 {
		t.Fatalf("expected 2 rule providers, got %+v", plan.RuleProviders)
	}
	if len(plan.Files) != 2 {
		t.Fatalf("expected proxy provider file and inline rule file, got %+v", plan.Files)
	}
	var youtube, ruInline config.RuleProvider
	for _, rp := range plan.RuleProviders {
		if rp.Name == "youtube" {
			youtube = rp
		}
		if rp.Name == "ru-inline" {
			ruInline = rp
		}
	}
	if youtube.Format != "mrs" {
		t.Fatalf("mrs provider should be classified as format=mrs, got %+v", youtube)
	}
	if ruInline.Section != "direct" || ruInline.URL != "" || ruInline.Path == "" {
		t.Fatalf("inline ru provider not materialized correctly: %+v", ruInline)
	}
	groups := map[string]config.Section{}
	for _, s := range plan.SectionGroups {
		groups[s.Name] = s
	}
	if got := groups["media"]; got.ProxyGroupType != "load-balance" || got.ProxyFilter != "♾️" || got.ProxyExcludeFilter != "🇷🇺" || got.ProxyStrategy != "sticky-sessions" || got.ProxyHealthCheckURL != "https://cp.cloudflare.com/generate_204" || got.ProxyHealthCheckInterval != 300 {
		t.Fatalf("media group not imported: %+v", got)
	}
	if got := groups["ai"]; got.ProxyGroupType != "load-balance" || got.ProxyExcludeFilter != "🇷🇺|YTRU|NoGemini" {
		t.Fatalf("ai group not imported: %+v", got)
	}
	if got := groups["common"]; got.ProxyGroupType != "load-balance" || got.ProxyExcludeFilter != "🇷🇺" {
		t.Fatalf("common group not imported: %+v", got)
	}
}

// proxy_only mode (the wizard Default-lists "proxy nodes URL" path) must
// import proxy providers but never rule providers, even from a full Clash
// profile that contains rule-providers/rules.
func TestPlanImportProxyOnlySkipsRules(t *testing.T) {
	data := []byte(`proxies:
  - name: node-a
    type: vless
    server: 192.0.2.1
    port: 443
rule-providers:
  youtube:
    type: http
    behavior: domain
    format: mrs
    url: https://example.com/youtube.mrs
    interval: 86400
rules:
  - RULE-SET,youtube,Media
`)
	a := AnalyzeContent("https://example.com/profile.yaml", data)
	plan := PlanImport(config.Default(), "https://example.com/profile.yaml", "nodes", "proxy_only", "minimal", a)
	if len(plan.ProxyProviders) < 1 {
		t.Fatalf("expected at least one proxy provider, got %+v", plan.ProxyProviders)
	}
	if len(plan.RuleProviders) != 0 {
		t.Fatalf("proxy_only must not import rule providers, got %+v", plan.RuleProviders)
	}
}

func TestPlanImportMapsRuleProvidersFromRuleTargets(t *testing.T) {
	data := []byte(`proxy-groups:
  - name: Common
    type: load-balance
    strategy: sticky-sessions
    filter: "♾️"
    include-all: true
  - name: Media
    type: load-balance
    strategy: sticky-sessions
    filter: YTRU
    include-all: true
  - name: AI
    type: load-balance
    strategy: sticky-sessions
    exclude-filter: "🇷🇺|YTRU|NoGemini"
    include-all: true
  - name: Messengers
    type: url-test
    url: https://cp.cloudflare.com/generate_204
    interval: 300
    filter: "TG|WA"
    include-all: true
  - name: Fallback
    type: fallback
    url: https://cp.cloudflare.com/generate_204
    interval: 300
    hidden: true
rule-providers:
  ai:
    type: http
    behavior: domain
    format: mrs
    url: https://example.com/ai.mrs
  blocked-itdog-domains:
    type: http
    behavior: classical
    format: text
    url: https://example.com/blocked.lst
  cloudflare-ips:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://example.com/cloudflare.mrs
  custom-provider:
    type: http
    behavior: domain
    format: mrs
    url: https://example.com/custom.mrs
  remote-control:
    type: http
    behavior: domain
    format: mrs
    url: https://example.com/remote.mrs
  reject-quic:
    type: inline
    behavior: classical
    payload:
      - AND,((NETWORK,udp),(DST-PORT,443))
rules:
  - RULE-SET,remote-control,DIRECT
  - RULE-SET,reject-quic,REJECT
  - RULE-SET,blocked-itdog-domains,Common
  - AND,((RULE-SET,cloudflare-ips),(NETWORK,udp),(DST-PORT,19200-19500)),Common
  - RULE-SET,custom-provider,Messengers
  - RULE-SET,ai,AI
`)
	a := AnalyzeContent("https://example.com/profile.yaml", data)
	plan := PlanImport(config.Default(), "https://example.com/profile.yaml", "remna", "auto", "minimal", a)
	providers := map[string]config.RuleProvider{}
	for _, rp := range plan.RuleProviders {
		providers[rp.Name] = rp
	}
	if got := providers["ai"]; got.Section != "ai" || got.RouteAction != "proxy" {
		t.Fatalf("ai mapped incorrectly: %+v", got)
	}
	if got := providers["ai"]; got.Priority != 60 {
		t.Fatalf("ai priority = %d, want subscription rule order priority 60", got.Priority)
	}
	if got := providers["blocked-itdog-domains"]; got.Section != "common" || got.RouteAction != "proxy" {
		t.Fatalf("blocked provider mapped incorrectly: %+v", got)
	}
	if got := providers["cloudflare-ips"]; got.Section != "common" || got.RouteAction != "proxy" {
		t.Fatalf("logical rule provider target mapped incorrectly: %+v", got)
	}
	if got := providers["cloudflare-ips"]; got.Priority != 40 {
		t.Fatalf("cloudflare priority = %d, want logical rule order priority 40", got.Priority)
	}
	if got := providers["custom-provider"]; got.Section != "messengers" || got.RouteAction != "proxy" {
		t.Fatalf("custom provider mapped incorrectly: %+v", got)
	}
	if got := providers["remote-control"]; got.Section != "direct" || got.RouteAction != "direct" {
		t.Fatalf("direct provider mapped incorrectly: %+v", got)
	}
	if got := providers["reject-quic"]; got.Section != "reject" || got.RouteAction != "reject" {
		t.Fatalf("reject provider mapped incorrectly: %+v", got)
	}
	groups := map[string]config.Section{}
	for _, s := range plan.SectionGroups {
		groups[s.Name] = s
	}
	if got := groups["messengers"]; got.Action != "proxy" || got.ProxyGroup != "Messengers" || got.ProxyGroupType != "url-test" || got.ProxyFilter != "TG|WA" || got.ProxyHealthCheckURL != "https://cp.cloudflare.com/generate_204" || got.ProxyHealthCheckInterval != 300 {
		t.Fatalf("custom section group not imported: %+v", got)
	}
	if got := groups["messengers"]; got.Priority != 50 {
		t.Fatalf("messengers section priority = %d, want first rule target order priority 50", got.Priority)
	}
	if _, ok := groups["fallback"]; ok {
		t.Fatalf("unused helper fallback group must not be imported as routing section: %+v", groups["fallback"])
	}
}
