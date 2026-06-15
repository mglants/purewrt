package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestZapretCheckStrategyRejectsUnsafeDomain(t *testing.T) {
	_, err := (Manager{}).ZapretCheckStrategy("example.org; reboot")
	if err == nil {
		t.Fatal("expected unsafe domain error")
	}
}

func TestZapretCheckStrategyRejectsUnsafeInterface(t *testing.T) {
	_, err := (Manager{}).ZapretCheckStrategy("example.org", "wan; reboot")
	if err == nil {
		t.Fatal("expected unsafe interface error")
	}
}

func TestZapretCheckRuleWarningForProxyDomain(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rulePath, []byte("DOMAIN-SUFFIX,example.org\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Sections = []config.Section{{Name: "common", Enabled: true, Action: "proxy", IPv4Enabled: true, IPv6Enabled: true}}
	c.RuleProviders = []config.RuleProvider{{Name: "test", Enabled: true, Format: "text", Path: rulePath, Section: "common"}}

	warning := zapretCheckRuleWarning(c, "www.example.org")
	if !strings.Contains(warning, "action \"proxy\"") {
		t.Fatalf("expected proxy warning, got %q", warning)
	}
}

func TestZapretCheckRuleWarningIgnoresZapretDomain(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rulePath, []byte("DOMAIN-SUFFIX,example.org\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Sections = []config.Section{{Name: "media", Enabled: true, Action: "zapret", IPv4Enabled: true, IPv6Enabled: true}}
	c.RuleProviders = []config.RuleProvider{{Name: "test", Enabled: true, Format: "text", Path: rulePath, Section: "media"}}

	if warning := zapretCheckRuleWarning(c, "example.org"); warning != "" {
		t.Fatalf("unexpected warning: %q", warning)
	}
}

func TestZapretCheckBypassCommands(t *testing.T) {
	if got := strings.Join(zapretCheckBypassAddCommand("203.0.113.10"), " "); got != "nft add element inet purewrt bypass4 { 203.0.113.10 }" {
		t.Fatalf("unexpected ipv4 add command: %s", got)
	}
	if got := strings.Join(zapretCheckBypassDeleteCommand("2001:db8::10"), " "); got != "nft delete element inet purewrt bypass6 { 2001:db8::10 }" {
		t.Fatalf("unexpected ipv6 delete command: %s", got)
	}
}

func TestParseZapretStrategies(t *testing.T) {
	out := "!!!!! test: working strategy found for ipv4 example.org : nfqws --payload=tls_client_hello --lua-desync=fake !!!!!\n"
	got := parseZapretStrategies(out)
	if len(got) != 1 || got[0] != "--payload=tls_client_hello --lua-desync=fake" {
		t.Fatalf("unexpected parsed strategies: %#v", got)
	}
}

func TestZapretCheckOptionDefaults(t *testing.T) {
	if defaultChoice("bad", "quick", "quick", "standard") != "quick" {
		t.Fatal("unexpected choice default")
	}
	if defaultBool("yes", "0") != "0" || defaultBool("1", "0") != "1" {
		t.Fatal("unexpected bool default")
	}
	if defaultNumber("abc", "1") != "1" || defaultNumber("5", "1") != "5" {
		t.Fatal("unexpected number default")
	}
}
