package generator

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// helper to round-trip YAML through the merger and pull a top-level key
// out as a typed slice for assertions.
func mustMerge(t *testing.T, base, mixin string) map[string]any {
	t.Helper()
	out, err := mergeMihomoYAML([]byte(base), []byte(mixin))
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatalf("merged output not valid YAML: %v\n---\n%s\n---", err, out)
	}
	return got
}

func TestMixinMerge_ScalarOverride(t *testing.T) {
	// Mixin replaces a top-level scalar (log-level) and leaves siblings alone.
	got := mustMerge(t,
		"log-level: warning\nmode: rule\nmixed-port: 7890\n",
		"log-level: debug\n")
	if got["log-level"] != "debug" {
		t.Errorf("log-level = %v, want debug", got["log-level"])
	}
	if got["mode"] != "rule" {
		t.Errorf("mode = %v, want rule (untouched)", got["mode"])
	}
	if got["mixed-port"] != 7890 {
		t.Errorf("mixed-port = %v (%T), want 7890", got["mixed-port"], got["mixed-port"])
	}
}

func TestMixinMerge_NestedMapMerge(t *testing.T) {
	// Mixin adds dns.enhanced-mode while base has other dns fields —
	// merge must keep base's other dns fields and add the new one.
	got := mustMerge(t,
		"dns:\n  enable: true\n  listen: 127.0.0.1:7874\n  ipv6: false\n",
		"dns:\n  enhanced-mode: redir-host\n")
	dns, ok := got["dns"].(map[string]any)
	if !ok {
		t.Fatalf("dns is %T, want map", got["dns"])
	}
	for _, kv := range []struct{ k string; v any }{
		{"enable", true},
		{"listen", "127.0.0.1:7874"},
		{"ipv6", false},
		{"enhanced-mode", "redir-host"},
	} {
		if dns[kv.k] != kv.v {
			t.Errorf("dns.%s = %v, want %v", kv.k, dns[kv.k], kv.v)
		}
	}
}

func TestMixinMerge_ArrayReplace(t *testing.T) {
	// Plain key (no purewrt- prefix) replaces the base array entirely.
	got := mustMerge(t,
		"rules:\n  - 'DOMAIN-SUFFIX,a.com,DIRECT'\n  - 'MATCH,Common'\n",
		"rules:\n  - 'DOMAIN,override.com,DIRECT'\n")
	rules, ok := got["rules"].([]any)
	if !ok {
		t.Fatalf("rules is %T, want []any", got["rules"])
	}
	if len(rules) != 1 || rules[0] != "DOMAIN,override.com,DIRECT" {
		t.Errorf("rules = %v, want exactly the mixin entry", rules)
	}
}

func TestMixinMerge_PrependArray(t *testing.T) {
	// purewrt-rules: prepends to rules: then the prefixed key is deleted.
	got := mustMerge(t,
		"rules:\n  - 'DOMAIN-SUFFIX,a.com,DIRECT'\n  - 'MATCH,Common'\n",
		"purewrt-rules:\n  - 'DOMAIN,my-override.com,DIRECT'\n  - 'DOMAIN,my-other.com,REJECT'\n")
	rules, ok := got["rules"].([]any)
	if !ok {
		t.Fatalf("rules is %T, want []any", got["rules"])
	}
	want := []string{
		"DOMAIN,my-override.com,DIRECT",
		"DOMAIN,my-other.com,REJECT",
		"DOMAIN-SUFFIX,a.com,DIRECT",
		"MATCH,Common",
	}
	if len(rules) != len(want) {
		t.Fatalf("rules len = %d, want %d (%v)", len(rules), len(want), rules)
	}
	for i, w := range want {
		if rules[i] != w {
			t.Errorf("rules[%d] = %v, want %s", i, rules[i], w)
		}
	}
	if _, leaked := got["purewrt-rules"]; leaked {
		t.Error("purewrt-rules prefix key leaked into output")
	}
}

func TestMixinMerge_PrependCreatesMissingBase(t *testing.T) {
	// purewrt-X when base has no X: still produces X with the prepend items.
	got := mustMerge(t,
		"mode: rule\n",
		"purewrt-listeners:\n  - {name: ss, type: shadowsocks, port: 12060}\n")
	listeners, ok := got["listeners"].([]any)
	if !ok {
		t.Fatalf("listeners is %T, want []any", got["listeners"])
	}
	if len(listeners) != 1 {
		t.Errorf("listeners len = %d, want 1", len(listeners))
	}
}

func TestMixinMerge_PrependNonListFallsBackToReplace(t *testing.T) {
	// purewrt-X where X has a non-list value behind it just renames to X.
	// Defensive — most users shouldn't hit this but we want predictable
	// behaviour (vs silently dropping the value).
	got := mustMerge(t,
		"log-level: info\n",
		"purewrt-log-level: debug\n")
	if got["log-level"] != "debug" {
		t.Errorf("log-level = %v, want debug", got["log-level"])
	}
	if _, leaked := got["purewrt-log-level"]; leaked {
		t.Error("purewrt-log-level leaked")
	}
}

func TestMixinMerge_InvalidYAMLFails(t *testing.T) {
	_, err := mergeMihomoYAML([]byte("ok: yes\n"), []byte("this is: : not yaml\n"))
	if err == nil {
		t.Fatal("expected error for invalid mixin YAML")
	}
	if !strings.Contains(err.Error(), "mixin") {
		t.Errorf("error message should mention mixin: %v", err)
	}
}

func TestMixinMerge_EmptyMixinIsIdentity(t *testing.T) {
	base := "log-level: info\nmode: rule\n"
	out, err := mergeMihomoYAML([]byte(base), []byte(""))
	if err != nil {
		t.Fatalf("empty mixin should not error: %v", err)
	}
	if string(out) != base {
		t.Errorf("empty mixin should return base verbatim;\ngot %q\nwant %q", out, base)
	}
}
