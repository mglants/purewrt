package manager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/provider"
)

func TestTruthy(t *testing.T) {
	t.Parallel()

	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		if !truthy(v) {
			t.Fatalf("truthy(%q) = false", v)
		}
	}
	for _, v := range []string{"", "0", "false", "off", "no"} {
		if truthy(v) {
			t.Fatalf("truthy(%q) = true", v)
		}
	}
}

func TestManagerClassify(t *testing.T) {
	t.Parallel()

	out, err := (Manager{}).Classify("youtube", "https://example.com/youtube.txt", "domain", "text")
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !strings.Contains(out, `"Section": "media"`) {
		t.Fatalf("classification output = %s", out)
	}
}

func TestRuleProviderStatusJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.txt")
	cfgPath := filepath.Join(dir, "purewrt")
	c := config.Default()
	c.RuleProviders = []config.RuleProvider{{Name: "rp1", Path: rulesPath, LastError: "old"}}
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	when := time.Date(2026, 5, 16, 3, 4, 0, 0, time.UTC)
	if err := provider.WriteMetadata(rulesPath, provider.Metadata{LastUpdate: when, LastSuccess: when, EntryCount: 7, ErrorMessage: "new"}); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	out, err := (Manager{ConfigPath: cfgPath}).RuleProviderStatusJSON()
	if err != nil {
		t.Fatalf("RuleProviderStatusJSON: %v", err)
	}
	var parsed struct {
		RuleProviders []struct {
			Name       string `json:"name"`
			EntryCount int    `json:"entry_count"`
			Error      string `json:"error"`
		} `json:"rule_providers"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(parsed.RuleProviders) != 1 || parsed.RuleProviders[0].Name != "rp1" || parsed.RuleProviders[0].EntryCount != 7 || parsed.RuleProviders[0].Error != "new" {
		t.Fatalf("status = %+v json=%s", parsed, out)
	}
	if err := os.Remove(rulesPath + ".meta.json"); err != nil {
		t.Fatal(err)
	}
	out, err = (Manager{ConfigPath: cfgPath}).RuleProviderStatusJSON()
	if err != nil || !strings.Contains(out, "old") {
		t.Fatalf("fallback out=%s err=%v", out, err)
	}
}
