package generator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestOONIConfigJSON(t *testing.T) {
	c := config.Default()
	c.OONI.Upload = true
	out := OONIConfigJSON(c)

	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("config.json is not valid JSON: %v\n%s", err, out)
	}
	if m["_informed_consent"] != true {
		t.Fatalf("expected _informed_consent true, got %v", m["_informed_consent"])
	}
	sharing, ok := m["sharing"].(map[string]any)
	if !ok || sharing["upload_results"] != true {
		t.Fatalf("expected sharing.upload_results true, got %v", m["sharing"])
	}
	if strings.Contains(string(out), "proxy") {
		t.Fatalf("config.json must NOT contain a proxy key (proxy is a CLI flag):\n%s", out)
	}

	// upload off ⇒ upload_results false
	c.OONI.Upload = false
	_ = json.Unmarshal(OONIConfigJSON(c), &m)
	sharing = m["sharing"].(map[string]any)
	if sharing["upload_results"] != false {
		t.Fatalf("expected upload_results false, got %v", sharing["upload_results"])
	}
}
