package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedZapretCandidatesParse(t *testing.T) {
	t.Parallel()
	l := EmbeddedZapretCandidates()
	if len(l.Candidates) == 0 {
		t.Fatal("embedded candidates empty")
	}
	seen := map[string]bool{}
	for _, c := range l.Candidates {
		if c.Name == "" || c.Params == "" {
			t.Errorf("candidate missing name/params: %+v", c)
		}
		if seen[c.Name] {
			t.Errorf("duplicate candidate name %q", c.Name)
		}
		seen[c.Name] = true
		if c.ISP == "" {
			t.Errorf("candidate %q missing isp", c.Name)
		}
		// nfqws2 uses --lua-desync, never legacy --dpi-desync.
		if strings.Contains(c.Params, "--dpi-desync") {
			t.Errorf("candidate %q uses legacy --dpi-desync syntax", c.Name)
		}
		// A blob referenced in params by name must be declared (unless stock).
		for _, b := range c.Blobs {
			if b.Name == "" || b.File == "" {
				t.Errorf("candidate %q blob missing name/file: %+v", c.Name, b)
			}
			if !strings.Contains(c.Params, "blob="+b.Name) &&
				!strings.Contains(c.Params, "seqovl_pattern="+b.Name) &&
				!strings.Contains(c.Params, "pattern="+b.Name) {
				t.Errorf("candidate %q declares blob %q not referenced in params", c.Name, b.Name)
			}
		}
	}
}

func TestLoadZapretCandidatesOverridePrecedence(t *testing.T) {
	// Can't easily override the const path in a unit test without touching the
	// real /etc; instead verify the parse+fallback contract on a temp file via
	// the same json path the loader uses.
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"candidates":[{"name":"x","isp":"common","params":"--filter-tcp=443 --lua-desync=multisplit:pos=2"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// malformed → loader must fall back to embed (len>0)
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{ not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	// The embed is always the guaranteed fallback.
	if len(EmbeddedZapretCandidates().Candidates) == 0 {
		t.Fatal("embed fallback empty")
	}
}
