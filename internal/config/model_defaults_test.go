package config

import (
	"os"
	"testing"
)

func TestTitleASCII(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"":          "",
		"   ":       "",
		"proxy":     "Proxy",
		"Proxy":     "Proxy",
		"pRoXy":     "PRoXy",
		"  common ": "Common",
	}
	for in, want := range tests {
		if got := TitleASCII(in); got != want {
			t.Fatalf("TitleASCII(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultsAssignSectionProxyGroup(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/config"
	uci := "config section 'media'\n\toption action 'proxy'\n\toption tproxy_port '7893'\n"
	if err := os.WriteFile(path, []byte(uci), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := c.Sections[0].ProxyGroup; got != "Media" {
		t.Fatalf("ProxyGroup = %q, want Media", got)
	}
	if got := c.Sections[0].Action; got != "proxy" {
		t.Fatalf("Action = %q, want proxy", got)
	}
	if got := c.Sections[0].ProxyGroupType; got != "url-test" {
		t.Fatalf("ProxyGroupType = %q, want url-test", got)
	}
	if got := c.Sections[0].ProxyStrategy; got != "sticky-sessions" {
		t.Fatalf("ProxyStrategy = %q, want sticky-sessions", got)
	}
}

func TestUpsertSectionProxyGroupDefaultsAppendedSections(t *testing.T) {
	t.Parallel()

	c := Default()
	c.Sections = nil
	c = UpsertSectionProxyGroup(c, Section{Name: "video"})

	if len(c.Sections) != 1 {
		t.Fatalf("sections length = %d, want 1", len(c.Sections))
	}
	s := c.Sections[0]
	if s.Name != "video" || s.ProxyGroup != "Video" {
		t.Fatalf("section = %+v, want name video and proxy group Video", s)
	}
	if s.Action != "proxy" || s.ProxyGroupType != "url-test" || s.ProxyStrategy != "sticky-sessions" {
		t.Fatalf("unexpected defaults: %+v", s)
	}
}
