package provider

import (
	"testing"

	"github.com/purewrt/purewrt/internal/version"
)

// Panels gate response format on a mihomo-ish UA (AGENTS.md: default UAs
// get base64, "mihomo*" gets Clash YAML), and some parse the version for
// feature gating — so the default UA reports the installed mihomo version
// with purewrt's own version in the comment.
func TestBuildDefaultUserAgent(t *testing.T) {
	if got, want := buildDefaultUserAgent("alpha-be9164e"), "mihomo/alpha-be9164e (purewrt/"+version.Version+")"; got != want {
		t.Fatalf("buildDefaultUserAgent = %q, want %q", got, want)
	}
	// Unknown mihomo version (not installed yet, e.g. wizard import on a
	// fresh box) still keeps the mihomo prefix so panel gating works.
	if got, want := buildDefaultUserAgent(""), "mihomo (purewrt/"+version.Version+")"; got != want {
		t.Fatalf("buildDefaultUserAgent(\"\") = %q, want %q", got, want)
	}
}

func TestMihomoVersionFromMeta(t *testing.T) {
	meta := []byte(`{"Channel":"alpha","Version":"alpha-be9164e","AssetName":"mihomo-linux-arm64-alpha-be9164e.gz"}`)
	if got := mihomoVersionFromMeta(meta); got != "alpha-be9164e" {
		t.Fatalf("mihomoVersionFromMeta = %q", got)
	}
	if got := mihomoVersionFromMeta([]byte("not json")); got != "" {
		t.Fatalf("garbage meta must yield empty, got %q", got)
	}
}

func TestMihomoVersionFromV(t *testing.T) {
	cases := map[string]string{
		"Mihomo Meta alpha-be9164e5 linux arm64 with go1.26.4 2026-06-21T21:28:08+00:00": "alpha-be9164e5",
		"Mihomo Meta v1.19.2 linux amd64 with go1.24.0 2026-01-01T00:00:00+00:00":        "v1.19.2",
		"Mihomo v1.19.2 linux amd64":                                                     "v1.19.2",
		"":                                                                               "",
		"unexpected output":                                                              "",
	}
	for in, want := range cases {
		if got := mihomoVersionFromV(in); got != want {
			t.Fatalf("mihomoVersionFromV(%q) = %q, want %q", in, got, want)
		}
	}
}
