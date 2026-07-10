package provider

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/purewrt/purewrt/internal/version"
)

var (
	uaOnce  sync.Once
	uaValue string
)

// DefaultUserAgent is the UA sent when a subscription/provider has no
// user_agent configured: "mihomo/<mihomo-version> (purewrt/<version>)".
// The mihomo prefix is load-bearing — panels gate the response format on
// it (AGENTS.md: default UAs get base64, "mihomo*" gets Clash YAML) — and
// the mihomo version lets panels that feature-gate on it serve configs the
// installed core can actually parse. Detected once per process.
func DefaultUserAgent() string {
	uaOnce.Do(func() { uaValue = buildDefaultUserAgent(detectMihomoVersion()) })
	return uaValue
}

func buildDefaultUserAgent(mihomoVersion string) string {
	if mihomoVersion == "" {
		return "mihomo (purewrt/" + version.Version + ")"
	}
	return "mihomo/" + mihomoVersion + " (purewrt/" + version.Version + ")"
}

// detectMihomoVersion prefers the updater's version marker (cheap, present
// on updater-managed installs) and falls back to `mihomo -v` for package-
// installed cores. Empty when mihomo isn't installed yet (wizard import on
// a fresh box).
func detectMihomoVersion() string {
	if b, err := os.ReadFile("/etc/purewrt/mihomo-bin/.mihomo-purewrt-version.json"); err == nil {
		if v := mihomoVersionFromMeta(b); v != "" {
			return v
		}
	}
	for _, bin := range []string{"/usr/bin/mihomo", "mihomo"} {
		if out, err := exec.Command(bin, "-v").Output(); err == nil {
			if v := mihomoVersionFromV(string(out)); v != "" {
				return v
			}
		}
	}
	return ""
}

func mihomoVersionFromMeta(b []byte) string {
	var m struct{ Version string }
	if err := json.Unmarshal(b, &m); err != nil {
		return ""
	}
	return strings.TrimSpace(m.Version)
}

// mihomoVersionFromV parses `mihomo -v` output: "Mihomo Meta <version>
// linux arm64 with go1.x ..." (the "Meta" token is absent on some builds).
func mihomoVersionFromV(out string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "Mihomo" {
		return ""
	}
	if fields[1] == "Meta" {
		if len(fields) < 3 {
			return ""
		}
		return fields[2]
	}
	return fields[1]
}
