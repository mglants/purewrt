package manager

import (
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// TestEffectiveUpdateProxyURL guards the "empty URL = local mihomo proxy"
// contract: enabling update_via_proxy with a cleared URL must route via
// the mixed-port listener the generated config always opens, not silently
// disable proxying.
func TestEffectiveUpdateProxyURL(t *testing.T) {
	c := config.Default()
	c.Settings.UpdateProxyURL = ""
	if got := effectiveUpdateProxyURL(c); got != config.LocalMihomoProxyURL() {
		t.Fatalf("empty URL must default to the local mihomo proxy, got %q", got)
	}
	c.Settings.UpdateProxyURL = "http://10.0.0.2:3128"
	if got := effectiveUpdateProxyURL(c); got != "http://10.0.0.2:3128" {
		t.Fatalf("explicit URL must win, got %q", got)
	}
}

// TestFallbackProxySuppressedWhenPrimaryProxied: when the primary download
// already goes through the (defaulted) local proxy, the fallback must be
// empty — a tautological re-attempt through the same proxy is wasted time.
func TestFallbackProxySuppressedWhenPrimaryProxied(t *testing.T) {
	c := config.Default()
	c.Settings.UpdateProxyURL = ""
	if got := fallbackProxyURL(c, config.LocalMihomoProxyURL()); got != "" {
		t.Fatalf("fallback must be suppressed when primary already uses it, got %q", got)
	}
	if got := fallbackProxyURL(c, ""); got != config.LocalMihomoProxyURL() {
		t.Fatalf("direct primary should fall back to the local proxy, got %q", got)
	}
}
