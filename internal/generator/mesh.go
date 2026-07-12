package generator

import (
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mesh"
)

// friendProxy is a consumable friend exit: a mihomo shadowsocks outbound
// pointing at the friend's mesh listener over the easytier overlay.
type friendProxy struct {
	Name     string // mihomo proxy name, "friend_<hwid hex24>" — hwid-keyed, rename-proof
	IP       string // overlay IPv4
	Port     int
	Password string // derived from the group PSK + the peer's advertised salt
}

// friendHWIDRE guards peer identities before they land in generated YAML —
// hwids arrive over the network from mesh-sync. The capture group is the
// hex24 tail that becomes the mihomo proxy name suffix; the display name is
// cosmetic and never enters generated configs.
var friendHWIDRE = regexp.MustCompile(`^purewrt-([0-9a-f]{24})$`)

// meshFriends returns the mihomo proxies for every consumable friend exit:
// enabled, exit offered, has an overlay IP, and credentials derive cleanly.
// Bad material (unparseable hex, malformed hwid) skips the peer — one broken
// peer must not stop the rest of the mesh from generating.
func meshFriends(c config.Config) []friendProxy {
	if !c.MeshActive() {
		return nil
	}
	psk, err := hex.DecodeString(c.Mesh.PSK)
	if err != nil || len(psk) == 0 {
		return nil
	}
	var out []friendProxy
	seen := map[string]bool{}
	for _, p := range c.MeshPeers {
		hw := friendHWIDRE.FindStringSubmatch(p.HWID)
		if !p.Enabled || !p.ExitOffered || p.OverlayIP == "" || hw == nil || seen[p.HWID] {
			continue
		}
		salt, err := hex.DecodeString(p.CredSalt(c.Mesh.PSK))
		if err != nil || len(salt) == 0 {
			continue
		}
		port := p.ListenPort
		if port <= 0 {
			port = c.Mesh.ListenPort
		}
		seen[p.HWID] = true
		out = append(out, friendProxy{
			// hwid-keyed: unique by construction and stable across the
			// friend's renames, so a cosmetic rename can never churn the
			// generated mihomo config.
			Name:     "friend_" + hw[1],
			IP:       p.OverlayIP,
			Port:     port,
			Password: mesh.DeriveSSPassword(psk, salt),
		})
	}
	return out
}

// meshListenerPassword derives this router's own mesh-in listener password.
// Empty string means the material is unusable and the listener (and with it
// the whole exit path) must not be emitted.
func meshListenerPassword(c config.Config) string {
	psk, err := hex.DecodeString(c.Mesh.PSK)
	if err != nil || len(psk) == 0 {
		return ""
	}
	salt, err := hex.DecodeString(c.Mesh.CredSalt())
	if err != nil || len(salt) == 0 {
		return ""
	}
	return mesh.DeriveSSPassword(psk, salt)
}

// meshExitViable reports whether this router can offer an exit at all:
// mesh joined, exit enabled, credentials derivable, and at least one own
// egress (provider nodes or referenced VPNs) for MeshExit to route through.
// Without members the group would be invalid YAML-wise (or silently fall
// back to `main`), so the listener isn't emitted either — friends fail fast
// with a connection error instead of a black hole.
func meshExitViable(c config.Config, enabledProviders []config.ProxyProvider) bool {
	if !c.MeshActive() || !c.Mesh.ExitEnabled || c.Mesh.ListenPort <= 0 {
		return false
	}
	if meshListenerPassword(c) == "" {
		return false
	}
	return len(enabledProviders) > 0 || len(referencedVPNs(c)) > 0
}

// writeMeshExitGroup emits the MeshExit url-test group — the ONLY egress for
// inbound friend traffic.
//
// INVARIANT (loop + liability prevention, tested): members are exclusively
// this host's own providers (use:) and referenced vpn_* outbounds (proxies:).
// Never DIRECT — friend traffic must not exit via this router's home IP.
// Never friend_* — A⇄B mutual fallback would ping-pong. Never section
// groups — after fallback wiring those may contain friend_* transitively.
//
// ExitFilter/ExitExcludeFilter scope which provider nodes friends may use —
// mihomo applies them to `use:` provider nodes only; explicit vpn_* members
// are always kept (same semantics as section groups). An over-narrow filter
// can leave the group empty at runtime: meshExitViable checks provider
// presence, not post-filter membership — the LuCI live preview is the
// operator's guard against that.
func writeMeshExitGroup(b *strings.Builder, c config.Config, providers []config.ProxyProvider) {
	vpnMembers := []string{}
	for _, v := range referencedVPNs(c) {
		vpnMembers = append(vpnMembers, vpnProxyName(v.Name))
	}
	writeProxyGroup(b, "MeshExit", "url-test", c.Mesh.ExitFilter, c.Mesh.ExitExcludeFilter, "", "", 0, providers, vpnMembers)
}

// writeSectionFallbackGroup wraps a section's local group with the shared
// Friends group: the public group name becomes a `fallback` preferring
// <name>_local, so the IN-NAME rule, LuCI group-select and NetCheckProbe
// keep working unchanged, and friends only carry traffic when every local
// node is dead.
func writeSectionFallbackGroup(b *strings.Builder, name, healthURL string, healthInterval int) {
	b.WriteString("  - name: " + name + "\n    type: fallback\n    proxies:\n      - " + name + "_local\n      - Friends\n")
	if healthURL == "" {
		healthURL = "https://cp.cloudflare.com/generate_204"
	}
	if healthInterval <= 0 {
		healthInterval = 300
	}
	b.WriteString("    url: " + healthURL + "\n    interval: " + itoa(healthInterval) + "\n")
}

// writeFriendsGroup emits the shared consumer-side group over every
// consumable friend exit: load-balance with sticky-sessions, so parallel
// flows spread across friends while each src/dst pair stays pinned, and
// health checks skip dead friends. Emitted once (sections reference it via
// their fallback wrapper), even for a single friend — uniform shape, stable
// name for LuCI. Hand-rolled instead of writeProxyGroup: that helper falls
// back to `use: [main]` when member-less, which must never happen here.
func writeFriendsGroup(b *strings.Builder, friends []friendProxy) {
	b.WriteString("  - name: Friends\n    type: load-balance\n    proxies:\n")
	for _, f := range friends {
		b.WriteString("      - " + f.Name + "\n")
	}
	b.WriteString("    url: https://cp.cloudflare.com/generate_204\n    interval: 300\n    strategy: sticky-sessions\n")
}
