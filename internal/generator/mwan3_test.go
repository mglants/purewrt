package generator

import (
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// TestPolicyCommandArgsSuppressBeforeFwmark guarantees the `suppress_prefixlength 0`
// rule lands at a higher priority (lower numeric value) than the proxy fwmark
// rule. Order matters: without this, marked router-originated traffic to a
// destination that has a specific main-table route (LAN subnet, netifd-managed
// WireGuard peer host route, user static route) would still be diverted into
// mihomo and break those flows.
func TestPolicyCommandArgsSuppressBeforeFwmark(t *testing.T) {
	cmds := PolicyCommands(config.Default())
	var suppressIdx, fwmarkIdx = -1, -1
	for i, c := range cmds {
		if strings.Contains(c, "lookup main suppress_prefixlength 0") && strings.HasPrefix(c, "ip rule add ") {
			suppressIdx = i
		}
		if strings.Contains(c, "fwmark 0x1/0xff") && strings.HasPrefix(c, "ip rule add ") {
			fwmarkIdx = i
			break
		}
	}
	if suppressIdx < 0 {
		t.Fatalf("missing `ip rule add ... lookup main suppress_prefixlength 0` in:\n%s", strings.Join(cmds, "\n"))
	}
	if fwmarkIdx < 0 {
		t.Fatalf("missing fwmark rule in:\n%s", strings.Join(cmds, "\n"))
	}
	if suppressIdx >= fwmarkIdx {
		t.Fatalf("suppress rule must be added before fwmark rule; got suppress@%d fwmark@%d", suppressIdx, fwmarkIdx)
	}
}

// TestPolicyCommandArgsSuppressIdempotentDeletePresent matches the existing
// fwmark rule's idempotent del+add pattern — apply must be safe to re-run
// without accumulating duplicate ip rules.
func TestPolicyCommandArgsSuppressIdempotentDeletePresent(t *testing.T) {
	cmds := PolicyCommands(config.Default())
	var delSeen bool
	for _, c := range cmds {
		if strings.HasPrefix(c, "ip rule del ") && strings.Contains(c, "lookup main suppress_prefixlength 0") {
			delSeen = true
			break
		}
	}
	if !delSeen {
		t.Fatalf("idempotent `ip rule del ... suppress_prefixlength 0` missing in:\n%s", strings.Join(cmds, "\n"))
	}
}

// TestPolicyCommandArgsSuppressMirrorsV6 — the suppress rule must be applied
// for both IPv4 and IPv6 so v6 VPN/LAN routes also win over the fwmark rule.
func TestPolicyCommandArgsSuppressMirrorsV6(t *testing.T) {
	cmds := PolicyCommands(config.Default())
	var v6Seen bool
	for _, c := range cmds {
		if strings.HasPrefix(c, "ip -6 rule add ") && strings.Contains(c, "lookup main suppress_prefixlength 0") {
			v6Seen = true
			break
		}
	}
	if !v6Seen {
		t.Fatalf("v6 suppress rule missing in:\n%s", strings.Join(cmds, "\n"))
	}
}

// TestPolicyCommandArgsSuppressFollowsIPRulePriority — if the user changes
// `Settings.IPRulePriority`, the suppress rule should sit one position above
// it (priority - 1) rather than be hardcoded to 99.
func TestPolicyCommandArgsSuppressFollowsIPRulePriority(t *testing.T) {
	c := config.Default()
	c.Settings.IPRulePriority = "500"
	cmds := PolicyCommands(c)
	var found bool
	for _, cmd := range cmds {
		if strings.Contains(cmd, "priority 499") && strings.Contains(cmd, "lookup main suppress_prefixlength 0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("suppress rule must use priority (IPRulePriority - 1) = 499 when IPRulePriority=500; got:\n%s", strings.Join(cmds, "\n"))
	}
}
