package checker

import (
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mihomoapi"
)

type MihomoMember struct {
	Name    string
	Alive   bool
	DelayMS int
}

type MihomoPath struct {
	Inbound   string
	Group     string
	GroupType string // live from mihomo (url-test/select/load-balance); falls back to configured
	Strategy  string // configured (load-balance only)
	Filter    string // configured proxy filter (applies to provider nodes)
	Providers []string
	VPNs      []string // vpn_<name> outbounds in this section's pool

	Reachable       bool
	Members         []MihomoMember
	SelectedNode    string
	SelectedAlive   bool
	SelectedDelayMS int
	Note            string
}

// MihomoForSection resolves the live mihomo group for a section: its
// configured outbound pool (subscription providers + VPN interfaces) and, when
// the controller is reachable, the group type, members with per-node
// alive/delay, and the currently selected node.
func MihomoForSection(c config.Config, sec config.Section) MihomoPath {
	p := MihomoPath{
		Inbound:   sec.ListenerName(),
		Group:     sec.ProxyGroup,
		GroupType: sec.ProxyGroupType,
		Strategy:  sec.ProxyStrategy,
		Filter:    sec.ProxyFilter,
	}
	if p.Group == "" {
		p.Group = config.TitleASCII(sec.Name)
	}
	// Configured pool (mirrors generator: use: providers + proxies: vpn_<name>).
	for _, pp := range c.ProxyProviders {
		if pp.Enabled {
			p.Providers = append(p.Providers, pp.Name)
		}
	}
	for _, v := range sec.VPNs {
		if _, ok := c.VPNForName(v); ok {
			p.VPNs = append(p.VPNs, "vpn_"+v)
		}
	}

	cli := mihomoapi.Client{Base: localController(c.Settings.ExternalController), Secret: c.Settings.Secret}
	proxies, err := cli.Proxies()
	if err != nil {
		p.Note = "controller unreachable: " + err.Error()
		return p
	}
	p.Reachable = true
	g, ok := proxies[p.Group]
	if !ok {
		p.Note = "group " + p.Group + " not found in mihomo"
		return p
	}
	if g.Type != "" {
		p.GroupType = g.Type
	}
	p.SelectedNode = g.Now
	for _, m := range g.All {
		mm := MihomoMember{Name: m}
		if px, ok := proxies[m]; ok {
			mm.Alive = px.Alive
			mm.DelayMS = proxyDelay(px)
		}
		p.Members = append(p.Members, mm)
	}
	if sel, ok := proxies[g.Now]; ok {
		p.SelectedAlive = sel.Alive
		p.SelectedDelayMS = proxyDelay(sel)
	}
	return p
}

// proxyDelay returns the live delay; mihomo reports the latest probe in
// history, leaving the top-level Delay 0 until a fresh test.
func proxyDelay(px mihomoapi.Proxy) int {
	if px.Delay > 0 {
		return px.Delay
	}
	if n := len(px.History); n > 0 {
		return px.History[n-1].Delay
	}
	return 0
}

// localController rewrites a wildcard external-controller bind to a loopback
// address so the check (running on the router) can reach it.
func localController(base string) string {
	switch {
	case base == "":
		return "127.0.0.1:9090"
	case strings.HasPrefix(base, "0.0.0.0:"):
		return "127.0.0.1:" + strings.TrimPrefix(base, "0.0.0.0:")
	case strings.HasPrefix(base, "[::]:"):
		return "127.0.0.1:" + strings.TrimPrefix(base, "[::]:")
	default:
		return base
	}
}
