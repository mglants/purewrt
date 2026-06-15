package manager

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// ProxyGroupMember is one selectable node inside a group, enriched with
// the latest health data mihomo holds for it.
type ProxyGroupMember struct {
	Name  string `json:"name"`
	Type  string `json:"type,omitempty"`
	Alive bool   `json:"alive"`
	Delay int    `json:"delay,omitempty"`
}

// ProxyGroupInfo is the LuCI-facing view of one mihomo proxy group.
type ProxyGroupInfo struct {
	Name    string             `json:"name"`
	Type    string             `json:"type"`
	Now     string             `json:"now,omitempty"`
	Section string             `json:"section,omitempty"` // owning routing section, when resolvable
	Members []ProxyGroupMember `json:"members"`
}

// listableGroupTypes are mihomo group types worth showing in the panel
// (they expose a member list + health data). Only Selector groups accept
// a manual node choice — url-test/fallback/load-balance pick nodes
// automatically, so the UI renders them read-only and ProxySelect
// rejects them.
var listableGroupTypes = []string{"Selector", "URLTest", "Fallback", "LoadBalance"}

// ProxyGroups lists mihomo's proxy groups with member health, sorted by
// name for stable UI rendering.
func (m Manager) ProxyGroups() ([]ProxyGroupInfo, error) {
	cli, err := m.mihomoClient()
	if err != nil {
		return nil, err
	}
	proxies, err := cli.Proxies()
	if err != nil {
		return nil, err
	}
	c, _ := m.Load()
	sectionByGroup := map[string]string{}
	for _, s := range c.Sections {
		if s.ProxyGroup != "" {
			sectionByGroup[s.ProxyGroup] = s.Name
		}
	}
	var out []ProxyGroupInfo
	for name, p := range proxies {
		if len(p.All) == 0 || !slices.Contains(listableGroupTypes, p.Type) {
			continue
		}
		// GLOBAL is mihomo's built-in group, only consulted in
		// `mode: global` — PureWRT always generates `mode: rule`, so
		// switching it does nothing. Listing it just confuses.
		if name == "GLOBAL" {
			continue
		}
		g := ProxyGroupInfo{Name: name, Type: p.Type, Now: p.Now, Section: sectionByGroup[name], Members: make([]ProxyGroupMember, 0, len(p.All))}
		for _, member := range p.All {
			mp := proxies[member]
			g.Members = append(g.Members, ProxyGroupMember{Name: member, Type: mp.Type, Alive: mp.Alive, Delay: mp.Delay})
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ProxySelectResult reports one switch operation.
type ProxySelectResult struct {
	Group   string `json:"group"`
	Node    string `json:"node"`
	Drained int    `json:"drained"`
}

// ProxySelect switches a group to a node and, unless drain is false,
// closes the group's in-flight connections so long-lived flows (video
// streams, websockets) re-establish through the new node instead of
// riding the old one until the kernel RSTs it. Per-connection delete
// errors are tolerated — a connection may close naturally between the
// snapshot and the delete.
func (m Manager) ProxySelect(group, node string, drain bool) (ProxySelectResult, error) {
	res := ProxySelectResult{Group: group, Node: node}
	cli, err := m.mihomoClient()
	if err != nil {
		return res, err
	}
	// Only Selector groups take a manual choice — url-test/fallback/
	// load-balance pick nodes automatically and would either reject the
	// PUT or silently revert on the next health tick. Refuse up front so
	// the UI can't pretend a no-op switch happened (and so we don't drain
	// live connections for nothing).
	if proxies, perr := cli.Proxies(); perr == nil {
		if p, ok := proxies[group]; ok && p.Type != "Selector" {
			return res, fmt.Errorf("group %s is type %s — manual node selection only works on Selector groups (the section's proxy_group_type setting controls this)", group, p.Type)
		}
	}
	if err := cli.SelectProxy(group, node); err != nil {
		return res, fmt.Errorf("select %s -> %s: %w", group, node, err)
	}
	if !drain {
		return res, nil
	}
	snap, err := cli.Connections()
	if err != nil {
		// Selection already happened; a failed drain just means old flows
		// linger. Report success with zero drained.
		return res, nil
	}
	for _, conn := range snap.Connections {
		if !slices.Contains(conn.Chains, group) {
			continue
		}
		if err := cli.DeleteConnection(conn.ID); err == nil {
			res.Drained++
		}
	}
	return res, nil
}

// ProxyDelayTest runs mihomo's group latency test. The probe URL comes
// from the owning section's health-check URL when configured, else the
// conventional generate_204 endpoint.
func (m Manager) ProxyDelayTest(group string) (map[string]int, error) {
	cli, err := m.mihomoClient()
	if err != nil {
		return nil, err
	}
	c, _ := m.Load()
	testURL := "https://www.gstatic.com/generate_204"
	for _, s := range c.Sections {
		if s.ProxyGroup == group && strings.TrimSpace(s.ProxyHealthCheckURL) != "" {
			testURL = s.ProxyHealthCheckURL
			break
		}
	}
	return cli.GroupDelayTest(group, testURL, 5000)
}
