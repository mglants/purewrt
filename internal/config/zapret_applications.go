package config

import (
	"fmt"
	"regexp"
	"strings"
)

// ZapretApplication is the persisted application-level configuration. Each
// assignment is device=candidate; runtime profiles and queues are derived.
type ZapretApplication struct {
	Name        string
	Enabled     bool
	Assignments []string
}

var zapretDeviceRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
var zapretApplicationRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,47}$`)

func (c *Config) CompileZapretApplications(list ZapretCandidateList) error {
	c.ZapretProfiles = nil
	c.ZapretStrategies = nil
	names := map[string]bool{}
	instances := map[string][]string{}
	candidates := map[string]bool{}
	for _, v := range list.Candidates {
		candidates[v.Name] = true
	}
	for _, app := range c.ZapretApplications {
		if !zapretApplicationRE.MatchString(app.Name) || names[app.Name] {
			return fmt.Errorf("invalid or duplicate Zapret application %q", app.Name)
		}
		names[app.Name] = true
		if !app.Enabled {
			continue
		}
		if len(app.Assignments) == 0 {
			return fmt.Errorf("Zapret application %s has no WAN assignments", app.Name)
		}
		devices := map[string]bool{}
		grouped := map[string]int{}
		for _, raw := range app.Assignments {
			device, candidate, ok := strings.Cut(raw, "=")
			if !ok || !zapretDeviceRE.MatchString(device) || device == "lo" || devices[device] {
				return fmt.Errorf("Zapret application %s has invalid or duplicate WAN assignment %q", app.Name, raw)
			}
			if !candidates[candidate] {
				return fmt.Errorf("Zapret application %s references missing library strategy %s", app.Name, candidate)
			}
			devices[device] = true
			if index, ok := grouped[candidate]; ok {
				c.ZapretProfiles[index].Interfaces = append(c.ZapretProfiles[index].Interfaces, device)
				continue
			}
			if len(c.ZapretStrategies) >= 255 {
				return fmt.Errorf("Zapret supports at most 255 application/WAN strategy combinations")
			}
			grouped[candidate] = len(c.ZapretProfiles)
			name := fmt.Sprintf("%s_w%d", app.Name, len(instances[app.Name])+1)
			instances[app.Name] = append(instances[app.Name], name)
			c.ZapretProfiles = append(c.ZapretProfiles, ZapretProfile{Name: name, Enabled: true, Interfaces: []string{device}})
			c.ZapretStrategies = append(c.ZapretStrategies, ZapretStrategy{Name: name, Enabled: true, Profile: name, Candidate: candidate, QueueNum: ZapretQueueBase, SelectorMark: uint32(len(c.ZapretStrategies)+1) << 16})
		}
	}
	for i := range c.Sections {
		sec := &c.Sections[i]
		if sec.ZapretApplicationNames == nil && len(sec.ZapretStrategies) > 0 {
			sec.ZapretApplicationNames = append([]string{}, sec.ZapretStrategies...)
		}
		sec.ZapretStrategies = nil
		for _, name := range sec.ZapretApplicationNames {
			if sec.Enabled && sec.Action == "zapret" && len(instances[name]) == 0 {
				return fmt.Errorf("section %s references missing or disabled Zapret application %s", sec.Name, name)
			}
			sec.ZapretStrategies = append(sec.ZapretStrategies, instances[name]...)
		}
	}
	return c.ResolveZapretReferences(list)
}
