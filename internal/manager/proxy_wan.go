package manager

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/system"
)

// ResolveProxyWANs does no probing when disabled. An unresolved selection is an
// error: never replace an explicitly pinned configuration with unmarked egress.
func ResolveProxyWANs(c config.Config) (config.Config, error) {
	return resolveProxyWANs(c, system.Runner{})
}

func resolveProxyWANs(c config.Config, r commandRunner) (config.Config, error) {
	c.Mwan3.ResolvedProxyWANs = nil
	if !c.Mwan3.ProxyWANEnabled {
		return c, nil
	}
	names := uniqueStrings(c.Mwan3.ProxyWANs)
	if len(names) == 0 {
		return c, fmt.Errorf("proxy WANs enabled: select at least one mwan3 interface")
	}
	uci, err := r.Run("uci", "-q", "show", "mwan3")
	if err != nil {
		return c, fmt.Errorf("proxy WANs require configured mwan3: %w", err)
	}
	enabled := map[string]bool{}
	for _, line := range strings.Split(uci, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "'\"")
		if v == "interface" && strings.HasPrefix(k, "mwan3.") {
			enabled[strings.TrimPrefix(k, "mwan3.")] = true
		}
	}
	for _, line := range strings.Split(uci, "\n") {
		k, v, _ := strings.Cut(line, "=")
		if strings.HasSuffix(k, ".enabled") && strings.Trim(v, "'\"") == "0" {
			delete(enabled, strings.TrimSuffix(strings.TrimPrefix(k, "mwan3."), ".enabled"))
		}
	}
	nets := readNetifdDevices(r)
	rules, err := r.Run("ip", "-4", "rule", "show")
	if err != nil {
		return c, fmt.Errorf("discover proxy WAN marks: %w", err)
	}
	type markedTable struct {
		mark, mask uint32
		table      string
	}
	devices := map[string]string{}
	var marks []markedTable
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		vals := map[string]string{}
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "iif", "lookup", "fwmark":
				vals[fields[i]] = fields[i+1]
			}
		}
		table := vals["lookup"]
		if table == "" {
			continue
		}
		if dev := vals["iif"]; dev != "" {
			devices[table] = dev
		}
		parts := strings.Split(vals["fwmark"], "/")
		if len(parts) != 2 {
			continue
		}
		mark, e1 := strconv.ParseUint(parts[0], 0, 32)
		mask, e2 := strconv.ParseUint(parts[1], 0, 32)
		if e1 == nil && e2 == nil && mark != 0 && mask != 0 && mark & ^mask == 0 {
			marks = append(marks, markedTable{uint32(mark), uint32(mask), table})
		}
	}
	pureMask, err := strconv.ParseUint(c.Settings.FwMarkMask, 0, 32)
	if err != nil {
		return c, fmt.Errorf("invalid PureWRT mark mask: %w", err)
	}
	used := map[uint32]bool{}
	for _, name := range names {
		if !safeIdentRE.MatchString(name) || !enabled[name] {
			return c, fmt.Errorf("proxy WAN %q is not an enabled mwan3 interface", name)
		}
		devs := nets[name]
		if len(devs) != 1 {
			return c, fmt.Errorf("proxy WAN %q has no unique netifd device", name)
		}
		var found []markedTable
		for _, m := range marks {
			if devices[m.table] == devs[0] {
				found = append(found, m)
			}
		}
		if len(found) != 1 {
			return c, fmt.Errorf("proxy WAN %q has no unique active mwan3 mark/table for %s", name, devs[0])
		}
		m := found[0]
		if uint64(m.mask)&pureMask != 0 {
			return c, fmt.Errorf("proxy WAN %q mark mask overlaps PureWRT routing marks", name)
		}
		for _, p := range c.EnabledZapretProfiles() {
			mark, ok := parseHexMark(p.FwMark)
			if !ok || mark == 0 {
				return c, fmt.Errorf("zapret profile %q has invalid fwmark %q", p.Name, p.FwMark)
			}
			if uint64(m.mask)&mark != 0 {
				return c, fmt.Errorf("proxy WAN %q mask 0x%x overlaps zapret profile %q mark %s", name, m.mask, p.Name, p.FwMark)
			}
		}
		if used[m.mark] {
			return c, fmt.Errorf("proxy WAN %q duplicates another selected WAN mark", name)
		}
		used[m.mark] = true
		c.Mwan3.ResolvedProxyWANs = append(c.Mwan3.ResolvedProxyWANs, config.ProxyWAN{Name: name, Device: devs[0], Mark: m.mark, Mask: m.mask, Table: m.table})
	}
	return c, nil
}
