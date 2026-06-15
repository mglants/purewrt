package manager

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/system"
)

type netifdDump struct {
	Interface []struct {
		Interface string `json:"interface"`
		Device    string `json:"device"`
		L3Device  string `json:"l3_device"`
	} `json:"interface"`
}

func ResolveZapretProfileInterfaces(c config.Config) config.Config {
	r := system.Runner{}
	return resolveZapretProfileInterfacesWithRunner(c, r)
}

func resolveZapretProfileInterfacesWithRunner(c config.Config, r commandRunner) config.Config {
	nets := readNetifdDevices(r)
	members := readMwan3Members(r)
	for i := range c.ZapretProfiles {
		p := c.NormalizeZapretProfile(c.ZapretProfiles[i])
		resolved := resolveZapretInterfaces(p, nets, members)
		if len(resolved) > 0 {
			p.Interfaces = resolved
		}
		c.ZapretProfiles[i] = p
	}
	return c
}

func resolveZapretInterfaces(p config.ZapretProfile, nets map[string][]string, members []string) []string {
	if p.Device != "" {
		return uniqueStrings([]string{p.Device})
	}
	if len(p.Interfaces) > 0 && p.InterfaceMode == "single" {
		return uniqueStrings(p.Interfaces)
	}
	switch p.InterfaceMode {
	case "mwan3_members":
		if len(members) > 0 {
			return members
		}
		if p.Network == "auto" {
			return wanLikeDevices(nets)
		}
	case "network":
		if p.Network != "" && p.Network != "auto" {
			return uniqueStrings(nets[p.Network])
		}
		if p.Network == "auto" {
			return wanLikeDevices(nets)
		}
	}
	if len(p.Interfaces) > 0 {
		return uniqueStrings(p.Interfaces)
	}
	return nil
}

func readNetifdDevices(r commandRunner) map[string][]string {
	out, err := r.Run("ubus", "call", "network.interface", "dump")
	if err != nil {
		return nil
	}
	var dump netifdDump
	if err := json.Unmarshal([]byte(out), &dump); err != nil {
		return nil
	}
	res := map[string][]string{}
	for _, iface := range dump.Interface {
		dev := iface.L3Device
		if dev == "" {
			dev = iface.Device
		}
		if iface.Interface != "" && dev != "" {
			res[iface.Interface] = append(res[iface.Interface], dev)
		}
	}
	return res
}

func readMwan3Members(r commandRunner) []string {
	out, err := r.Run("uci", "-q", "show", "mwan3")
	if err != nil {
		return nil
	}
	networks := []string{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ".interface=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		v := strings.Trim(parts[1], "'\"")
		if v != "" {
			networks = append(networks, v)
		}
	}
	nets := readNetifdDevices(r)
	devices := []string{}
	for _, n := range networks {
		if ds := nets[n]; len(ds) > 0 {
			devices = append(devices, ds...)
		} else {
			devices = append(devices, n)
		}
	}
	return uniqueStrings(devices)
}

func wanLikeDevices(nets map[string][]string) []string {
	devices := []string{}
	keys := make([]string, 0, len(nets))
	for k := range nets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.HasPrefix(k, "wan") {
			devices = append(devices, nets[k]...)
		}
	}
	return uniqueStrings(devices)
}

func uniqueStrings(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
