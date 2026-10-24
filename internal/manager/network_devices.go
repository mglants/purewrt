package manager

import (
	"encoding/json"
	"strings"
)

type netifdDump struct {
	Interface []struct {
		Interface string `json:"interface"`
		Device    string `json:"device"`
		L3Device  string `json:"l3_device"`
	} `json:"interface"`
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
