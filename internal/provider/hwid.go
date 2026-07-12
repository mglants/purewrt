package provider

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

// AutomaticHWID is the router's device identity: sha256 over stable hardware
// sources (machine-id, base MACs), hashed so raw MACs never leave the box.
// The hostname is deliberately NOT in the seed — it is mutable, and both
// consumers need stability: subscription panels key device tracking on this
// id, and the friend mesh derives peer credentials from it (a rename must
// not mint a new identity). Hostname is only the last-resort seed when no
// hardware source exists at all.
func AutomaticHWID() string {
	parts := []string{}
	for _, p := range []string{"/etc/machine-id", "/sys/class/net/br-lan/address", "/sys/class/net/eth0/address"} {
		if b, err := os.ReadFile(p); err == nil {
			v := strings.TrimSpace(string(b))
			if v != "" {
				parts = append(parts, v)
			}
		}
	}
	if len(parts) == 0 {
		if h, err := os.Hostname(); err == nil && h != "" {
			parts = append(parts, h)
		}
	}
	seed := strings.Join(parts, "|")
	if seed == "" {
		seed = "purewrt-unknown-device"
	}
	h := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("purewrt-%x", h[:12])
}

// AutomaticOSVersion returns the bare OS release ("25.12.4") for the
// x-ver-os header — the OS *name* travels separately in x-device-os.
func AutomaticOSVersion() string {
	if b, err := os.ReadFile("/etc/openwrt_release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "DISTRIB_RELEASE=") {
				return strings.Trim(strings.TrimPrefix(line, "DISTRIB_RELEASE="), "'\"")
			}
		}
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "VERSION_ID=") {
				return strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "'\"")
			}
		}
	}
	return "unknown"
}

func AutomaticDeviceModel() string {
	for _, p := range []string{"/tmp/sysinfo/model", "/proc/device-tree/model"} {
		if b, err := os.ReadFile(p); err == nil {
			v := strings.Trim(strings.TrimSpace(string(b)), "\x00")
			if v != "" {
				return v
			}
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "OpenWrt Router"
}

func (o DownloadOptions) EffectiveHWID() string       { return AutomaticHWID() }
func (o DownloadOptions) EffectiveDeviceName() string { return AutomaticDeviceModel() }
