package generator

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/logging"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/rules"
	"github.com/purewrt/purewrt/internal/system"
)

type generationFingerprint struct {
	Version     int                        `json:"version"`
	Hash        string                     `json:"hash"`
	Groups      map[string]string          `json:"groups,omitempty"`
	GeneratedAt time.Time                  `json:"generated_at"`
	Inputs      generationFingerprintInput `json:"inputs"`
}

type GenerationGroups struct {
	Mihomo        bool
	OpenWrtBundle bool
	Firewall      bool
	Mwan3         bool
	Zapret        bool
	Policy        bool
	Mesh          bool
}

func (g GenerationGroups) Any() bool {
	return g.Mihomo || g.OpenWrtBundle || g.Firewall || g.Mwan3 || g.Zapret || g.Policy || g.Mesh
}
func (GenerationGroups) All() GenerationGroups {
	return GenerationGroups{Mihomo: true, OpenWrtBundle: true, Firewall: true, Mwan3: true, Zapret: true, Policy: true, Mesh: true}
}

type generationGroupCacheStatus struct {
	Name   string
	Status string
	Reason string
}

type generationFingerprintInput struct {
	CacheVersion     int                     `json:"cache_version"`
	Settings         config.Settings         `json:"settings"`
	DNS              config.DNS              `json:"dns"`
	Mwan3            config.Mwan3            `json:"mwan3"`
	Sections         []config.Section        `json:"sections"`
	RuleProvider     []ruleProviderFPEntry   `json:"rule_providers"`
	Bypass           config.Bypass           `json:"bypass"`
	VPNs             []config.VPN            `json:"vpns"`
	Devices          []config.Device         `json:"devices"`
	Zapret           []config.ZapretProfile  `json:"zapret"`
	ZapretStrategies []config.ZapretStrategy `json:"zapret_strategies"`
	OONI             config.OONI             `json:"ooni"`
	Mesh             config.Mesh             `json:"mesh"`
	MeshPeers        []meshPeerFPEntry       `json:"mesh_peers"`
}

// meshPeerFPEntry is the fingerprint-material subset of a MeshPeer:
// liveness fields (LastSeen/LastError) are deliberately excluded so a
// mesh-sync heartbeat can't dirty the generation cache.
type meshPeerFPEntry struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	OverlayIP   string `json:"overlay_ip"`
	ListenPort  int    `json:"listen_port"`
	ExitOffered bool   `json:"exit_offered"`
}

func meshPeerFPEntries(c config.Config) []meshPeerFPEntry {
	out := make([]meshPeerFPEntry, 0, len(c.MeshPeers))
	for _, p := range c.MeshPeers {
		out = append(out, meshPeerFPEntry{Name: p.Name, Enabled: p.Enabled, OverlayIP: p.OverlayIP, ListenPort: p.ListenPort, ExitOffered: p.ExitOffered})
	}
	return out
}

type ruleProviderFPEntry struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Format      string `json:"format"`
	Path        string `json:"path"`
	Checksum    string `json:"checksum"`
	Section     string `json:"section"`
	Priority    int    `json:"priority"`
	RouteAction string `json:"route_action"`
}

type openWrtSectionFPEntry struct {
	Name        string
	Enabled     bool
	Action      string
	TPROXYPort  int
	IPv4Enabled bool
	IPv6Enabled bool
	UDPMode     string
	Priority    int
	Mwan3Policy string
	VPNs        []string
	SourceCIDR4 []string
	SourceCIDR6 []string
}

// fingerprintPath returns where the generation fingerprint lives. We keep
// it under RuntimeDir (typically /tmp/purewrt, tmpfs) so it's tied to
// kernel-state lifetime: a reboot wipes both the runtime nft/dnsmasq
// outputs and the fingerprint together, which means the next apply sees
// "fingerprint missing" and re-applies the full ruleset automatically —
// no need to special-case a reboot in the apply path.
//
// If a fingerprint at the legacy persistent location still exists (older
// installs that wrote it next to mihomo.yaml in /etc/purewrt/generated),
// we deliberately ignore it and rebuild fresh: that file represents a
// pre-reboot world we can't trust anymore.
func fingerprintPath(c config.Config) string {
	runtimeDir := c.RuntimeDir()
	if runtimeDir == "" {
		runtimeDir = "/tmp/purewrt"
	}
	return filepath.Join(runtimeDir, "generated", "purewrt.generation.fingerprint.json")
}

func currentGenerationFingerprint(c config.Config) (generationFingerprint, error) {
	log := logging.New(c.Settings.LogLevel)
	defer log.DebugTimer("generate: fingerprint")()
	c.Settings.GeneratedDir = ""
	c.Settings.RuntimeDir = ""
	c.Settings.MihomoConfig = ""
	c.Settings.DNSMasqIncludeDir = ""
	in := generationFingerprintInput{CacheVersion: rules.ArtifactVersion, Settings: c.Settings, DNS: c.DNS, Mwan3: c.Mwan3, Sections: c.Sections, Bypass: c.Bypass, VPNs: c.VPNs, Devices: c.Devices, Zapret: c.ZapretProfiles, ZapretStrategies: c.ZapretStrategies, OONI: c.OONI, Mesh: c.Mesh, MeshPeers: meshPeerFPEntries(c)}
	// Per-provider checksum reads are the most expensive part of fingerprint
	// — each call reads the file and SHA-256s it. Track aggregate size +
	// wall time so we can see if this stage alone explains a slow apply.
	checksumStart := time.Now()
	var checksumBytes int64
	for _, rp := range c.RuleProviders {
		if rp.Path != "" {
			if st, err := os.Stat(rp.Path); err == nil {
				checksumBytes += st.Size()
			}
		}
		in.RuleProvider = append(in.RuleProvider, ruleProviderFPEntry{Name: rp.Name, Enabled: rp.Enabled, Format: rp.Format, Path: rp.Path, Checksum: provider.ArtifactChecksum(rp.Path), Section: rp.Section, Priority: rp.Priority, RouteAction: rp.RouteAction})
	}
	log.Debug("generate: fingerprint checksums providers=%d bytes=%d took=%v", len(c.RuleProviders), checksumBytes, time.Since(checksumStart))
	b, err := json.Marshal(in)
	if err != nil {
		return generationFingerprint{}, err
	}
	h := sha256.Sum256(b)
	groups, err := generationGroupHashes(c, in)
	if err != nil {
		return generationFingerprint{}, err
	}
	return generationFingerprint{Version: 3, Hash: fmt.Sprintf("%x", h[:]), Groups: groups, GeneratedAt: time.Now().UTC(), Inputs: in}, nil
}

func generationGroupHashes(c config.Config, in generationFingerprintInput) (map[string]string, error) {
	openWrtSections := make([]openWrtSectionFPEntry, 0, len(c.Sections))
	for _, s := range c.Sections {
		openWrtSections = append(openWrtSections, openWrtSectionFPEntry{Name: s.Name, Enabled: s.Enabled, Action: s.Action, TPROXYPort: s.TPROXYPort, IPv4Enabled: s.IPv4Enabled, IPv6Enabled: s.IPv6Enabled, UDPMode: s.UDPMode, Priority: s.Priority, Mwan3Policy: s.Mwan3Policy, VPNs: s.VPNs, SourceCIDR4: s.SourceCIDR4, SourceCIDR6: s.SourceCIDR6})
	}
	proxyProviders := c.ProxyProviders
	groups := map[string]any{
		"mihomo":         map[string]any{"settings": in.Settings, "dns": in.DNS, "sections": in.Sections, "proxy_providers": proxyProviders, "rule_providers": in.RuleProvider, "vpns": in.VPNs, "mesh": in.Mesh, "mesh_peers": in.MeshPeers},
		"openwrt_bundle": map[string]any{"settings": in.Settings, "dns": in.DNS, "sections": openWrtSections, "rule_providers": in.RuleProvider, "bypass": in.Bypass, "vpns": in.VPNs, "devices": in.Devices, "zapret": in.Zapret, "ooni": in.OONI},
		"firewall":       map[string]any{"dns_hijack": c.DNS.HijackLANDNS, "lan_source_zones": c.Settings.LANSourceZones, "fwmark": c.Settings.FwMark, "fwmark_mask": c.Settings.FwMarkMask, "mesh": in.Mesh},
		"mwan3":          map[string]any{"mwan3": in.Mwan3, "proxy_providers": proxyProviders},
		"zapret":         map[string]any{"zapret": in.Zapret, "sections": openWrtSections},
		"policy":         map[string]any{"settings": in.Settings, "vpns": in.VPNs, "devices": in.Devices, "sections": openWrtSections},
		"mesh":           map[string]any{"mesh": in.Mesh, "mesh_peers": in.MeshPeers},
	}
	out := map[string]string{}
	for name, v := range groups {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		out[name] = fmt.Sprintf("%x", h[:])
	}
	return out, nil
}

func generationDirtyGroups(c config.Config, fp generationFingerprint, checkPaths GeneratedPaths, force bool) (GenerationGroups, string) {
	if force {
		return GenerationGroups{}.All(), "forced"
	}
	b, err := os.ReadFile(fingerprintPath(c))
	if err != nil {
		if os.IsNotExist(err) {
			return GenerationGroups{}.All(), "fingerprint missing"
		}
		return GenerationGroups{}.All(), "fingerprint read failed: " + err.Error()
	}
	var old generationFingerprint
	if err := json.Unmarshal(b, &old); err != nil {
		return GenerationGroups{}.All(), "fingerprint invalid: " + err.Error()
	}
	if old.Version != fp.Version || len(old.Groups) == 0 {
		return GenerationGroups{}.All(), fmt.Sprintf("fingerprint version changed old=%d new=%d", old.Version, fp.Version)
	}
	g := GenerationGroups{}
	if old.Groups["mihomo"] != fp.Groups["mihomo"] || !pathComplete(checkPaths.MihomoConfig) {
		g.Mihomo = true
	}
	if old.Groups["openwrt_bundle"] != fp.Groups["openwrt_bundle"] || !pathComplete(checkPaths.NFTFile) || !pathComplete(checkPaths.NFTSetsFile) || !dirComplete(dnsmasqFragmentDir(checkPaths)) {
		g.OpenWrtBundle = true
	}
	if old.Groups["firewall"] != fp.Groups["firewall"] || (len(FirewallRules(c)) > 0 && !pathComplete(checkPaths.FirewallFile)) {
		g.Firewall = true
	}
	if old.Groups["mwan3"] != fp.Groups["mwan3"] || (len(Mwan3Rules(c)) > 0 && !pathComplete(checkPaths.Mwan3File)) {
		g.Mwan3 = true
	}
	if old.Groups["zapret"] != fp.Groups["zapret"] || !pathComplete(checkPaths.ZapretEnv) {
		g.Zapret = true
	}
	if old.Groups["policy"] != fp.Groups["policy"] {
		g.Policy = true
	}
	if old.Groups["mesh"] != fp.Groups["mesh"] || (c.MeshActive() && !pathComplete(checkPaths.EasytierConfig)) {
		g.Mesh = true
	}
	if !g.Any() {
		return g, "all groups unchanged"
	}
	return g, "one or more groups changed or outputs missing"
}

func generationGroupCacheStatuses(c config.Config, fp generationFingerprint, paths GeneratedPaths) []generationGroupCacheStatus {
	old, reason, ok := readPreviousGenerationFingerprint(c, fp)
	if !ok {
		return allGenerationGroupCacheStatuses("miss", reason)
	}
	var out []generationGroupCacheStatus
	for _, name := range generationGroupNames() {
		status := generationGroupCacheStatus{Name: name, Status: "hit", Reason: "unchanged"}
		if old.Groups[name] != fp.Groups[name] {
			status.Status = "miss"
			status.Reason = "hash changed"
		} else if reason := generationGroupOutputMissingReason(c, paths, name); reason != "" {
			status.Status = "miss"
			status.Reason = reason
		}
		out = append(out, status)
	}
	return out
}

func readPreviousGenerationFingerprint(c config.Config, fp generationFingerprint) (generationFingerprint, string, bool) {
	b, err := os.ReadFile(fingerprintPath(c))
	if err != nil {
		if os.IsNotExist(err) {
			return generationFingerprint{}, "fingerprint missing", false
		}
		return generationFingerprint{}, "fingerprint read failed: " + err.Error(), false
	}
	var old generationFingerprint
	if err := json.Unmarshal(b, &old); err != nil {
		return generationFingerprint{}, "fingerprint invalid: " + err.Error(), false
	}
	if old.Version != fp.Version || len(old.Groups) == 0 {
		return generationFingerprint{}, fmt.Sprintf("fingerprint version changed old=%d new=%d", old.Version, fp.Version), false
	}
	return old, "", true
}

func allGenerationGroupCacheStatuses(status, reason string) []generationGroupCacheStatus {
	out := make([]generationGroupCacheStatus, 0, len(generationGroupNames()))
	for _, name := range generationGroupNames() {
		out = append(out, generationGroupCacheStatus{Name: name, Status: status, Reason: reason})
	}
	return out
}

func generationGroupNames() []string {
	return []string{"mihomo", "openwrt_bundle", "firewall", "mwan3", "zapret", "policy", "mesh"}
}

func generationGroupOutputMissingReason(c config.Config, paths GeneratedPaths, name string) string {
	switch name {
	case "mihomo":
		return missingPathReason(paths.MihomoConfig, "mihomo config missing")
	case "openwrt_bundle":
		for _, check := range []struct {
			path   string
			reason string
		}{{paths.NFTFile, "nft main missing"}, {paths.NFTSetsFile, "nft sets missing"}} {
			if reason := missingPathReason(check.path, check.reason); reason != "" {
				return reason
			}
		}
		if !dirComplete(dnsmasqFragmentDir(paths)) {
			return "dnsmasq fragment dir missing"
		}
	case "firewall":
		if len(FirewallRules(c)) > 0 {
			return missingPathReason(paths.FirewallFile, "firewall output missing")
		}
	case "mwan3":
		if len(Mwan3Rules(c)) > 0 {
			return missingPathReason(paths.Mwan3File, "mwan3 output missing")
		}
	case "zapret":
		return missingPathReason(paths.ZapretEnv, "zapret env missing")
	case "mesh":
		if c.MeshActive() {
			return missingPathReason(paths.EasytierConfig, "easytier config missing")
		}
	}
	return ""
}

func missingPathReason(path, reason string) string {
	if !pathComplete(path) {
		return reason
	}
	return ""
}

func pathComplete(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirComplete(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func generationFingerprintState(c config.Config, fp generationFingerprint) (bool, string) {
	b, err := os.ReadFile(fingerprintPath(c))
	if err != nil {
		if os.IsNotExist(err) {
			return false, "fingerprint missing"
		}
		return false, "fingerprint read failed: " + err.Error()
	}
	var old generationFingerprint
	if err := json.Unmarshal(b, &old); err != nil {
		return false, "fingerprint invalid: " + err.Error()
	}
	if old.Version != fp.Version {
		return false, fmt.Sprintf("fingerprint version changed old=%d new=%d", old.Version, fp.Version)
	}
	if old.Hash != fp.Hash {
		return false, "fingerprint hash changed"
	}
	return true, "fingerprint unchanged"
}

func writeGenerationFingerprint(c config.Config, fp generationFingerprint) error {
	b, err := json.MarshalIndent(fp, "", "  ")
	if err != nil {
		return err
	}
	_, err = system.WriteIfChanged(fingerprintPath(c), append(b, '\n'), 0600)
	return err
}
