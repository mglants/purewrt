package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/purewrt/purewrt/internal/mesh"
	"github.com/purewrt/purewrt/internal/system"
)

// DefaultGeoSources returns canonical MetaCubeX URLs for the three geo
// files. Used as documentation for the UCI options and as the auto-
// seed source when a user adds their first geo-backed rule provider
// (see seedGeoDefaults). Users wanting a mirror can override per-target.
//
// Lives in this package (not internal/manager) so write.go can call it
// without circular-import gymnastics; internal/manager re-exports a
// thin proxy for callers that already use it from there.
func DefaultGeoSources() map[string]string {
	return map[string]string{
		"geoip":   "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat",
		"geosite": "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat",
		"mmdb":    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb",
	}
}

// Serialize renders the full Config back to UCI text — the canonical
// normalization pass. Exported (in addition to Save) so the export/import
// feature can produce a portable config bundle without touching disk.
func Serialize(c Config) []byte {
	var b bytes.Buffer
	// libuci section ids share one namespace per file across ALL types — a
	// duplicate id under a different type is a hard parse error that bricks
	// every uci consumer. Reserve the ids of every unconditionally-named
	// section up front (fixed singletons, routing sections whose parser
	// reads the id only, device sections), then let sectionHeader hand out
	// the rest first-come-first-served with anonymous + `option name`
	// fallback for the losers.
	// Type prefixes make cross-type collisions structurally impossible; the
	// map still guards same-type duplicates and the fixed singleton ids.
	seen := map[string]bool{
		"settings": true, "dns": true, "mwan3": true, "ooni": true, "bypass": true, "mesh": true,
	}
	if c.Bypass.Name != "" {
		seen[c.Bypass.Name] = true
	}
	writeMain(&b, c.Settings)
	writeDNS(&b, c.DNS)
	writeMwan3(&b, c.Mwan3)
	for _, p := range c.ZapretProfiles {
		writeZapretProfile(&b, p, seen)
	}
	for _, s := range c.ZapretStrategies {
		writeZapretStrategy(&b, s, seen)
	}
	for _, v := range c.VPNs {
		writeVPN(&b, v, seen)
	}
	for _, d := range c.Devices {
		writeDevice(&b, d)
	}
	for _, s := range c.Sections {
		writeSection(&b, s, seen)
	}
	for _, s := range c.Subscriptions {
		writeSubscription(&b, s, seen)
	}
	for _, p := range c.ProxyProviders {
		writeProxyProvider(&b, p, seen)
	}
	for _, p := range c.RuleProviders {
		writeRuleProvider(&b, p, seen)
	}
	writeBypass(&b, c.Bypass)
	writeOONI(&b, c.OONI)
	writeMesh(&b, c.Mesh)
	for _, p := range c.MeshPeers {
		writeMeshPeer(&b, p)
	}
	return b.Bytes()
}

func Save(path string, c Config) error {
	return system.AtomicWrite(path, Serialize(c), 0600)
}

// Backup copies path to <path>.purewrt.bak before a Save overwrites it.
// Missing source is fine (fresh install). Every caller treats the backup as
// best-effort and discards the error, so a real I/O failure is warned here —
// once, centrally — instead of vanishing at eight call sites: it means no
// rollback copy will exist for the save that follows.
func Backup(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		fmt.Fprintf(os.Stderr, "warning: config backup of %s failed: %v\n", path, err)
		return "", err
	}
	backup := filepath.Join(filepath.Dir(path), filepath.Base(path)+".purewrt.bak")
	if err := system.AtomicWrite(backup, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: config backup to %s failed: %v\n", backup, err)
		return backup, err
	}
	return backup, nil
}

func EnsureDefaults(c Config) Config {
	defaults := Default()
	seen := map[string]bool{}
	for _, s := range c.Sections {
		seen[s.Name] = true
	}
	for _, s := range defaults.Sections {
		if !seen[s.Name] {
			c.Sections = append(c.Sections, s)
		}
	}
	sort.SliceStable(c.Sections, func(i, j int) bool { return c.Sections[i].Priority < c.Sections[j].Priority })
	return c
}

func UpsertSubscription(c Config, s Subscription) Config {
	for i := range c.Subscriptions {
		if c.Subscriptions[i].Name == s.Name || c.Subscriptions[i].URL == s.URL {
			c.Subscriptions[i] = s
			return c
		}
	}
	c.Subscriptions = append(c.Subscriptions, s)
	return c
}

func UpsertProxyProvider(c Config, p ProxyProvider) Config {
	for i := range c.ProxyProviders {
		if c.ProxyProviders[i].Name == p.Name || (p.URL != "" && c.ProxyProviders[i].URL == p.URL) {
			old := c.ProxyProviders[i]
			if old.Mwan3Policy != "" {
				p.Mwan3Policy = old.Mwan3Policy
			}
			c.ProxyProviders[i] = p
			return c
		}
	}
	c.ProxyProviders = append(c.ProxyProviders, p)
	return c
}

func UpsertRuleProvider(c Config, p RuleProvider) Config {
	for i := range c.RuleProviders {
		if c.RuleProviders[i].Name == p.Name || (p.URL != "" && c.RuleProviders[i].URL == p.URL) {
			old := c.RuleProviders[i]
			if old.UserOverriddenSection {
				p.Section = old.Section
				p.UserOverriddenSection = true
			}
			if old.UserOverriddenAction {
				p.RouteAction = old.RouteAction
				p.UserOverriddenAction = true
			}
			if old.Priority != 0 {
				p.Priority = old.Priority
			}
			if !old.Enabled {
				p.Enabled = false
			}
			c.RuleProviders[i] = p
			c = seedGeoDefaults(c, p)
			return c
		}
	}
	c.RuleProviders = append(c.RuleProviders, p)
	c = seedGeoDefaults(c, p)
	return c
}

// seedGeoDefaults pre-fills Settings.GeoRefresh{GeoIP,GeoSite,MMDB}URL
// from the canonical MetaCubeX URLs when a geo-backed rule provider is
// added and the corresponding URL is still empty. Without this the
// next `geo-refresh` would fall back to the same defaults silently —
// seeding makes the values visible in the Settings page so users can
// edit them to point at a mirror without first running geo-refresh.
//
// We don't un-seed when a provider is later deleted: the URL becomes
// the user's value at that point, deleting the provider is not a
// reason to discard their configured download source.
func seedGeoDefaults(c Config, p RuleProvider) Config {
	d := DefaultGeoSources()
	switch p.Format {
	case "geosite":
		if c.Settings.GeoRefreshGeoSiteURL == "" {
			c.Settings.GeoRefreshGeoSiteURL = d["geosite"]
		}
	case "geoip":
		if c.Settings.GeoRefreshGeoIPURL == "" {
			c.Settings.GeoRefreshGeoIPURL = d["geoip"]
		}
		// MMDB isn't load-bearing for the nftset-expansion path but the
		// existing geo-refresh cron downloads it anyway when configured,
		// and a future GeoIP rule provider that uses MMDB benefits.
		if c.Settings.GeoRefreshMMDBURL == "" {
			c.Settings.GeoRefreshMMDBURL = d["mmdb"]
		}
	}
	return c
}

func UpsertSectionProxyGroup(c Config, s Section) Config {
	for i := range c.Sections {
		if c.Sections[i].Name == s.Name {
			if c.Sections[i].UserOverriddenProxyGroup {
				return c
			}
			if s.ProxyGroup != "" {
				c.Sections[i].ProxyGroup = s.ProxyGroup
			}
			if s.ProxyGroupType != "" {
				c.Sections[i].ProxyGroupType = s.ProxyGroupType
			}
			c.Sections[i].ProxyFilter = s.ProxyFilter
			c.Sections[i].ProxyExcludeFilter = s.ProxyExcludeFilter
			if s.ProxyStrategy != "" {
				c.Sections[i].ProxyStrategy = s.ProxyStrategy
			}
			c.Sections[i].ProxyHealthCheckURL = s.ProxyHealthCheckURL
			c.Sections[i].ProxyHealthCheckInterval = s.ProxyHealthCheckInterval
			return c
		}
	}
	if s.Name != "" {
		if s.Action == "" {
			s.Action = "proxy"
		}
		if s.ProxyGroup == "" {
			s.ProxyGroup = TitleASCII(s.Name)
		}
		if s.ProxyGroupType == "" {
			s.ProxyGroupType = "url-test"
		}
		if s.ProxyStrategy == "" {
			s.ProxyStrategy = "sticky-sessions"
		}
		c.Sections = append(c.Sections, s)
	}
	return c
}

func q(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }

// uciIDRE matches names usable as UCI section identifiers (libuci rejects
// anything outside [A-Za-z0-9_]).
var uciIDRE = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// Per-type section-id prefixes. libuci section ids share ONE namespace per
// config file across all types, so the display name is carved into a
// type-scoped id (`rp_youtube`, `sec_youtube`, `zs_youtube` can coexist —
// all displaying as "youtube"). The parser strips the prefix back off
// (idName in uci.go); devices already follow this pattern with dev_.
const (
	prefixSection       = "sec_"
	prefixSubscription  = "sub_"
	prefixProxyProvider = "pp_"
	prefixRuleProvider  = "rp_"
	prefixVPN           = "vpn_"
	prefixZapretProfile = "zp_"
	prefixZapretStrat   = "zs_"
)

// sectionHeader writes `config <typ> '<prefix><name>'` when the name is a
// valid UCI identifier — the type-prefixed section id carries the name and
// the parser recovers it by stripping the prefix — and reports false: no
// name option needed. Names with dots/dashes can't be section ids, so those
// keep the legacy anonymous header and report true so the caller emits
// `option name`. Repeated same-type names also fall back to anonymous:
// libuci merges duplicate section ids last-wins, which would silently drop
// all but one entry (our validate rejects duplicates, but Serialize must
// never lose data on its own).
func sectionHeader(b *bytes.Buffer, typ, prefix, name string, seen map[string]bool) (needNameOpt bool) {
	id := prefix + name
	if !seen[id] && uciIDRE.MatchString(name) {
		seen[id] = true
		fmt.Fprintf(b, "config %s %s\n", typ, q(id))
		return false
	}
	seen[id] = true
	fmt.Fprintln(b, "config "+typ)
	return true
}

func yn(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
func opt(b *bytes.Buffer, key, val string) { fmt.Fprintf(b, "    option %s %s\n", key, q(val)) }
func optNonEmpty(b *bytes.Buffer, key, val string) {
	if val != "" {
		opt(b, key, val)
	}
}
func optb(b *bytes.Buffer, key string, val bool)    { opt(b, key, yn(val)) }
func opti(b *bytes.Buffer, key string, val int)     { opt(b, key, fmt.Sprintf("%d", val)) }
func opti64(b *bytes.Buffer, key string, val int64) { opt(b, key, fmt.Sprintf("%d", val)) }
func listv(b *bytes.Buffer, key string, vals []string) {
	for _, v := range vals {
		fmt.Fprintf(b, "    list %s %s\n", key, q(v))
	}
}

func writeMain(b *bytes.Buffer, s Settings) {
	fmt.Fprintln(b, "config main 'settings'")
	opti(b, "config_version", s.ConfigVersion)
	optb(b, "enabled", s.Enabled)
	opt(b, "workdir", s.Workdir)
	opt(b, "runtime_dir", s.RuntimeDir)
	optNonEmpty(b, "generated_dir", s.GeneratedDir)
	optNonEmpty(b, "dnsmasq_include_dir", s.DNSMasqIncludeDir)
	opt(b, "mihomo_bin", s.MihomoBin)
	optNonEmpty(b, "mihomo_config", s.MihomoConfig)
	optb(b, "mihomo_allow_lan", s.MihomoAllowLAN)
	opt(b, "external_controller", s.ExternalController)
	opt(b, "secret", s.Secret)
	opt(b, "dns_backend", s.DNSBackend)
	opt(b, "firewall_backend", s.FirewallBackend)
	opt(b, "fwmark", s.FwMark)
	opt(b, "fwmark_mask", s.FwMarkMask)
	opt(b, "route_table", s.RouteTable)
	opt(b, "ip_rule_priority", s.IPRulePriority)
	optb(b, "ipv6", s.IPv6)
	optb(b, "fake_ip", s.FakeIP)
	optb(b, "sniffer", s.Sniffer)
	opt(b, "dns_listen", s.DNSListen)
	optb(b, "auto_reload", s.AutoReload)
	optb(b, "safe_apply", s.SafeApply)
	optb(b, "rollback_on_fail", s.RollbackOnFail)
	opti64(b, "apply_backup_max_bytes", s.ApplyBackupMaxBytes)
	opt(b, "mihomo_channel", s.MihomoChannel)
	opt(b, "mihomo_release_api", s.MihomoReleaseAPI)
	opt(b, "mihomo_stable_release_api", s.MihomoStableReleaseAPI)
	optb(b, "mihomo_mixin_enabled", s.MihomoMixinEnabled)
	optb(b, "mihomo_auto_update_enabled", s.MihomoAutoUpdateEnabled)
	opt(b, "mihomo_auto_update_cron", s.MihomoAutoUpdateCron)
	optb(b, "net_check_enabled", s.NetCheckEnabled)
	optNonEmpty(b, "net_check_cron", s.NetCheckCron)
	opti(b, "net_check_bytes", s.NetCheckBytes)
	opt(b, "mihomo_version", s.MihomoVersion)
	opt(b, "mihomo_arch", s.MihomoArch)
	opt(b, "mihomo_asset_url", s.MihomoAssetURL)
	opt(b, "mihomo_sha256_url", s.MihomoSHA256URL)
	optb(b, "mihomo_geodata_enabled", s.MihomoGeodataEnabled)
	optb(b, "update_via_proxy", s.UpdateViaProxy)
	optb(b, "suppress_hwid", s.SuppressHWID)
	opt(b, "update_proxy_url", s.UpdateProxyURL)
	opti(b, "update_concurrency", s.UpdateConcurrency)
	optb(b, "auto_update_enabled", s.AutoUpdateEnabled)
	opt(b, "auto_update_cron", s.AutoUpdateCron)
	optb(b, "reload_after_update", s.ReloadAfterUpdate)
	opti(b, "backup_retention", s.BackupRetention)
	optb(b, "background_updates", s.BackgroundUpdates)
	opti(b, "boot_update_delay", s.BootUpdateDelay)
	opti(b, "update_nice", s.UpdateNice)
	opti(b, "update_ionice_class", s.UpdateIONiceClass)
	opti(b, "update_ionice_level", s.UpdateIONiceLevel)
	optb(b, "dashboard_enabled", s.DashboardEnabled)
	opt(b, "dashboard_listen", s.DashboardListen)
	opt(b, "dashboard_path", s.DashboardPath)
	opt(b, "dashboard_url", s.DashboardURL)
	optNonEmpty(b, "default_lists_base_url", s.DefaultListsBaseURL)
	opt(b, "dashboard_name", s.DashboardName)
	opt(b, "resource_profile", s.ResourceProfile)
	opt(b, "cache_mode", s.CacheMode)
	opt(b, "cache_dir", s.CacheDir)
	opt(b, "artifact_cache_mode", s.ArtifactCacheMode)
	opti64(b, "artifact_cache_max_bytes", s.ArtifactCacheMaxBytes)
	opti(b, "artifact_cache_max_entries", s.ArtifactCacheMaxEntries)
	opt(b, "rule_dedup_mode", s.RuleDedupMode)
	opt(b, "log_level", s.LogLevel)
	optNonEmpty(b, "log_format", s.LogFormat)
	listv(b, "api_listen", s.APIListen)
	optNonEmpty(b, "notify_url", s.NotifyURL)
	optNonEmpty(b, "notify_format", s.NotifyFormat)
	listv(b, "notify_on", s.NotifyOn)
	optb(b, "metrics_enabled", s.MetricsEnabled)
	optNonEmpty(b, "geo_refresh_geoip_url", s.GeoRefreshGeoIPURL)
	optNonEmpty(b, "geo_refresh_geoip_sha", s.GeoRefreshGeoIPSHA)
	optNonEmpty(b, "geo_refresh_geosite_url", s.GeoRefreshGeoSiteURL)
	optNonEmpty(b, "geo_refresh_geosite_sha", s.GeoRefreshGeoSiteSHA)
	optNonEmpty(b, "geo_refresh_mmdb_url", s.GeoRefreshMMDBURL)
	optNonEmpty(b, "geo_refresh_mmdb_sha", s.GeoRefreshMMDBSHA)
	optNonEmpty(b, "geo_refresh_dir", s.GeoRefreshGeoIPDir)
	optNonEmpty(b, "geo_refresh_cron", s.GeoRefreshCron)
	optb(b, "bootstrap_doh_enabled", s.BootstrapDoHEnabled)
	listv(b, "bootstrap_doh_resolver", s.BootstrapDoHResolvers)
	opti(b, "bootstrap_doh_timeout_ms", s.BootstrapDoHTimeoutMs)
	optb(b, "bootstrap_proxy_fallback", s.BootstrapProxyFallback)
	opt(b, "bootstrap_tls_fingerprint", s.BootstrapTLSFingerprint)
	optNonEmpty(b, "bootstrap_tofu_path", s.BootstrapTOFUPath)
	opti(b, "bootstrap_tofu_ttl_sec", s.BootstrapTOFUTTLSec)
	optb(b, "bootstrap_health_gate", s.BootstrapHealthGate)
	opt(b, "ipv6_mode", s.IPv6Mode)
	optb(b, "ipv6_reject_when_off", s.IPv6RejectWhenOff)
	optb(b, "router_output_proxy", s.RouterOutputProxy)
	opt(b, "cgroup_v2_path", s.CgroupV2Path)
	optb(b, "wizard_vpn_pending", s.WizardVPNPending)
	optb(b, "wizard_zapret_pending", s.WizardZapretPending)
	listv(b, "ipv6_wan_interface", s.IPv6WANInterfaces)
	listv(b, "lan_source_zone", s.LANSourceZones)
	fmt.Fprintln(b)
}
func writeDNS(b *bytes.Buffer, d DNS) {
	fmt.Fprintln(b, "config dns 'dns'")
	optb(b, "enabled", d.Enabled)
	opt(b, "backend", d.Backend)
	opt(b, "upstream_mode", d.UpstreamMode)
	listv(b, "vpns", d.VPNs)
	optb(b, "hijack_lan_dns", d.HijackLANDNS)
	optb(b, "block_dot", d.BlockDoT)
	optb(b, "block_doh3", d.BlockDoH3)
	optb(b, "block_doq", d.BlockDoQ)
	listv(b, "doh3_block_ip4", d.DoH3BlockIPs4)
	listv(b, "doh3_block_ip6", d.DoH3BlockIPs6)
	opt(b, "doh_policy", d.DoHPolicy)
	opt(b, "listen", d.Listen)
	optb(b, "fake_ip", d.FakeIP)
	opt(b, "enhanced_mode", d.EnhancedMode)
	opt(b, "proxy_group_type", d.ProxyGroupType)
	opt(b, "proxy_filter", d.ProxyFilter)
	opt(b, "proxy_exclude_filter", d.ProxyExcludeFilter)
	opt(b, "proxy_strategy", d.ProxyStrategy)
	listv(b, "doh_upstream", d.DoHUpstreams)
	listv(b, "udp_upstream", d.UDPUpstreams)
	listv(b, "doq_upstream", d.DoQUpstreams)
	fmt.Fprintln(b)
}
func writeMwan3(b *bytes.Buffer, m Mwan3) {
	fmt.Fprintln(b, "config mwan3 'mwan3'")
	opt(b, "mode", m.Mode)
	optb(b, "detect", m.Detect)
	optb(b, "mmx_mask_auto", m.MMXMaskAuto)
	opt(b, "mwan3_mask", m.Mwan3Mask)
	opt(b, "purewrt_mark", m.PureWRTMark)
	opt(b, "purewrt_mask", m.PureWRTMask)
	opt(b, "rule_priority", m.RulePriority)
	optb(b, "integrated_rules", m.IntegratedRules)
	fmt.Fprintln(b)
}

func writeZapretProfile(b *bytes.Buffer, p ZapretProfile, seen map[string]bool) {
	if sectionHeader(b, "zapret_profile", prefixZapretProfile, p.Name, seen) {
		opt(b, "name", p.Name)
	}
	optb(b, "enabled", p.Enabled)
	opt(b, "network", p.Network)
	opt(b, "device", p.Device)
	opt(b, "interface_mode", p.InterfaceMode)
	listv(b, "interface", p.Interfaces)
	opt(b, "fwmark", p.FwMark)
	opt(b, "nfqws_bin", p.NFQWSBin)
	opt(b, "tpws_bin", p.TPWSBin)
	optNonEmpty(b, "lua_bundle_dir", p.LuaBundleDir)
	listv(b, "blob", p.Blobs)
	fmt.Fprintln(b)
}

func writeZapretStrategy(b *bytes.Buffer, s ZapretStrategy, seen map[string]bool) {
	if sectionHeader(b, "zapret_strategy", prefixZapretStrat, s.Name, seen) {
		opt(b, "name", s.Name)
	}
	optb(b, "enabled", s.Enabled)
	opt(b, "profile", s.Profile)
	opt(b, "preset", s.Preset)
	opti(b, "queue_num", s.QueueNum)
	listv(b, "protocols", s.Protocols)
	opt(b, "tcp_ports", s.TCPPorts)
	opt(b, "udp_ports", s.UDPPorts)
	opti(b, "tcp_pkt_out", s.TCPPktOut)
	opti(b, "tcp_pkt_in", s.TCPPktIn)
	opti(b, "udp_pkt_out", s.UDPPktOut)
	opti(b, "udp_pkt_in", s.UDPPktIn)
	opt(b, "params", s.Params)
	fmt.Fprintln(b)
}

func writeVPN(b *bytes.Buffer, v VPN, seen map[string]bool) {
	if sectionHeader(b, "vpn", prefixVPN, v.Name, seen) {
		opt(b, "name", v.Name)
	}
	optb(b, "enabled", v.Enabled)
	opt(b, "interface", v.Interface)
	fmt.Fprintln(b)
}

// deviceSectionName mirrors the LuCI Devices page's id convention
// (`dev_<mac-without-colons>`) so the Go serializer and LuCI write the SAME
// named section per device instead of Go emitting an anonymous one that
// duplicates LuCI's — the mismatch left stale sections that couldn't be
// unassigned. Named + dedupe-on-parse gives exactly one section per MAC.
func deviceSectionName(mac string) string {
	return "dev_" + strings.ReplaceAll(strings.ToLower(mac), ":", "")
}

func writeDevice(b *bytes.Buffer, d Device) {
	fmt.Fprintf(b, "config device %s\n", q(deviceSectionName(d.MAC)))
	opt(b, "name", d.Name)
	optb(b, "enabled", d.Enabled)
	opt(b, "mac", d.MAC)
	// Section and Exclude are mutually exclusive; Exclude wins if both are set.
	if d.Exclude {
		optb(b, "exclude", true)
	} else {
		optNonEmpty(b, "section", d.Section)
	}
	fmt.Fprintln(b)
}
func writeSection(b *bytes.Buffer, s Section, seen map[string]bool) {
	if sectionHeader(b, "section", prefixSection, s.Name, seen) {
		opt(b, "name", s.Name)
	}
	optb(b, "enabled", s.Enabled)
	opt(b, "action", s.Action)
	opti(b, "tproxy_port", s.TPROXYPort)
	opt(b, "proxy_group", s.ProxyGroup)
	opt(b, "proxy_group_type", s.ProxyGroupType)
	opt(b, "proxy_filter", s.ProxyFilter)
	opt(b, "proxy_exclude_filter", s.ProxyExcludeFilter)
	opt(b, "proxy_strategy", s.ProxyStrategy)
	opt(b, "proxy_health_check_url", s.ProxyHealthCheckURL)
	opti(b, "proxy_health_check_interval", s.ProxyHealthCheckInterval)
	optb(b, "user_overridden_proxy_group", s.UserOverriddenProxyGroup)
	optb(b, "ipv4_enabled", s.IPv4Enabled)
	optb(b, "ipv6_enabled", s.IPv6Enabled)
	opt(b, "udp_mode", s.UDPMode)
	opti(b, "priority", s.Priority)
	opt(b, "mwan3_policy", s.Mwan3Policy)
	listv(b, "vpns", s.VPNs)
	listv(b, "zapret_strategy", s.ZapretStrategies)
	listv(b, "source_cidr4", s.SourceCIDR4)
	listv(b, "source_cidr6", s.SourceCIDR6)
	fmt.Fprintln(b)
}
func writeSubscription(b *bytes.Buffer, s Subscription, seen map[string]bool) {
	if sectionHeader(b, "subscription", prefixSubscription, s.Name, seen) {
		opt(b, "name", s.Name)
	}
	optb(b, "enabled", s.Enabled)
	opt(b, "url", s.URL)
	opt(b, "mode", s.Mode)
	opt(b, "preset_if_no_rules", s.PresetIfNoRules)
	optb(b, "import_rules_on_low_resource", s.ImportRulesOnLowResource)
	optb(b, "auto_apply", s.AutoApply)
	opti(b, "interval", s.Interval)
	opt(b, "hwid", s.HWID)
	opt(b, "device_name", s.DeviceName)
	opt(b, "user_agent", s.UserAgent)
	listv(b, "header", s.Headers)
	listv(b, "mirror", s.Mirrors)
	optNonEmpty(b, "pin_sha256", s.PinSHA256)
	optb(b, "suppress_hwid", s.SuppressHWID)
	fmt.Fprintln(b)
}
func writeProxyProvider(b *bytes.Buffer, p ProxyProvider, seen map[string]bool) {
	if sectionHeader(b, "proxy_provider", prefixProxyProvider, p.Name, seen) {
		opt(b, "name", p.Name)
	}
	optb(b, "enabled", p.Enabled)
	opt(b, "type", p.Type)
	opt(b, "url", p.URL)
	opti(b, "interval", p.Interval)
	opt(b, "path", p.Path)
	optb(b, "health_check", p.HealthCheck)
	opt(b, "health_check_url", p.HealthCheckURL)
	opti(b, "health_check_interval", p.HealthCheckInterval)
	opt(b, "mwan3_policy", p.Mwan3Policy)
	opt(b, "hwid", p.HWID)
	opt(b, "device_name", p.DeviceName)
	opt(b, "user_agent", p.UserAgent)
	listv(b, "header", p.Headers)
	listv(b, "mirror", p.Mirrors)
	optNonEmpty(b, "pin_sha256", p.PinSHA256)
	optb(b, "suppress_hwid", p.SuppressHWID)
	fmt.Fprintln(b)
}
func writeRuleProvider(b *bytes.Buffer, p RuleProvider, seen map[string]bool) {
	if sectionHeader(b, "rule_provider", prefixRuleProvider, p.Name, seen) {
		opt(b, "name", p.Name)
	}
	optb(b, "enabled", p.Enabled)
	opt(b, "behavior", p.Behavior)
	opt(b, "format", p.Format)
	opt(b, "parse_mode", p.ParseMode)
	opt(b, "url", p.URL)
	opti(b, "interval", p.Interval)
	opt(b, "path", p.Path)
	opt(b, "section", p.Section)
	opt(b, "category", p.Category)
	opt(b, "source_kind", p.SourceKind)
	opt(b, "route_action", p.RouteAction)
	opti(b, "priority", p.Priority)
	opt(b, "source_subscription", p.SourceSubscription)
	opt(b, "detected_category", p.DetectedCategory)
	optb(b, "user_overridden_section", p.UserOverriddenSection)
	optb(b, "user_overridden_action", p.UserOverriddenAction)
	opt(b, "user_agent", p.UserAgent)
	listv(b, "header", p.Headers)
	listv(b, "mirror", p.Mirrors)
	optNonEmpty(b, "pin_sha256", p.PinSHA256)
	opt(b, "last_error", p.LastError)
	opt(b, "geo_target", p.GeoTarget)
	fmt.Fprintln(b)
}
func writeBypass(b *bytes.Buffer, bp Bypass) {
	if bp.Name == "" && len(bp.CIDR4) == 0 && len(bp.CIDR6) == 0 && len(bp.ProxyServerCIDR4) == 0 && len(bp.ProxyServerCIDR6) == 0 && len(bp.SourceCIDR4) == 0 && len(bp.SourceCIDR6) == 0 {
		return
	}
	fmt.Fprintf(b, "config bypass %s\n", q(bp.Name))
	listv(b, "cidr4", bp.CIDR4)
	listv(b, "cidr6", bp.CIDR6)
	listv(b, "proxy_server_cidr4", bp.ProxyServerCIDR4)
	listv(b, "proxy_server_cidr6", bp.ProxyServerCIDR6)
	listv(b, "source_cidr4", bp.SourceCIDR4)
	listv(b, "source_cidr6", bp.SourceCIDR6)
	fmt.Fprintln(b)
}

// writeMesh emits nothing while the feature is dormant so untouched installs
// keep byte-identical configs. A joined config stores exactly one secret —
// the sync-code — plus only the options that differ from DefaultMesh().
func writeMesh(b *bytes.Buffer, m Mesh) {
	if !m.Enabled && m.Code == "" {
		return
	}
	d := DefaultMesh()
	fmt.Fprintln(b, "config mesh 'mesh'")
	optb(b, "enabled", m.Enabled)
	opt(b, "code", m.Code)
	opt(b, "hwid", m.HWID)
	opt(b, "node_name", m.NodeName)
	optb(b, "exit_enabled", m.ExitEnabled)
	if m.ListenPort != d.ListenPort {
		opti(b, "listen_port", m.ListenPort)
	}
	if m.APIMeshPort != d.APIMeshPort {
		opti(b, "api_mesh_port", m.APIMeshPort)
	}
	if m.DeviceName != d.DeviceName {
		opt(b, "device_name", m.DeviceName)
	}
	// community_peer is always written when active: it is the rendezvous list
	// users are meant to see and edit to point at their own servers.
	listv(b, "community_peer", m.CommunityPeers)
	if !meshExtrasMatchCode(m.Code, m.ExtraPeers) {
		listv(b, "extra_peer", m.ExtraPeers)
	}
	if m.EasytierBin != d.EasytierBin {
		opt(b, "easytier_bin", m.EasytierBin)
	}
	if m.RPCPortal != d.RPCPortal {
		opt(b, "rpc_portal", m.RPCPortal)
	}
	if m.SyncCron != d.SyncCron {
		opt(b, "sync_cron", m.SyncCron)
	}
	if m.PeerTTLDays != d.PeerTTLDays {
		opti(b, "peer_ttl_days", m.PeerTTLDays)
	}
	fmt.Fprintln(b)
}

// meshExtrasMatchCode reports whether the extra_peer list is exactly what the
// stored code's TLVs already carry — if so the list needs no separate option
// (the parser falls back to the TLVs).
func meshExtrasMatchCode(codeStr string, extras []string) bool {
	if codeStr == "" {
		return len(extras) == 0
	}
	code, err := mesh.DecodeCode(codeStr)
	if err != nil {
		return false
	}
	if len(code.ExtraPeers) != len(extras) {
		return false
	}
	for i := range extras {
		if code.ExtraPeers[i] != extras[i] {
			return false
		}
	}
	return true
}

// writeMeshPeer emits anonymous sections: peer names carry dashes
// (hostnames), which are invalid in UCI section names — same reason
// zapret_profile sections are anonymous. No credential material is stored:
// the peer's ss password derives from (group PSK, name).
func writeMeshPeer(b *bytes.Buffer, p MeshPeer) {
	fmt.Fprintln(b, "config mesh_peer")
	opt(b, "hwid", p.HWID)
	opt(b, "name", p.Name)
	optb(b, "enabled", p.Enabled)
	opt(b, "overlay_ip", p.OverlayIP)
	if p.ListenPort != DefaultMesh().ListenPort {
		opti(b, "listen_port", p.ListenPort)
	}
	optb(b, "exit_offered", p.ExitOffered)
	optNonEmpty(b, "last_seen", p.LastSeen)
	optNonEmpty(b, "last_error", p.LastError)
	fmt.Fprintln(b)
}

func writeOONI(b *bytes.Buffer, o OONI) {
	fmt.Fprintln(b, "config ooni 'ooni'")
	optb(b, "enabled", o.Enabled)
	optb(b, "upload", o.Upload)
	opt(b, "schedule", o.Schedule)
	opt(b, "proxy", o.Proxy)
	opt(b, "home", o.Home)
	opt(b, "user", o.User)
	fmt.Fprintln(b)
}
