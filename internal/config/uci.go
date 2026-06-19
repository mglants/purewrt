package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func Load(path string) (Config, error) {
	c := Default()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	defer func() { _ = f.Close() }()
	type sec struct {
		typ, name string
		opts      map[string][]string
	}
	var sections []sec
	cur := sec{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "config":
			if cur.typ != "" {
				sections = append(sections, cur)
			}
			cur = sec{typ: unq(fields[1]), opts: map[string][]string{}}
			if len(fields) > 2 {
				cur.name = unq(fields[2])
			}
		case "option":
			if len(fields) >= 3 {
				cur.opts[unq(fields[1])] = []string{unq(strings.Join(fields[2:], " "))}
			}
		case "list":
			if len(fields) >= 3 {
				k := unq(fields[1])
				cur.opts[k] = append(cur.opts[k], unq(strings.Join(fields[2:], " ")))
			}
		}
	}
	if cur.typ != "" {
		sections = append(sections, cur)
	}
	c.Sections = nil
	c.Subscriptions = nil
	c.ProxyProviders = nil
	c.RuleProviders = nil
	c.VPNs = nil
	c.ZapretProfiles = nil
	c.ZapretStrategies = nil
	for _, x := range sections {
		applySection(&c, x)
	}
	if len(c.Sections) == 0 {
		c.Sections = Default().Sections
	}
	return c, s.Err()
}

func unq(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "'")
	v = strings.Trim(v, "\"")
	return v
}
func one(m map[string][]string, k, d string) string {
	if v := m[k]; len(v) > 0 {
		return v[0]
	}
	return d
}
func list(m map[string][]string, k string, d []string) []string {
	if v := m[k]; len(v) > 0 {
		return v
	}
	return d
}
func b(m map[string][]string, k string, d bool) bool {
	v := one(m, k, "")
	if v == "" {
		return d
	}
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}
func i(m map[string][]string, k string, d int) int {
	v := one(m, k, "")
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return n
}

func i64(m map[string][]string, k string, d int64) int64 {
	v := one(m, k, "")
	if v == "" {
		return d
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return d
	}
	return n
}

func applySection(c *Config, x struct {
	typ, name string
	opts      map[string][]string
}) {
	switch x.typ {
	case "main":
		c.Settings.ConfigVersion = i(x.opts, "config_version", c.Settings.ConfigVersion)
		c.Settings.Enabled = b(x.opts, "enabled", c.Settings.Enabled)
		c.Settings.Workdir = one(x.opts, "workdir", c.Settings.Workdir)
		c.Settings.RuntimeDir = one(x.opts, "runtime_dir", c.Settings.RuntimeDir)
		c.Settings.GeneratedDir = one(x.opts, "generated_dir", c.Settings.GeneratedDir)
		c.Settings.DNSMasqIncludeDir = one(x.opts, "dnsmasq_include_dir", c.Settings.DNSMasqIncludeDir)
		c.Settings.MihomoBin = one(x.opts, "mihomo_bin", c.Settings.MihomoBin)
		c.Settings.MihomoConfig = one(x.opts, "mihomo_config", c.Settings.MihomoConfig)
		c.Settings.MihomoAllowLAN = b(x.opts, "mihomo_allow_lan", c.Settings.MihomoAllowLAN)
		c.Settings.ExternalController = one(x.opts, "external_controller", c.Settings.ExternalController)
		c.Settings.Secret = one(x.opts, "secret", c.Settings.Secret)
		c.Settings.DNSBackend = one(x.opts, "dns_backend", c.Settings.DNSBackend)
		c.Settings.FirewallBackend = one(x.opts, "firewall_backend", c.Settings.FirewallBackend)
		c.Settings.FwMark = one(x.opts, "fwmark", c.Settings.FwMark)
		c.Settings.FwMarkMask = one(x.opts, "fwmark_mask", c.Settings.FwMarkMask)
		c.Settings.RouteTable = one(x.opts, "route_table", c.Settings.RouteTable)
		c.Settings.IPRulePriority = one(x.opts, "ip_rule_priority", c.Settings.IPRulePriority)
		c.Settings.IPv6 = b(x.opts, "ipv6", c.Settings.IPv6)
		c.Settings.FakeIP = b(x.opts, "fake_ip", c.Settings.FakeIP)
		c.Settings.Sniffer = b(x.opts, "sniffer", c.Settings.Sniffer)
		c.Settings.DNSListen = one(x.opts, "dns_listen", c.Settings.DNSListen)
		c.Settings.AutoReload = b(x.opts, "auto_reload", c.Settings.AutoReload)
		c.Settings.SafeApply = b(x.opts, "safe_apply", c.Settings.SafeApply)
		c.Settings.RollbackOnFail = b(x.opts, "rollback_on_fail", c.Settings.RollbackOnFail)
		c.Settings.ApplyBackupMaxBytes = i64(x.opts, "apply_backup_max_bytes", c.Settings.ApplyBackupMaxBytes)
		c.Settings.MihomoChannel = one(x.opts, "mihomo_channel", c.Settings.MihomoChannel)
		c.Settings.MihomoReleaseAPI = one(x.opts, "mihomo_release_api", c.Settings.MihomoReleaseAPI)
		c.Settings.MihomoStableReleaseAPI = one(x.opts, "mihomo_stable_release_api", c.Settings.MihomoStableReleaseAPI)
		c.Settings.MihomoMixinEnabled = b(x.opts, "mihomo_mixin_enabled", c.Settings.MihomoMixinEnabled)
		c.Settings.MihomoAutoUpdateEnabled = b(x.opts, "mihomo_auto_update_enabled", c.Settings.MihomoAutoUpdateEnabled)
		c.Settings.MihomoAutoUpdateCron = one(x.opts, "mihomo_auto_update_cron", c.Settings.MihomoAutoUpdateCron)
		c.Settings.MihomoVersion = one(x.opts, "mihomo_version", c.Settings.MihomoVersion)
		c.Settings.MihomoArch = one(x.opts, "mihomo_arch", c.Settings.MihomoArch)
		c.Settings.MihomoAssetURL = one(x.opts, "mihomo_asset_url", c.Settings.MihomoAssetURL)
		c.Settings.MihomoSHA256URL = one(x.opts, "mihomo_sha256_url", c.Settings.MihomoSHA256URL)
		c.Settings.MihomoGeodataEnabled = b(x.opts, "mihomo_geodata_enabled", c.Settings.MihomoGeodataEnabled)
		c.Settings.UpdateViaProxy = b(x.opts, "update_via_proxy", c.Settings.UpdateViaProxy)
		c.Settings.UpdateProxyURL = one(x.opts, "update_proxy_url", c.Settings.UpdateProxyURL)
		c.Settings.UpdateConcurrency = i(x.opts, "update_concurrency", c.Settings.UpdateConcurrency)
		c.Settings.AutoUpdateEnabled = b(x.opts, "auto_update_enabled", c.Settings.AutoUpdateEnabled)
		c.Settings.AutoUpdateCron = one(x.opts, "auto_update_cron", c.Settings.AutoUpdateCron)
		c.Settings.ReloadAfterUpdate = b(x.opts, "reload_after_update", c.Settings.ReloadAfterUpdate)
		c.Settings.BackupRetention = i(x.opts, "backup_retention", c.Settings.BackupRetention)
		c.Settings.BackgroundUpdates = b(x.opts, "background_updates", c.Settings.BackgroundUpdates)
		c.Settings.BootUpdateDelay = i(x.opts, "boot_update_delay", c.Settings.BootUpdateDelay)
		c.Settings.UpdateNice = i(x.opts, "update_nice", c.Settings.UpdateNice)
		c.Settings.UpdateIONiceClass = i(x.opts, "update_ionice_class", c.Settings.UpdateIONiceClass)
		c.Settings.UpdateIONiceLevel = i(x.opts, "update_ionice_level", c.Settings.UpdateIONiceLevel)
		c.Settings.DashboardEnabled = b(x.opts, "dashboard_enabled", c.Settings.DashboardEnabled)
		c.Settings.DashboardListen = one(x.opts, "dashboard_listen", c.Settings.DashboardListen)
		c.Settings.DashboardPath = one(x.opts, "dashboard_path", c.Settings.DashboardPath)
		c.Settings.DashboardURL = one(x.opts, "dashboard_url", c.Settings.DashboardURL)
		c.Settings.DefaultListsBaseURL = one(x.opts, "default_lists_base_url", c.Settings.DefaultListsBaseURL)
		c.Settings.DashboardName = one(x.opts, "dashboard_name", c.Settings.DashboardName)
		c.Settings.ResourceProfile = one(x.opts, "resource_profile", c.Settings.ResourceProfile)
		c.Settings.CacheMode = one(x.opts, "cache_mode", c.Settings.CacheMode)
		c.Settings.CacheDir = one(x.opts, "cache_dir", c.Settings.CacheDir)
		c.Settings.ArtifactCacheMode = one(x.opts, "artifact_cache_mode", c.Settings.ArtifactCacheMode)
		c.Settings.ArtifactCacheMaxBytes = i64(x.opts, "artifact_cache_max_bytes", c.Settings.ArtifactCacheMaxBytes)
		c.Settings.ArtifactCacheMaxEntries = i(x.opts, "artifact_cache_max_entries", c.Settings.ArtifactCacheMaxEntries)
		c.Settings.RuleDedupMode = one(x.opts, "rule_dedup_mode", c.Settings.RuleDedupMode)
		c.Settings.LogLevel = one(x.opts, "log_level", c.Settings.LogLevel)
		c.Settings.LogFormat = one(x.opts, "log_format", c.Settings.LogFormat)
		c.Settings.APIListen = list(x.opts, "api_listen", c.Settings.APIListen)
		c.Settings.NotifyURL = one(x.opts, "notify_url", c.Settings.NotifyURL)
		c.Settings.NotifyFormat = one(x.opts, "notify_format", c.Settings.NotifyFormat)
		c.Settings.NotifyOn = list(x.opts, "notify_on", c.Settings.NotifyOn)
		c.Settings.MetricsEnabled = b(x.opts, "metrics_enabled", c.Settings.MetricsEnabled)
		c.Settings.GeoRefreshGeoIPURL = one(x.opts, "geo_refresh_geoip_url", c.Settings.GeoRefreshGeoIPURL)
		c.Settings.GeoRefreshGeoIPSHA = one(x.opts, "geo_refresh_geoip_sha", c.Settings.GeoRefreshGeoIPSHA)
		c.Settings.GeoRefreshGeoSiteURL = one(x.opts, "geo_refresh_geosite_url", c.Settings.GeoRefreshGeoSiteURL)
		c.Settings.GeoRefreshGeoSiteSHA = one(x.opts, "geo_refresh_geosite_sha", c.Settings.GeoRefreshGeoSiteSHA)
		c.Settings.GeoRefreshMMDBURL = one(x.opts, "geo_refresh_mmdb_url", c.Settings.GeoRefreshMMDBURL)
		c.Settings.GeoRefreshMMDBSHA = one(x.opts, "geo_refresh_mmdb_sha", c.Settings.GeoRefreshMMDBSHA)
		c.Settings.GeoRefreshGeoIPDir = one(x.opts, "geo_refresh_dir", c.Settings.GeoRefreshGeoIPDir)
		c.Settings.GeoRefreshCron = one(x.opts, "geo_refresh_cron", c.Settings.GeoRefreshCron)
		c.Settings.BootstrapDoHEnabled = b(x.opts, "bootstrap_doh_enabled", c.Settings.BootstrapDoHEnabled)
		c.Settings.BootstrapDoHResolvers = list(x.opts, "bootstrap_doh_resolver", c.Settings.BootstrapDoHResolvers)
		c.Settings.BootstrapDoHTimeoutMs = i(x.opts, "bootstrap_doh_timeout_ms", c.Settings.BootstrapDoHTimeoutMs)
		c.Settings.BootstrapProxyFallback = b(x.opts, "bootstrap_proxy_fallback", c.Settings.BootstrapProxyFallback)
		c.Settings.BootstrapTLSFingerprint = one(x.opts, "bootstrap_tls_fingerprint", c.Settings.BootstrapTLSFingerprint)
		c.Settings.BootstrapTOFUPath = one(x.opts, "bootstrap_tofu_path", c.Settings.BootstrapTOFUPath)
		c.Settings.BootstrapTOFUTTLSec = i(x.opts, "bootstrap_tofu_ttl_sec", c.Settings.BootstrapTOFUTTLSec)
		c.Settings.BootstrapHealthGate = b(x.opts, "bootstrap_health_gate", c.Settings.BootstrapHealthGate)
		c.Settings.ZapretUpstreamConfigPath = one(x.opts, "zapret_upstream_config_path", c.Settings.ZapretUpstreamConfigPath)
		c.Settings.IPv6Mode = one(x.opts, "ipv6_mode", c.Settings.IPv6Mode)
		c.Settings.IPv6RejectWhenOff = b(x.opts, "ipv6_reject_when_off", c.Settings.IPv6RejectWhenOff)
		c.Settings.RouterOutputProxy = b(x.opts, "router_output_proxy", c.Settings.RouterOutputProxy)
		c.Settings.CgroupV2Path = one(x.opts, "cgroup_v2_path", c.Settings.CgroupV2Path)
		c.Settings.WizardVPNPending = b(x.opts, "wizard_vpn_pending", c.Settings.WizardVPNPending)
		c.Settings.WizardZapretPending = b(x.opts, "wizard_zapret_pending", c.Settings.WizardZapretPending)
		c.Settings.IPv6WANInterfaces = list(x.opts, "ipv6_wan_interface", c.Settings.IPv6WANInterfaces)
		c.Settings.LANSourceZones = list(x.opts, "lan_source_zone", c.Settings.LANSourceZones)
	case "dns":
		c.DNS.Enabled = b(x.opts, "enabled", c.DNS.Enabled)
		c.DNS.Backend = one(x.opts, "backend", c.DNS.Backend)
		c.DNS.UpstreamMode = one(x.opts, "upstream_mode", c.DNS.UpstreamMode)
		c.DNS.VPNs = list(x.opts, "vpns", c.DNS.VPNs)
		c.DNS.HijackLANDNS = b(x.opts, "hijack_lan_dns", c.DNS.HijackLANDNS)
		c.DNS.BlockDoT = b(x.opts, "block_dot", c.DNS.BlockDoT)
		c.DNS.BlockDoH3 = b(x.opts, "block_doh3", c.DNS.BlockDoH3)
		c.DNS.BlockDoQ = b(x.opts, "block_doq", c.DNS.BlockDoQ)
		c.DNS.DoH3BlockIPs4 = list(x.opts, "doh3_block_ip4", c.DNS.DoH3BlockIPs4)
		c.DNS.DoH3BlockIPs6 = list(x.opts, "doh3_block_ip6", c.DNS.DoH3BlockIPs6)
		c.DNS.DoHPolicy = one(x.opts, "doh_policy", c.DNS.DoHPolicy)
		c.DNS.Listen = one(x.opts, "listen", c.DNS.Listen)
		c.DNS.FakeIP = b(x.opts, "fake_ip", c.DNS.FakeIP)
		c.DNS.EnhancedMode = one(x.opts, "enhanced_mode", c.DNS.EnhancedMode)
		c.DNS.ProxyGroupType = one(x.opts, "proxy_group_type", c.DNS.ProxyGroupType)
		c.DNS.ProxyFilter = one(x.opts, "proxy_filter", c.DNS.ProxyFilter)
		c.DNS.ProxyExcludeFilter = one(x.opts, "proxy_exclude_filter", c.DNS.ProxyExcludeFilter)
		c.DNS.ProxyStrategy = one(x.opts, "proxy_strategy", c.DNS.ProxyStrategy)
		c.DNS.DoHUpstreams = list(x.opts, "doh_upstream", c.DNS.DoHUpstreams)
		c.DNS.UDPUpstreams = list(x.opts, "udp_upstream", c.DNS.UDPUpstreams)
		c.DNS.DoQUpstreams = list(x.opts, "doq_upstream", c.DNS.DoQUpstreams)
	case "mwan3":
		c.Mwan3.Mode = one(x.opts, "mode", c.Mwan3.Mode)
		c.Mwan3.Detect = b(x.opts, "detect", c.Mwan3.Detect)
		c.Mwan3.MMXMaskAuto = b(x.opts, "mmx_mask_auto", c.Mwan3.MMXMaskAuto)
		c.Mwan3.Mwan3Mask = one(x.opts, "mwan3_mask", c.Mwan3.Mwan3Mask)
		c.Mwan3.PureWRTMark = one(x.opts, "purewrt_mark", c.Mwan3.PureWRTMark)
		c.Mwan3.PureWRTMask = one(x.opts, "purewrt_mask", c.Mwan3.PureWRTMask)
		c.Mwan3.RulePriority = one(x.opts, "rule_priority", c.Mwan3.RulePriority)
		c.Mwan3.IntegratedRules = b(x.opts, "integrated_rules", c.Mwan3.IntegratedRules)
	case "zapret_profile":
		name := one(x.opts, "name", x.name)
		if name == "" {
			name = "wan"
		}
		p := ZapretProfile{Name: name, Enabled: b(x.opts, "enabled", true)}
		p.Network = one(x.opts, "network", "auto")
		p.Device = one(x.opts, "device", "")
		p.InterfaceMode = one(x.opts, "interface_mode", "")
		p.Interfaces = list(x.opts, "interface", nil)
		p.QueueNum = i(x.opts, "queue_num", 0)
		p.TPWSPort = i(x.opts, "tpws_port", 0)
		p.FwMark = one(x.opts, "fwmark", "")
		p.MaxPktOut = i(x.opts, "max_pkt_out", 0)
		p.MaxPktIn = i(x.opts, "max_pkt_in", 0)
		p.NFQWSBin = one(x.opts, "nfqws_bin", "")
		p.TPWSBin = one(x.opts, "tpws_bin", "")
		p.Params = one(x.opts, "params", "")
		p.LuaBundleDir = one(x.opts, "lua_bundle_dir", "")
		c.ZapretProfiles = append(c.ZapretProfiles, p)
	case "zapret_strategy":
		zs := ZapretStrategy{Name: one(x.opts, "name", x.name), Enabled: b(x.opts, "enabled", true)}
		zs.Profile = one(x.opts, "profile", "wan")
		zs.QueueNum = i(x.opts, "queue_num", 0)
		zs.Protocols = list(x.opts, "protocols", list(x.opts, "protocol", nil))
		zs.TCPPorts = one(x.opts, "tcp_ports", "")
		zs.UDPPorts = one(x.opts, "udp_ports", "")
		zs.TCPPktOut = i(x.opts, "tcp_pkt_out", 0)
		zs.TCPPktIn = i(x.opts, "tcp_pkt_in", 0)
		zs.UDPPktOut = i(x.opts, "udp_pkt_out", 0)
		zs.UDPPktIn = i(x.opts, "udp_pkt_in", 0)
		zs.Preset = one(x.opts, "preset", "")
		zs.Params = one(x.opts, "params", "")
		zs.FakeDir = one(x.opts, "fake_dir", "")
		c.ZapretStrategies = append(c.ZapretStrategies, zs)
	case "vpn":
		v := VPN{Name: one(x.opts, "name", x.name), Interface: "wg0"}
		if v.Name == "" {
			v.Name = "vpn"
		}
		v.Enabled = b(x.opts, "enabled", v.Enabled)
		v.Interface = one(x.opts, "interface", v.Interface)
		c.VPNs = append(c.VPNs, v)
	case "device":
		d := Device{
			Name:    one(x.opts, "name", x.name),
			MAC:     strings.ToLower(strings.TrimSpace(one(x.opts, "mac", ""))),
			Section: one(x.opts, "section", ""),
			Enabled: b(x.opts, "enabled", true),
		}
		if d.MAC != "" {
			c.Devices = append(c.Devices, d)
		}
	case "section":
		c.Sections = append(c.Sections, Section{Name: x.name, Enabled: b(x.opts, "enabled", true), Action: one(x.opts, "action", "proxy"), TPROXYPort: i(x.opts, "tproxy_port", 7893), ProxyGroup: one(x.opts, "proxy_group", TitleASCII(x.name)), ProxyGroupType: one(x.opts, "proxy_group_type", "url-test"), ProxyFilter: one(x.opts, "proxy_filter", ""), ProxyExcludeFilter: one(x.opts, "proxy_exclude_filter", ""), ProxyStrategy: one(x.opts, "proxy_strategy", "sticky-sessions"), ProxyHealthCheckURL: one(x.opts, "proxy_health_check_url", ""), ProxyHealthCheckInterval: i(x.opts, "proxy_health_check_interval", 0), UserOverriddenProxyGroup: b(x.opts, "user_overridden_proxy_group", false), IPv4Enabled: b(x.opts, "ipv4_enabled", true), IPv6Enabled: b(x.opts, "ipv6_enabled", true), UDPMode: one(x.opts, "udp_mode", "proxy"), Priority: i(x.opts, "priority", 100), Mwan3Policy: one(x.opts, "mwan3_policy", ""), VPNs: list(x.opts, "vpns", nil), ZapretStrategies: list(x.opts, "zapret_strategy", nil), SourceCIDR4: list(x.opts, "source_cidr4", nil), SourceCIDR6: list(x.opts, "source_cidr6", nil)})
	case "subscription":
		c.Subscriptions = append(c.Subscriptions, Subscription{Name: one(x.opts, "name", x.name), Enabled: b(x.opts, "enabled", true), URL: one(x.opts, "url", ""), Mode: one(x.opts, "mode", "auto"), PresetIfNoRules: one(x.opts, "preset_if_no_rules", "minimal"), ImportRulesOnLowResource: b(x.opts, "import_rules_on_low_resource", false), AutoApply: b(x.opts, "auto_apply", false), Interval: i(x.opts, "interval", 86400), HWID: one(x.opts, "hwid", ""), DeviceName: one(x.opts, "device_name", ""), UserAgent: one(x.opts, "user_agent", "mihomo-purewrt"), Headers: list(x.opts, "header", nil), Mirrors: list(x.opts, "mirror", nil), PinSHA256: one(x.opts, "pin_sha256", ""), SuppressHWID: b(x.opts, "suppress_hwid", false)})
	case "proxy_provider":
		c.ProxyProviders = append(c.ProxyProviders, ProxyProvider{Name: one(x.opts, "name", x.name), Enabled: b(x.opts, "enabled", true), Type: one(x.opts, "type", "http"), URL: one(x.opts, "url", ""), Interval: i(x.opts, "interval", 86400), Path: one(x.opts, "path", "/etc/purewrt/providers/"+x.name+".yaml"), HealthCheck: b(x.opts, "health_check", true), HealthCheckURL: one(x.opts, "health_check_url", "https://cp.cloudflare.com/generate_204"), HealthCheckInterval: i(x.opts, "health_check_interval", 300), Mwan3Policy: one(x.opts, "mwan3_policy", ""), HWID: one(x.opts, "hwid", ""), DeviceName: one(x.opts, "device_name", ""), UserAgent: one(x.opts, "user_agent", ""), Headers: list(x.opts, "header", nil), Mirrors: list(x.opts, "mirror", nil), PinSHA256: one(x.opts, "pin_sha256", ""), SuppressHWID: b(x.opts, "suppress_hwid", false)})
	case "rule_provider":
		name := one(x.opts, "name", x.name)
		format := one(x.opts, "format", "text")
		c.RuleProviders = append(c.RuleProviders, RuleProvider{Name: name, Enabled: b(x.opts, "enabled", true), Behavior: one(x.opts, "behavior", "domain"), Format: format, ParseMode: one(x.opts, "parse_mode", "auto"), URL: one(x.opts, "url", ""), Interval: i(x.opts, "interval", 86400), Path: one(x.opts, "path", ruleProviderPath(c.Settings.Workdir, name, format)), Section: one(x.opts, "section", "common"), Category: one(x.opts, "category", ""), SourceKind: one(x.opts, "source_kind", ""), RouteAction: one(x.opts, "route_action", ""), Priority: i(x.opts, "priority", 0), SourceSubscription: one(x.opts, "source_subscription", ""), DetectedCategory: one(x.opts, "detected_category", ""), UserOverriddenSection: b(x.opts, "user_overridden_section", false), UserOverriddenAction: b(x.opts, "user_overridden_action", false), HWID: one(x.opts, "hwid", ""), DeviceName: one(x.opts, "device_name", ""), UserAgent: one(x.opts, "user_agent", ""), Headers: list(x.opts, "header", nil), Mirrors: list(x.opts, "mirror", nil), PinSHA256: one(x.opts, "pin_sha256", ""), LastError: one(x.opts, "last_error", ""), GeoTarget: one(x.opts, "geo_target", "")})
	case "bypass":
		c.Bypass.Name = one(x.opts, "name", x.name)
		c.Bypass.CIDR4 = list(x.opts, "cidr4", nil)
		c.Bypass.CIDR6 = list(x.opts, "cidr6", nil)
		c.Bypass.ProxyServerCIDR4 = list(x.opts, "proxy_server_cidr4", nil)
		c.Bypass.ProxyServerCIDR6 = list(x.opts, "proxy_server_cidr6", nil)
		c.Bypass.SourceCIDR4 = list(x.opts, "source_cidr4", nil)
		c.Bypass.SourceCIDR6 = list(x.opts, "source_cidr6", nil)
	}
}

func ruleProviderPath(workdir, name, format string) string {
	if workdir == "" {
		workdir = DefaultWorkdir
	}
	// .mrs for the binary mihomo ruleset, .txt for everything else.
	// The text branch is the catch-all — the parser auto-classifies
	// FQDNs / IPs / CIDRs / mihomo rule expressions from a flat file.
	ext := "txt"
	if strings.ToLower(format) == "mrs" {
		ext = "mrs"
	}
	if name == "" {
		name = "rules"
	}
	return filepath.Join(workdir, "rulesets", name+"."+ext)
}
