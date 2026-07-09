package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

func TitleASCII(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

const (
	DefaultWorkdir      = "/etc/purewrt"
	DefaultRuntimeDir   = "/tmp/purewrt"
	DefaultMihomoConfig = "/etc/purewrt/generated/mihomo.yaml"
	ZapretQueueBase     = 200
	// DefaultMihomoMixedPort is the HTTP/SOCKS proxy port the generated
	// mihomo config always opens. The update-via-proxy path and the
	// bootstrap proxy fallback default to this local listener.
	DefaultMihomoMixedPort = 7890
	// DefaultNetCheckProbePort is the loopback `mixed` listener the generated
	// config exposes for net-check --per-node: traffic to it is routed via the
	// NetCheckProbe select group, so net-check can pin one node/group/VPN at a
	// time and measure real throughput. Loopback-only; carries no traffic
	// unless net-check drives it.
	DefaultNetCheckProbePort = 7899
)

// LocalMihomoProxyURL is the URL of the local mihomo proxy listener that
// generator.Mihomo always emits (`mixed-port`). Single source of truth so
// the generator, the update-proxy default, and the bootstrap fallback
// can't drift apart.
func LocalMihomoProxyURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", DefaultMihomoMixedPort)
}

// DefaultBootstrapDoHResolvers returns the censorship-resistant DoH endpoint
// pool used to look up subscription, mihomo-update, and geo-data hosts before
// the proxy core is running. Every entry uses an IP-literal host so the
// resolver itself never depends on the system DNS to find itself.
//
// The list intentionally goes beyond Cloudflare/Google/Quad9: in heavily
// censored regions (RU/IR/CN) those three are the first IPs blacklisted, so
// PureWRT also seeds AdGuard, Mullvad, and Yandex endpoints. None of them is
// individually uncensored — but the union is harder to fully blanket-block
// than any single provider, and rotating across them is exactly the kind of
// resistance the bootstrap path needs.
func DefaultBootstrapDoHResolvers() []string {
	return []string{
		"https://1.1.1.1/dns-query",      // Cloudflare
		"https://1.0.0.1/dns-query",      // Cloudflare secondary
		"https://8.8.8.8/dns-query",      // Google
		"https://9.9.9.9/dns-query",      // Quad9
		"https://94.140.14.14/dns-query", // AdGuard
		"https://94.140.15.15/dns-query", // AdGuard secondary
		"https://194.242.2.2/dns-query",  // Mullvad
		"https://77.88.8.1/dns-query",    // Yandex
	}
}

// DefaultDoH3BlockIPs4 returns the IPv4 endpoints (Cloudflare, Google,
// Quad9, AdGuard, NextDNS) that ship hardcoded DoH3 (HTTPS-over-QUIC)
// resolvers in modern browsers and devices. Blocking UDP/443 to these
// IPs forces those clients back onto the LAN-hijacked plain DNS path so
// the nftset population works as designed.
func DefaultDoH3BlockIPs4() []string {
	return []string{
		"1.1.1.1", "1.0.0.1", // Cloudflare
		"8.8.8.8", "8.8.4.4", // Google
		"9.9.9.9", "149.112.112.112", // Quad9
		"94.140.14.14", "94.140.15.15", // AdGuard
		"45.90.28.0/24", "45.90.30.0/24", // NextDNS
	}
}

// DefaultDoH3BlockIPs6 mirrors DefaultDoH3BlockIPs4 for IPv6.
func DefaultDoH3BlockIPs6() []string {
	return []string{
		"2606:4700:4700::1111", "2606:4700:4700::1001", // Cloudflare
		"2001:4860:4860::8888", "2001:4860:4860::8844", // Google
		"2620:fe::fe", "2620:fe::9", // Quad9
		"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", // AdGuard
	}
}

type Config struct {
	Settings         Settings
	DNS              DNS
	Mwan3            Mwan3
	ZapretProfiles   []ZapretProfile
	ZapretStrategies []ZapretStrategy
	VPNs             []VPN
	Devices          []Device
	Sections         []Section
	Subscriptions    []Subscription
	ProxyProviders   []ProxyProvider
	RuleProviders    []RuleProvider
	Bypass           Bypass
	OONI             OONI
}

type Settings struct {
	ConfigVersion           int
	Enabled                 bool
	Workdir                 string
	RuntimeDir              string
	GeneratedDir            string
	DNSMasqIncludeDir       string
	MihomoBin               string
	MihomoConfig            string
	// MihomoAllowLAN controls mihomo's allow-lan. Default false binds the
	// mixed-port HTTP/SOCKS proxy to 127.0.0.1 only, so a LAN scan can't
	// detect or use the router as an open proxy. The download-via-proxy
	// fallback uses the loopback listener, so it keeps working. Set true
	// to let LAN clients point at the router as an explicit proxy.
	MihomoAllowLAN          bool
	ExternalController      string
	Secret                  string
	DNSBackend              string
	FirewallBackend         string
	FwMark                  string
	FwMarkMask              string
	RouteTable              string
	IPRulePriority          string
	IPv6                    bool
	FakeIP                  bool
	Sniffer                 bool
	DNSListen               string
	AutoReload              bool
	SafeApply               bool
	RollbackOnFail          bool
	BackupRetention         int
	ApplyBackupMaxBytes     int64
	MihomoChannel           string
	MihomoReleaseAPI        string // alpha-channel GitHub API URL (kept for back-compat — defaults to the Prerelease-Alpha tag URL)
	MihomoStableReleaseAPI  string // stable-channel GitHub API URL (latest release)
	MihomoVersion           string
	MihomoArch              string
	MihomoAssetURL          string
	MihomoSHA256URL         string
	MihomoGeodataEnabled    bool
	// MihomoMixinEnabled gates the user-mixin merge in generator.Mihomo.
	// When true, <Workdir>/mihomo-mixin.yaml gets deep-merged into the
	// generated base on every apply. Off by default — existing installs
	// get the same generated YAML as before.
	MihomoMixinEnabled      bool
	// MihomoAutoUpdateEnabled drives the cron entry that periodically
	// re-runs `purewrt mihomo-auto-update`. Off by default — auto-
	// updating a routing daemon is opt-in. When the post-install warmup
	// fails, MihomoInstallRelease auto-reverts to /usr/bin/mihomo so a
	// bad release doesn't take the proxy down between cron ticks.
	MihomoAutoUpdateEnabled bool
	// MihomoAutoUpdateCron is the schedule the init script writes into
	// /etc/crontabs/root. Default is once a day at 04:23 — different
	// minute from the subscription-update entry (17 */6) so the two
	// jobs don't fight over flash I/O on the same boundary.
	MihomoAutoUpdateCron    string
	// NetCheckEnabled gates the cron entry that periodically runs
	// `purewrt net-check`, recording throughput/verdict metrics. Off by
	// default — the probe transfers real bytes through the proxy, so it
	// costs subscription quota; opt in when you want continuous history.
	NetCheckEnabled bool
	// NetCheckCron is the schedule written into /etc/crontabs/root. Empty
	// disables the scheduled run (manual only). Suggested "*/30 * * * *".
	NetCheckCron string
	// NetCheckBytes is the per-probe transfer size for the cron run, smaller
	// than the interactive default to bound quota (default ~2 MiB).
	NetCheckBytes           int
	UpdateViaProxy          bool
	UpdateProxyURL          string
	UpdateConcurrency       int
	AutoUpdateEnabled       bool
	AutoUpdateCron          string
	ReloadAfterUpdate       bool
	BackgroundUpdates       bool
	BootUpdateDelay         int
	UpdateNice              int
	UpdateIONiceClass       int
	UpdateIONiceLevel       int
	DashboardEnabled        bool
	DashboardListen         string
	DashboardPath           string
	DashboardURL            string
	// DefaultListsBaseURL is the release base for nftset-builder's pre-built
	// native lists. The wizard reads <base>/catalog.json and derives each
	// list's URL as <base>/<file>. Empty disables the wizard's default-lists
	// source.
	DefaultListsBaseURL     string
	DashboardName           string
	ResourceProfile         string
	CacheMode               string
	CacheDir                string
	ArtifactCacheMode       string
	ArtifactCacheMaxBytes   int64
	ArtifactCacheMaxEntries int
	RuleDedupMode           string
	LogLevel                string
	LogFormat               string // "text" (default) | "json" — flips the *Fields slog backend to JSON for headless ingestion
	MetricsEnabled          bool   // when true, purewrt-api serves /metrics in Prometheus text exposition format
	// APIListen is the list of host:port addresses purewrt-api binds.
	// Empty = default "0.0.0.0:8787" (all interfaces — OpenWrt's default
	// firewall still blocks WAN input, so this means LAN exposure). Set
	// one or more explicit addresses to pick interfaces, e.g.
	// "127.0.0.1:8787" for loopback-only or "192.168.1.1:8787" for LAN.
	APIListen []string
	// Push notifications for operational events. Empty NotifyURL disables.
	// NotifyFormat: "webhook" (JSON POST, default) | "ntfy" (text body +
	// Title header). NotifyOn filters events; empty = all of
	// update_failure, sub_expiry, mihomo_revert.
	NotifyURL    string
	NotifyFormat string
	NotifyOn     []string
	// Geo data refresh. Empty URL disables the corresponding target.
	// SHA expectations are optional — when present, the downloaded file's
	// SHA-256 must match before atomic swap. Defaults pull from the
	// MetaCubeX project (same source mihomo expects).
	GeoRefreshGeoIPURL     string
	GeoRefreshGeoIPSHA     string
	GeoRefreshGeoSiteURL   string
	GeoRefreshGeoSiteSHA   string
	GeoRefreshMMDBURL      string
	GeoRefreshMMDBSHA      string
	GeoRefreshGeoIPDir     string // where to write geoip.dat (default /etc/purewrt/geo)
	GeoRefreshCron         string // "" disables the cron (manual only); default "7 3 * * *"
	BootstrapDoHEnabled     bool
	BootstrapDoHResolvers   []string
	BootstrapDoHTimeoutMs   int
	BootstrapProxyFallback  bool
	BootstrapTLSFingerprint string // "off" | "browser" (default)
	BootstrapTOFUPath       string // empty -> default; "off" disables
	BootstrapTOFUTTLSec     int    // 0 -> default (7 days)
	BootstrapHealthGate     bool   // run resolvers probe before apply; abort if zero endpoints answer
	// Where the compiled upstream-format NFQWS2_OPT file goes (consumed by
	// upstream /etc/init.d/zapret2) is NOT a setting — the generator
	// auto-derives it from the installed upstream package. See
	// generator.zapretUpstreamConfigPath.
	IPv6Mode string // "" / "auto" (default), "on", "off"
	IPv6RejectWhenOff       bool
	// RouterOutputProxy gates the OUTPUT chain that proxies router-originated
	// traffic through mihomo using the same destination-set match as the
	// existing PREROUTING. Default true so the router's own traffic (updates,
	// the blocking-heuristics probe, etc.) takes the same proxied path as LAN
	// clients instead of going direct; loop-safe via the mihomo cgroup
	// exemption + @proxy_server_bypass. Turn off via UCI `option
	// router_output_proxy '0'`.
	RouterOutputProxy bool
	// CgroupV2Path is the cgroupv2 path used in `socket cgroupv2 level N` to
	// exempt mihomo's own outbound from re-marking. Modern procd places
	// mihomo at `services/mihomo/<instance>`, so the default matches any
	// instance of the mihomo service. Slash-separated; the `level N` count
	// is auto-derived from the segment count. OpenWrt 24.10+ ships cgroupv2
	// only, so the legacy `meta cgroup <classid>` fallback was removed.
	CgroupV2Path string
	// WizardVPNPending is set by the setup wizard when the user indicates
	// they plan to configure a VPN later but isn't doing so during the
	// wizard run. Surfaces as an info banner on the Subscriptions page
	// (the landing page after wizard) pointing at the VPN Routing tab.
	// The VPN Routing page clears the flag when any VPN section is saved.
	WizardVPNPending bool
	// WizardZapretPending mirrors WizardVPNPending for DPI bypass: the
	// wizard sets it when zapret is installed and the user asked for a
	// reminder; the General page renders a banner pointing at the Zapret
	// tab until it's cleared.
	WizardZapretPending bool
	// IPv6WANInterfaces are the /etc/config/network section names that
	// PureWRT disables when IPv6 routing is turned off (and re-enables when
	// v6 is back on). Multi-WAN setups can have several v6 uplinks (e.g.
	// wan6 + a 6in4 tunnel, or wan6 + wan2_6) — all listed entries are
	// toggled together. Empty list = autodetect at apply time: scan
	// /etc/config/network and pick every interface section with
	// proto=dhcpv6 (or fall back to "wan6" by convention when nothing
	// matches). Set explicitly when an ISP's v6 uplink lives under a
	// different section name than the autodetect catches.
	IPv6WANInterfaces []string
	// LANSourceZones are the fw4 firewall zones whose clients PureWRT routes.
	// For each, PureWRT generates the DNS-hijack redirect + a DNS input-accept
	// (when DNS.HijackLANDNS) and — always — a TPROXY input-accept keyed on
	// FwMark, so TPROXY'd packets are accepted even on zones with
	// `input REJECT` (multi-VLAN setups). Empty = ["lan"] (single-zone default;
	// the extra accepts are harmless when the zone is `input ACCEPT`).
	LANSourceZones []string
}

type DNS struct {
	Enabled            bool
	Backend            string
	UpstreamMode       string
	// VPNs lists VPN names whose interfaces join the DNSProxy pool, so mihomo's
	// DNS-upstream egress can route out a VPN — lets a no-subscription setup
	// reach censored DoH/DoT/DoQ resolvers. Empty = today (providers/direct).
	VPNs               []string
	HijackLANDNS       bool
	BlockDoT           bool
	BlockDoH3          bool
	BlockDoQ           bool
	DoH3BlockIPs4      []string // IPv4 dst addrs to reject on UDP/443
	DoH3BlockIPs6      []string // IPv6 dst addrs to reject on UDP/443
	DoHPolicy          string
	Listen             string
	FakeIP             bool
	EnhancedMode       string
	ProxyGroupType     string
	ProxyFilter        string
	ProxyExcludeFilter string
	ProxyStrategy      string
	DoHUpstreams       []string
	UDPUpstreams       []string
	DoQUpstreams       []string // e.g. quic://dns.adguard-dns.com or quic://94.140.14.14
}

type Mwan3 struct {
	Mode            string
	Detect          bool
	MMXMaskAuto     bool
	Mwan3Mask       string
	PureWRTMark     string
	PureWRTMask     string
	RulePriority    string
	IntegratedRules bool
}

type ZapretProfile struct {
	Name          string
	Enabled       bool
	Network       string
	Device        string
	InterfaceMode string
	Interfaces    []string
	QueueNum      int
	TPWSPort      int
	FwMark        string
	MaxPktOut     int
	MaxPktIn      int
	NFQWSBin      string
	TPWSBin       string
	Params        string
	// LuaBundleDir is the directory containing zapret2's Lua scripts. The
	// generated NFQWS2_OPT prepends --lua-init=@<dir>/zapret-{lib,antidpi,
	// auto}.lua so named blobs like `fake_default_tls` resolve at runtime.
	// Empty falls back to /opt/zapret2/lua.
	LuaBundleDir string
	// Blobs are custom nfqws2 fake payloads declared in the NFQWS2_OPT head as
	// --blob=<entry>. Each entry is the raw nfqws2 form "name:@/path/file.bin"
	// or "name:0xHEX...". Once declared, a strategy references it by name
	// (fake:blob=name, seqovl_pattern=name, syndata:blob=name). The three stock
	// blobs (fake_default_tls/http/quic) need no declaration. Blobs are global
	// to the single nfqws2 daemon, so the generator unions them across all
	// enabled profiles and dedups by name.
	Blobs []string
}

type ZapretStrategy struct {
	Name      string
	Enabled   bool
	Profile   string
	QueueNum  int
	Protocols []string
	TCPPorts  string
	UDPPorts  string
	TCPPktOut int
	TCPPktIn  int
	UDPPktOut int
	UDPPktIn  int
	Preset    string
	Params    string
}

// VPN is a tunnel interface mihomo can egress through. Routing is done by
// mihomo (a `type: direct` outbound bound to Interface via interface-name),
// not the kernel — so only the interface name matters here. Sections/DNS pick
// VPNs by Name and pool them with subscription nodes under a proxy group.
type VPN struct {
	Name      string
	Enabled   bool
	Interface string
}

// Device maps one LAN device (by MAC) to a routing section — the LuCI
// Devices page's persistence model. MAC-based rather than IP-based so
// DHCP churn and IPv6 privacy addresses can't rot the assignment; the
// nftables side matches `ether saddr`, which only works for devices on
// the directly attached L2 segment (same limitation as fw4 MAC rules).
type Device struct {
	Name    string // display label snapshot (hostname at assignment time)
	MAC     string // lowercase aa:bb:cc:dd:ee:ff
	Section string // routing section name; empty = unassigned
	Enabled bool
	// Exclude bypasses purewrt entirely for this MAC (emits an early
	// `ether saddr <mac> return` in prerouting) — the device routes direct as
	// if purewrt weren't there. Mutually exclusive with Section.
	Exclude bool
}

type Section struct {
	Name                     string
	Enabled                  bool
	Action                   string
	TPROXYPort               int
	ProxyGroup               string
	ProxyGroupType           string
	ProxyFilter              string
	ProxyExcludeFilter       string
	ProxyStrategy            string
	ProxyHealthCheckURL      string
	ProxyHealthCheckInterval int
	UserOverriddenProxyGroup bool
	IPv4Enabled              bool
	IPv6Enabled              bool
	UDPMode                  string
	Priority                 int
	Mwan3Policy              string
	VPNs                     []string // VPN names whose interfaces join this section's proxy pool
	ZapretStrategies         []string
	SourceCIDR4              []string
	SourceCIDR6              []string
}

type Subscription struct {
	Name                     string
	Enabled                  bool
	URL                      string
	Mode                     string
	PresetIfNoRules          string
	ImportRulesOnLowResource bool
	AutoApply                bool
	Interval                 int
	HWID                     string
	DeviceName               string
	UserAgent                string
	Headers                  []string
	Mirrors                  []string
	PinSHA256                string
	// SuppressHWID disables router-derived HWID/device-name injection (URL
	// query + HTTP headers) for this subscription only. Use when the panel
	// operator isn't fully trusted, or to keep subscription fetches
	// indistinguishable across devices. Default false → existing behaviour.
	SuppressHWID bool
}

type ProxyProvider struct {
	Name                string
	Enabled             bool
	Type                string
	URL                 string
	Interval            int
	Path                string
	HealthCheck         bool
	HealthCheckURL      string
	HealthCheckInterval int
	Mwan3Policy         string
	HWID                string
	DeviceName          string
	UserAgent           string
	Headers             []string
	Mirrors             []string
	PinSHA256           string
	SuppressHWID        bool
}

type RuleProvider struct {
	Name                  string
	Enabled               bool
	Behavior              string
	Format                string
	ParseMode             string
	URL                   string
	Interval              int
	Path                  string
	Section               string
	Category              string
	SourceKind            string
	RouteAction           string
	Priority              int
	SourceSubscription    string
	DetectedCategory      string
	UserOverriddenSection bool
	UserOverriddenAction  bool
	HWID                  string
	DeviceName            string
	UserAgent             string
	Headers               []string
	Mirrors               []string
	PinSHA256             string
	SuppressHWID          bool
	LastError             string
	// GeoTarget is the v2ray-dat entry name (geosite category or geoip
	// country code) this provider extracts from
	// <Settings.GeoRefreshGeoIPDir>/{geosite,geoip}.dat. Set only when
	// Format is "geosite" or "geoip"; ignored otherwise. URL and Path
	// stay empty for geo-backed providers — the local dat file is the
	// source.
	GeoTarget             string
}

type Bypass struct {
	Name             string
	CIDR4            []string
	CIDR6            []string
	ProxyServerCIDR4 []string
	ProxyServerCIDR6 []string
	SourceCIDR4      []string
	SourceCIDR6      []string
}

// OONI configures the optional OONI Probe censorship-measurement runner.
// The probe runs via cron (not a daemon — `ooniprobe run unattended` is a
// oneshot) as a dedicated non-root user. Its backend/API traffic (check-in,
// upload) is routed through mihomo's mixed-port via the `--proxy` flag, while
// measurements go direct (OONI's `--proxy` is backend-only by design, and the
// nft OUTPUT-chain `skuid` exemption keeps the probe's direct sockets from
// being transparently TPROXY'd). ooniprobe is an optional 25.12 companion
// package; LuCI degrades gracefully when the binary is absent.
type OONI struct {
	Enabled  bool
	Upload   bool   // submit measurements to OONI's public archive
	Schedule string // cron expression for the run
	Proxy    string // --proxy value; mihomo mixed-port by default
	Home     string // OONI_HOME (config.json + measurement DB live here)
	User     string // dedicated non-root user the probe runs as

	// UID is resolved from User at apply time (getpwnam) and used for the
	// nft OUTPUT-chain `meta skuid` exemption. Not persisted to UCI; a zero
	// value means the user could not be resolved (treat OONI as inactive for
	// nft purposes so a stale enable flag can't break ruleset load).
	UID int
}

func Default() Config {
	return Config{
		Settings:         Settings{ConfigVersion: 1, Enabled: true, Workdir: DefaultWorkdir, RuntimeDir: DefaultRuntimeDir, DNSMasqIncludeDir: "", MihomoBin: "/usr/bin/mihomo", MihomoConfig: DefaultMihomoConfig, MihomoAllowLAN: false, ExternalController: "127.0.0.1:9090", Secret: "auto-generated-secret", DNSBackend: "dnsmasq", FirewallBackend: "nftables", FwMark: "0x1", FwMarkMask: "0xff", RouteTable: "100", IPRulePriority: "100", IPv6: true, DNSListen: "127.0.0.1:7874", AutoReload: true, SafeApply: true, RollbackOnFail: true, BackupRetention: 3, ApplyBackupMaxBytes: 0, MihomoChannel: "alpha", MihomoReleaseAPI: "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/Prerelease-Alpha", MihomoStableReleaseAPI: "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", MihomoMixinEnabled: false, MihomoAutoUpdateEnabled: false, MihomoAutoUpdateCron: "23 4 * * *", NetCheckEnabled: false, NetCheckCron: "", NetCheckBytes: 2 << 20, MihomoGeodataEnabled: false, UpdateViaProxy: false, UpdateProxyURL: "http://127.0.0.1:7890", UpdateConcurrency: 2, AutoUpdateEnabled: true, AutoUpdateCron: "17 */6 * * *", ReloadAfterUpdate: true, BackgroundUpdates: true, BootUpdateDelay: 0, UpdateNice: 19, UpdateIONiceClass: 3, UpdateIONiceLevel: 7, DashboardEnabled: true, DashboardListen: "0.0.0.0:9090", DashboardPath: "/etc/purewrt/dashboard", DashboardURL: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip", DashboardName: "metacubexd", DefaultListsBaseURL: "https://github.com/mglants/purewrt-lists/releases/latest/download/", ResourceProfile: "standard", CacheMode: "auto", CacheDir: "", ArtifactCacheMode: "auto", ArtifactCacheMaxBytes: 16777216, ArtifactCacheMaxEntries: 50000, RuleDedupMode: "auto", LogLevel: "warn", BootstrapDoHEnabled: true, BootstrapDoHResolvers: DefaultBootstrapDoHResolvers(), BootstrapDoHTimeoutMs: 8000, BootstrapProxyFallback: true, BootstrapTLSFingerprint: "browser", IPv6Mode: "auto", IPv6RejectWhenOff: false, RouterOutputProxy: true, CgroupV2Path: "services/mihomo", LANSourceZones: []string{"lan"}},
		DNS:              DNS{Enabled: true, Backend: "dnsmasq", UpstreamMode: "mihomo", HijackLANDNS: true, BlockDoT: true, BlockDoH3: true, BlockDoQ: true, DoH3BlockIPs4: DefaultDoH3BlockIPs4(), DoH3BlockIPs6: DefaultDoH3BlockIPs6(), DoHPolicy: "proxy", Listen: "127.0.0.1:7874", EnhancedMode: "normal", ProxyGroupType: "url-test", ProxyStrategy: "sticky-sessions", DoHUpstreams: []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"}, UDPUpstreams: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}},
		Mwan3:            Mwan3{Mode: "coexist", Detect: true, MMXMaskAuto: true, PureWRTMark: "0x1", PureWRTMask: "0xff", RulePriority: "100"},
		ZapretProfiles:   []ZapretProfile{{Name: "wan", Enabled: false, Network: "auto", Interfaces: []string{"wan"}, InterfaceMode: "mwan3_members", FwMark: "0x40000000", NFQWSBin: "/usr/libexec/zapret/nfqws2", TPWSBin: "/usr/libexec/zapret/tpws", LuaBundleDir: "/usr/libexec/zapret/lua"}},
		ZapretStrategies: []ZapretStrategy{{Name: "youtube_tcp", Enabled: false, Profile: "wan", Protocols: []string{"tcp"}, TCPPorts: "443", TCPPktOut: 15, TCPPktIn: 6, Preset: "youtube_tcp", Params: "--filter-tcp=443 --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5:ip_autottl=-2,3-20:ip6_autottl=-2,3-20 --lua-desync=multisplit:pos=midsld"}, {Name: "youtube_quic", Enabled: false, Profile: "wan", Protocols: []string{"udp"}, UDPPorts: "443", UDPPktOut: 9, UDPPktIn: 0, Preset: "youtube_quic", Params: "--filter-udp=443 --payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6:ip_autottl=-2,3-20:ip6_autottl=-2,3-20"}},
		// VPNs starts empty — the LuCI Sections page + VPN modal handle
		// the no-VPN-configured case cleanly (empty dropdown / "add VPN"
		// prompt). Shipping a placeholder `config vpn 'vpn'` led to users
		// finding a disabled stub in their config and wondering whether
		// it was theirs, vs. being able to add VPNs explicitly when they
		// want one.
		VPNs:             []VPN{},
		Sections:         []Section{{Name: "media", Enabled: true, Action: "proxy", TPROXYPort: 7894, ProxyGroup: "Media", ProxyGroupType: "url-test", ProxyStrategy: "sticky-sessions", IPv4Enabled: true, IPv6Enabled: true, UDPMode: "proxy", Priority: 10}, {Name: "ai", Enabled: true, Action: "proxy", TPROXYPort: 7895, ProxyGroup: "AI", ProxyGroupType: "url-test", ProxyStrategy: "sticky-sessions", IPv4Enabled: true, IPv6Enabled: true, UDPMode: "proxy", Priority: 20}, {Name: "common", Enabled: true, Action: "proxy", TPROXYPort: 7893, ProxyGroup: "Common", ProxyGroupType: "url-test", ProxyStrategy: "sticky-sessions", IPv4Enabled: true, IPv6Enabled: true, UDPMode: "proxy", Priority: 60}},
		Bypass:           Bypass{Name: "bypass"},
		OONI:             OONI{Enabled: false, Upload: true, Schedule: "0 */6 * * *", Proxy: "socks5://127.0.0.1:7890", Home: "/tmp/ooni", User: "ooniprobe"},
	}
}

// OONISettings returns the OONI config with empty fields filled from defaults,
// so generator/cron callers never emit a blank proxy/home/schedule/user.
func (c Config) OONISettings() OONI {
	o := c.OONI
	d := Default().OONI
	if o.Schedule == "" {
		o.Schedule = d.Schedule
	}
	if o.Proxy == "" {
		o.Proxy = d.Proxy
	}
	if o.Home == "" {
		o.Home = d.Home
	}
	if o.User == "" {
		o.User = d.User
	}
	return o
}

func (c Config) EnabledZapretProfiles() []ZapretProfile {
	out := []ZapretProfile{}
	for _, p := range c.ZapretProfiles {
		if p.Enabled && p.Name != "" {
			out = append(out, c.NormalizeZapretProfile(p))
		}
	}
	return out
}

func (c Config) NormalizeZapretProfile(p ZapretProfile) ZapretProfile {
	p.InterfaceMode = strings.ToLower(strings.TrimSpace(p.InterfaceMode))
	switch p.InterfaceMode {
	case "single", "network", "mwan3_members":
	case "":
		if p.Device != "" {
			p.InterfaceMode = "single"
		} else if (p.Network == "" || p.Network == "auto") && c.Mwan3.Detect {
			p.InterfaceMode = "mwan3_members"
		} else {
			p.InterfaceMode = "network"
		}
	default:
		p.InterfaceMode = "single"
	}
	if p.Network == "" {
		p.Network = "auto"
	}
	if p.NFQWSBin == "" {
		p.NFQWSBin = "/usr/libexec/zapret/nfqws2"
	}
	if p.LuaBundleDir == "" {
		p.LuaBundleDir = "/usr/libexec/zapret/lua"
	}
	if p.FwMark == "" {
		p.FwMark = "0x40000000"
	}
	p.Interfaces = normalizeInterfaceList(p.Interfaces)
	if len(p.Interfaces) == 0 {
		if p.Device != "" {
			p.Interfaces = []string{p.Device}
		} else if p.Network != "auto" {
			p.Interfaces = []string{p.Network}
		} else {
			p.Interfaces = []string{"wan"}
		}
	}
	return p
}

func normalizeInterfaceList(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

func (c Config) ZapretProfileByName(name string) (ZapretProfile, bool) {
	for _, p := range c.EnabledZapretProfiles() {
		if p.Name == name {
			return p, true
		}
	}
	return ZapretProfile{}, false
}

func (c Config) ZapretStrategyByName(name string) (ZapretStrategy, bool) {
	for i, s := range c.ZapretStrategies {
		if s.Name == name && s.Enabled {
			return c.NormalizeZapretStrategyAt(s, i), true
		}
	}
	return ZapretStrategy{}, false
}

func (c Config) NormalizeZapretStrategy(s ZapretStrategy) ZapretStrategy {
	return c.NormalizeZapretStrategyAt(s, -1)
}

func (c Config) NormalizeZapretStrategyAt(s ZapretStrategy, index int) ZapretStrategy {
	if s.Profile == "" {
		s.Profile = "wan"
	}
	if s.QueueNum == 0 && index >= 0 {
		s.QueueNum = ZapretQueueBase + index
	}
	if len(s.Protocols) == 0 {
		s.Protocols = []string{"tcp"}
	}
	if s.TCPPktOut == 0 {
		s.TCPPktOut = 15
	}
	if s.TCPPktIn == 0 {
		s.TCPPktIn = 6
	}
	if s.UDPPktOut == 0 {
		s.UDPPktOut = 9
	}
	return s
}

func (c Config) ResourceProfile() string {
	switch strings.ToLower(strings.TrimSpace(c.Settings.ResourceProfile)) {
	case "low":
		return "low"
	case "high":
		return "high"
	default:
		return "standard"
	}
}

func (c Config) LowResource() bool { return c.ResourceProfile() == "low" }

// IPv6Routed reports whether the bypass plane should emit IPv6 nftables /
// dnsmasq nftset / mihomo listener rules. The semantics:
//
//   - IPv6Mode "on": always on, ignoring resource profile.
//   - IPv6Mode "off": always off (and the user is opting into the explicit
//     v4-only path — independent of whether the device has a v6 default
//     route).
//   - IPv6Mode "auto" (or empty): legacy behaviour — on iff Settings.IPv6
//     is true and the resource profile is not low.
//
// This consolidates a previously-scattered idiom and makes the "silently
// disabled when LowResource()" footgun a deliberate choice.
func (c Config) IPv6Routed() bool {
	switch strings.ToLower(strings.TrimSpace(c.Settings.IPv6Mode)) {
	case "on":
		return true
	case "off":
		return false
	default:
		return c.Settings.IPv6 && !c.LowResource()
	}
}

func (c Config) HighResource() bool { return c.ResourceProfile() == "high" }

func (c Config) CacheDir() string {
	if strings.TrimSpace(c.Settings.CacheDir) != "" {
		return c.Settings.CacheDir
	}
	if c.LowResource() || strings.EqualFold(c.Settings.CacheMode, "tmpfs") {
		return filepath.Join(c.RuntimeDir(), "cache")
	}
	workdir := c.Settings.Workdir
	if workdir == "" {
		workdir = DefaultWorkdir
	}
	return filepath.Join(workdir, "cache")
}

func (c Config) RuntimeDir() string {
	if c.Settings.RuntimeDir != "" {
		return c.Settings.RuntimeDir
	}
	return DefaultRuntimeDir
}

func (c Config) VPNByName(name string) (VPN, bool) {
	for _, v := range c.VPNs {
		if v.Name == name {
			return v, true
		}
	}
	return VPN{}, false
}

// VPNForName returns the VPN with the given name if it is enabled and has an
// interface — the eligibility check for joining a mihomo proxy pool.
func (c Config) VPNForName(name string) (VPN, bool) {
	if name == "" {
		return VPN{}, false
	}
	for _, v := range c.VPNs {
		if v.Name == name {
			if v.Enabled && v.Interface != "" {
				return v, true
			}
			return VPN{}, false
		}
	}
	return VPN{}, false
}

func (c Config) SectionByName(name string) (Section, bool) {
	for _, s := range c.Sections {
		if s.Name == name {
			return s, true
		}
	}
	return Section{}, false
}

// NextTPROXYPort returns a free TPROXY listener port for a newly-created
// proxy section: one past the highest port already in use, with a base of
// 7896 so it never collides with the default sections (7893/7894/7895) or
// the lower mihomo ports (mixed 7890, dns 7874).
func (c Config) NextTPROXYPort() int {
	max := 7895
	for _, s := range c.Sections {
		if s.TPROXYPort > max {
			max = s.TPROXYPort
		}
	}
	return max + 1
}
func (s Section) ListenerName() string { return fmt.Sprintf("tproxy-%s", s.Name) }
func (s Section) NFTSet4() string {
	if s.Action == "direct" {
		return "direct4"
	}
	if s.Action == "reject" {
		return "reject4"
	}
	return "proxy_" + s.Name + "4"
}
func (s Section) NFTSet6() string {
	if s.Action == "direct" {
		return "direct6"
	}
	if s.Action == "reject" {
		return "reject6"
	}
	return "proxy_" + s.Name + "6"
}
