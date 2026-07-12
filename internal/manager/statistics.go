package manager

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/rules"
)

type Statistics struct {
	LastUpdate                     string                 `json:"last_update"`
	ResourceProfile                string                 `json:"resource_profile"`
	Cache                          CacheStatistics        `json:"cache"`
	VPNRoutes                      []VPNRouteStatistics   `json:"vpn_routes"`
	SkippedSubscriptionRuleImports int                    `json:"skipped_subscription_rule_imports"`
	RuleProviders                  []ProviderStatistics   `json:"rule_providers"`
	ProxyProviders                 []ProviderStatistics   `json:"proxy_providers"`
	NFTables                       []NFTSetStatistics     `json:"nftables"`
	DNSMasq                        []DNSMasqSetStatistics `json:"dnsmasq"`
	Services                       []ServiceStatus        `json:"services"`
}

type ServiceStatus struct {
	Name        string `json:"name"`
	PID         int    `json:"pid,omitempty"`
	StartedUnix int64  `json:"started_unix,omitempty"`
	UptimeSec   int64  `json:"uptime_sec,omitempty"`
}

type VPNRouteStatistics struct {
	Name       string `json:"name"`
	Interface  string `json:"interface"`
	RouteTable string `json:"route_table"`
	Enabled    bool   `json:"enabled"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

type CacheStatistics struct {
	Mode       string `json:"mode"`
	Dir        string `json:"dir"`
	Bytes      int64  `json:"bytes"`
	Entries    int    `json:"entries"`
	MaxBytes   int64  `json:"max_bytes"`
	MaxEntries int    `json:"max_entries"`
}

type ProviderStatistics struct {
	Name        string `json:"name"`
	URL         string `json:"url,omitempty"`
	Path        string `json:"path,omitempty"`
	Section     string `json:"section,omitempty"`
	Action      string `json:"action,omitempty"`
	Enabled     bool   `json:"enabled"`
	EntryCount  int    `json:"entry_count,omitempty"`
	LastUpdate  string `json:"last_update,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	Error       string `json:"error,omitempty"`
}

type NFTSetStatistics struct {
	Set         string `json:"set"`
	Description string `json:"description"`
	Bytes       int64  `json:"bytes"`
	Entries     int    `json:"entries"`
	// HitPackets / HitBytes mirror the named-counter nftables maintains for
	// each set: one counter per set, incremented by every chain rule that
	// references @<set>. Reset on each `nft -f` apply.
	HitPackets uint64 `json:"hit_packets"`
	HitBytes   uint64 `json:"hit_bytes"`
}

type DNSMasqSetStatistics struct {
	Set     string              `json:"set"`
	Loaded  bool                `json:"loaded"`
	Entries int                 `json:"entries"`
	Items   []DNSMasqSetElement `json:"items,omitempty"`
	Error   string              `json:"error,omitempty"`
	// HitPackets / HitBytes — same shape as NFTSetStatistics; dynamic (dns_*)
	// sets each get their own counter via the consumer rules that match them.
	HitPackets uint64   `json:"hit_packets"`
	HitBytes   uint64   `json:"hit_bytes"`
	Sample     []string `json:"sample,omitempty"`
	Limited    bool     `json:"limited,omitempty"`
}

type DNSMasqSetElement struct {
	IP      string `json:"ip"`
	Timeout int    `json:"timeout"`
}

func (m Manager) StatisticsJSON() (string, error) {
	c, err := m.Load()
	if err != nil {
		return "", err
	}
	s := Statistics{ResourceProfile: c.ResourceProfile(), Cache: CacheStatistics{Mode: c.Settings.CacheMode, Dir: c.CacheDir(), MaxBytes: c.Settings.ArtifactCacheMaxBytes, MaxEntries: c.Settings.ArtifactCacheMaxEntries}}
	if cacheStats, err := provider.CleanupArtifacts(c.CacheDir(), provider.CacheLimits{}); err == nil {
		s.Cache.Bytes = cacheStats.Bytes
		s.Cache.Entries = cacheStats.Entries
	}
	if c.LowResource() {
		for _, sub := range c.Subscriptions {
			if sub.Enabled && !sub.ImportRulesOnLowResource {
				s.SkippedSubscriptionRuleImports++
			}
		}
	}
	s.VPNRoutes = vpnRouteStats(c)
	latest := time.Time{}
	for _, rp := range c.RuleProviders {
		ps := ProviderStatistics{Name: rp.Name, URL: rp.URL, Path: rp.Path, Section: rp.Section, Action: effectiveSectionAction(c, rp.Section), Enabled: rp.Enabled}
		if meta, ok := readProviderMetadata(rp.Path); ok {
			ps.LastUpdate = formatTime(meta.LastUpdate)
			ps.LastSuccess = formatTime(meta.LastSuccess)
			ps.Error = meta.ErrorMessage
			ps.EntryCount = meta.EntryCount
			if meta.LastUpdate.After(latest) {
				latest = meta.LastUpdate
			}
		}
		// Manual / locally-edited text providers are never fetched, so they
		// have no .meta.json and report EntryCount=0. Count their rules from
		// the file so they show up in statistics like URL-backed providers.
		if ps.EntryCount == 0 {
			ps.EntryCount = localEntryCount(rp)
		}
		s.RuleProviders = append(s.RuleProviders, ps)
	}
	for _, pp := range c.ProxyProviders {
		ps := ProviderStatistics{Name: pp.Name, URL: pp.URL, Path: pp.Path, Enabled: pp.Enabled}
		if meta, ok := readProviderMetadata(pp.Path); ok {
			ps.LastUpdate = formatTime(meta.LastUpdate)
			ps.LastSuccess = formatTime(meta.LastSuccess)
			ps.Error = meta.ErrorMessage
			if meta.LastUpdate.After(latest) {
				latest = meta.LastUpdate
			}
		}
		s.ProxyProviders = append(s.ProxyProviders, ps)
	}
	if !latest.IsZero() {
		s.LastUpdate = latest.Format("02.01.2006-15:04")
	}
	s.NFTables = nftStats(c)
	s.DNSMasq = dnsmasqStats(c)
	s.Services = serviceStatuses()
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// localEntryCount counts rules in a rule-provider's local file for providers
// that never get downloaded metadata — manual providers (and any locally
// edited text list) carry no .meta.json, so their EntryCount would otherwise
// read 0 in statistics. Mirrors the text parser's rule count so the number
// matches what URL-backed text providers report. native_import and binary
// (mrs) / geo formats are left to their metadata.
func localEntryCount(rp config.RuleProvider) int {
	if rp.Path == "" || rp.ParseMode == "native_import" {
		return 0
	}
	switch rp.Format {
	case "", "text":
		// countable below
	default:
		return 0
	}
	data, err := os.ReadFile(rp.Path)
	if err != nil {
		return 0
	}
	return len(rules.ParseText(rp.Name, data).Rules)
}

func effectiveSectionAction(c config.Config, section string) string {
	if sec, ok := c.SectionByName(section); ok && sec.Action != "" {
		return sec.Action
	}
	return ""
}

func readProviderMetadata(path string) (provider.Metadata, bool) {
	data, err := os.ReadFile(path + ".meta.json")
	if err != nil {
		return provider.Metadata{}, false
	}
	var meta provider.Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return provider.Metadata{}, false
	}
	return meta, true
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("02.01.2006-15:04")
}

func nftStats(c config.Config) []NFTSetStatistics {
	sets := map[string]string{"bypass4": "bypass IPv4", "bypass6": "bypass IPv6", "direct4": "direct IPv4", "direct6": "direct IPv6", "reject4": "reject IPv4", "reject6": "reject IPv6"}
	for _, sec := range c.Sections {
		sets[sec.NFTSet4()] = sec.Name + " " + sec.Action + " IPv4"
		sets[sec.NFTSet6()] = sec.Name + " " + sec.Action + " IPv6"
	}
	setNames := make([]string, 0, len(sets))
	for set := range sets {
		setNames = append(setNames, set)
	}
	active := activeNFTSetStats(setNames)
	counters := nftCounterStats()
	var out []NFTSetStatistics
	for set, desc := range sets {
		st := active[set]
		if st.Set == "" {
			st = NFTSetStatistics{Set: set, Bytes: fileSize("/var/run/purewrt/" + set + ".set"), Entries: countSetElements("/var/run/purewrt/" + set + ".set")}
		}
		st.Description = desc
		if ctr, ok := counters[set]; ok {
			st.HitPackets = ctr.Packets
			st.HitBytes = ctr.Bytes
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Set < out[j].Set })
	return out
}

// nftCounter is the parsed shape of one named counter from `nft -j list
// counters`. We only care about the running totals — handle/family/table can
// be inferred from context.
type nftCounter struct {
	Packets uint64
	Bytes   uint64
}

// nftCounterStats returns one counter per set name (e.g. proxy_common4,
// dns_proxy_common4). Empty map when the table isn't loaded or nft is
// unavailable; callers tolerate missing entries as zero-valued counters so
// the stats page degrades gracefully on a fresh install or after a manual
// `nft flush`.
func nftCounterStats() map[string]nftCounter {
	out := map[string]nftCounter{}
	if !nftPureWRTTableLoaded() {
		return out
	}
	data, err := exec.Command("nft", "-j", "list", "counters", "table", "inet", "purewrt").Output()
	if err != nil {
		return out
	}
	return parseNFTJSONCounters(data)
}

func parseNFTJSONCounters(data []byte) map[string]nftCounter {
	var root struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	out := map[string]nftCounter{}
	for _, item := range root.NFTables {
		raw, ok := item["counter"]
		if !ok {
			continue
		}
		var ctr struct {
			Name    string `json:"name"`
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
		}
		if err := json.Unmarshal(raw, &ctr); err != nil || ctr.Name == "" {
			continue
		}
		out[ctr.Name] = nftCounter{Packets: ctr.Packets, Bytes: ctr.Bytes}
	}
	return out
}

func activeNFTSetStats(sets []string) map[string]NFTSetStatistics {
	out := map[string]NFTSetStatistics{}
	if !nftPureWRTTableLoaded() {
		return out
	}
	for _, set := range sets {
		data, err := exec.Command("nft", "-j", "list", "set", "inet", "purewrt", set).Output()
		if err == nil {
			for name, st := range parseNFTJSONSetStats(data) {
				out[name] = st
			}
		}
	}
	return out
}

func parseNFTJSONSetStats(data []byte) map[string]NFTSetStatistics {
	var root struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	out := map[string]NFTSetStatistics{}
	for _, item := range root.NFTables {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var set struct {
			Name     string            `json:"name"`
			Elem     []json.RawMessage `json:"elem"`
			Elements []json.RawMessage `json:"elements"`
		}
		if err := json.Unmarshal(raw, &set); err != nil || set.Name == "" {
			continue
		}
		entries := len(set.Elem)
		if entries == 0 {
			entries = len(set.Elements)
		}
		out[set.Name] = NFTSetStatistics{Set: set.Name, Bytes: int64(len(raw)), Entries: entries}
	}
	return out
}

func dnsSetStats(c config.Config) []DNSMasqSetStatistics {
	sets := dnsmasqDNSSetNames(c)
	out := make([]DNSMasqSetStatistics, 0, len(sets))
	if !nftPureWRTTableLoaded() {
		for _, set := range sets {
			out = append(out, DNSMasqSetStatistics{Set: set, Error: "not loaded"})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Set < out[j].Set })
		return out
	}
	counters := nftCounterStats()
	for _, set := range sets {
		st := DNSMasqSetStatistics{Set: set}
		data, err := exec.Command("nft", "-j", "list", "set", "inet", "purewrt", set).Output()
		if err != nil {
			st.Error = "not loaded"
			out = append(out, st)
			continue
		}
		items, count := parseDNSMasqNFTJSONSet(data, 200)
		st.Loaded = true
		st.Items = items
		st.Entries = count
		st.Limited = count > len(items)
		if ctr, ok := counters[set]; ok {
			st.HitPackets = ctr.Packets
			st.HitBytes = ctr.Bytes
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Set < out[j].Set })
	return out
}

func dnsmasqStats(c config.Config) []DNSMasqSetStatistics { return dnsSetStats(c) }

func nftPureWRTTableLoaded() bool {
	data, err := exec.Command("nft", "list", "tables").Output()
	return err == nil && strings.Contains(string(data), "table inet purewrt")
}

func dnsmasqDNSSetNames(c config.Config) []string {
	seen := map[string]bool{}
	add := func(set string) {
		if set != "" {
			seen["dns_"+set] = true
		}
	}
	for _, set := range []string{"bypass4", "proxy_server_bypass4", "direct4", "reject4"} {
		add(set)
	}
	if c.Settings.IPv6 && !c.LowResource() {
		for _, set := range []string{"bypass6", "proxy_server_bypass6", "direct6", "reject6"} {
			add(set)
		}
	}
	for _, sec := range c.Sections {
		if sec.Action == "proxy" || sec.Action == "zapret" {
			add(sec.NFTSet4())
			if c.Settings.IPv6 && !c.LowResource() {
				add(sec.NFTSet6())
			}
		}
	}
	out := make([]string, 0, len(seen))
	for set := range seen {
		out = append(out, set)
	}
	sort.Strings(out)
	return out
}

func parseDNSMasqNFTJSONSet(data []byte, limit int) ([]DNSMasqSetElement, int) {
	var root struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, 0
	}
	var out []DNSMasqSetElement
	count := 0
	for _, item := range root.NFTables {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var set struct {
			Elem     []json.RawMessage `json:"elem"`
			Elements []json.RawMessage `json:"elements"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			continue
		}
		elems := set.Elem
		if len(elems) == 0 {
			elems = set.Elements
		}
		for _, elem := range elems {
			count++
			if limit > 0 && len(out) >= limit {
				continue
			}
			if v, ok := parseDNSMasqNFTJSONElement(elem); ok {
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timeout < out[j].Timeout })
	return out, count
}

func parseDNSMasqNFTJSONElement(data json.RawMessage) (DNSMasqSetElement, bool) {
	var wrapped struct {
		Elem struct {
			Val     string `json:"val"`
			Expires int    `json:"expires"`
		} `json:"elem"`
		Val     string `json:"val"`
		Expires int    `json:"expires"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		var s string
		if err := json.Unmarshal(data, &s); err == nil && s != "" {
			return DNSMasqSetElement{IP: s}, true
		}
		return DNSMasqSetElement{}, false
	}
	if wrapped.Elem.Val != "" {
		return DNSMasqSetElement{IP: wrapped.Elem.Val, Timeout: wrapped.Elem.Expires}, true
	}
	if wrapped.Val != "" {
		return DNSMasqSetElement{IP: wrapped.Val, Timeout: wrapped.Expires}, true
	}
	return DNSMasqSetElement{}, false
}

// vpnRouteStats reports each VPN interface's liveness. VPNs are now mihomo
// `direct` outbounds (interface-name) rather than kernel routing tables, so
// "healthy" just means the interface exists and is up; mihomo's own url-test
// (dashboard) reflects per-VPN reachability.
func vpnRouteStats(c config.Config) []VPNRouteStatistics {
	var out []VPNRouteStatistics
	for _, v := range c.VPNs {
		st := VPNRouteStatistics{Name: v.Name, Interface: v.Interface, Enabled: v.Enabled}
		if !v.Enabled {
			st.OK = true
			out = append(out, st)
			continue
		}
		if v.Interface == "" {
			st.Error = "missing interface"
			out = append(out, st)
			continue
		}
		if err := exec.Command("ip", "link", "show", "dev", v.Interface, "up").Run(); err != nil {
			st.Error = "interface down"
		} else {
			st.OK = true
		}
		out = append(out, st)
	}
	return out
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func countSetElements(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(data), ",") + strings.Count(string(data), "\n")
}

func serviceStatuses() []ServiceStatus {
	return []ServiceStatus{serviceStatusFor("mihomo"), serviceStatusFor("purewrt-api")}
}

// serviceStatusFor probes /proc/<pid>/stat to derive the wall-clock uptime of
// a procd-managed service. Returns an entry with just Name set if the
// process isn't running or /proc isn't readable — the caller renders that as
// "stopped" rather than erroring out.
//
// For "mihomo" we deliberately bypass busybox `pidof`: when the running
// binary is a GitHub-installed one named "mihomo-Prerelease-Alpha" or
// "mihomo-alpha-d08c885", its /proc/<pid>/comm gets truncated to 15
// chars (TASK_COMM_LEN), so `pidof mihomo` returns nothing and the
// General page shows the service as "stopped" even when it's running.
// mihomoPID() walks /proc and confirms via /proc/<pid>/exe basename,
// which holds the untruncated path.
func serviceStatusFor(name string) ServiceStatus {
	s := ServiceStatus{Name: name}
	var pid int
	if name == "mihomo" {
		pid = mihomoPID()
	} else {
		out, err := exec.Command("pidof", name).Output()
		if err != nil {
			return s
		}
		fields := strings.Fields(strings.TrimSpace(string(out)))
		if len(fields) == 0 {
			return s
		}
		p, err := strconv.Atoi(fields[0])
		if err != nil || p <= 0 {
			return s
		}
		pid = p
	}
	if pid <= 0 {
		return s
	}
	s.PID = pid
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return s
	}
	// /proc/<pid>/stat: pid (comm) state ... — the comm field is in parens
	// and may contain spaces, so split on the last ")".
	line := string(statBytes)
	closeParen := strings.LastIndex(line, ")")
	if closeParen < 0 {
		return s
	}
	rest := strings.Fields(line[closeParen+1:])
	// starttime is field 22 of /proc/<pid>/stat. We've already consumed pid
	// (1) and comm (2), so it's index 19 in `rest`.
	if len(rest) < 20 {
		return s
	}
	startTicks, err := strconv.ParseInt(rest[19], 10, 64)
	if err != nil {
		return s
	}
	uptimeBytes, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return s
	}
	uptimeFields := strings.Fields(string(uptimeBytes))
	if len(uptimeFields) == 0 {
		return s
	}
	sysUptimeF, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return s
	}
	sysUptime := int64(sysUptimeF)
	// HZ=100 is the OpenWrt default; if a custom kernel changes CONFIG_HZ
	// the uptime will be off by a constant factor (not load-bearing).
	const HZ int64 = 100
	procStartSec := startTicks / HZ
	procUptime := sysUptime - procStartSec
	if procUptime < 0 {
		procUptime = 0
	}
	bootTime := time.Now().Unix() - sysUptime
	s.StartedUnix = bootTime + procStartSec
	s.UptimeSec = procUptime
	return s
}
