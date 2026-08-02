package manager

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mesh"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/mihomoapi"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/proxyguard"
)

// LiveMetrics renders gauges whose values are authoritative only at scrape
// time. They deliberately do not live in metrics-state.json: countdowns,
// file ages, nftset sizes and proxy-guard membership would otherwise freeze
// at the last CLI operation.
func (m Manager) LiveMetrics(c config.Config) string {
	r := metrics.NewRegistry()
	recordLiveConfigMetrics(r, c)
	m.recordLiveServiceMetrics(r, c)
	m.recordLiveMeshMetrics(r, c)
	recordLiveUpgradeMetrics(r, c)
	recordLiveNFTMetrics(r, c)
	recordLiveProxyGuardMetrics(r, c)
	return r.Render()
}

func recordLiveConfigMetrics(r *metrics.Registry, c config.Config) {
	expiry := r.NewGauge("purewrt_subscription_min_seconds_to_expiry", "Minimum seconds-to-expiry across all enabled subscriptions; negative = expired")
	expiryAt := r.NewGauge("purewrt_subscription_min_expiry_timestamp_seconds", "Unix timestamp of the earliest enabled subscription expiry")
	if seconds, ok := minSubscriptionSecondsToExpiry(c); ok {
		expiry.Set(seconds)
		expiryAt.Set(float64(time.Now().Add(time.Duration(seconds * float64(time.Second))).Unix()))
	}

	geoModified := r.NewGauge("purewrt_geodata_modified_timestamp_seconds", "Unix modification timestamp of each geodata file", "dataset")
	for dataset, modified := range geodataModTimes(c) {
		geoModified.Set(float64(modified.Unix()), dataset)
	}

	recordLiveProviderMetrics(r, c)

	r.NewGauge("purewrt_zapret_strategies_active", "Number of enabled zapret strategies in the compiled NFQWS2_OPT").Set(float64(countEnabledZapretStrategies(c)))
}

func geodataModTimes(c config.Config) map[string]time.Time {
	dir := c.Settings.GeoRefreshGeoIPDir
	if dir == "" {
		dir = "/etc/purewrt/geo"
	}
	files := map[string]string{"geoip": "geoip.dat", "geosite": "geosite.dat", "mmdb": "country.mmdb"}
	out := make(map[string]time.Time, len(files))
	for dataset, name := range files {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			out[dataset] = info.ModTime()
		}
	}
	return out
}

func recordLiveProviderMetrics(r *metrics.Registry, c config.Config) {
	updateSuccess := r.NewGauge("purewrt_provider_update_success", "Whether the provider's latest update attempt succeeded (1=yes, 0=no)", "provider", "type")
	lastAttempt := r.NewGauge("purewrt_provider_last_attempt_timestamp_seconds", "Unix timestamp of the provider's latest update attempt", "provider", "type")
	lastSuccess := r.NewGauge("purewrt_provider_last_success_timestamp_seconds", "Unix timestamp of the provider's latest successful update", "provider", "type")
	entries := r.NewGauge("purewrt_provider_entries", "Current known entry count for an enabled provider", "provider", "type")

	for _, rp := range c.RuleProviders {
		if !rp.Enabled {
			continue
		}
		count := localEntryCount(rp)
		if meta, ok := readProviderMetadata(rp.Path); ok {
			if meta.EntryCount > 0 {
				count = meta.EntryCount
			}
			recordProviderFreshness(updateSuccess, lastAttempt, lastSuccess, meta, rp.Name, "rule")
		} else if rp.URL != "" || provider.IsGeoFormat(rp.Format) {
			updateSuccess.Set(0, rp.Name, "rule")
		}
		entries.Set(float64(count), rp.Name, "rule")
	}
	for _, pp := range c.ProxyProviders {
		if !pp.Enabled {
			continue
		}
		count := 0
		if meta, ok := readProviderMetadata(pp.Path); ok {
			count = meta.EntryCount
			recordProviderFreshness(updateSuccess, lastAttempt, lastSuccess, meta, pp.Name, "proxy")
		} else if pp.URL != "" {
			updateSuccess.Set(0, pp.Name, "proxy")
		}
		if count == 0 {
			count = proxyProviderFileEntryCount(pp.Path)
		}
		entries.Set(float64(count), pp.Name, "proxy")
	}

	expires := r.NewGauge("purewrt_subscription_expiry_timestamp_seconds", "Unix expiry timestamp advertised by an enabled subscription", "subscription")
	used := r.NewGauge("purewrt_subscription_used_bytes", "Bytes used according to an enabled subscription's latest metadata", "subscription")
	total := r.NewGauge("purewrt_subscription_total_bytes", "Total quota bytes according to an enabled subscription's latest metadata", "subscription")
	for _, subscription := range c.Subscriptions {
		if !subscription.Enabled || subscription.URL == "" {
			continue
		}
		path := filepath.Join(c.Settings.Workdir, "providers", subscription.Name+".yaml")
		meta, err := provider.ReadMetadata(path)
		if err != nil {
			continue
		}
		if !meta.SubExpire.IsZero() {
			expires.Set(float64(meta.SubExpire.Unix()), subscription.Name)
		}
		used.Set(float64(meta.SubUsedBytes), subscription.Name)
		total.Set(float64(meta.SubTotalBytes), subscription.Name)
	}
}

func proxyProviderFileEntryCount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return provider.AnalyzeContent(path, data).ProxyNodes
}

func recordProviderFreshness(updateSuccess, lastAttempt, lastSuccess *metrics.Gauge, meta provider.Metadata, name, providerType string) {
	updateSuccess.Set(boolFloat(!meta.LastSuccess.IsZero() && meta.ErrorMessage == ""), name, providerType)
	if !meta.LastUpdate.IsZero() {
		lastAttempt.Set(float64(meta.LastUpdate.Unix()), name, providerType)
	}
	if !meta.LastSuccess.IsZero() {
		lastSuccess.Set(float64(meta.LastSuccess.Unix()), name, providerType)
	}
}

type controllerMetricCacheEntry struct {
	at time.Time
	up bool
}

var controllerMetricCache = struct {
	sync.Mutex
	entries map[string]controllerMetricCacheEntry
}{entries: map[string]controllerMetricCacheEntry{}}

func (m Manager) recordLiveServiceMetrics(r *metrics.Registry, c config.Config) {
	key := localControllerAddr(c) + "\x00" + c.Settings.Secret
	controllerMetricCache.Lock()
	entry, ok := controllerMetricCache.entries[key]
	if !ok || time.Since(entry.at) >= 15*time.Second {
		entry = controllerMetricCacheEntry{
			at: time.Now(),
			up: (mihomoapi.Client{Base: localControllerAddr(c), Secret: c.Settings.Secret}).ReachableWithin(time.Second),
		}
		controllerMetricCache.entries[key] = entry
	}
	controllerMetricCache.Unlock()
	statuses := serviceStatuses()
	statuses = append(statuses, zapretServiceStatuses(c)...)
	if c.MeshActive() {
		bin := c.Mesh.EasytierBin
		if bin == "" {
			bin = config.DefaultMesh().EasytierBin
		}
		statuses = append(statuses, serviceStatusForProcess("mesh", filepath.Base(bin)))
	}
	recordServiceMetrics(r, statuses, entry.up)
}

func zapretServiceStatuses(c config.Config) []ServiceStatus {
	procs := zapretProcs()
	seen := map[string]bool{}
	var statuses []ServiceStatus
	for _, section := range c.Sections {
		if !section.Enabled || section.Action != "zapret" {
			continue
		}
		for i, name := range section.ZapretStrategies {
			if seen[name] {
				continue
			}
			strategy, ok := c.ZapretStrategyByName(name)
			if !ok {
				continue
			}
			seen[name] = true
			strategy = c.NormalizeZapretStrategyAt(strategy, i)
			serviceName := "zapret/" + strategy.Name
			if pid := procs[strategy.QueueNum]; pid > 0 {
				statuses = append(statuses, serviceStatusForPID(serviceName, pid))
			} else {
				statuses = append(statuses, ServiceStatus{Name: serviceName})
			}
		}
	}
	return statuses
}

func recordServiceMetrics(r *metrics.Registry, statuses []ServiceStatus, controllerUp bool) {
	up := r.NewGauge("purewrt_service_up", "Whether a managed service process is running (1=yes, 0=no)", "service")
	started := r.NewGauge("purewrt_service_start_time_seconds", "Unix timestamp when a running managed service process started", "service")
	for _, status := range statuses {
		up.Set(boolFloat(status.PID > 0), status.Name)
		if status.PID > 0 && status.StartedUnix > 0 {
			started.Set(float64(status.StartedUnix), status.Name)
		}
	}
	r.NewGauge("purewrt_mihomo_controller_up", "Whether the authenticated mihomo controller is reachable (1=yes, 0=no)").Set(boolFloat(controllerUp))
}

type liveMeshSnapshot struct {
	overlayOK bool
	peers     map[string]mesh.OverlayPeer
	exitOK    bool
	exits     map[string]mihomoapi.Proxy
}

type liveMeshCacheEntry struct {
	at       time.Time
	snapshot liveMeshSnapshot
}

var liveMeshCache = struct {
	sync.Mutex
	entries map[string]liveMeshCacheEntry
}{entries: map[string]liveMeshCacheEntry{}}

func (m Manager) recordLiveMeshMetrics(r *metrics.Registry, c config.Config) {
	r.NewGauge("purewrt_mesh_active", "Whether the friends mesh is configured and active (1=yes, 0=no)").Set(boolFloat(c.MeshActive()))
	r.NewGauge("purewrt_mesh_local_exit_enabled", "Whether this router offers its proxy exit to mesh friends (1=yes, 0=no)").Set(boolFloat(c.MeshActive() && c.Mesh.ExitEnabled))
	if !c.MeshActive() {
		return
	}
	recordMeshMetrics(r, c, m.collectLiveMeshSnapshot(c))
}

func (m Manager) collectLiveMeshSnapshot(c config.Config) liveMeshSnapshot {
	key := c.RuntimeDir() + "\x00" + c.Mesh.RPCPortal + "\x00" + localControllerAddr(c)
	liveMeshCache.Lock()
	defer liveMeshCache.Unlock()
	if cached, ok := liveMeshCache.entries[key]; ok && time.Since(cached.at) < 15*time.Second {
		return cached.snapshot
	}

	snapshot := liveMeshSnapshot{peers: map[string]mesh.OverlayPeer{}, exits: map[string]mihomoapi.Proxy{}}
	cli := m.meshCLI(c)
	if cli.Run == nil {
		cli.Run = liveMeshRunner
	}
	if peers, err := cli.Peers(); err == nil {
		snapshot.overlayOK = true
		for _, peer := range peers {
			snapshot.peers[peer.IPv4] = peer
		}
	}
	if proxies, err := (mihomoapi.Client{Base: localControllerAddr(c), Secret: c.Settings.Secret}).Proxies(); err == nil {
		snapshot.exitOK = true
		snapshot.exits = proxies
	}
	liveMeshCache.entries[key] = liveMeshCacheEntry{at: time.Now(), snapshot: snapshot}
	return snapshot
}

func liveMeshRunner(bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bin, args...).Output()
}

func recordMeshMetrics(r *metrics.Registry, c config.Config, snapshot liveMeshSnapshot) {
	collection := r.NewGauge("purewrt_mesh_collection_success", "Whether a live friends-mesh source was collected successfully (1=yes, 0=no)", "source")
	collection.Set(boolFloat(snapshot.overlayOK), "overlay")
	collection.Set(boolFloat(snapshot.exitOK), "mihomo")
	friends := r.NewGauge("purewrt_mesh_friends", "Number of configured mesh friends by current state", "state")
	info := r.NewGauge("purewrt_mesh_friend_info", "Configured mesh friend identity", "friend", "hwid", "overlay_ip")
	enabled := r.NewGauge("purewrt_mesh_friend_enabled", "Whether this friend's exit is enabled locally (1=yes, 0=no)", "friend", "hwid")
	linkUp := r.NewGauge("purewrt_mesh_friend_link_up", "Whether the EasyTier overlay link to a friend is up (1=yes, 0=no)", "friend", "hwid")
	linkInfo := r.NewGauge("purewrt_mesh_friend_link_info", "Current EasyTier link type to a friend", "friend", "hwid", "link")
	latency := r.NewGauge("purewrt_mesh_friend_latency_milliseconds", "Current EasyTier link latency to a friend in milliseconds", "friend", "hwid")
	exitOffered := r.NewGauge("purewrt_mesh_friend_exit_offered", "Whether a friend advertises an exit (1=yes, 0=no)", "friend", "hwid")
	exitUp := r.NewGauge("purewrt_mesh_friend_exit_up", "Whether an enabled advertised friend exit is healthy in mihomo (1=yes, 0=no)", "friend", "hwid")
	exitDelay := r.NewGauge("purewrt_mesh_friend_exit_delay_milliseconds", "Latest mihomo health-check delay through a friend exit in milliseconds", "friend", "hwid")

	liveCount := 0
	healthyExitCount := 0
	for _, friend := range c.MeshPeers {
		info.Set(1, friend.Name, friend.HWID, friend.OverlayIP)
		enabled.Set(boolFloat(friend.Enabled), friend.Name, friend.HWID)
		exitOffered.Set(boolFloat(friend.ExitOffered), friend.Name, friend.HWID)
		peer, live := snapshot.peers[friend.OverlayIP]
		if friend.OverlayIP == "" {
			live = false
		}
		linkUp.Set(boolFloat(live), friend.Name, friend.HWID)
		link := "down"
		if live {
			liveCount++
			link = "direct"
			if peer.Relay {
				link = "relay"
			}
			if peer.LatencyMs > 0 {
				latency.Set(peer.LatencyMs, friend.Name, friend.HWID)
			}
		}
		linkInfo.Set(1, friend.Name, friend.HWID, link)

		if !snapshot.exitOK || !friend.Enabled || !friend.ExitOffered || friend.OverlayIP == "" {
			continue
		}
		proxyName := meshFriendProxyName(friend.HWID)
		proxy, found := snapshot.exits[proxyName]
		healthy := found && proxy.Alive
		exitUp.Set(boolFloat(healthy), friend.Name, friend.HWID)
		if healthy {
			healthyExitCount++
		}
		if found && proxy.Delay > 0 {
			exitDelay.Set(float64(proxy.Delay), friend.Name, friend.HWID)
		}
	}
	friends.Set(float64(len(c.MeshPeers)), "configured")
	friends.Set(float64(liveCount), "live")
	friends.Set(float64(healthyExitCount), "exit_healthy")
}

func meshFriendProxyName(hwid string) string {
	if !meshHWIDRE.MatchString(hwid) {
		return ""
	}
	return "friend_" + strings.TrimPrefix(hwid, "purewrt-")
}

type liveUpgradeCacheEntry struct {
	at      time.Time
	checked time.Time
	rows    []PackageUpdate
	ok      bool
}

var liveUpgradeCache = struct {
	sync.Mutex
	entries map[string]liveUpgradeCacheEntry
}{entries: map[string]liveUpgradeCacheEntry{}}

func recordLiveUpgradeMetrics(r *metrics.Registry, c config.Config) {
	liveUpgradeCache.Lock()
	defer liveUpgradeCache.Unlock()
	entry, ok := liveUpgradeCache.entries[c.RuntimeDir()]
	if !ok || time.Since(entry.at) >= 5*time.Minute {
		entry.rows, entry.ok = localPackageUpdates()
		entry.at = time.Now()
		entry.checked = entry.at
		liveUpgradeCache.entries[c.RuntimeDir()] = entry
	}
	recordUpgradeMetrics(r, entry.rows, entry.ok, entry.checked)
}

// localPackageUpdates reads only apk's local installed/upgradable views. It
// must never run `apk update`: a Prometheus scrape cannot mutate package state
// or block on the network. The LuCI refresh action owns index refreshes.
func localPackageUpdates() ([]PackageUpdate, bool) {
	if _, err := exec.LookPath("apk"); err != nil {
		return nil, false
	}
	installed, err := apkListInstalled()
	if err != nil {
		return nil, false
	}
	data, err := exec.Command("apk", "list", "-u").Output()
	if err != nil {
		return nil, false
	}
	available := parseApkList(data)
	rows := make([]PackageUpdate, 0, len(packagesToTrack))
	for _, name := range packagesToTrack {
		installedVersion, present := installed[name]
		if !present {
			continue
		}
		availableVersion := available[name]
		rows = append(rows, PackageUpdate{
			Name:             name,
			Installed:        installedVersion,
			Available:        availableVersion,
			UpgradeAvailable: availableVersion != "" && installedVersion != availableVersion,
		})
	}
	return rows, true
}

func recordUpgradeMetrics(r *metrics.Registry, rows []PackageUpdate, ok bool, checked time.Time) {
	r.NewGauge("purewrt_upgrade_check_success", "Whether the local apk upgrade view was collected successfully (1=yes, 0=no)").Set(boolFloat(ok))
	if !checked.IsZero() {
		r.NewGauge("purewrt_upgrade_check_timestamp_seconds", "Unix timestamp of the latest local apk upgrade check").Set(float64(checked.Unix()))
	}
	available := r.NewGauge("purewrt_upgrade_available", "Whether an installed PureWRT-related package has an upgrade in the local apk index (1=yes, 0=no)", "package")
	for _, row := range rows {
		available.Set(boolFloat(row.UpgradeAvailable), row.Name)
	}
}

type nftMetricTarget struct {
	section string
	family  string
	set     string
}

func recordLiveNFTMetrics(r *metrics.Registry, c config.Config) {
	cardinality := r.NewGauge("purewrt_nftset_cardinality", "Current element count per dnsmasq-populated section nftset", "section", "family")
	collectorOK := r.NewGauge("purewrt_nftset_collection_success", "Whether live PureWRT nftset cardinalities were collected successfully (1=yes, 0=no)")
	targets := nftMetricTargets(c)
	entries, ok := collectNFTMetricEntries(c.RuntimeDir(), targets)
	if !ok {
		collectorOK.Set(0)
		return
	}
	collectorOK.Set(1)
	for _, target := range targets {
		cardinality.Set(float64(entries[target.set]), target.section, target.family)
	}
}

type nftMetricCacheEntry struct {
	at        time.Time
	targetKey string
	entries   map[string]int
	ok        bool
}

const liveNFTCollectionTimeout = 5 * time.Second

var nftMetricCache = struct {
	sync.Mutex
	byRuntime map[string]nftMetricCacheEntry
}{byRuntime: map[string]nftMetricCacheEntry{}}

// nft set enumeration can be non-trivial on a small router. Cache one
// collection for 30 seconds so a HA Prometheus pair or a dashboard refresh
// cannot repeatedly serialize the same dynamic sets.
func collectNFTMetricEntries(runtimeDir string, targets []nftMetricTarget) (map[string]int, bool) {
	nftMetricCache.Lock()
	defer nftMetricCache.Unlock()
	targetKey := nftMetricTargetsKey(targets)
	if cached, ok := nftMetricCache.byRuntime[runtimeDir]; ok && time.Since(cached.at) < 30*time.Second && cached.targetKey == targetKey {
		return cached.entries, cached.ok
	}
	ctx, cancel := context.WithTimeout(context.Background(), liveNFTCollectionTimeout)
	defer cancel()
	entries := map[string]int{}
	ok := true
	for _, target := range targets {
		data, err := exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", "purewrt", target.set).Output()
		if err != nil {
			ok = false
			break
		}
		sets := parseNFTJSONSetStats(data)
		stat, found := sets[target.set]
		if !found {
			ok = false
			break
		}
		entries[target.set] = stat.Entries
	}
	nftMetricCache.byRuntime[runtimeDir] = nftMetricCacheEntry{at: time.Now(), targetKey: targetKey, entries: entries, ok: ok}
	return entries, ok
}

func nftMetricTargetsKey(targets []nftMetricTarget) string {
	var b strings.Builder
	for _, target := range targets {
		b.WriteString(target.set)
		b.WriteByte(0)
	}
	return b.String()
}

func nftMetricTargets(c config.Config) []nftMetricTarget {
	base := []struct {
		section string
		set4    string
		set6    string
	}{
		{"bypass", "dns_bypass4", "dns_bypass6"},
		{"proxy_server_bypass", "dns_proxy_server_bypass4", "dns_proxy_server_bypass6"},
		{"direct", "dns_direct4", "dns_direct6"},
		{"reject", "dns_reject4", "dns_reject6"},
	}
	seen := map[string]bool{}
	var out []nftMetricTarget
	add := func(section, family, set string) {
		key := section + "\x00" + family
		if set != "" && !seen[key] {
			seen[key] = true
			out = append(out, nftMetricTarget{section: section, family: family, set: set})
		}
	}
	for _, item := range base {
		add(item.section, "ipv4", item.set4)
		if c.IPv6Routed() {
			add(item.section, "ipv6", item.set6)
		}
	}
	for _, section := range c.Sections {
		if !section.Enabled || (section.Action != "proxy" && section.Action != "zapret") {
			continue
		}
		add(section.Name, "ipv4", "dns_"+section.NFTSet4())
		if c.IPv6Routed() {
			add(section.Name, "ipv6", "dns_"+section.NFTSet6())
		}
	}
	return out
}

func recordLiveProxyGuardMetrics(r *metrics.Registry, c config.Config) {
	r.NewGauge("purewrt_proxy_guard_enabled", "Whether adaptive proxy guard is enabled (1=yes, 0=no)").Set(boolFloat(c.Settings.ProxyGuardEnabled))
	valid := r.NewGauge("purewrt_proxy_guard_state_valid", "Whether proxy-guard runtime state loaded successfully (1=yes, 0=no)")
	state, err := proxyguard.Load(c)
	if err != nil {
		valid.Set(0)
		return
	}
	valid.Set(1)
	if !c.Settings.ProxyGuardEnabled {
		return
	}
	if !state.LastRun.IsZero() {
		r.NewGauge("purewrt_proxy_guard_state_last_run_timestamp_seconds", "Unix timestamp represented by the current proxy-guard routing state").Set(float64(state.LastRun.Unix()))
	}

	members := r.NewGauge("purewrt_proxy_guard_members", "Current concrete proxy-guard members by state and kind", "state", "kind")
	untested := r.NewGauge("purewrt_proxy_guard_untested_members", "Current members without a completed real-transfer probe")
	groupMembers := r.NewGauge("purewrt_proxy_guard_group_members", "Current proxy-guard group membership by role", "group", "role")
	nodeInfo := r.NewGauge("purewrt_proxy_guard_node_info", "Current proxy-guard member identity and state", "node", "provider", "kind", "state", "reason")
	nodeDown := r.NewGauge("purewrt_proxy_guard_node_download_kbps", "Last measured proxy-guard node download throughput in kbps", "node")
	nodeDelay := r.NewGauge("purewrt_proxy_guard_node_delay_ms", "Last measured proxy-guard node latency in milliseconds", "node")
	nodeJitter := r.NewGauge("purewrt_proxy_guard_node_jitter_ms", "Current proxy-guard node latency jitter in milliseconds", "node")
	nodeProbe := r.NewGauge("purewrt_proxy_guard_node_last_probe_timestamp_seconds", "Unix timestamp of the last real-transfer probe for a node", "node")
	nodeQuarantined := r.NewGauge("purewrt_proxy_guard_node_quarantined_at_timestamp_seconds", "Unix timestamp when a node entered quarantine", "node")
	nodeRetry := r.NewGauge("purewrt_proxy_guard_node_retry_after_timestamp_seconds", "Unix timestamp after which a quarantined node may be recovery-probed", "node")
	nodeBadStreak := r.NewGauge("purewrt_proxy_guard_node_bad_streak", "Current consecutive bad-signal streak for a node", "node")
	nodeRecoveryStreak := r.NewGauge("purewrt_proxy_guard_node_recovery_streak", "Current consecutive clean recovery-probe streak for a node", "node")

	counts := map[string]int{}
	untestedCount := 0
	for name, node := range state.Nodes {
		if node == nil {
			continue
		}
		kind := node.Kind
		if kind == "" {
			kind = "proxy"
		}
		stateName := proxyGuardMetricState(node.State)
		counts[stateName+"\x00"+kind]++
		if node.LastProbe.IsZero() {
			untestedCount++
		}
		reason := proxyGuardMetricReason(node.Reason)
		nodeInfo.Set(1, name, node.Provider, kind, stateName, reason)
		if !node.LastProbe.IsZero() {
			nodeDown.Set(node.LastDownKbps, name)
			nodeProbe.Set(float64(node.LastProbe.Unix()), name)
		}
		if len(node.LatenciesMS) > 0 {
			nodeDelay.Set(float64(node.LastDelayMS), name)
			nodeJitter.Set(float64(node.JitterMS), name)
		}
		if !node.QuarantinedAt.IsZero() {
			nodeQuarantined.Set(float64(node.QuarantinedAt.Unix()), name)
		}
		if !node.RetryAfter.IsZero() {
			nodeRetry.Set(float64(node.RetryAfter.Unix()), name)
		}
		nodeBadStreak.Set(float64(node.BadStreak), name)
		nodeRecoveryStreak.Set(float64(node.RecoveryStreak), name)
	}
	for key, count := range counts {
		stateName, kind, _ := strings.Cut(key, "\x00")
		members.Set(float64(count), stateName, kind)
	}
	untested.Set(float64(untestedCount))

	for name, group := range state.Groups {
		if group == nil {
			continue
		}
		membersInGroup := make(map[string]bool, len(group.Members))
		for _, member := range group.Members {
			membersInGroup[member] = true
		}
		quarantined := 0
		for member := range membersInGroup {
			if node := state.Nodes[member]; node != nil && node.State == proxyguard.Quarantined {
				quarantined++
			}
		}
		lastResortSet := make(map[string]bool, len(group.LastResorts))
		for _, member := range group.LastResorts {
			if membersInGroup[member] {
				if node := state.Nodes[member]; node != nil && node.State == proxyguard.Quarantined {
					lastResortSet[member] = true
				}
			}
		}
		candidates := len(membersInGroup)
		lastResort := len(lastResortSet)
		groupMembers.Set(float64(candidates), name, "candidate")
		groupMembers.Set(float64(candidates-quarantined+lastResort), name, "effective")
		groupMembers.Set(float64(quarantined-lastResort), name, "excluded")
		groupMembers.Set(float64(lastResort), name, "last_resort")
	}
}

func proxyGuardMetricState(state string) string {
	switch state {
	case proxyguard.Healthy, proxyguard.Suspect, proxyguard.Quarantined:
		return state
	default:
		return "unknown"
	}
}

func proxyGuardMetricReason(reason string) string {
	reason = strings.ToLower(reason)
	switch {
	case reason == "":
		return "none"
	case strings.Contains(reason, "latency"):
		return "latency"
	case strings.Contains(reason, "probe failed"):
		return "probe_error"
	case strings.Contains(reason, "download"):
		return "throughput"
	case strings.Contains(reason, "recovery"):
		return "recovery"
	default:
		return "other"
	}
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

// MetricsStatePath is the atomic persistent event registry read by the API.
func MetricsStatePath(c config.Config) string {
	return filepath.Join(c.RuntimeDir(), "metrics-state.json")
}
