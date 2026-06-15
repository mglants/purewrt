package metrics

// Process-wide metric vars exposed by PureWRT. Defined here so call sites
// can `metrics.ApplyTotal.WithLabelValues("ok")` without juggling registration
// order. Adding a new metric: declare it in this file with a clear HELP
// string, then increment / Set from the relevant package.

// DurationBucketsMS is the shared latency bucket layout (milliseconds).
var DurationBucketsMS = []float64{10, 50, 100, 250, 500, 1000, 5000}

var (
	// ApplyTotal — count of `purewrt apply` invocations, labelled by outcome
	// ("ok" | "rollback" | "error"). Reading: success rate of the apply
	// pipeline, useful for alerting on a sudden flood of rollbacks.
	ApplyTotal = NewCounter("purewrt_apply_total", "Apply attempts by outcome", "result")

	// ProviderDownloadTotal — count of provider/subscription fetches by
	// outcome ("ok" | "not_modified" | "error" | "mirror_failover").
	// Tracks transport health: spike of "error" means the bootstrap path
	// is degraded.
	ProviderDownloadTotal = NewCounter("purewrt_provider_download_total", "Provider download outcomes", "result")

	// ResolversHealth — 1 if the latest DoH/DoQ/DoT probe to the labelled
	// endpoint succeeded, 0 otherwise. Set by Manager.ResolversProbe at
	// each apply (when bootstrap_health_gate=1) and by manual probes.
	// (Per-endpoint gauge would need labels; we expose it as a counter
	// of probe outcomes instead — same alerting signal.)
	ResolversProbeTotal = NewCounter("purewrt_resolvers_probe_total", "DoH resolver probe outcomes", "endpoint", "result")

	// GenerateDurationMS — generator latency histogram, labelled by
	// generation group (mihomo, openwrt_bundle, firewall, mwan3, zapret).
	// PromQL: histogram_quantile(0.95, rate(purewrt_generate_duration_ms_bucket[1h])).
	GenerateDurationMS = NewHistogram("purewrt_generate_duration_ms", "Generator duration in ms by group", DurationBucketsMS, "group")

	// ApplyDurationMS — end-to-end `purewrt apply` latency histogram.
	ApplyDurationMS = NewHistogram("purewrt_apply_duration_ms", "Apply pipeline duration in ms", DurationBucketsMS)

	// SubscriptionSecondsToExpiry — time until each subscription expires.
	// Single Gauge instance per subscription (we cheat label-wise by
	// updating one shared gauge; see SubscriptionExpiry helpers below for
	// the labelled variant).
	SubscriptionMinSecondsToExpiry = NewGauge("purewrt_subscription_min_seconds_to_expiry", "Minimum seconds-to-expiry across all enabled subscriptions; negative = expired")

	// GeoDataAgeSeconds — age of the most recently refreshed geoip.dat /
	// geosite.dat file. Cron-driven update; alerting threshold ~7 days.
	GeoDataAgeSeconds = NewGauge("purewrt_geoip_data_age_seconds", "Age of the newest geo data file on disk")

	// NFTSetCardinality — how many entries each section's nftset holds.
	// Surfaces "dnsmasq stopped populating set" outages quickly.
	NFTSetCardinality = NewCounter("purewrt_nftset_cardinality", "Element count per section nftset (counter; reset on regenerate)", "section", "family")

	// ZapretStrategiesActive — count of enabled zapret_strategy sections.
	// One-shot gauge; set on apply.
	ZapretStrategiesActive = NewGauge("purewrt_zapret_strategies_active", "Number of enabled zapret strategies in the compiled NFQWS2_OPT")
)
