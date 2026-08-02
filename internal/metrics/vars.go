package metrics

// Process-wide metric vars exposed by PureWRT. Product metrics intentionally
// use gauges for current/latest state and histograms for duration
// distributions; cumulative event counters are not exported.

// DurationBucketsSeconds preserves sub-millisecond work while retaining
// enough range for full generation of large provider sets on small routers.
var DurationBucketsSeconds = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// OperationDurationBucketsSeconds covers slower end-to-end router operations
// such as apply while retaining useful resolution for quick no-op runs.
var OperationDurationBucketsSeconds = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 180}

var (
	// ResolverProbeSuccess is the latest probe state for each configured
	// bootstrap resolver. Old endpoint labels are reconciled on every probe.
	ResolverProbeSuccess = NewGauge("purewrt_resolver_probe_success", "Whether the latest bootstrap resolver probe succeeded (1=yes, 0=no)", "endpoint")

	// GenerateDurationSeconds covers the complete WriteAllToResult call,
	// including fingerprint/cache work. result is generated|cache_hit|error.
	GenerateDurationSeconds = NewHistogram("purewrt_generate_duration_seconds", "Complete generator duration in seconds by result", DurationBucketsSeconds, "result")

	// GenerateStageDurationSeconds measures the complete executed stage,
	// including computation/streaming and its output write. stage is one of
	// rule_outputs|mihomo|dnsmasq|nft|nftsets|firewall|mwan3|zapret|easytier.
	GenerateStageDurationSeconds = NewHistogram("purewrt_generate_stage_duration_seconds", "Generator stage duration in seconds", DurationBucketsSeconds, "stage")

	// ApplyDurationSeconds — end-to-end `purewrt apply` latency histogram.
	ApplyDurationSeconds = NewHistogram("purewrt_apply_duration_seconds", "Apply pipeline duration in seconds", OperationDurationBucketsSeconds)
	ApplyLastAttempt     = NewGauge("purewrt_apply_last_attempt_timestamp_seconds", "Unix timestamp of the last apply attempt")
	ApplyLastSuccess     = NewGauge("purewrt_apply_last_success_timestamp_seconds", "Unix timestamp of the last successful apply")
	ApplyLastRunSuccess  = NewGauge("purewrt_apply_last_run_success", "Whether the last apply attempt succeeded (1=yes, 0=no)")

	// Latest update-job state spans the short-lived CLI processes that perform
	// subscription/provider, geodata, mihomo, and mesh maintenance.
	UpdateLastAttempt     = NewGauge("purewrt_update_last_attempt_timestamp_seconds", "Unix timestamp of the latest update job attempt", "job")
	UpdateLastSuccess     = NewGauge("purewrt_update_last_success_timestamp_seconds", "Unix timestamp of the latest successful update job run", "job")
	UpdateLastRunSuccess  = NewGauge("purewrt_update_last_run_success", "Whether the latest update job run succeeded (1=yes, 0=no)", "job")
	UpdateLastRunDuration = NewGauge("purewrt_update_last_run_duration_seconds", "Duration of the latest update job run in seconds", "job")

	// --- net-check (set by Manager.NetCheck on each interactive/cron run) ---

	// NetCheckDownloadKbps / NetCheckUploadKbps — last measured real
	// throughput through the proxy mixed-port (kilobits/sec). A node passing
	// url-test but reading ~0 here is throttled/broken — the signal url-test
	// can't surface. 0 = the probe failed/timed out.
	NetCheckDownloadKbps = NewGauge("purewrt_netcheck_download_kbps", "Last net-check download throughput via proxy (kbps)")
	NetCheckUploadKbps   = NewGauge("purewrt_netcheck_upload_kbps", "Last net-check upload throughput via proxy (kbps)")

	// NetCheckDirectDomesticKbps — direct (no proxy) throughput to a domestic
	// endpoint; gates WAN liveness independent of foreign censorship.
	NetCheckDirectDomesticKbps = NewGauge("purewrt_netcheck_direct_domestic_kbps", "Last net-check direct domestic throughput (kbps)")

	// NetCheckVerdict — 1 if the last run's overall verdict was "ok", else 0.
	NetCheckVerdict = NewGauge("purewrt_netcheck_verdict", "Last net-check overall verdict (1=ok, 0=fail)")

	// NetCheckLastRun — unix seconds of the last net-check run; lets a scraper
	// alert on staleness (cron stopped firing).
	NetCheckLastRun = NewGauge("purewrt_netcheck_last_run_timestamp_seconds", "Unix timestamp of the last net-check run")

	// NetCheckLayerStatus exposes exactly one current status sample per layer.
	// NetCheckNodeStatus does the same for the latest --per-node run.
	NetCheckLayerStatus = NewGauge("purewrt_netcheck_layer_status", "Latest net-check layer status (the current layer/status pair has value 1)", "layer", "status")
	NetCheckNodeStatus  = NewGauge("purewrt_netcheck_node_status", "Latest per-node net-check status (the current node/status pair has value 1)", "node", "status")

	// --- adaptive proxy guard latest operation state ---
	// Membership and measurements are rendered directly from proxy-guard.json.
	ProxyGuardLastAttempt            = NewGauge("purewrt_proxy_guard_last_attempt_timestamp_seconds", "Unix timestamp of the last proxy-guard attempt")
	ProxyGuardLastSuccess            = NewGauge("purewrt_proxy_guard_last_success_timestamp_seconds", "Unix timestamp of the last successful proxy-guard run")
	ProxyGuardLastRunSuccess         = NewGauge("purewrt_proxy_guard_last_run_success", "Whether the last proxy-guard attempt succeeded (1=yes, 0=no)")
	ProxyGuardLastRunDurationSeconds = NewGauge("purewrt_proxy_guard_last_run_duration_seconds", "Duration of the last proxy-guard attempt in seconds")
)
