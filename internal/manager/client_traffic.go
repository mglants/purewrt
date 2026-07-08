package manager

// ClientTraffic — observe a LAN client's blocked flows by joining
// conntrack state with live packet inspection. The router sees every
// packet the client sends/receives because it's the default gateway,
// even when the client isn't in PureWRT's source list.
//
// Five signal sources, joined per (proto, dst_ip, dst_port):
//   1. /proc/net/nf_conntrack — flow state + [UNREPLIED] flag
//   2. DNS query/reply pairs (from packet inspection, not dnsmasq toggle)
//   3. ICMP type 3 (destination unreachable) — the "actively rejected" signal
//   4. TCP RST — distinguishes peer-rejection from silent-drop
//   5. TLS ClientHello SNI — hostname even when DoH/DoT hides DNS
//
// All packet sources come from one tcpdump subprocess piping pcap bytes
// to stdin. Lifetime is tied to ctx — ctx cancel propagates as SIGKILL
// to tcpdump via exec.CommandContext. No persistent state, no UCI mutation.
//
// Split across files:
//   client_traffic.go        — shared types, entry points, dedup, orchestration
//   client_traffic_pcap.go   — pcap reader + packet/DNS/TLS/QUIC decoding
//   client_traffic_flow.go   — conntrack parsing + flow classification
//   client_traffic_enrich.go — hostname / nftset / ASN enrichment state

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/purewrt/purewrt/internal/ipdb"
)

// Event is one piece of the report stream. Type identifies the payload;
// Data is the JSON encoding of one of the *Data structs below.
type Event struct {
	Type      string          `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// StreamOpts tunes a ClientTrafficStream session. Zero values are safe.
type StreamOpts struct {
	EveryConntrack time.Duration // how often to tick conntrack (default 2s)
	LANInterface   string        // empty → auto-detect via UCI
	Verbose        bool          // include healthy flows in conntrack snapshots
}

// FlowSummary is one conntrack flow's projection into the report.
type FlowSummary struct {
	Proto     string `json:"proto"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	SrcPort   int    `json:"src_port,omitempty"`
	State     string `json:"state,omitempty"`
	Unreplied bool   `json:"unreplied,omitempty"`
	Assured   bool   `json:"assured,omitempty"`
	Offload   bool   `json:"offload,omitempty"`
	Lopsided  bool   `json:"lopsided,omitempty"`
	// Stalled marks a flow where the connection got established (TCP
	// handshake completed, or UDP/QUIC client kept sending) but the server
	// went silent after at most one reply packet — the DPI/SNI
	// post-handshake-drop fingerprint. Unlike Unreplied (no reply at all)
	// this catches drops that happen *after* the handshake, which would
	// otherwise render as a healthy ESTABLISHED flow.
	Stalled bool `json:"stalled,omitempty"`
	// Frozen marks a download-shaped ESTABLISHED flow that received real
	// reply data and then made ZERO reply progress for a sustained window
	// (~10s) while the connection stayed open — the DPI mid-stream-cut
	// fingerprint. This is a delta-based signal computed in emitConntrack
	// (flowSummaryFor can't see it). Surfaced as a *soft* signal because it
	// can't be cleanly distinguished from a legitimate idle keep-alive.
	Frozen       bool   `json:"frozen,omitempty"`
	OrigPackets  int    `json:"orig_packets"`
	OrigBytes    int64  `json:"orig_bytes"`
	ReplyPackets int    `json:"reply_packets"`
	ReplyBytes   int64  `json:"reply_bytes"`
	Hostname     string `json:"hostname,omitempty"`
	TTLRem       int    `json:"ttl_rem,omitempty"`
	// Nftsets lists the PureWRT nftset memberships of DestIP (e.g.
	// "direct", "proxy_common", "reject"). Tells the user where this
	// destination is currently classified — if a flow is UNREPLIED AND
	// it's in "proxy_common", the section's proxy is failing rather than
	// the ISP blocking the destination outright. Empty means the dest
	// goes through the default route.
	Nftsets []string `json:"nftsets,omitempty"`
	// Bogon flags flows whose destination is on a private / link-local /
	// multicast / loopback / broadcast / CGNAT / test-net prefix. These
	// are never "blocked externally" — they're LAN broadcast probes (KDE
	// Connect, mDNS), self-traffic, etc. UI hides them by default; a
	// toggle brings them back when the user is debugging LAN issues.
	Bogon bool `json:"bogon,omitempty"`
	// ASN/ASOrg/Country come from the offline iptoasn database (loaded
	// when the user has installed it via `purewrt ipdb-update`). All three
	// empty when the DB isn't installed or the IP isn't in the routing
	// table — the LuCI side renders them only when non-zero so missing
	// enrichment is silent rather than visually noisy.
	ASN     uint32 `json:"asn,omitempty"`
	ASOrg   string `json:"as_org,omitempty"`
	Country string `json:"country,omitempty"`
}

type ConntrackSnapshotData struct {
	Flows       []FlowSummary `json:"flows"`
	TotalFlows  int           `json:"total_flows"`
	SkippedIPv6 int           `json:"skipped_ipv6,omitempty"`
}

type DNSQueryData struct {
	Client   string `json:"client"`
	Server   string `json:"server"`
	QType    string `json:"qtype"`
	Hostname string `json:"hostname"`
	ID       int    `json:"id"`
	Source   string `json:"source"` // "dns" or "mdns"
}

type DNSReplyData struct {
	Client   string   `json:"client"`
	Hostname string   `json:"hostname"`
	Answers  []string `json:"answers"`
	ID       int      `json:"id"`
}

// rejectEnrichment is embedded into every rejection event so the LuCI side
// can render the same nftset / ASN / country / hostname context that flows
// already show. The relevant IP is event-type-specific (ICMP: original
// dest; TCP RST: from; QUIC retry: dest) but the fields are uniform.
type rejectEnrichment struct {
	Hostname string   `json:"hostname,omitempty"`
	Nftsets  []string `json:"nftsets,omitempty"`
	ASN      uint32   `json:"asn,omitempty"`
	ASOrg    string   `json:"as_org,omitempty"`
	Country  string   `json:"country,omitempty"`
}

type ICMPUnreachableData struct {
	From          string `json:"from"`
	To            string `json:"to"`
	Code          int    `json:"code"`
	CodeText      string `json:"code_text"`
	OriginalDest  string `json:"original_dest,omitempty"`
	OriginalPort  int    `json:"original_port,omitempty"`
	OriginalProto string `json:"original_proto,omitempty"`
	// Source attributes the ICMP sender: "peer" when the unreachable came
	// from the destination the client was trying to reach, "middlebox"
	// when an intermediate hop (router, carrier, DPI appliance) sent it.
	// Empty when the inner IP header was truncated and the original
	// destination is unknown.
	Source string `json:"source,omitempty"`
	// Bogon = true when the sender (From) is on a bogon prefix OR the
	// original destination (the host the client was trying to reach) is.
	// Almost always means "your own router or a LAN device responded" —
	// noise for "what's blocked externally". UI hides these unless the
	// showBogons toggle is on.
	Bogon bool `json:"bogon,omitempty"`
	rejectEnrichment
}

type TCPRSTData struct {
	From     string `json:"from"`
	FromPort int    `json:"from_port"`
	To       string `json:"to"`
	ToPort   int    `json:"to_port"`
	Source   string `json:"source"` // "peer" or "middlebox"
	// Bogon = RST came from a bogon prefix (your router, a LAN service).
	// Usually self-traffic or LAN broadcast noise, not external rejection.
	Bogon bool `json:"bogon,omitempty"`
	rejectEnrichment
}

type SNIData struct {
	Client   string `json:"client"`
	Dest     string `json:"dest"`
	DestPort int    `json:"dest_port"`
	SNI      string `json:"sni"`
	Proto    string `json:"proto"`
}

type QUICRetryData struct {
	Client        string `json:"client"`
	Dest          string `json:"dest"`
	DestPort      int    `json:"dest_port"`
	InitialCount  int    `json:"initial_count"`
	WindowSeconds int    `json:"window_seconds"`
	// Bogon = client was retrying QUIC to a bogon prefix. Means the
	// destination is on the LAN (almost certainly self-inflicted), not an
	// external block.
	Bogon bool `json:"bogon,omitempty"`
	rejectEnrichment
}

type WarningData struct {
	Message string `json:"message"`
}

type ErrorData struct {
	Message string `json:"message"`
}

// ClientTrafficStream runs the long-running collector. emit is called
// from internal goroutines and MUST be safe for concurrent use. Returns
// when ctx is cancelled or an unrecoverable error occurs.
func (m Manager) ClientTrafficStream(ctx context.Context, clientIP string, opts StreamOpts, emit func(Event)) error {
	if opts.EveryConntrack == 0 {
		opts.EveryConntrack = 2 * time.Second
	}
	// Collapse the ~2-3× duplicates tcpdump emits per packet on br-lan
	// (one observation per bridge port the packet visits). 1 s window is
	// wide enough for any plausible replication delay and tight enough to
	// keep legitimate repeat events (a client re-sending the same DNS
	// query a few seconds apart) visible.
	emit = newDedupCache(1 * time.Second).wrap(emit)

	ip := net.ParseIP(clientIP)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4: %q", clientIP)
	}
	clientIP = ip.To4().String()

	if _, err := exec.LookPath("tcpdump"); err != nil {
		emit(makeEvent("error", ErrorData{Message: "tcpdump not installed; install with: apk add tcpdump-mini"}))
		return fmt.Errorf("tcpdump not in PATH: %w", err)
	}

	iface := opts.LANInterface
	if iface == "" {
		iface = detectLANInterface(clientIP)
	}
	if iface == "" {
		return fmt.Errorf("could not determine LAN interface; pass StreamOpts.LANInterface")
	}

	// Shared hostname enrichment state populated by DNS replies + SNI extracts.
	hostnames := &hostnameMap{m: make(map[string][]string)}

	// Per-session nftset snapshot. Refreshed every 10s in a background
	// goroutine so the UI knows which set (direct / reject / proxy_<section>)
	// currently claims each destination — useful for distinguishing
	// "section proxy is broken" from "ISP is blocking the dest."
	nftsets := newNftsetEnricher()
	go nftsets.runRefreshLoop(ctx, 10*time.Second)

	// Offline IP→ASN database, loaded once per session if installed. Stays
	// nil when the user hasn't run `purewrt ipdb-update` — the conntrack
	// emitter handles nil gracefully and the UI surfaces a one-shot
	// "install for ASN enrichment" hint instead. Path follows the
	// configured Workdir so non-default installs use their own slot.
	c, _ := m.Load()
	ipdbPath := ipdb.GZPath(c.Settings.Workdir)
	// Load the ASN DB in the background so a slow/contended ipdb.Load never
	// delays the first conntrack snapshot. Capture starts immediately;
	// enrichment kicks in once the DB is ready (asnHolder is nil-safe).
	asndb := &asnHolder{}
	go func() {
		if db, err := ipdb.Load(ipdbPath); err == nil {
			asndb.set(db)
		} else if !os.IsNotExist(err) {
			emit(makeEvent("warning", WarningData{Message: "ipdb load failed: " + err.Error()}))
		} else {
			emit(makeEvent("warning", WarningData{Message: "IP database not installed — run `purewrt ipdb-update` for ASN/country/org enrichment"}))
		}
	}()

	// QUIC retry detector — sliding window of UDP/443 outbound packets per dst.
	quicRetries := &quicRetryTracker{
		retries: make(map[string]*quicRetryState),
		window:  2 * time.Second,
		minHits: 3,
	}

	// Conntrack ticker goroutine.
	var prev map[string]*ctEntry
	tickerDone := make(chan struct{})
	go func() {
		defer close(tickerDone)
		tick := time.NewTicker(opts.EveryConntrack)
		defer tick.Stop()
		// Emit the first snapshot immediately so the UI has something to show.
		prev = emitConntrack(clientIP, prev, hostnames, nftsets, asndb, opts.Verbose, emit)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				prev = emitConntrack(clientIP, prev, hostnames, nftsets, asndb, opts.Verbose, emit)
			}
		}
	}()

	// tcpdump pcap subprocess — one filter covering DNS, ICMP, TCP RST,
	// TLS ClientHellos on 443, and QUIC Initials on UDP/443.
	bpf := fmt.Sprintf(
		"host %s and ("+
			"port 53 or port 5353 or "+ // DNS / mDNS
			"icmp or "+ // ICMP unreachable
			"(tcp and tcp[tcpflags] & tcp-rst != 0) or "+ // TCP RST
			"(tcp port 443) or "+ // TLS SNI
			"(udp port 443)"+ // QUIC
			")",
		clientIP)
	cmd := exec.CommandContext(ctx, "tcpdump",
		"-lnp", "-i", iface, "-s", "512", "-w", "-",
		"-U", // unbuffered: flush each packet immediately
		bpf,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("tcpdump stdout pipe: %w", err)
	}
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("tcpdump start: %w", err)
	}

	// Drain stderr to keep tcpdump from blocking on a full pipe.
	go func() {
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			// First few stderr lines are tcpdump banners; rare runtime errors
			// after that get logged but don't fail the session.
			_ = s.Text()
		}
	}()

	enr := &packetEnrichers{
		hostnames: hostnames,
		nftsets:   nftsets,
		asndb:     asndb,
		quic:      quicRetries,
	}
	// Stop promptly on deadline/cancel: killing tcpdump alone sometimes leaves
	// runPcapReader blocked in io.ReadFull (idle client → no EOF delivered
	// quickly), so the session overran its --max-seconds by a wide margin.
	// Closing stdout here forces the blocked read to return at once.
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			_ = stdout.Close()
		case <-stopped:
		}
	}()
	pcapErr := runPcapReader(stdout, clientIP, enr, emit)
	close(stopped)

	// On reader exit, ensure subprocess is dead and conntrack ticker stops.
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	<-tickerDone

	if pcapErr != nil && ctx.Err() == nil {
		return fmt.Errorf("pcap reader: %w", pcapErr)
	}
	emit(makeEvent("done", nil))
	return nil
}

// --- helpers --------------------------------------------------------------

func makeEvent(typ string, data any) Event {
	ev := Event{Type: typ, Timestamp: time.Now().UTC()}
	if data != nil {
		b, _ := json.Marshal(data)
		ev.Data = b
	}
	return ev
}

func detectLANInterface(clientIP string) string {
	// Best: the interface the client is actually reachable on. Handles VLANs
	// and bridges — e.g. a client on br-lan.2 while network.lan.device is a
	// bridge port like lan1, in which case tcpdump on lan1 would miss its
	// packet-level events (DNS/SNI/RST).
	if clientIP != "" {
		if out, err := exec.Command("ip", "-o", "route", "get", clientIP).Output(); err == nil {
			if dev := routeDev(string(out)); dev != "" {
				return dev
			}
		}
	}
	// Next: the configured LAN device.
	out, err := exec.Command("uci", "-q", "get", "network.lan.device").Output()
	if err == nil {
		s := strings.TrimSpace(string(out))
		if s != "" {
			return s
		}
	}
	// Fallback: first br-* interface.
	entries, _ := os.ReadDir("/sys/class/net")
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "br-") {
			return e.Name()
		}
	}
	return ""
}

// routeDev extracts the "dev X" token from `ip route get` output, e.g.
// "192.168.214.212 dev br-lan.2 src 192.168.214.1 uid 0" → "br-lan.2".
func routeDev(s string) string {
	fields := strings.Fields(s)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// --- emit-side dedup -----------------------------------------------------
//
// tcpdump on br-lan sees the same packet once per bridge port it visits,
// so a single mDNS broadcast or TLS ClientHello often arrives 2-3 times
// with near-identical timestamps. Without dedup the DNS panel and SNI
// stream end up triplicated. We collapse near-duplicates per
// (type, identity) within a small time window.

type dedupCache struct {
	mu     sync.Mutex
	last   map[string]time.Time
	window time.Duration
}

func newDedupCache(window time.Duration) *dedupCache {
	return &dedupCache{last: make(map[string]time.Time, 256), window: window}
}

// wrap returns a new emit-function that drops events whose dedup key was
// already emitted within `window`. Non-keyable event types (warning,
// done, conntrack-snapshot) always pass through.
func (d *dedupCache) wrap(emit func(Event)) func(Event) {
	return func(ev Event) {
		key := dedupKey(ev)
		if key == "" {
			emit(ev)
			return
		}
		d.mu.Lock()
		if ts, ok := d.last[key]; ok && ev.Timestamp.Sub(ts) >= 0 && ev.Timestamp.Sub(ts) < d.window {
			d.mu.Unlock()
			return
		}
		d.last[key] = ev.Timestamp
		// Periodic GC — drop entries older than 2× the window. Triggered
		// by map size to keep the bookkeeping bounded for long live sessions.
		if len(d.last) > 4096 {
			cutoff := ev.Timestamp.Add(-2 * d.window)
			for k, t := range d.last {
				if t.Before(cutoff) {
					delete(d.last, k)
				}
			}
		}
		d.mu.Unlock()
		emit(ev)
	}
}

// dedupKey returns the identity tuple that defines "this is the same
// event" for replication-collapse purposes. Empty string means "don't
// dedup this type" — used for stateful events like conntrack-snapshot
// where duplicates are impossible and the JSON parse would be wasted work.
func dedupKey(ev Event) string {
	switch ev.Type {
	case "dns-query":
		var d DNSQueryData
		if json.Unmarshal(ev.Data, &d) == nil {
			return "dq|" + d.Client + "|" + d.Hostname + "|" + d.QType + "|" + strconv.Itoa(d.ID)
		}
	case "dns-reply":
		var d DNSReplyData
		if json.Unmarshal(ev.Data, &d) == nil {
			return "dr|" + d.Client + "|" + d.Hostname + "|" + strings.Join(d.Answers, ",") + "|" + strconv.Itoa(d.ID)
		}
	case "tls-sni", "quic-sni":
		var d SNIData
		if json.Unmarshal(ev.Data, &d) == nil {
			return "sni|" + d.Client + "|" + d.Dest + "|" + strconv.Itoa(d.DestPort) + "|" + d.SNI
		}
	case "icmp-unreachable":
		var d ICMPUnreachableData
		if json.Unmarshal(ev.Data, &d) == nil {
			return "icmp|" + d.From + "|" + d.OriginalDest + "|" + strconv.Itoa(d.OriginalPort) + "|" + strconv.Itoa(d.Code)
		}
	case "tcp-rst":
		var d TCPRSTData
		if json.Unmarshal(ev.Data, &d) == nil {
			return "rst|" + d.From + "|" + strconv.Itoa(d.FromPort) + "|" + d.To + "|" + strconv.Itoa(d.ToPort)
		}
	}
	return ""
}

// --- snapshot wrapper ----------------------------------------------------

// ClientTrafficReport is the bundled output of a fixed-duration snapshot.
type ClientTrafficReport struct {
	ClientIP    string                `json:"client_ip"`
	StartedAt   time.Time             `json:"started_at"`
	Seconds     int                   `json:"seconds"`
	LatestFlow  ConntrackSnapshotData `json:"latest_flow"`
	DNSQueries  []DNSQueryData        `json:"dns_queries,omitempty"`
	DNSReplies  []DNSReplyData        `json:"dns_replies,omitempty"`
	ICMPRej     []ICMPUnreachableData `json:"icmp_rejected,omitempty"`
	TCPResets   []TCPRSTData          `json:"tcp_resets,omitempty"`
	SNIs        []SNIData             `json:"snis,omitempty"`
	QUICRetries []QUICRetryData       `json:"quic_retries,omitempty"`
	Warnings    []string              `json:"warnings,omitempty"`
}

// ClientTrafficSnapshot runs a bounded session and returns the accumulated
// report. Suitable for `purewrt client-traffic --seconds=30` (no --live).
//
// Forces Verbose=true so the FINAL conntrack tick includes ALL active
// flows, not just those that changed since the previous tick. The
// new-vs-changed filter is a live-mode UX feature — for one-shot snapshots
// the user wants a complete inventory, even of idle flows.
func (m Manager) ClientTrafficSnapshot(clientIP string, seconds int, opts StreamOpts) (ClientTrafficReport, error) {
	if seconds < 5 {
		seconds = 5
	}
	if seconds > 120 {
		seconds = 120
	}
	opts.Verbose = true
	rep := ClientTrafficReport{
		ClientIP:  clientIP,
		StartedAt: time.Now().UTC(),
		Seconds:   seconds,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()

	var mu sync.Mutex
	emit := func(ev Event) {
		mu.Lock()
		defer mu.Unlock()
		switch ev.Type {
		case "conntrack-snapshot":
			var d ConntrackSnapshotData
			_ = json.Unmarshal(ev.Data, &d)
			rep.LatestFlow = d // last write wins
		case "dns-query":
			var d DNSQueryData
			_ = json.Unmarshal(ev.Data, &d)
			rep.DNSQueries = append(rep.DNSQueries, d)
		case "dns-reply":
			var d DNSReplyData
			_ = json.Unmarshal(ev.Data, &d)
			rep.DNSReplies = append(rep.DNSReplies, d)
		case "icmp-unreachable":
			var d ICMPUnreachableData
			_ = json.Unmarshal(ev.Data, &d)
			rep.ICMPRej = append(rep.ICMPRej, d)
		case "tcp-rst":
			var d TCPRSTData
			_ = json.Unmarshal(ev.Data, &d)
			rep.TCPResets = append(rep.TCPResets, d)
		case "tls-sni", "quic-sni":
			var d SNIData
			_ = json.Unmarshal(ev.Data, &d)
			rep.SNIs = append(rep.SNIs, d)
		case "quic-retry":
			var d QUICRetryData
			_ = json.Unmarshal(ev.Data, &d)
			rep.QUICRetries = append(rep.QUICRetries, d)
		case "warning":
			var d WarningData
			_ = json.Unmarshal(ev.Data, &d)
			rep.Warnings = append(rep.Warnings, d.Message)
		}
	}
	err := m.ClientTrafficStream(ctx, clientIP, opts, emit)
	if err != nil && ctx.Err() != context.DeadlineExceeded {
		return rep, err
	}
	return rep, nil
}

func makeEventTS(ts time.Time, typ string, data any) Event {
	ev := Event{Type: typ, Timestamp: ts}
	if data != nil {
		b, _ := json.Marshal(data)
		ev.Data = b
	}
	return ev
}
