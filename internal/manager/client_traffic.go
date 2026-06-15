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

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
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
	Proto        string   `json:"proto"`
	DestIP       string   `json:"dest_ip"`
	DestPort     int      `json:"dest_port"`
	SrcPort      int      `json:"src_port,omitempty"`
	State        string   `json:"state,omitempty"`
	Unreplied    bool     `json:"unreplied,omitempty"`
	Assured      bool     `json:"assured,omitempty"`
	Offload      bool     `json:"offload,omitempty"`
	Lopsided     bool     `json:"lopsided,omitempty"`
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
	Frozen bool `json:"frozen,omitempty"`
	OrigPackets  int      `json:"orig_packets"`
	OrigBytes    int64    `json:"orig_bytes"`
	ReplyPackets int      `json:"reply_packets"`
	ReplyBytes   int64    `json:"reply_bytes"`
	Hostname     string   `json:"hostname,omitempty"`
	TTLRem       int      `json:"ttl_rem,omitempty"`
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
		iface = detectLANInterface()
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
	var asndb *ipdb.DB
	if db, err := ipdb.Load(ipdbPath); err == nil {
		asndb = db
	} else if !os.IsNotExist(err) {
		emit(makeEvent("warning", WarningData{Message: "ipdb load failed: " + err.Error()}))
	} else {
		emit(makeEvent("warning", WarningData{Message: "IP database not installed — run `purewrt ipdb-update` for ASN/country/org enrichment"}))
	}

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
	pcapErr := runPcapReader(stdout, clientIP, enr, emit)

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

func detectLANInterface() string {
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

// --- hostname enrichment shared state -------------------------------------

type hostnameMap struct {
	mu sync.Mutex
	m  map[string][]string // dstIP -> []hostname (most-recent-last)
}

func (h *hostnameMap) add(ip, host string) {
	if ip == "" || host == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, existing := range h.m[ip] {
		if existing == host {
			return
		}
	}
	h.m[ip] = append(h.m[ip], host)
	if len(h.m[ip]) > 5 {
		h.m[ip] = h.m[ip][len(h.m[ip])-5:]
	}
}

func (h *hostnameMap) get(ip string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.m[ip]
	if len(hs) == 0 {
		return ""
	}
	return hs[len(hs)-1]
}

// --- QUIC retry tracker ---------------------------------------------------

type quicRetryState struct {
	timestamps []time.Time
	emitted    bool
}

type quicRetryTracker struct {
	mu      sync.Mutex
	retries map[string]*quicRetryState
	window  time.Duration
	minHits int
}

// observe records one outbound QUIC initial. Returns the count of hits
// within the sliding window if the threshold was just crossed (so callers
// emit once per burst), or 0 otherwise.
func (q *quicRetryTracker) observe(dst string, dport int, now time.Time) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := fmt.Sprintf("%s:%d", dst, dport)
	st := q.retries[key]
	if st == nil {
		st = &quicRetryState{}
		q.retries[key] = st
	}
	// Drop timestamps outside the sliding window.
	cutoff := now.Add(-q.window)
	cleaned := st.timestamps[:0]
	for _, t := range st.timestamps {
		if t.After(cutoff) {
			cleaned = append(cleaned, t)
		}
	}
	cleaned = append(cleaned, now)
	st.timestamps = cleaned
	if len(cleaned) >= q.minHits && !st.emitted {
		st.emitted = true
		return len(cleaned)
	}
	if len(cleaned) < q.minHits {
		st.emitted = false
	}
	return 0
}

// --- nftset enrichment ---------------------------------------------------
//
// Snapshots the PureWRT nft table once at session start and refreshes every
// ~10s in a background goroutine. Lookups by destination IP return the set
// memberships, which we attach to FlowSummary so the UI can show e.g. "this
// destination is currently in proxy_common" — answering the question
// "is the section's proxy failing, or is the ISP just blocking the dest?"

type nftsetEnricher struct {
	mu sync.RWMutex
	// Exact-match lookups. Populated by sets that use literal element
	// addresses (the dns_* timeout-bearing sets dnsmasq feeds into).
	ipToSets map[string][]string
	// Prefix-match lookups. Populated by interval sets — proxy_<section>4
	// holds CIDR ranges like 149.154.160.0/20 (Telegram), and an arbitrary
	// dest IP inside that range needs a containment test, not equality.
	// Sorted ascending by prefix start so we can binary-search by IP.
	cidrs []cidrEntry
}

type cidrEntry struct {
	pfx  netip.Prefix
	name string
}

func newNftsetEnricher() *nftsetEnricher {
	return &nftsetEnricher{ipToSets: map[string][]string{}}
}

func (n *nftsetEnricher) refresh() error {
	// Step 1: enumerate set names via list-table — that gives us the
	// schema (set names + flags) but, importantly, does NOT include
	// elements for interval-flagged sets. nft chooses to summarise those
	// in list-table output, only emitting the full element list for
	// list-set <name>.
	out, err := exec.Command("nft", "-j", "list", "table", "inet", "purewrt").Output()
	if err != nil {
		return err
	}
	var doc struct {
		Nftables []struct {
			Set *struct {
				Name  string   `json:"name"`
				Flags []string `json:"flags"`
			} `json:"set,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return err
	}
	nextIPs := map[string][]string{}
	var nextCIDRs []cidrEntry
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		setName := normaliseSetName(item.Set.Name)
		if setName == "" {
			continue
		}
		// Step 2: pull the full element list for this set. ~14 sets × ~50 ms
		// each = a one-off cost paid every refresh tick (10 s), well within
		// budget. Errors are logged but non-fatal — a flaky set shouldn't
		// kill enrichment for the others.
		setOut, err := exec.Command("nft", "-j", "list", "set", "inet", "purewrt", item.Set.Name).Output()
		if err != nil {
			continue
		}
		var setDoc struct {
			Nftables []struct {
				Set *struct {
					Elem []json.RawMessage `json:"elem"`
				} `json:"set,omitempty"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(setOut, &setDoc); err != nil {
			continue
		}
		for _, sItem := range setDoc.Nftables {
			if sItem.Set == nil {
				continue
			}
			for _, raw := range sItem.Set.Elem {
				if pfx, ok := parseNftPrefix(raw); ok {
					nextCIDRs = append(nextCIDRs, cidrEntry{pfx: pfx, name: setName})
					continue
				}
				ip := parseNftElem(raw)
				if ip == "" {
					continue
				}
				// Some sets emit literal "X.X.X.X/N" as a bare string for
				// /32-equivalent entries; treat those as CIDRs too.
				if strings.ContainsAny(ip, "/-") {
					if pfx, ok := parsePrefixOrRange(ip); ok {
						nextCIDRs = append(nextCIDRs, cidrEntry{pfx: pfx, name: setName})
					}
					continue
				}
				already := false
				for _, s := range nextIPs[ip] {
					if s == setName {
						already = true
						break
					}
				}
				if !already {
					nextIPs[ip] = append(nextIPs[ip], setName)
				}
			}
		}
	}
	n.mu.Lock()
	n.ipToSets = nextIPs
	n.cidrs = nextCIDRs
	n.mu.Unlock()
	return nil
}

// parseNftPrefix handles the third element shape — interval/CIDR entries
// from nft -j look like {"prefix": {"addr": "1.0.0.0", "len": 24}}. Returns
// false for the other two shapes (bare string / {elem:{val:...}}), which
// the caller falls back to via parseNftElem.
func parseNftPrefix(raw json.RawMessage) (netip.Prefix, bool) {
	var obj struct {
		Prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return netip.Prefix{}, false
	}
	if obj.Prefix.Addr == "" {
		return netip.Prefix{}, false
	}
	addr, err := netip.ParseAddr(obj.Prefix.Addr)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, obj.Prefix.Len), true
}

// parsePrefixOrRange handles both nft element formats for interval entries:
//   - "1.2.3.0/24"        → single Prefix
//   - "1.2.3.0-1.2.3.255"  → degenerate range; we collapse to a single /N
//     when the range is a whole subnet, otherwise drop (rare in practice;
//     iptoasn-style arbitrary ranges aren't what PureWRT generates).
func parsePrefixOrRange(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p, true
	}
	// "start-end" form: try parsing both endpoints; only collapse when the
	// range happens to be CIDR-aligned (common for the 1-IP "/32" case).
	if i := strings.Index(s, "-"); i > 0 {
		start, err := netip.ParseAddr(s[:i])
		if err != nil {
			return netip.Prefix{}, false
		}
		end, err := netip.ParseAddr(s[i+1:])
		if err != nil {
			return netip.Prefix{}, false
		}
		if start == end {
			return netip.PrefixFrom(start, 32), true
		}
		// Drop multi-IP non-CIDR ranges — a /20 etc. would have arrived as
		// "X/N" already, so this branch is just exotic outliers.
		return netip.Prefix{}, false
	}
	return netip.Prefix{}, false
}

// parseNftElem handles the two element shapes nft -j emits: a bare string
// like "1.2.3.4" for entries without metadata, and {"elem":{"val":"1.2.3.4",
// "timeout":..,"expires":..}} for sets with timeouts.
func parseNftElem(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj struct {
		Elem struct {
			Val string `json:"val"`
		} `json:"elem"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Elem.Val
	}
	return ""
}

// normaliseSetName strips the trailing 4/6 family suffix but keeps the
// dns_ prefix when present — so the user can distinguish:
//   - "proxy_media"      → IP entered the set from a static CIDR rule
//   - "dns_proxy_media"  → dnsmasq resolved a domain to this IP (TTL-bound)
//
// Both can be present for the same IP (CIDR matches + a domain happened to
// resolve to a covered address). Showing them separately tells the user
// WHY this destination is currently routed where it is — a domain match is
// a much stronger "the user is actually going to this hostname" signal
// than a CIDR coincidence.
//
// Returns "" for bypass-class sets — those describe the router's WAN-side
// infrastructure rather than client-destination classification, so they're
// noise in the per-flow display.
func normaliseSetName(s string) string {
	if l := len(s); l > 0 && (s[l-1] == '4' || s[l-1] == '6') {
		s = s[:l-1]
	}
	switch s {
	case "bypass", "proxy_server_bypass", "dns_bypass", "dns_proxy_server_bypass":
		return ""
	}
	return s
}

func (n *nftsetEnricher) get(ip string) []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var out []string
	// Exact-match dns_* entries first.
	if v, ok := n.ipToSets[ip]; ok {
		out = append(out, v...)
	}
	// Then walk the CIDR list and append every set whose range contains
	// this IP. Linear scan over ~hundreds-to-thousands of prefixes is
	// fine — the lookup is per-flow and per-tick, not per-packet.
	if len(n.cidrs) > 0 {
		if addr, err := netip.ParseAddr(ip); err == nil {
			for _, c := range n.cidrs {
				if c.pfx.Contains(addr) {
					if !contains(out, c.name) {
						out = append(out, c.name)
					}
				}
			}
		}
	}
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// runRefreshLoop refreshes the snapshot every interval until ctx is cancelled.
// First refresh happens immediately so the very first conntrack tick can use
// the enrichment.
func (n *nftsetEnricher) runRefreshLoop(ctx context.Context, interval time.Duration) {
	_ = n.refresh()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = n.refresh()
		}
	}
}

// --- conntrack -----------------------------------------------------------

type ctEntry struct {
	Proto        string
	SrcIP        string
	DstIP        string
	SrcPort      int
	DstPort      int
	State        string // TCP only
	Unreplied    bool
	Assured      bool
	Offload      bool
	OrigPackets  int
	OrigBytes    int64
	ReplyPackets int
	ReplyBytes   int64
	TTLRem       int
	// frozenTicks counts consecutive conntrack ticks this flow has made zero
	// reply progress while download-shaped + ESTABLISHED. Carried forward via
	// the prev map across ticks (not parsed from /proc); see emitConntrack.
	frozenTicks int
}

func (e *ctEntry) key() string {
	return fmt.Sprintf("%s|%s:%d->%s:%d", e.Proto, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
}

func emitConntrack(clientIP string, prev map[string]*ctEntry, hostnames *hostnameMap, nftsets *nftsetEnricher, asndb *ipdb.DB, verbose bool, emit func(Event)) map[string]*ctEntry {
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		emit(makeEvent("warning", WarningData{Message: "cannot read /proc/net/nf_conntrack: " + err.Error()}))
		return prev
	}
	curr := make(map[string]*ctEntry)
	skippedV6 := 0
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "ipv6 ") {
			if strings.Contains(line, "src="+clientIP+" ") {
				// won't happen (different proto) but track for the warning
			}
			skippedV6++
			continue
		}
		ent := parseConntrackLine(line)
		if ent == nil || ent.SrcIP != clientIP {
			continue
		}
		curr[ent.key()] = ent
	}

	out := make([]FlowSummary, 0, len(curr))
	for k, ent := range curr {
		fs := flowSummaryFor(ent)
		// Mid-stream freeze (delta-based): carry the per-flow frozen-tick
		// counter forward from the previous tick. frozenStep reports whether
		// this flow made zero reply progress on a download-shaped ESTABLISHED
		// connection; after ~10s (5 ticks) of that we flag it as Frozen.
		p := prev[k]
		if frozenStep(p, ent) {
			ent.frozenTicks = p.frozenTicks + 1
		}
		if ent.frozenTicks >= 5 {
			fs.Frozen = true
		}
		// Only include interesting flows in the snapshot unless verbose:
		//   - new since last tick
		//   - orig_packets increased since last tick
		//   - currently unreplied / lopsided / stalled / frozen
		include := verbose
		if p == nil {
			include = true
		} else if ent.OrigPackets > p.OrigPackets {
			include = true
		}
		if ent.Unreplied || fs.Lopsided || fs.Stalled || fs.Frozen {
			include = true
		}
		if !include {
			continue
		}
		if h := hostnames.get(ent.DstIP); h != "" {
			fs.Hostname = h
		}
		if nftsets != nil {
			fs.Nftsets = nftsets.get(ent.DstIP)
		}
		if asndb != nil && !fs.Bogon {
			if addr, err := netip.ParseAddr(ent.DstIP); err == nil {
				lk := asndb.Lookup(addr)
				fs.ASN = lk.ASN
				fs.ASOrg = lk.ASOrg
				fs.Country = lk.Country
			}
		}
		out = append(out, fs)
	}

	// Sort: UNREPLIED first, then by orig_packets desc.
	sortFlows(out)

	emit(makeEvent("conntrack-snapshot", ConntrackSnapshotData{
		Flows:       out,
		TotalFlows:  len(curr),
		SkippedIPv6: skippedV6,
	}))
	return curr
}

func sortFlows(fs []FlowSummary) {
	// Simple insertion sort — N is small (typically <50).
	for i := 1; i < len(fs); i++ {
		j := i
		for j > 0 && lessFlow(fs[j], fs[j-1]) {
			fs[j], fs[j-1] = fs[j-1], fs[j]
			j--
		}
	}
}

func lessFlow(a, b FlowSummary) bool {
	if a.Unreplied != b.Unreplied {
		return a.Unreplied // unreplied first
	}
	if a.Stalled != b.Stalled {
		return a.Stalled // then DPI post-handshake drops
	}
	if a.Frozen != b.Frozen {
		return a.Frozen // then mid-stream freezes
	}
	if a.Lopsided != b.Lopsided {
		return a.Lopsided
	}
	return a.OrigPackets > b.OrigPackets
}

// isBogonIPv4 returns true if ip is a destination that can't possibly
// represent "blocked external traffic" — RFC1918 / loopback / link-local /
// multicast / broadcast / CGNAT / IETF test ranges. Built on top of
// net.IP's IsPrivate/IsLoopback/etc. with the extra ranges they miss
// (Go's IsPrivate covers 10/8 + 172.16/12 + 192.168/16 only).
func isBogonIPv4(s string) bool {
	p := net.ParseIP(s)
	if p == nil {
		return false
	}
	p4 := p.To4()
	if p4 == nil {
		return false
	}
	if p.IsLoopback() || p.IsMulticast() || p.IsLinkLocalUnicast() ||
		p.IsLinkLocalMulticast() || p.IsUnspecified() || p.IsPrivate() ||
		p.IsInterfaceLocalMulticast() {
		return true
	}
	a, b, c := p4[0], p4[1], p4[2]
	switch {
	case a == 100 && b >= 64 && b <= 127: // CGNAT 100.64/10
		return true
	case a == 192 && b == 0 && c == 0: // 192.0.0/24 (IETF)
		return true
	case a == 192 && b == 0 && c == 2: // 192.0.2/24 TEST-NET-1
		return true
	case a == 198 && (b == 18 || b == 19): // 198.18/15 benchmarking
		return true
	case a == 198 && b == 51 && c == 100: // 198.51.100/24 TEST-NET-2
		return true
	case a == 203 && b == 0 && c == 113: // 203.0.113/24 TEST-NET-3
		return true
	case a >= 240: // 240/4 future-use + 255.255.255.255 broadcast
		return true
	}
	return false
}

func flowSummaryFor(e *ctEntry) FlowSummary {
	fs := FlowSummary{
		Proto:        e.Proto,
		DestIP:       e.DstIP,
		DestPort:     e.DstPort,
		SrcPort:      e.SrcPort,
		State:        e.State,
		Unreplied:    e.Unreplied,
		Assured:      e.Assured,
		Offload:      e.Offload,
		OrigPackets:  e.OrigPackets,
		OrigBytes:    e.OrigBytes,
		ReplyPackets: e.ReplyPackets,
		ReplyBytes:   e.ReplyBytes,
		TTLRem:       e.TTLRem,
	}
	// Lopsided: bidirectional flow that ought to have many replies but
	// barely got any. Apex's typical stall fingerprint.
	if e.Assured && e.ReplyPackets < 5 && e.OrigPackets > 20 {
		fs.Lopsided = true
	}
	// Stalled: DPI/SNI post-handshake drop. The connection got far enough
	// that the client kept sending, but the server gave back at most one
	// packet (TCP SYN-ACK, or a lone QUIC Retry) and then went silent.
	// This is *not* Unreplied (which is a fully silent drop) and stalls
	// below the Lopsided packet bar, so without this it renders as OK.
	switch e.Proto {
	case "tcp":
		// Handshake completed (assured), only the SYN-ACK came back, the
		// client sent the ClientHello + retransmits and got nothing. A
		// genuine upload would still draw ACKs so ReplyPackets would grow.
		if e.Assured && e.ReplyPackets <= 1 && e.OrigPackets >= 4 && e.OrigBytes > e.ReplyBytes*4 {
			fs.Stalled = true
		}
	case "udp":
		// No handshake to anchor on, so use a stricter orig bar (>=5): the
		// client retried several times into the void. Skip 53/123 — pure
		// request/response protocols never produce this shape. Fire-and-
		// forget and one-shot request/response UDP never reach >=5 orig
		// packets with <=1 reply.
		if e.DstPort != 53 && e.DstPort != 123 &&
			e.ReplyPackets <= 1 && e.OrigPackets >= 5 && e.OrigBytes > e.ReplyBytes*4 {
			fs.Stalled = true
		}
	}
	fs.Bogon = isBogonIPv4(e.DstIP)
	return fs
}

// frozenStep reports whether cur looks like a download-shaped ESTABLISHED TCP
// flow that made ZERO reply progress since prev — the per-tick component of
// the mid-stream-cut detector. Callers accumulate this across ticks
// (ctEntry.frozenTicks) and flag a flow Frozen once it persists ~10s.
//
// The gates: substantial reply data already received (>16KB, so it's past the
// handshake — not the Stalled fingerprint), a clear download shape
// (reply >> orig, so chat/keepalive symmetric flows don't qualify), still
// ESTABLISHED (a cleanly finished download leaves ESTABLISHED via FIN), not
// offloaded (offloaded flows don't update conntrack counters, so "frozen" is
// meaningless), and reply counters byte-for-byte unchanged this tick.
func frozenStep(prev, cur *ctEntry) bool {
	if prev == nil || cur == nil {
		return false
	}
	return cur.Proto == "tcp" && cur.State == "ESTABLISHED" && cur.Assured && !cur.Offload &&
		cur.ReplyBytes > 16384 && cur.ReplyBytes > cur.OrigBytes*2 &&
		cur.ReplyBytes == prev.ReplyBytes && cur.ReplyPackets == prev.ReplyPackets
}

// parseConntrackLine returns a parsed ctEntry or nil if the line isn't a
// valid IPv4 TCP/UDP entry we care about. Skips ipv6 lines silently —
// caller handles the warning count.
func parseConntrackLine(line string) *ctEntry {
	fields := strings.Fields(line)
	if len(fields) < 7 || fields[0] != "ipv4" {
		return nil
	}
	proto := fields[2]
	if proto != "tcp" && proto != "udp" {
		return nil
	}
	// fields[4] is the TTL-remaining seconds.
	ttl, _ := strconv.Atoi(fields[4])
	ent := &ctEntry{Proto: proto, TTLRem: ttl}
	// For TCP fields[5] is the state name (ESTABLISHED/...). For UDP it's
	// already the first src= token.
	tupleStart := 5
	if proto == "tcp" {
		ent.State = fields[5]
		tupleStart = 6
	}
	// Walk the rest of the fields, collecting two sets of (src,dst,sport,dport,packets,bytes).
	gotOrig := false
	for i := tupleStart; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "[UNREPLIED]":
			ent.Unreplied = true
		case f == "[ASSURED]":
			ent.Assured = true
		case f == "[OFFLOAD]" || f == "[HW_OFFLOAD]":
			ent.Offload = true
		case strings.HasPrefix(f, "src="):
			v := strings.TrimPrefix(f, "src=")
			if !gotOrig {
				ent.SrcIP = v
			}
		case strings.HasPrefix(f, "dst="):
			v := strings.TrimPrefix(f, "dst=")
			if !gotOrig {
				ent.DstIP = v
			}
		case strings.HasPrefix(f, "sport="):
			v := strings.TrimPrefix(f, "sport=")
			if !gotOrig {
				ent.SrcPort, _ = strconv.Atoi(v)
			}
		case strings.HasPrefix(f, "dport="):
			v := strings.TrimPrefix(f, "dport=")
			if !gotOrig {
				ent.DstPort, _ = strconv.Atoi(v)
			}
		case strings.HasPrefix(f, "packets="):
			v := strings.TrimPrefix(f, "packets=")
			n, _ := strconv.Atoi(v)
			if !gotOrig {
				ent.OrigPackets = n
			} else {
				ent.ReplyPackets = n
			}
		case strings.HasPrefix(f, "bytes="):
			v := strings.TrimPrefix(f, "bytes=")
			n, _ := strconv.ParseInt(v, 10, 64)
			if !gotOrig {
				ent.OrigBytes = n
				gotOrig = true // bytes= is the last field of the original tuple
			} else {
				ent.ReplyBytes = n
			}
		}
	}
	if ent.SrcIP == "" || ent.DstIP == "" {
		return nil
	}
	return ent
}

// --- pcap reader ---------------------------------------------------------
//
// PCAP file format (RFC 1761-ish; tcpdump --version 4.99 emits this by
// default without --keep-going / --pcapng): 24-byte global header, then
// 16-byte per-packet header + caplen bytes of frame data. Linktype tells
// us what's wrapping the IP layer; we expect EN10MB (=1) for br-lan.

const (
	pcapMagicLE   = 0xa1b2c3d4
	pcapMagicBE   = 0xd4c3b2a1
	linkTypeEN10MB = 1
)

// packetEnrichers bundles everything a packet-level parser needs to
// attach hostname / nftset / ASN / QUIC-retry context to its emitted
// events. One field per data source, passed by pointer so a single nil-safe
// nftsets/asndb keeps the snapshot path working when the user hasn't
// installed the IP database.
type packetEnrichers struct {
	hostnames *hostnameMap
	nftsets   *nftsetEnricher
	asndb     *ipdb.DB
	quic      *quicRetryTracker
}

// enrich looks up ip in every available source and fills the rejectEnrichment
// struct embedded into rejection events. Safe to call with a nil receiver
// (no-op) so callers don't need to gate per field.
func (e *packetEnrichers) enrich(ip string) rejectEnrichment {
	var r rejectEnrichment
	if e == nil || ip == "" {
		return r
	}
	if e.hostnames != nil {
		r.Hostname = e.hostnames.get(ip)
	}
	if e.nftsets != nil {
		r.Nftsets = e.nftsets.get(ip)
	}
	if e.asndb != nil {
		if addr, err := netip.ParseAddr(ip); err == nil {
			lk := e.asndb.Lookup(addr)
			r.ASN, r.ASOrg, r.Country = lk.ASN, lk.ASOrg, lk.Country
		}
	}
	return r
}

func runPcapReader(r io.Reader, clientIP string, enr *packetEnrichers, emit func(Event)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var hdr [24]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return fmt.Errorf("pcap global header: %w", err)
	}
	magic := binary.LittleEndian.Uint32(hdr[0:4])
	var ord binary.ByteOrder = binary.LittleEndian
	if magic == pcapMagicBE {
		ord = binary.BigEndian
	} else if magic != pcapMagicLE {
		return fmt.Errorf("pcap: unrecognized magic 0x%x", magic)
	}
	linkType := ord.Uint32(hdr[20:24])
	if linkType != linkTypeEN10MB {
		return fmt.Errorf("pcap: unexpected linktype %d (only EN10MB supported)", linkType)
	}

	var rec [16]byte
	for {
		if _, err := io.ReadFull(br, rec[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return fmt.Errorf("pcap record header: %w", err)
		}
		tsSec := ord.Uint32(rec[0:4])
		tsUsec := ord.Uint32(rec[4:8])
		caplen := ord.Uint32(rec[8:12])
		// origlen := ord.Uint32(rec[12:16]) — unused
		if caplen > 65535 {
			return fmt.Errorf("pcap: caplen %d implausible", caplen)
		}
		buf := make([]byte, caplen)
		if _, err := io.ReadFull(br, buf); err != nil {
			return fmt.Errorf("pcap packet body: %w", err)
		}
		ts := time.Unix(int64(tsSec), int64(tsUsec)*1000).UTC()
		parsePacket(ts, buf, clientIP, enr, emit)
	}
}

// --- ethernet + IPv4 + TCP/UDP/ICMP parsers ------------------------------

// parsePacket dispatches one Ethernet frame to the right protocol handler.
// Ignores anything that isn't IPv4 + TCP/UDP/ICMP.
func parsePacket(ts time.Time, frame []byte, clientIP string, enr *packetEnrichers, emit func(Event)) {
	if len(frame) < 14 {
		return
	}
	ethType := binary.BigEndian.Uint16(frame[12:14])
	if ethType != 0x0800 { // IPv4
		return
	}
	ip := frame[14:]
	if len(ip) < 20 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return
	}
	proto := ip[9]
	srcIP := net.IP(ip[12:16]).String()
	dstIP := net.IP(ip[16:20]).String()
	payload := ip[ihl:]

	switch proto {
	case 6: // TCP
		parseTCP(ts, srcIP, dstIP, payload, clientIP, enr, emit)
	case 17: // UDP
		parseUDP(ts, srcIP, dstIP, payload, clientIP, enr, emit)
	case 1: // ICMP
		parseICMP(ts, srcIP, dstIP, payload, clientIP, enr, emit)
	}
}

func parseTCP(ts time.Time, srcIP, dstIP string, tcp []byte, clientIP string, enr *packetEnrichers, emit func(Event)) {
	if len(tcp) < 20 {
		return
	}
	srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
	dstPort := int(binary.BigEndian.Uint16(tcp[2:4]))
	dataOff := int(tcp[12]>>4) * 4
	flags := tcp[13]
	if dataOff > len(tcp) {
		return
	}
	// RST flag — distinguish peer (src=destIP we tried) vs middlebox.
	if flags&0x04 != 0 {
		// Outbound side: client sent the RST. Skip; we want inbound RSTs
		// that interrupted the client's connection.
		if srcIP == clientIP {
			return
		}
		emit(makeEventTS(ts, "tcp-rst", TCPRSTData{
			From: srcIP, FromPort: srcPort,
			To: dstIP, ToPort: dstPort,
			Source: "peer", // we can't reliably distinguish peer vs middlebox from one packet;
			// label as "peer" by default — a future enhancement can correlate
			// with the original connection's destination.
			Bogon:            isBogonIPv4(srcIP),
			rejectEnrichment: enr.enrich(srcIP),
		}))
		return
	}
	// SYN-without-ACK on TCP/443 → likely TLS ClientHello follows. Look at
	// payload for TLS record type 0x16 (handshake).
	if srcIP != clientIP || dstPort != 443 {
		return
	}
	payload := tcp[dataOff:]
	if sni := extractTLSSNI(payload); sni != "" {
		enr.hostnames.add(dstIP, sni)
		emit(makeEventTS(ts, "tls-sni", SNIData{
			Client: srcIP, Dest: dstIP, DestPort: dstPort,
			SNI: sni, Proto: "tcp",
		}))
	}
}

func parseUDP(ts time.Time, srcIP, dstIP string, udp []byte, clientIP string, enr *packetEnrichers, emit func(Event)) {
	if len(udp) < 8 {
		return
	}
	srcPort := int(binary.BigEndian.Uint16(udp[0:2]))
	dstPort := int(binary.BigEndian.Uint16(udp[2:4]))
	payload := udp[8:]

	switch {
	case srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353:
		parseDNS(ts, srcIP, dstIP, srcPort, dstPort, payload, clientIP, enr.hostnames, emit)
	case dstPort == 443 && srcIP == clientIP:
		// QUIC outbound on UDP/443. Track for retry detection. Initial
		// packets have first byte in range 0xc0–0xff (long header).
		if len(payload) > 0 && payload[0] >= 0xc0 {
			if n := enr.quic.observe(dstIP, dstPort, ts); n > 0 {
				emit(makeEventTS(ts, "quic-retry", QUICRetryData{
					Client: clientIP, Dest: dstIP, DestPort: dstPort,
					InitialCount: n, WindowSeconds: 2,
					Bogon:            isBogonIPv4(dstIP),
					rejectEnrichment: enr.enrich(dstIP),
				}))
			}
		}
	}
}

func parseICMP(ts time.Time, srcIP, dstIP string, icmp []byte, clientIP string, enr *packetEnrichers, emit func(Event)) {
	if len(icmp) < 8 {
		return
	}
	typ := icmp[0]
	code := icmp[1]
	if typ != 3 { // destination unreachable
		return
	}
	// The client side: we want unreachables addressed TO the client (i.e.
	// the client sent a packet, something upstream sent back an ICMP).
	if dstIP != clientIP {
		return
	}
	// Bytes 8+ are the inner IP header + first 8 bytes of original payload —
	// gives us the original destination IP/port the client was trying.
	d := ICMPUnreachableData{
		From:     srcIP,
		To:       dstIP,
		Code:     int(code),
		CodeText: icmpCodeText(code),
	}
	if len(icmp) >= 8+20 {
		inner := icmp[8:]
		ihl := int(inner[0]&0x0f) * 4
		if ihl >= 20 && len(inner) >= ihl+8 {
			origProto := inner[9]
			origDst := net.IP(inner[16:20]).String()
			d.OriginalDest = origDst
			switch origProto {
			case 6:
				d.OriginalProto = "tcp"
				d.OriginalPort = int(binary.BigEndian.Uint16(inner[ihl+2 : ihl+4]))
			case 17:
				d.OriginalProto = "udp"
				d.OriginalPort = int(binary.BigEndian.Uint16(inner[ihl+2 : ihl+4]))
			}
		}
	}
	// Attribute the sender: an unreachable from the original destination
	// itself is the peer refusing; one from any other IP is an
	// intermediate hop — for admin-prohibited codes that's the signature
	// of a filtering middlebox (DPI appliance, carrier ACL).
	if d.OriginalDest != "" {
		if srcIP == d.OriginalDest {
			d.Source = "peer"
		} else {
			d.Source = "middlebox"
		}
	}
	// Bogon when the ICMP responder OR the original destination is on a
	// bogon prefix. Either case means a LAN-side device is involved and
	// this isn't "the internet rejected you".
	d.Bogon = isBogonIPv4(srcIP) || (d.OriginalDest != "" && isBogonIPv4(d.OriginalDest))
	// Enrich against the ORIGINAL destination (what the client was trying
	// to reach), not the ICMP sender — that's the IP the user cares about
	// classifying. The ICMP source could be an intermediate router with
	// no proxy mapping of its own.
	enrichIP := d.OriginalDest
	if enrichIP == "" {
		enrichIP = srcIP
	}
	d.rejectEnrichment = enr.enrich(enrichIP)
	emit(makeEventTS(ts, "icmp-unreachable", d))
}

func icmpCodeText(code byte) string {
	switch code {
	case 0:
		return "net unreachable"
	case 1:
		return "host unreachable"
	case 2:
		return "protocol unreachable"
	case 3:
		return "port unreachable"
	case 9:
		return "net admin-prohibited"
	case 10:
		return "host admin-prohibited"
	case 13:
		return "communication admin-prohibited (filtered)"
	default:
		return fmt.Sprintf("code %d", code)
	}
}

// --- DNS parser ----------------------------------------------------------
//
// We need just enough DNS to grab the question name from queries and the
// A/AAAA answers from replies. RFC 1035 wire format; no compression beyond
// the 0xc0 pointer trick.

func parseDNS(ts time.Time, srcIP, dstIP string, srcPort, dstPort int, payload []byte, clientIP string, hostnames *hostnameMap, emit func(Event)) {
	if len(payload) < 12 {
		return
	}
	id := int(binary.BigEndian.Uint16(payload[0:2]))
	flags := binary.BigEndian.Uint16(payload[2:4])
	qd := int(binary.BigEndian.Uint16(payload[4:6]))
	an := int(binary.BigEndian.Uint16(payload[6:8]))
	isReply := flags&0x8000 != 0

	off := 12
	var firstName string
	var firstQType uint16
	for i := 0; i < qd && off < len(payload); i++ {
		name, n, ok := dnsName(payload, off)
		if !ok || off+n+4 > len(payload) {
			return
		}
		off += n
		qtype := binary.BigEndian.Uint16(payload[off : off+2])
		off += 4
		if i == 0 {
			firstName = name
			firstQType = qtype
		}
	}
	if firstName == "" {
		return
	}
	if !isReply {
		// Query: client→resolver. Source must be the LAN client.
		if srcIP != clientIP {
			return
		}
		src := "dns"
		if srcPort == 5353 || dstPort == 5353 {
			src = "mdns"
		}
		emit(makeEventTS(ts, "dns-query", DNSQueryData{
			Client: srcIP, Server: dstIP, QType: dnsQTypeName(firstQType),
			Hostname: firstName, ID: id, Source: src,
		}))
		return
	}
	// Reply: resolver→client (or upstream→our resolver). Accept if:
	//   - addressed unicast to the client (normal DNS), OR
	//   - addressed to the mDNS multicast group when the source port is
	//     5353 (mDNS replies are broadcast back to 224.0.0.251, not
	//     addressed to the original querier — so the "dst == client"
	//     check that works for unicast DNS would drop every mDNS answer).
	isMDNS := srcPort == 5353 || dstPort == 5353
	if dstIP != clientIP && !(isMDNS && (dstIP == "224.0.0.251" || dstIP == "ff02::fb")) {
		return
	}
	answers := make([]string, 0, an)
	for i := 0; i < an && off < len(payload); i++ {
		_, n, ok := dnsName(payload, off)
		if !ok || off+n+10 > len(payload) {
			break
		}
		off += n
		rrType := binary.BigEndian.Uint16(payload[off : off+2])
		off += 8 // type+class+ttl
		rdl := int(binary.BigEndian.Uint16(payload[off : off+2]))
		off += 2
		if off+rdl > len(payload) {
			break
		}
		switch rrType {
		case 1: // A
			if rdl == 4 {
				a := net.IP(payload[off : off+4]).String()
				answers = append(answers, a)
				hostnames.add(a, firstName)
			}
		case 28: // AAAA — track but won't show in IPv4-only view
			if rdl == 16 {
				answers = append(answers, net.IP(payload[off:off+16]).String())
			}
		}
		off += rdl
	}
	if len(answers) > 0 {
		emit(makeEventTS(ts, "dns-reply", DNSReplyData{
			Client: dstIP, Hostname: firstName, Answers: answers, ID: id,
		}))
	}
}

// dnsName reads a name starting at off. Returns the decoded name, total
// bytes consumed from off, and ok=true on success. Handles pointer
// compression with one level of indirection (sufficient for typical DNS).
func dnsName(b []byte, off int) (string, int, bool) {
	var parts []string
	orig := off
	jumped := false
	consumed := 0
	for off < len(b) {
		l := int(b[off])
		if l == 0 {
			off++
			if !jumped {
				consumed = off - orig
			} else {
				consumed = orig + 2 - orig // pointer = 2 bytes
				_ = consumed
			}
			return strings.Join(parts, "."), consumed, true
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(b) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(b[off:off+2])) & 0x3fff
			if ptr >= off {
				return "", 0, false // forward pointer rejected
			}
			if !jumped {
				consumed = off + 2 - orig
				jumped = true
			}
			off = ptr
			continue
		}
		if off+1+l > len(b) {
			return "", 0, false
		}
		parts = append(parts, string(b[off+1:off+1+l]))
		off += 1 + l
	}
	return "", 0, false
}

func dnsQTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 65:
		return "HTTPS"
	case 33:
		return "SRV"
	case 16:
		return "TXT"
	case 12:
		return "PTR"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// --- TLS ClientHello SNI extractor ---------------------------------------
//
// We see only the very first bytes of the TCP segment — tcpdump snaplen is
// 512. Just enough for a ClientHello + SNI. RFC 5246/8446.
//
// TLS record layer:
//   [0]  Content Type (0x16 = handshake)
//   [1..2] Version
//   [3..4] Length
//   [5...] handshake message
//
// Handshake (ClientHello):
//   [0]  HandshakeType (0x01 = ClientHello)
//   [1..3] Length (24-bit)
//   [4..5] Version
//   [6..37] Random (32 bytes)
//   [38] SessionID length, then SessionID
//   then CipherSuites length (2), then suites
//   then CompressionMethods length (1), then methods
//   then Extensions length (2), then extensions
//
// Each extension: type(2) + length(2) + data. Type 0x0000 = server_name.

func extractTLSSNI(tcpPayload []byte) string {
	if len(tcpPayload) < 5 {
		return ""
	}
	if tcpPayload[0] != 0x16 {
		return ""
	}
	// recLen := int(binary.BigEndian.Uint16(tcpPayload[3:5]))
	hs := tcpPayload[5:]
	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	// HandshakeLength is 24-bit at hs[1..3]; we just use what's available
	p := 4
	if p+2+32 > len(hs) {
		return ""
	}
	p += 2 + 32 // version + random
	if p >= len(hs) {
		return ""
	}
	sidLen := int(hs[p])
	p += 1 + sidLen
	if p+2 > len(hs) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(hs[p : p+2]))
	p += 2 + csLen
	if p+1 > len(hs) {
		return ""
	}
	cmLen := int(hs[p])
	p += 1 + cmLen
	if p+2 > len(hs) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(hs[p : p+2]))
	p += 2
	end := p + extLen
	if end > len(hs) {
		end = len(hs)
	}
	for p+4 <= end {
		extType := binary.BigEndian.Uint16(hs[p : p+2])
		extDataLen := int(binary.BigEndian.Uint16(hs[p+2 : p+4]))
		p += 4
		if p+extDataLen > end {
			break
		}
		if extType == 0x0000 && extDataLen >= 5 {
			// server_name extension: list length (2) + name type (1) + name length (2) + name bytes
			snList := hs[p : p+extDataLen]
			if len(snList) < 5 {
				p += extDataLen
				continue
			}
			// listLen := binary.BigEndian.Uint16(snList[0:2])
			nameLen := int(binary.BigEndian.Uint16(snList[3:5]))
			if 5+nameLen > len(snList) {
				p += extDataLen
				continue
			}
			return string(snList[5 : 5+nameLen])
		}
		p += extDataLen
	}
	return ""
}

// --- snapshot wrapper ----------------------------------------------------

// ClientTrafficReport is the bundled output of a fixed-duration snapshot.
type ClientTrafficReport struct {
	ClientIP   string                  `json:"client_ip"`
	StartedAt  time.Time               `json:"started_at"`
	Seconds    int                     `json:"seconds"`
	LatestFlow ConntrackSnapshotData   `json:"latest_flow"`
	DNSQueries []DNSQueryData          `json:"dns_queries,omitempty"`
	DNSReplies []DNSReplyData          `json:"dns_replies,omitempty"`
	ICMPRej    []ICMPUnreachableData   `json:"icmp_rejected,omitempty"`
	TCPResets  []TCPRSTData            `json:"tcp_resets,omitempty"`
	SNIs       []SNIData               `json:"snis,omitempty"`
	QUICRetries []QUICRetryData        `json:"quic_retries,omitempty"`
	Warnings   []string                `json:"warnings,omitempty"`
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
