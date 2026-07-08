package manager

// Conntrack/flow-state tracking for ClientTraffic: /proc/net/nf_conntrack
// parsing, flow summaries, unreplied/lopsided/stalled/frozen classification,
// and bogon detection.

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

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

func emitConntrack(clientIP string, prev map[string]*ctEntry, hostnames *hostnameMap, nftsets *nftsetEnricher, asndb *asnHolder, verbose bool, emit func(Event)) map[string]*ctEntry {
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
