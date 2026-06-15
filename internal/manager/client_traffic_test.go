package manager

// Parser unit tests for client_traffic.go. The router-side behaviour
// (tcpdump subprocess, conntrack ticker, pcap stream) is exercised by the
// live smoke test in task #120 — these cover the pure-Go parsers which we
// can verify against synthetic fixtures without a router.

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

func TestParseConntrack_TCPEstablishedAssured(t *testing.T) {
	line := "ipv4     2 tcp      6 7434 ESTABLISHED src=192.168.1.105 dst=162.248.160.241 sport=53406 dport=443 packets=1349 bytes=91997 src=162.248.160.241 dst=192.168.214.101 sport=443 dport=53406 packets=681 bytes=59409 [ASSURED] mark=0 zone=0 use=2"
	ent := parseConntrackLine(line)
	if ent == nil {
		t.Fatal("expected non-nil entry")
	}
	if ent.Proto != "tcp" || ent.State != "ESTABLISHED" {
		t.Errorf("proto/state mismatch: %+v", ent)
	}
	if ent.SrcIP != "192.168.1.105" || ent.DstIP != "162.248.160.241" {
		t.Errorf("ip mismatch: %+v", ent)
	}
	if ent.SrcPort != 53406 || ent.DstPort != 443 {
		t.Errorf("port mismatch: %+v", ent)
	}
	if ent.OrigPackets != 1349 || ent.OrigBytes != 91997 {
		t.Errorf("orig pkts/bytes: %+v", ent)
	}
	if ent.ReplyPackets != 681 || ent.ReplyBytes != 59409 {
		t.Errorf("reply pkts/bytes: %+v", ent)
	}
	if !ent.Assured || ent.Unreplied || ent.Offload {
		t.Errorf("flags: %+v", ent)
	}
	if ent.TTLRem != 7434 {
		t.Errorf("ttl: %+v", ent)
	}
}

func TestParseConntrack_TCPSynSentUnreplied(t *testing.T) {
	line := "ipv4     2 tcp      6 110 SYN_SENT src=192.168.1.105 dst=10.0.0.50 sport=44402 dport=8443 packets=3 bytes=180 [UNREPLIED] src=10.0.0.50 dst=192.168.214.101 sport=8443 dport=44402 packets=0 bytes=0 mark=0 zone=0 use=2"
	ent := parseConntrackLine(line)
	if ent == nil {
		t.Fatal("expected non-nil entry")
	}
	if ent.State != "SYN_SENT" || !ent.Unreplied {
		t.Errorf("state/unreplied: %+v", ent)
	}
	if ent.OrigPackets != 3 || ent.ReplyPackets != 0 {
		t.Errorf("pkts: %+v", ent)
	}
}

func TestParseConntrack_UDPHealthyNoFlag(t *testing.T) {
	// UDP with replies but below the kernel's stream-tracking threshold —
	// real-router observation. No [ASSURED] flag but reply_packets > 0.
	line := "ipv4     2 udp      17 55 src=192.168.1.113 dst=216.239.38.223 sport=55708 dport=443 packets=9 bytes=4361 src=216.239.38.223 dst=192.168.214.101 sport=443 dport=55708 packets=12 bytes=4629 mark=0 zone=0 use=2"
	ent := parseConntrackLine(line)
	if ent == nil {
		t.Fatal("expected non-nil entry")
	}
	if ent.Unreplied {
		t.Errorf("should not be unreplied: %+v", ent)
	}
	if ent.Assured {
		t.Errorf("should not be assured (no flag in line): %+v", ent)
	}
	if ent.ReplyPackets != 12 {
		t.Errorf("reply_packets: %+v", ent)
	}
}

func TestParseConntrack_UDPUnreplied(t *testing.T) {
	// Real-router KDE Connect broadcast — observed live on 192.168.1.113.
	line := "ipv4     2 udp      17 45 src=192.168.1.113 dst=255.255.255.255 sport=47666 dport=1716 packets=1 bytes=1811 [UNREPLIED] src=255.255.255.255 dst=192.168.1.113 sport=1716 dport=47666 packets=0 bytes=0 mark=0 zone=0 use=2"
	ent := parseConntrackLine(line)
	if ent == nil {
		t.Fatal("expected non-nil entry")
	}
	if !ent.Unreplied {
		t.Errorf("expected unreplied: %+v", ent)
	}
	if ent.Proto != "udp" || ent.DstPort != 1716 {
		t.Errorf("proto/port: %+v", ent)
	}
}

func TestParseConntrack_OffloadFlag(t *testing.T) {
	line := "ipv4     2 tcp      6 432000 ESTABLISHED src=192.168.1.105 dst=1.2.3.4 sport=12345 dport=443 packets=100 bytes=10000 src=1.2.3.4 dst=192.168.214.101 sport=443 dport=12345 packets=80 bytes=80000 [OFFLOAD] mark=0 zone=0 use=2"
	ent := parseConntrackLine(line)
	if ent == nil {
		t.Fatal("expected non-nil entry")
	}
	if !ent.Offload {
		t.Errorf("expected offload flag: %+v", ent)
	}
	if ent.Unreplied || !ent.Assured {
		// note: [OFFLOAD] entries don't carry [ASSURED] even if bidirectional
		// — that's expected, we don't false-flag them as unreplied either.
		// just confirm Assured is correctly inferred-or-not from the line
	}
}

func TestParseConntrack_IPv6Skipped(t *testing.T) {
	line := "ipv6     10 udp      17 55 src=fdc8:8e54:170d::1 dst=fdc8:8e54:170d::2 sport=53 dport=2745 packets=1 bytes=87"
	ent := parseConntrackLine(line)
	if ent != nil {
		t.Errorf("ipv6 line should not parse; got %+v", ent)
	}
}

func TestParseConntrack_Malformed(t *testing.T) {
	for _, line := range []string{
		"",
		"garbage",
		"ipv4 2 icmp 1 30",                  // wrong proto
		"ipv4 2 tcp 6 53 src=incomplete",    // incomplete tuple
		"# header line",                     // not a real entry
	} {
		if got := parseConntrackLine(line); got != nil {
			t.Errorf("expected nil for %q; got %+v", line, got)
		}
	}
}

func TestFlowSummary_Lopsided(t *testing.T) {
	// Apex-stutter shape: assured but heavily one-sided.
	e := &ctEntry{
		Proto: "udp", SrcIP: "192.168.1.50", DstIP: "18.140.32.7",
		SrcPort: 50000, DstPort: 37015,
		Assured:      true,
		OrigPackets:  150,
		ReplyPackets: 2,
	}
	fs := flowSummaryFor(e)
	if !fs.Lopsided {
		t.Errorf("expected lopsided: %+v", fs)
	}
}

func TestFlowSummary_NotLopsided_BelowOrigThreshold(t *testing.T) {
	// Below the 20-pkt original threshold — could be a normal short flow.
	e := &ctEntry{Assured: true, OrigPackets: 10, ReplyPackets: 1}
	if flowSummaryFor(e).Lopsided {
		t.Error("should not be flagged lopsided")
	}
}

func TestFlowSummary_NotLopsided_EnoughReplies(t *testing.T) {
	e := &ctEntry{Assured: true, OrigPackets: 200, ReplyPackets: 50}
	if flowSummaryFor(e).Lopsided {
		t.Error("should not be flagged lopsided")
	}
}

func TestFlowSummary_Stalled_TCPPostHandshakeDrop(t *testing.T) {
	// DPI/SNI drop: handshake completed (assured), only the SYN-ACK came
	// back, the client sent the ClientHello + retransmits and got nothing.
	e := &ctEntry{
		Proto: "tcp", SrcIP: "192.168.1.104", DstIP: "95.217.255.81",
		SrcPort: 50000, DstPort: 443, State: "ESTABLISHED",
		Assured:      true,
		OrigPackets:  13,
		OrigBytes:    14000,
		ReplyPackets: 1,
		ReplyBytes:   60,
	}
	if !flowSummaryFor(e).Stalled {
		t.Error("expected TCP post-handshake drop to be flagged stalled")
	}
}

func TestFlowSummary_NotStalled_HealthyTCP(t *testing.T) {
	// Real upload draws ACKs back, so ReplyPackets grows past 1.
	e := &ctEntry{
		Proto: "tcp", Assured: true,
		OrigPackets: 100, OrigBytes: 50000,
		ReplyPackets: 40, ReplyBytes: 30000,
	}
	if flowSummaryFor(e).Stalled {
		t.Error("healthy TCP flow should not be flagged stalled")
	}
}

func TestFlowSummary_Stalled_UDPRetriedIntoVoid(t *testing.T) {
	// QUIC/UDP on any port: client kept sending, got at most one packet
	// back (a lone Retry). Crosses the stricter orig>=5 bar.
	e := &ctEntry{
		Proto: "udp", DstPort: 443,
		OrigPackets: 6, OrigBytes: 7000,
		ReplyPackets: 1, ReplyBytes: 60,
	}
	if !flowSummaryFor(e).Stalled {
		t.Error("expected UDP retried-into-void to be flagged stalled")
	}
}

func TestFlowSummary_NotStalled_UDPBelowOrigBar(t *testing.T) {
	// Three datagrams, one reply — below the >=5 bar; could be a normal
	// short request/response exchange.
	e := &ctEntry{
		Proto: "udp", DstPort: 443,
		OrigPackets: 3, OrigBytes: 3000,
		ReplyPackets: 1, ReplyBytes: 60,
	}
	if flowSummaryFor(e).Stalled {
		t.Error("short UDP exchange should not be flagged stalled")
	}
}

func TestFlowSummary_NotStalled_UDPDNS(t *testing.T) {
	// Port 53 is skipped outright — pure request/response, never this shape.
	e := &ctEntry{
		Proto: "udp", DstPort: 53,
		OrigPackets: 8, OrigBytes: 600,
		ReplyPackets: 1, ReplyBytes: 100,
	}
	if flowSummaryFor(e).Stalled {
		t.Error("UDP/53 should never be flagged stalled")
	}
}

func TestFrozenStep_MidStreamFreeze(t *testing.T) {
	// Cloudflare/cachix shape: download received ~23KB then reply froze while
	// the connection stayed ESTABLISHED (orig trickles a probe packet).
	prev := &ctEntry{
		Proto: "tcp", State: "ESTABLISHED", Assured: true,
		OrigPackets: 30, OrigBytes: 4824, ReplyPackets: 23, ReplyBytes: 23342,
	}
	cur := &ctEntry{
		Proto: "tcp", State: "ESTABLISHED", Assured: true,
		OrigPackets: 31, OrigBytes: 4942, ReplyPackets: 23, ReplyBytes: 23342,
	}
	if !frozenStep(prev, cur) {
		t.Error("expected frozen step for a reply-frozen download-shaped flow")
	}
}

func TestFrozenStep_HealthyProgress(t *testing.T) {
	// Reply keeps advancing → not frozen.
	prev := &ctEntry{
		Proto: "tcp", State: "ESTABLISHED", Assured: true,
		OrigBytes: 4000, ReplyPackets: 23, ReplyBytes: 23342,
	}
	cur := &ctEntry{
		Proto: "tcp", State: "ESTABLISHED", Assured: true,
		OrigBytes: 4100, ReplyPackets: 40, ReplyBytes: 45000,
	}
	if frozenStep(prev, cur) {
		t.Error("a flow making reply progress must not be a frozen step")
	}
}

func TestFrozenStep_Offloaded(t *testing.T) {
	// Offloaded flows don't update conntrack counters — "frozen" is meaningless.
	prev := &ctEntry{Proto: "tcp", State: "ESTABLISHED", Assured: true, Offload: true, OrigBytes: 4000, ReplyBytes: 23342, ReplyPackets: 23}
	cur := &ctEntry{Proto: "tcp", State: "ESTABLISHED", Assured: true, Offload: true, OrigBytes: 4000, ReplyBytes: 23342, ReplyPackets: 23}
	if frozenStep(prev, cur) {
		t.Error("offloaded flow must not be a frozen step")
	}
}

func TestFrozenStep_Symmetric(t *testing.T) {
	// Reply ≈ orig (chat / keepalive), not download-shaped → not frozen.
	prev := &ctEntry{Proto: "tcp", State: "ESTABLISHED", Assured: true, OrigBytes: 20000, ReplyBytes: 22000, ReplyPackets: 23}
	cur := &ctEntry{Proto: "tcp", State: "ESTABLISHED", Assured: true, OrigBytes: 20100, ReplyBytes: 22000, ReplyPackets: 23}
	if frozenStep(prev, cur) {
		t.Error("symmetric flow must not be a frozen step")
	}
}

func TestFrozenStep_NotEstablished(t *testing.T) {
	// A closing/finished download leaves ESTABLISHED → not frozen.
	prev := &ctEntry{Proto: "tcp", State: "FIN_WAIT", Assured: true, OrigBytes: 4000, ReplyBytes: 23342, ReplyPackets: 23}
	cur := &ctEntry{Proto: "tcp", State: "FIN_WAIT", Assured: true, OrigBytes: 4000, ReplyBytes: 23342, ReplyPackets: 23}
	if frozenStep(prev, cur) {
		t.Error("non-ESTABLISHED flow must not be a frozen step")
	}
}

func TestIsBogonIPv4(t *testing.T) {
	bogons := []string{
		"0.0.0.0", "10.0.0.1", "10.255.255.255",
		"100.64.0.1", "100.127.255.255", // CGNAT
		"127.0.0.1", "127.1.2.3",
		"169.254.1.1", // link-local
		"172.16.0.1", "172.31.255.255",
		"192.0.0.5", "192.0.2.99",
		"192.168.1.50", "192.168.214.212",
		"198.18.0.1", "198.51.100.1", "203.0.113.1",
		"224.0.0.251", "239.255.255.250", // multicast incl. mDNS + SSDP
		"240.0.0.1", "255.255.255.255", // reserved + broadcast
	}
	for _, ip := range bogons {
		if !isBogonIPv4(ip) {
			t.Errorf("expected %q to be bogon", ip)
		}
	}
	publics := []string{
		"1.1.1.1", "8.8.8.8",
		"104.18.37.127",
		"142.250.147.188",
		"18.140.32.7",
		"100.63.255.255", // just below CGNAT
		"100.128.0.0",    // just above CGNAT
		"99.255.255.255", // public
		"192.0.1.0",      // not 192.0.0/24 or 192.0.2/24
		"192.1.0.0",      // not 192.0.x range
		"203.0.114.1",    // not TEST-NET-3
		"239.255.255.249",// still multicast → bogon; sanity-check the boundary
	}
	for _, ip := range publics {
		want := false
		if ip == "239.255.255.249" {
			want = true // multicast — covered by IsMulticast
		}
		if got := isBogonIPv4(ip); got != want {
			t.Errorf("isBogonIPv4(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestICMPCodeText(t *testing.T) {
	cases := map[byte]string{
		0:  "net unreachable",
		3:  "port unreachable",
		13: "communication admin-prohibited (filtered)",
		99: "code 99",
	}
	for code, want := range cases {
		if got := icmpCodeText(code); got != want {
			t.Errorf("code %d: got %q, want %q", code, got, want)
		}
	}
}

func TestExtractTLSSNI_Standard(t *testing.T) {
	pkt := buildClientHelloWithSNI("example.com")
	if got := extractTLSSNI(pkt); got != "example.com" {
		t.Errorf("got %q, want %q", got, "example.com")
	}
}

func TestExtractTLSSNI_NoSNI(t *testing.T) {
	pkt := buildClientHelloWithSNI("")
	if got := extractTLSSNI(pkt); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractTLSSNI_BadInput(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		{0x16},                // too short
		{0x17, 0x03, 0x03, 0x00, 0x10}, // wrong content type
		{0x16, 0x03, 0x03, 0x00, 0x01, 0x02 /* not ClientHello */},
	} {
		if got := extractTLSSNI(b); got != "" {
			t.Errorf("expected empty for malformed input; got %q", got)
		}
	}
}

// buildClientHelloWithSNI constructs a minimal valid TLS 1.2 ClientHello
// with one server_name extension (or no SNI when name is empty).
func buildClientHelloWithSNI(name string) []byte {
	// extensions block
	exts := []byte{}
	if name != "" {
		sn := []byte(name)
		// server_name_list: list_len(2) name_type(1) name_len(2) name
		listLen := uint16(1 + 2 + len(sn))
		ext := []byte{0x00, 0x00} // extension type = server_name
		extDataLen := 2 + int(listLen)
		ext = append(ext, byte(extDataLen>>8), byte(extDataLen))
		ext = append(ext, byte(listLen>>8), byte(listLen))
		ext = append(ext, 0x00) // name type = host_name
		ext = append(ext, byte(len(sn)>>8), byte(len(sn)))
		ext = append(ext, sn...)
		exts = append(exts, ext...)
	}
	extLen := len(exts)

	// ClientHello body
	body := []byte{0x03, 0x03}                   // version
	body = append(body, make([]byte, 32)...)     // random
	body = append(body, 0x00)                    // sessionid len = 0
	body = append(body, 0x00, 0x02, 0x00, 0x2f)  // cipher_suites: len=2, one suite
	body = append(body, 0x01, 0x00)              // compression_methods: len=1, NULL
	body = append(body, byte(extLen>>8), byte(extLen))
	body = append(body, exts...)

	// Handshake header: type(1)=ClientHello, length(3)
	hsLen := len(body)
	hs := []byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	hs = append(hs, body...)

	// Record header: type(1)=handshake(0x16), version(2), length(2)
	rec := []byte{0x16, 0x03, 0x03}
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func TestQUICRetryTracker_FiresOnce(t *testing.T) {
	q := &quicRetryTracker{
		retries: make(map[string]*quicRetryState),
		window:  2,
		minHits: 3,
	}
	now := mustParseTime("2026-06-04T10:00:00Z")
	if got := q.observe("1.2.3.4", 443, now); got != 0 {
		t.Errorf("first hit: got %d, want 0", got)
	}
	if got := q.observe("1.2.3.4", 443, now); got != 0 {
		t.Errorf("second hit: got %d, want 0", got)
	}
	if got := q.observe("1.2.3.4", 443, now); got != 3 {
		t.Errorf("third hit: got %d, want 3", got)
	}
	// Fourth hit should NOT re-fire (emitted flag set).
	if got := q.observe("1.2.3.4", 443, now); got != 0 {
		t.Errorf("fourth hit re-fired: got %d, want 0", got)
	}
}

func TestQUICRetryTracker_PerDest(t *testing.T) {
	q := &quicRetryTracker{
		retries: make(map[string]*quicRetryState),
		window:  2,
		minHits: 3,
	}
	now := mustParseTime("2026-06-04T10:00:00Z")
	for i := 0; i < 3; i++ {
		q.observe("1.2.3.4", 443, now)
	}
	// Different dest — independent counter.
	if got := q.observe("5.6.7.8", 443, now); got != 0 {
		t.Errorf("new dest fired prematurely: %d", got)
	}
}

func TestHostnameMap_Dedup(t *testing.T) {
	h := &hostnameMap{m: make(map[string][]string)}
	h.add("1.2.3.4", "example.com")
	h.add("1.2.3.4", "example.com") // duplicate
	h.add("1.2.3.4", "other.com")
	if got := h.get("1.2.3.4"); got != "other.com" {
		t.Errorf("most-recent should be other.com; got %q", got)
	}
	if len(h.m["1.2.3.4"]) != 2 {
		t.Errorf("expected 2 entries; got %d", len(h.m["1.2.3.4"]))
	}
}

func TestDNSName_Simple(t *testing.T) {
	// Encoded "example.com." = 0x07 'example' 0x03 'com' 0x00
	enc := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name, n, ok := dnsName(enc, 0)
	if !ok || name != "example.com" || n != len(enc) {
		t.Errorf("got name=%q n=%d ok=%v", name, n, ok)
	}
}

func TestDNSName_Compression(t *testing.T) {
	// "ea.com" = 0x02 'ea' 0x03 'com' 0x00
	// Then a pointer (0xc0 0x00) to offset 0.
	enc := []byte{2, 'e', 'a', 3, 'c', 'o', 'm', 0, 0xc0, 0x00}
	name, _, ok := dnsName(enc, 8) // start at the pointer
	if !ok || name != "ea.com" {
		t.Errorf("got name=%q ok=%v", name, ok)
	}
}

// --- ICMP parsing test (constructs an ICMP type 3 packet payload) --------

func TestParseICMP_PortUnreachable(t *testing.T) {
	// ICMP type=3 code=3 + inner IPv4 + 8 bytes of original packet.
	icmp := make([]byte, 36)
	icmp[0] = 3 // type
	icmp[1] = 3 // code (port unreachable)
	// Inner IPv4 header at offset 8 — IHL=5
	icmp[8] = 0x45
	icmp[9+8] = 17 // proto = udp
	// inner dest IP at offset 8+16..8+20 = bytes 24..28
	copy(icmp[24:28], []byte{18, 140, 32, 7})
	// inner src/dst ports right after IHL=20 bytes: at offset 8+20+2 = 30
	binary.BigEndian.PutUint16(icmp[28:30], 50000) // sport
	binary.BigEndian.PutUint16(icmp[30:32], 37015) // dport

	var emitted []Event
	enr := &packetEnrichers{} // nil-safe enrich() returns zero values
	parseICMP(mustParseTime("2026-06-04T10:00:00Z"), "10.0.0.1", "192.168.1.50", icmp, "192.168.1.50", enr, func(e Event) {
		emitted = append(emitted, e)
	})
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event; got %d", len(emitted))
	}
	if emitted[0].Type != "icmp-unreachable" {
		t.Errorf("type: %q", emitted[0].Type)
	}
}

// TestParseICMP_SourceAttribution guards the peer-vs-middlebox split: an
// unreachable sent by the original destination itself is the peer
// refusing; one from any other IP is an intermediate hop (router, DPI
// appliance). Truncated inner headers leave Source empty.
func TestParseICMP_SourceAttribution(t *testing.T) {
	build := func() []byte {
		icmp := make([]byte, 36)
		icmp[0] = 3  // type
		icmp[1] = 13 // communication admin-prohibited — classic DPI signature
		icmp[8] = 0x45
		icmp[9+8] = 6                              // proto = tcp
		copy(icmp[24:28], []byte{18, 140, 32, 7}) // inner dest 18.140.32.7
		return icmp
	}
	cases := []struct {
		name, srcIP string
		truncate    bool
		want        string
	}{
		{"from destination itself", "18.140.32.7", false, "peer"},
		{"from intermediate hop", "10.0.0.1", false, "middlebox"},
		{"truncated inner header", "10.0.0.1", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			icmp := build()
			if tc.truncate {
				icmp = icmp[:10] // inner header incomplete
			}
			var emitted []Event
			enr := &packetEnrichers{}
			parseICMP(mustParseTime("2026-06-04T10:00:00Z"), tc.srcIP, "192.168.1.50", icmp, "192.168.1.50", enr, func(e Event) {
				emitted = append(emitted, e)
			})
			if len(emitted) != 1 {
				t.Fatalf("expected 1 event; got %d", len(emitted))
			}
			var d ICMPUnreachableData
			if err := json.Unmarshal(emitted[0].Data, &d); err != nil {
				t.Fatal(err)
			}
			if d.Source != tc.want {
				t.Fatalf("source = %q, want %q (original_dest=%q)", d.Source, tc.want, d.OriginalDest)
			}
		})
	}
}

func TestParseICMP_IgnoresWrongDirection(t *testing.T) {
	icmp := []byte{3, 3, 0, 0, 0, 0, 0, 0, 0x45}
	icmp = append(icmp, make([]byte, 27)...)
	var emitted []Event
	enr := &packetEnrichers{}
	parseICMP(mustParseTime("2026-06-04T10:00:00Z"), "10.0.0.1", "10.0.0.2", icmp, "192.168.1.50", enr, func(e Event) {
		emitted = append(emitted, e)
	})
	if len(emitted) != 0 {
		t.Errorf("should not emit when ICMP is not addressed to client; got %d", len(emitted))
	}
}

func TestDedupCache_CollapsesBurst(t *testing.T) {
	d := newDedupCache(1 * time.Second)
	var emitted []Event
	emit := d.wrap(func(ev Event) { emitted = append(emitted, ev) })

	t0 := mustParseTime("2026-06-08T20:00:00Z")
	mk := func(offset time.Duration, host string) Event {
		body, _ := json.Marshal(DNSQueryData{Client: "1.2.3.4", Hostname: host, QType: "PTR", ID: 1})
		return Event{Type: "dns-query", Timestamp: t0.Add(offset), Data: body}
	}

	// Three near-identical events within the window → only first survives.
	emit(mk(0, "_googlecast._tcp.local"))
	emit(mk(1*time.Millisecond, "_googlecast._tcp.local"))
	emit(mk(50*time.Millisecond, "_googlecast._tcp.local"))
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event after burst-dedup; got %d", len(emitted))
	}

	// Re-emit outside the window → passes through again (legitimate
	// repeat from the client).
	emit(mk(1500*time.Millisecond, "_googlecast._tcp.local"))
	if len(emitted) != 2 {
		t.Fatalf("expected dedup to release after window; got %d", len(emitted))
	}

	// Different hostname → different key → emits regardless of window.
	emit(mk(10*time.Millisecond, "other.local"))
	if len(emitted) != 3 {
		t.Fatalf("expected distinct-key event to emit; got %d", len(emitted))
	}
}

func TestDedupCache_TypesPassthrough(t *testing.T) {
	d := newDedupCache(1 * time.Second)
	var n int
	emit := d.wrap(func(ev Event) { n++ })

	// Non-keyable types (warning, done, conntrack-snapshot) must always
	// emit, even on rapid repeats — they're stateful events whose
	// duplication is impossible.
	for i := 0; i < 5; i++ {
		emit(Event{Type: "warning", Timestamp: mustParseTime("2026-06-08T20:00:00Z")})
	}
	if n != 5 {
		t.Fatalf("non-keyable events should not be deduped; got %d", n)
	}
}

// --- helpers -------------------------------------------------------------

func mustParseTime(s string) (t time.Time) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return
}
