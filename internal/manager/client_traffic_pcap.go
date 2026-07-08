package manager

// Packet decoding for ClientTraffic: pcap stream reader, ethernet/IPv4/
// TCP/UDP/ICMP parsers, DNS wire-format parsing, TLS ClientHello SNI
// extraction, and the QUIC-initial retry tracker.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

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

// --- pcap reader ---------------------------------------------------------
//
// PCAP file format (RFC 1761-ish; tcpdump --version 4.99 emits this by
// default without --keep-going / --pcapng): 24-byte global header, then
// 16-byte per-packet header + caplen bytes of frame data. Linktype tells
// us what's wrapping the IP layer; we expect EN10MB (=1) for br-lan.

const (
	pcapMagicLE    = 0xa1b2c3d4
	pcapMagicBE    = 0xd4c3b2a1
	linkTypeEN10MB = 1
)

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
