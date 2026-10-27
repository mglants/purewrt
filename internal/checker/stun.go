package checker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// UDP canaries follow normal router routing, just like the HTTP canaries.
// They deliberately do not use Zapret's generated-packet mark: it disables
// conntrack and makes ordinary replies look unsolicited to the firewall.
func probeSTUN(ctx context.Context, target string) (r CanaryResult) {
	r.Target = "stun://" + target
	r.Confidence = ConfidenceLow
	start := time.Now()
	defer func() { r.Latency = time.Since(start); r.LatencyMS = r.Latency.Milliseconds() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", target)
	if err != nil {
		r.Verdict, r.Reason = "udp_fail", err.Error()
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	r.SysIPs = []string{conn.RemoteAddr().(*net.UDPAddr).IP.String()}
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request, 1)
	binary.BigEndian.PutUint32(request[4:], 0x2112a442)
	if _, err = rand.Read(request[8:]); err != nil {
		r.Verdict, r.Reason = "udp_fail", err.Error()
		return
	}
	deadline, _ := ctx.Deadline()
	buf := make([]byte, 2048)
	for attempt := 0; attempt < 3; attempt++ {
		until := time.Now().Add(time.Second)
		if until.After(deadline) {
			until = deadline
		}
		conn.SetDeadline(until)
		if _, err = conn.Write(request); err != nil {
			break
		}
		for {
			var n int
			n, err = conn.Read(buf)
			if err != nil {
				break
			}
			mapped, valid := stunMappedAddress(buf[:n], request[8:])
			if !valid {
				continue
			} // unrelated/malformed replies never count as success
			r.Verdict, r.Confidence = VerdictOK, ConfidenceHigh
			r.Reason = "UDP STUN reply validated; public endpoint " + mapped
			return
		}
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			break
		}
	}
	r.Verdict = "udp_fail"
	if e, ok := err.(net.Error); (ok && e.Timeout()) || ctx.Err() == context.DeadlineExceeded {
		r.Verdict = "udp_timeout"
	}
	r.Reason = fmt.Sprintf("No valid UDP STUN reply: %v; endpoint or network failure, not proof of blocking", err)
	return
}

// Require a complete Binding Success Response with our transaction ID and
// a correctly sized mapped-address attribute (RFC 5389).
func stunMappedAddress(packet, transaction []byte) (string, bool) {
	if len(packet) < 20 || len(transaction) != 12 || binary.BigEndian.Uint16(packet) != 0x0101 ||
		binary.BigEndian.Uint32(packet[4:]) != 0x2112a442 || !bytes.Equal(packet[8:20], transaction) {
		return "", false
	}
	length := int(binary.BigEndian.Uint16(packet[2:]))
	if length%4 != 0 || length+20 != len(packet) {
		return "", false
	}
	mapped := ""
	for pos := 20; pos < len(packet); {
		if pos+4 > len(packet) {
			return "", false
		}
		kind, size := binary.BigEndian.Uint16(packet[pos:]), int(binary.BigEndian.Uint16(packet[pos+2:]))
		next := pos + 4 + (size+3)&^3
		if next > len(packet) {
			return "", false
		}
		v := packet[pos+4 : pos+4+size]
		if kind == 0x20 || kind == 1 {
			if size < 4 || v[0] != 0 {
				return "", false
			}
			if !(v[1] == 1 && size == 8 || v[1] == 2 && size == 20) {
				return "", false
			}
			port := binary.BigEndian.Uint16(v[2:])
			ip := append(net.IP(nil), v[4:]...)
			if kind == 0x20 {
				port ^= 0x2112
				mask := append([]byte{0x21, 0x12, 0xa4, 0x42}, transaction...)
				for i := range ip {
					ip[i] ^= mask[i]
				}
			}
			mapped = net.JoinHostPort(ip.String(), fmt.Sprint(port))
		}
		pos = next
	}
	return mapped, mapped != ""
}

func udpBlockingCanaries(ctx context.Context) []CanaryResult {
	targets := []string{"stun.cloudflare.com:3478", "stun.nextcloud.com:443"}
	results := make([]CanaryResult, len(targets))
	done := make(chan int, len(targets))
	for i, target := range targets {
		go func(i int, target string) { results[i] = probeSTUN(ctx, target); done <- i }(i, target)
	}
	for range targets {
		<-done
	}
	return results
}
