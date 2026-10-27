package checker

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func stunTestReply(tx []byte) []byte {
	p := make([]byte, 32)
	binary.BigEndian.PutUint16(p, 0x101)
	binary.BigEndian.PutUint16(p[2:], 12)
	binary.BigEndian.PutUint32(p[4:], 0x2112a442)
	copy(p[8:20], tx)
	binary.BigEndian.PutUint16(p[20:], 0x20)
	binary.BigEndian.PutUint16(p[22:], 8)
	p[25] = 1
	binary.BigEndian.PutUint16(p[26:], 54321^0x2112)
	for i, b := range []byte{203, 0, 113, 7} {
		p[28+i] = b ^ p[4+i]
	}
	return p
}

func TestSTUNReplyValidation(t *testing.T) {
	tx := []byte("transaction1")
	good := stunTestReply(tx)
	if addr, ok := stunMappedAddress(good, tx); !ok || addr != "203.0.113.7:54321" {
		t.Fatalf("%s %v", addr, ok)
	}
	for _, kind := range []string{"transaction", "type", "cookie", "length", "attribute", "family", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			p := append([]byte(nil), good...)
			switch kind {
			case "transaction":
				p[8] ^= 1
			case "type":
				p[0] = 0
			case "cookie":
				p[4] = 0
			case "length":
				p[3] = 11
			case "attribute":
				p[23] = 40
			case "family":
				p[25] = 3
			case "truncated":
				p = p[:31]
			}
			if _, ok := stunMappedAddress(p, tx); ok {
				t.Fatal("accepted invalid reply")
			}
		})
	}
}

func TestSTUNProbe(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 128)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil || n < 20 {
			return
		}
		// A mismatched transaction must be ignored, then the valid reply accepted.
		bad := stunTestReply([]byte("wrong-value!"))
		conn.WriteTo(bad, addr)
		conn.WriteTo(stunTestReply(buf[8:20]), addr)
	}()
	r := probeSTUN(context.Background(), conn.LocalAddr().String())
	if r.Verdict != VerdictOK || r.Confidence != ConfidenceHigh {
		t.Fatalf("%+v", r)
	}
}

func TestSTUNProbeDeadline(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := probeSTUN(ctx, conn.LocalAddr().String())
	if r.Verdict == VerdictOK || r.Confidence != ConfidenceLow {
		t.Fatalf("%+v", r)
	}
	if time.Since(start) > time.Second {
		t.Fatal("ignored cancellation")
	}
}
