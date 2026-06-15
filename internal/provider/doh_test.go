package provider

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBuildDNSQueryAndParseAnswers(t *testing.T) {
	t.Parallel()
	q, err := buildDNSQuery("example.com", 1)
	if err != nil {
		t.Fatalf("buildDNSQuery: %v", err)
	}
	// Header: 12 bytes; QNAME: 0x07example0x03com0x00 = 13 bytes; QTYPE+QCLASS: 4 bytes.
	if len(q) != 12+13+4 {
		t.Fatalf("query length = %d, want %d", len(q), 12+13+4)
	}
	if got := binary.BigEndian.Uint16(q[2:4]); got != 0x0100 {
		t.Fatalf("flags = %#x, want 0x0100 (RD)", got)
	}

	// Build a synthetic response containing one A record for 203.0.113.7.
	resp := bytes.NewBuffer(nil)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180) // QR=1, RD=1, RA=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // qdcount
	binary.BigEndian.PutUint16(hdr[6:8], 1)      // ancount
	resp.Write(hdr)
	// Question: copy from query (everything after header).
	resp.Write(q[12:])
	// Answer: name pointer to offset 12, type A, class IN, ttl=300, rdlen=4, rdata.
	resp.Write([]byte{0xC0, 0x0C})
	tcr := make([]byte, 10)
	binary.BigEndian.PutUint16(tcr[0:2], 1) // type A
	binary.BigEndian.PutUint16(tcr[2:4], 1) // class IN
	binary.BigEndian.PutUint32(tcr[4:8], 300)
	binary.BigEndian.PutUint16(tcr[8:10], 4)
	resp.Write(tcr)
	resp.Write([]byte{203, 0, 113, 7})

	ips, err := parseDNSAnswers(resp.Bytes(), 1)
	if err != nil {
		t.Fatalf("parseDNSAnswers: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(203, 0, 113, 7)) {
		t.Fatalf("ips = %v, want [203.0.113.7]", ips)
	}
}

func TestDoHResolverLookupHost(t *testing.T) {
	t.Parallel()
	// Fake DoH server: parses wire-format query, returns A record for any
	// hostname (203.0.113.5) and a NoAnswer for AAAA.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
		if err != nil || len(body) < 12 {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		// Echo question with a synthesized answer; for type AAAA return no
		// answers so the resolver still treats the lookup as successful.
		qtype := uint16(0)
		off := 12
		for off < len(body) && body[off] != 0 {
			off += 1 + int(body[off])
		}
		if off+5 <= len(body) {
			qtype = binary.BigEndian.Uint16(body[off+1 : off+3])
		}
		resp := bytes.NewBuffer(nil)
		hdr := make([]byte, 12)
		binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
		binary.BigEndian.PutUint16(hdr[4:6], 1)
		if qtype == 1 {
			binary.BigEndian.PutUint16(hdr[6:8], 1)
		}
		resp.Write(hdr)
		resp.Write(body[12:])
		if qtype == 1 {
			resp.Write([]byte{0xC0, 0x0C})
			tcr := make([]byte, 10)
			binary.BigEndian.PutUint16(tcr[0:2], 1)
			binary.BigEndian.PutUint16(tcr[2:4], 1)
			binary.BigEndian.PutUint32(tcr[4:8], 60)
			binary.BigEndian.PutUint16(tcr[8:10], 4)
			resp.Write(tcr)
			resp.Write([]byte{203, 0, 113, 5})
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp.Bytes())
	}))
	defer srv.Close()

	r := NewDoHResolver([]string{srv.URL}, 3*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(203, 0, 113, 5)) {
		t.Fatalf("ips = %v, want [203.0.113.5]", ips)
	}

	// IP literal short-circuits without hitting DoH.
	ips, err = r.LookupHost(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("IP literal LookupHost: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("IP literal ips = %v", ips)
	}
}

func TestDoHResolverFailsAllEndpoints(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusForbidden)
	}))
	defer srv.Close()

	r := NewDoHResolver([]string{srv.URL}, 1*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.LookupHost(ctx, "example.com"); err == nil {
		t.Fatal("expected error, got nil")
	}
}
