package mihomoapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// makeFrame builds a single text WebSocket frame with FIN=1, no mask
// (server→client). Helper for the fake mihomo server below.
func makeFrame(payload []byte) []byte {
	var hdr []byte
	hdr = append(hdr, 0x81) // FIN=1, opcode=text
	switch {
	case len(payload) < 126:
		hdr = append(hdr, byte(len(payload)))
	case len(payload) < 65536:
		hdr = append(hdr, 126, 0, 0)
		binary.BigEndian.PutUint16(hdr[len(hdr)-2:], uint16(len(payload)))
	default:
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(len(payload)))
		hdr = append(hdr, 127)
		hdr = append(hdr, ext...)
	}
	return append(hdr, payload...)
}

// fakeMihomoWS implements a tiny WebSocket server that replies to the
// Upgrade handshake and then streams the supplied frames.
func fakeMihomoWS(t *testing.T, frames [][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Sec-WebSocket-Key")
		if key == "" {
			http.Error(w, "missing key", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer func() { _ = conn.Close() }()
		acceptHash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		accept := base64.StdEncoding.EncodeToString(acceptHash[:])
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		_, _ = brw.WriteString(resp)
		_ = brw.Flush()
		for _, f := range frames {
			if _, err := conn.Write(f); err != nil {
				return
			}
		}
		// Send a close frame at end so the client cleanly exits.
		_, _ = conn.Write([]byte{0x88, 0x00})
	}))
	return srv
}

// hostOf strips http:// from an httptest URL.
func hostOf(srv *httptest.Server) string {
	u, _ := url.Parse(srv.URL)
	return u.Host
}

func TestWSReadFrameSmall(t *testing.T) {
	t.Parallel()
	buf := bytes.NewReader(makeFrame([]byte(`{"up":1,"down":2}`)))
	br := bufio.NewReader(buf)
	got, err := wsReadFrame(br)
	if err != nil {
		t.Fatalf("wsReadFrame: %v", err)
	}
	if string(got) != `{"up":1,"down":2}` {
		t.Fatalf("payload = %q", got)
	}
}

func TestWSReadFrameExtended16(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte("x"), 200)
	buf := bytes.NewReader(makeFrame(payload))
	br := bufio.NewReader(buf)
	got, err := wsReadFrame(br)
	if err != nil {
		t.Fatalf("wsReadFrame: %v", err)
	}
	if len(got) != 200 {
		t.Fatalf("got %d bytes, want 200", len(got))
	}
}

func TestWSReadFrameCloseReturnsEOF(t *testing.T) {
	t.Parallel()
	// Close frame: opcode=0x8, FIN=1, no payload.
	buf := bytes.NewReader([]byte{0x88, 0x00})
	br := bufio.NewReader(buf)
	if _, err := wsReadFrame(br); err != io.EOF {
		t.Fatalf("expected io.EOF on close, got %v", err)
	}
}

func TestWSReadFrameRejectsHugeFrame(t *testing.T) {
	t.Parallel()
	// 64-bit length set to 8 GiB — must be refused.
	hdr := []byte{0x81, 127, 0, 0, 0, 2, 0, 0, 0, 0}
	br := bufio.NewReader(bytes.NewReader(hdr))
	if _, err := wsReadFrame(br); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected refusal, got %v", err)
	}
}

func TestSubscribeTrafficStreamsFrames(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		makeFrame([]byte(`{"up":100,"down":200}`)),
		makeFrame([]byte(`{"up":300,"down":400}`)),
	}
	srv := fakeMihomoWS(t, frames)
	defer srv.Close()

	cli := Client{Base: hostOf(srv), Secret: "tok"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, errs, err := cli.SubscribeTraffic(ctx)
	if err != nil {
		t.Fatalf("SubscribeTraffic: %v", err)
	}
	var got []TrafficSample
	timeout := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case s, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed before receiving 2 samples; got %d", len(got))
			}
			got = append(got, s)
		case e, ok := <-errs:
			if !ok {
				// errs closed cleanly; keep draining ch.
				errs = nil
				continue
			}
			t.Fatalf("err channel: %v", e)
		case <-timeout:
			t.Fatalf("timeout waiting for samples (got %d)", len(got))
		}
	}
	if got[0].Up != 100 || got[1].Down != 400 {
		t.Fatalf("samples = %+v", got)
	}
}

// Ensure wsDial rejects servers that DON'T upgrade.
func TestWSDialRejectsNonUpgradeServer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := wsDial(ctx, hostOf(srv), "/traffic", "")
	if err == nil {
		t.Fatal("expected upgrade rejection")
	}
}

// Tiny smoke check — verify we can dial a TCP server that hangs without
// blocking on the test budget.
func TestWSDialTimesOutOnSilentServer(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			time.Sleep(5 * time.Second)
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _, err = wsDial(ctx, ln.Addr().String(), "/traffic", "")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
