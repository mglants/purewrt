package mihomoapi

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Minimal stdlib WebSocket reader used to consume mihomo's /traffic and
// /connections streams. We never speak to the server after the initial
// HTTP Upgrade — mihomo pushes one JSON line per frame — so the client→
// server side reduces to "send Upgrade, then read forever." Skipping a
// full WebSocket implementation lets us avoid bringing gorilla/websocket
// or a similar third-party dep into the OpenWrt build.
//
// Spec corners covered: text frames (opcode 0x1), continuation frames
// (opcode 0x0), close frames (opcode 0x8 → return io.EOF), ping frames
// (opcode 0x9 → discard, the underlying TCP keepalive is fine for this
// use case). Binary, mask-from-server, and compression are intentionally
// unsupported — mihomo never sends them.

// wsDial performs an HTTP/1.1 Upgrade handshake and returns the live conn
// + a bufio.Reader positioned right at the first WebSocket frame. The
// caller is responsible for closing conn when done with the stream.
func wsDial(ctx context.Context, base, path, secret string) (net.Conn, *bufio.Reader, error) {
	u, err := url.Parse("http://" + base + path)
	if err != nil {
		return nil, nil, fmt.Errorf("ws: parse url: %w", err)
	}
	if secret != "" {
		q := u.Query()
		if q.Get("token") == "" {
			q.Set("token", secret)
			u.RawQuery = q.Encode()
		}
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, nil, fmt.Errorf("ws: dial %s: %w", host, err)
	}
	key, err := wsKey()
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	req := strings.Builder{}
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", u.RequestURI())
	fmt.Fprintf(&req, "Host: %s\r\n", u.Host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", key)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	if secret != "" {
		fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", secret)
	}
	req.WriteString("\r\n")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("ws: write upgrade: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("ws: read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("ws: upgrade rejected: %s", resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("ws: server did not upgrade to websocket: %q", resp.Header.Get("Upgrade"))
	}
	return conn, br, nil
}

// wsKey returns a fresh random 16-byte value base64'd as required by
// RFC 6455 §4.1. Mihomo doesn't validate the Sec-WebSocket-Accept response
// (and neither do we) but we generate the key correctly for any future
// server that does enforce it.
func wsKey() (string, error) {
	var k [16]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// wsReadFrame returns the next text-payload frame's bytes, transparently
// joining continuation frames and silently discarding ping/pong control
// frames. Returns io.EOF on a server-initiated close.
func wsReadFrame(br *bufio.Reader) ([]byte, error) {
	var payload []byte
	for {
		hdr, err := readN(br, 2)
		if err != nil {
			return nil, err
		}
		fin := hdr[0]&0x80 != 0
		opcode := hdr[0] & 0x0F
		masked := hdr[1]&0x80 != 0
		length := int64(hdr[1] & 0x7F)
		switch length {
		case 126:
			b, err := readN(br, 2)
			if err != nil {
				return nil, err
			}
			length = int64(binary.BigEndian.Uint16(b))
		case 127:
			b, err := readN(br, 8)
			if err != nil {
				return nil, err
			}
			length = int64(binary.BigEndian.Uint64(b))
		}
		var mask [4]byte
		if masked {
			b, err := readN(br, 4)
			if err != nil {
				return nil, err
			}
			copy(mask[:], b)
		}
		// Refuse pathologically large frames so a misbehaving server
		// can't push the device into OOM. 4 MiB is well above what
		// mihomo's connection-list snapshot ever produces.
		if length < 0 || length > 4<<20 {
			return nil, fmt.Errorf("ws: refusing frame of %d bytes", length)
		}
		data, err := readN(br, int(length))
		if err != nil {
			return nil, err
		}
		if masked {
			for i := range data {
				data[i] ^= mask[i&3]
			}
		}
		switch opcode {
		case 0x0, 0x1:
			// Continuation or text. Append; stop when FIN bit set.
			payload = append(payload, data...)
			if fin {
				return payload, nil
			}
		case 0x8:
			return nil, io.EOF
		case 0x9, 0xA:
			// ping / pong — discard. Mihomo doesn't actually use these
			// but the spec requires we tolerate them.
			continue
		default:
			return nil, fmt.Errorf("ws: unsupported opcode 0x%x", opcode)
		}
	}
}

func readN(r io.Reader, n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

