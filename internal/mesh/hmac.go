package mesh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"sync"
	"time"
)

// MaxClockSkew bounds how far a request timestamp may drift from the
// verifier's clock. Routers sync via ntpd, so 120s is generous.
const MaxClockSkew = 120 * time.Second

// Header names used by the mesh API auth scheme.
const (
	HeaderTime  = "X-PWMesh-Time"
	HeaderNonce = "X-PWMesh-Nonce"
	HeaderMAC   = "X-PWMesh-MAC"
)

func requestMAC(key []byte, ts int64, nonce, method, path string) []byte {
	m := hmac.New(sha256.New, key)
	writeField(m, strconv.FormatInt(ts, 10))
	writeField(m, nonce)
	writeField(m, method)
	writeField(m, path)
	return m.Sum(nil)
}

func writeField(m hash.Hash, s string) {
	m.Write([]byte(s))
	m.Write([]byte{'\n'})
}

// SignRequest computes the request MAC for the mesh API auth headers.
func SignRequest(key []byte, ts int64, nonce, method, path string) string {
	return hex.EncodeToString(requestMAC(key, ts, nonce, method, path))
}

// SignResponse authenticates a response so a spoofed peer cannot feed bogus
// credentials back to the prober: MAC over the request's ts+nonce and the
// response body hash.
func SignResponse(key []byte, ts int64, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	m := hmac.New(sha256.New, key)
	writeField(m, strconv.FormatInt(ts, 10))
	writeField(m, nonce)
	writeField(m, hex.EncodeToString(sum[:]))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyResponse checks a response MAC produced by SignResponse.
func VerifyResponse(key []byte, ts int64, nonce string, body []byte, mac string) error {
	if !hmacEqualHex(mac, SignResponse(key, ts, nonce, body)) {
		return errors.New("mesh: response MAC mismatch")
	}
	return nil
}

// VerifyRequest validates the auth headers of an inbound mesh API request:
// MAC correctness, clock-skew window, and nonce uniqueness within the window.
func VerifyRequest(key []byte, now time.Time, ts int64, nonce, method, path, mac string, cache *NonceCache) error {
	if nonce == "" {
		return errors.New("mesh: missing nonce")
	}
	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(MaxClockSkew/time.Second) {
		return errors.New("mesh: request timestamp outside allowed window")
	}
	if !hmacEqualHex(mac, SignRequest(key, ts, nonce, method, path)) {
		return errors.New("mesh: request MAC mismatch")
	}
	if cache != nil && !cache.Remember(nonce, now) {
		return errors.New("mesh: nonce replay")
	}
	return nil
}

func hmacEqualHex(a, b string) bool {
	ab, err := hex.DecodeString(a)
	if err != nil {
		return false
	}
	bb, err := hex.DecodeString(b)
	if err != nil {
		return false
	}
	return hmac.Equal(ab, bb)
}

// NonceCache is a bounded set of recently seen nonces providing replay
// protection inside the clock-skew window. Oldest entries fall out on
// capacity or TTL expiry.
type NonceCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	limit int
	seen  map[string]time.Time
	order []string
}

// NewNonceCache builds a cache holding up to limit nonces for ttl.
func NewNonceCache(limit int, ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl, limit: limit, seen: make(map[string]time.Time)}
}

// Remember records a nonce; it reports false when the nonce was already
// present (a replay).
func (c *NonceCache) Remember(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Expire by TTL first, then bound by capacity.
	for len(c.order) > 0 {
		oldest := c.order[0]
		at, ok := c.seen[oldest]
		if ok && now.Sub(at) <= c.ttl && len(c.order) < c.limit {
			break
		}
		if ok && now.Sub(at) <= c.ttl && len(c.order) >= c.limit {
			// capacity eviction
			delete(c.seen, oldest)
			c.order = c.order[1:]
			continue
		}
		delete(c.seen, oldest)
		c.order = c.order[1:]
	}

	if _, dup := c.seen[nonce]; dup {
		return false
	}
	c.seen[nonce] = now
	c.order = append(c.order, nonce)
	return true
}
