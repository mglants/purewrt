package provider

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/purewrt/purewrt/internal/system"
)

// DefaultTOFUPath is where the trust-on-first-use DNS cache lives by default.
// Picked to be in the persistent etc tree so the cache survives reboot — the
// whole point is that day-2 updates don't need DoH at all.
const DefaultTOFUPath = "/etc/purewrt/dns-tofu.json"

// DefaultTOFUTTL is how long a cached entry is trusted before we go back to
// DoH. Seven days is long enough that a censored ISP can't force us off the
// cache between updates, short enough that real upstream IP rotation isn't
// stuck on a dead host indefinitely.
const DefaultTOFUTTL = 7 * 24 * time.Hour

// TOFUEntry is one host's cached resolution.
type TOFUEntry struct {
	IPs      []string  `json:"ips"`
	StoredAt time.Time `json:"stored_at"`
	TTL      int64     `json:"ttl_seconds"`
	LastUsed time.Time `json:"last_used,omitempty"`
}

// TOFUCache is a small, file-backed trust-on-first-use IP cache. After any
// successful DoH lookup the resolver stashes (host → IPs) here; subsequent
// dials read the cache first and skip DoH entirely. The cache is invalidated
// per-host on connection failure so a genuine IP rotation isn't permanent.
//
// Concurrency: an internal RWMutex protects the map. Persistence: lazy load on
// first access, atomic write on Store / Invalidate. The on-disk format is
// JSON; small (~1 KB per host) so we can rewrite the whole file each change
// without flash-wear concerns at typical update cadence.
type TOFUCache struct {
	path    string
	ttl     time.Duration
	mu      sync.RWMutex
	loaded  bool
	entries map[string]TOFUEntry
}

// NewTOFUCache builds a cache rooted at path with the given TTL. path empty
// uses DefaultTOFUPath; ttl zero uses DefaultTOFUTTL.
func NewTOFUCache(path string, ttl time.Duration) *TOFUCache {
	if path == "" {
		path = DefaultTOFUPath
	}
	if ttl <= 0 {
		ttl = DefaultTOFUTTL
	}
	return &TOFUCache{path: path, ttl: ttl, entries: map[string]TOFUEntry{}}
}

// Lookup returns the cached IPs for host iff the entry is present and fresh.
// Stale entries are removed lazily so the file shrinks over time.
func (c *TOFUCache) Lookup(host string) ([]net.IP, bool) {
	host = canonHost(host)
	if host == "" {
		return nil, false
	}
	c.ensureLoaded()
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if c.isStale(e) {
		c.mu.Lock()
		delete(c.entries, host)
		c.persistLocked()
		c.mu.Unlock()
		return nil, false
	}
	ips := make([]net.IP, 0, len(e.IPs))
	for _, s := range e.IPs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, false
	}
	// Touch LastUsed so cache pruning can prefer keeping warm entries; not
	// load-bearing, so we don't bother to persist on read.
	c.mu.Lock()
	e.LastUsed = time.Now().UTC()
	c.entries[host] = e
	c.mu.Unlock()
	return ips, true
}

// Store records a successful resolution. Replaces any prior entry.
func (c *TOFUCache) Store(host string, ips []net.IP) {
	host = canonHost(host)
	if host == "" || len(ips) == 0 {
		return
	}
	strs := make([]string, 0, len(ips))
	for _, ip := range ips {
		strs = append(strs, ip.String())
	}
	c.ensureLoaded()
	c.mu.Lock()
	c.entries[host] = TOFUEntry{
		IPs:      strs,
		StoredAt: time.Now().UTC(),
		TTL:      int64(c.ttl.Seconds()),
	}
	c.persistLocked()
	c.mu.Unlock()
}

// Invalidate drops the cached entry for host. Callers should invoke this on
// connection failures (RST, refused, TLS handshake fail) so an IP rotation at
// the origin isn't masked by a stale cache hit.
func (c *TOFUCache) Invalidate(host string) {
	host = canonHost(host)
	if host == "" {
		return
	}
	c.ensureLoaded()
	c.mu.Lock()
	if _, ok := c.entries[host]; ok {
		delete(c.entries, host)
		c.persistLocked()
	}
	c.mu.Unlock()
}

// All returns a snapshot copy of the cache, mainly for diagnostics.
func (c *TOFUCache) All() map[string]TOFUEntry {
	c.ensureLoaded()
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]TOFUEntry, len(c.entries))
	for k, v := range c.entries {
		out[k] = v
	}
	return out
}

func (c *TOFUCache) isStale(e TOFUEntry) bool {
	ttl := time.Duration(e.TTL) * time.Second
	if ttl <= 0 {
		ttl = c.ttl
	}
	return time.Since(e.StoredAt) > ttl
}

func (c *TOFUCache) ensureLoaded() {
	c.mu.RLock()
	loaded := c.loaded
	c.mu.RUnlock()
	if loaded {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded {
		return
	}
	c.loaded = true
	b, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var disk map[string]TOFUEntry
	if err := json.Unmarshal(b, &disk); err == nil && disk != nil {
		c.entries = disk
	}
}

// persistLocked writes the in-memory map back to disk. Caller must hold the
// write lock. Failure to persist is logged-ignored: the cache stays useful
// in memory even if the disk write fails (e.g. read-only flash).
func (c *TOFUCache) persistLocked() {
	if c.path == "" {
		return
	}
	if dir := filepath.Dir(c.path); dir != "" {
		_ = os.MkdirAll(dir, 0700)
	}
	b, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return
	}
	_ = system.AtomicWrite(c.path, append(b, '\n'), 0600)
}

func canonHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimSuffix(h, ".")
	if h == "" || net.ParseIP(h) != nil {
		// IP literals can't be cached as host→IP mappings.
		return ""
	}
	return h
}
