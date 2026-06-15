package provider

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestTOFUStoreThenLookup(t *testing.T) {
	t.Parallel()
	c := NewTOFUCache(filepath.Join(t.TempDir(), "tofu.json"), time.Hour)
	c.Store("example.com", []net.IP{net.IPv4(203, 0, 113, 5), net.ParseIP("2001:db8::1")})
	ips, ok := c.Lookup("example.com")
	if !ok || len(ips) != 2 {
		t.Fatalf("Lookup returned %v ok=%v, want 2 IPs", ips, ok)
	}
	if !ips[0].Equal(net.IPv4(203, 0, 113, 5)) {
		t.Fatalf("first IP = %v", ips[0])
	}
}

func TestTOFULookupCaseInsensitive(t *testing.T) {
	t.Parallel()
	c := NewTOFUCache(filepath.Join(t.TempDir(), "tofu.json"), time.Hour)
	c.Store("Example.com.", []net.IP{net.IPv4(203, 0, 113, 5)})
	if _, ok := c.Lookup("EXAMPLE.com"); !ok {
		t.Fatal("expected case-insensitive lookup hit")
	}
}

func TestTOFUStaleEntryEvicted(t *testing.T) {
	t.Parallel()
	c := NewTOFUCache(filepath.Join(t.TempDir(), "tofu.json"), 10*time.Millisecond)
	c.Store("example.com", []net.IP{net.IPv4(203, 0, 113, 5)})
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.Lookup("example.com"); ok {
		t.Fatal("expected stale entry to be evicted")
	}
}

func TestTOFUInvalidate(t *testing.T) {
	t.Parallel()
	c := NewTOFUCache(filepath.Join(t.TempDir(), "tofu.json"), time.Hour)
	c.Store("example.com", []net.IP{net.IPv4(203, 0, 113, 5)})
	c.Invalidate("example.com")
	if _, ok := c.Lookup("example.com"); ok {
		t.Fatal("expected invalidated entry to be gone")
	}
}

func TestTOFUPersistAcrossInstances(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "tofu.json")
	c1 := NewTOFUCache(path, time.Hour)
	c1.Store("example.com", []net.IP{net.IPv4(203, 0, 113, 5)})
	c2 := NewTOFUCache(path, time.Hour)
	ips, ok := c2.Lookup("example.com")
	if !ok || len(ips) != 1 {
		t.Fatalf("second instance failed to load cache: ok=%v ips=%v", ok, ips)
	}
}

func TestTOFURejectsIPLiteralHost(t *testing.T) {
	t.Parallel()
	c := NewTOFUCache(filepath.Join(t.TempDir(), "tofu.json"), time.Hour)
	c.Store("1.2.3.4", []net.IP{net.IPv4(5, 6, 7, 8)})
	if _, ok := c.Lookup("1.2.3.4"); ok {
		t.Fatal("expected IP-literal hostnames to be rejected from cache")
	}
}
