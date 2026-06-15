package checker

import (
	"errors"
	"net"
	"testing"
)

func TestResolveWithLookup(t *testing.T) {
	t.Parallel()

	res := resolveWithLookup("example.com", func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2001:db8::1")}, nil
	})
	if len(res.A) != 1 || res.A[0] != "1.1.1.1" || len(res.AAAA) != 1 || res.AAAA[0] != "2001:db8::1" {
		t.Fatalf("result = %+v", res)
	}

	res = resolveWithLookup("bad.example", func(string) ([]net.IP, error) {
		return nil, errors.New("lookup failed")
	})
	if res.Error != "lookup failed" {
		t.Fatalf("error result = %+v", res)
	}
}
