package checker

import (
	"errors"
	"reflect"
	"testing"
)

type fakeRunner struct {
	out  string
	err  error
	name string
	args []string
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	f.name = name
	f.args = append([]string(nil), args...)
	return f.out, f.err
}

func TestNFTSetContainsWithRunner(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{out: "element 1.1.1.1"}
	ok, out := nftSetContainsWithRunner(r, "dns_media4", "1.1.1.1")
	if !ok || out != r.out {
		t.Fatalf("ok=%v out=%q", ok, out)
	}
	if r.name != "nft" {
		t.Fatalf("name = %q", r.name)
	}
	wantArgs := []string{"get", "element", "inet", "purewrt", "dns_media4", "{", "1.1.1.1", "}"}
	if !reflect.DeepEqual(r.args, wantArgs) {
		t.Fatalf("args = %#v", r.args)
	}

	r = &fakeRunner{out: "not found", err: errors.New("missing")}
	ok, out = nftSetContainsWithRunner(r, "dns_media4", "1.1.1.1")
	if ok || out != "not found" {
		t.Fatalf("error ok=%v out=%q", ok, out)
	}

	// Interval/CIDR set: `nft get element` succeeds (exit 0) for an IP covered
	// by a range but prints the RANGE, not the queried IP. Membership must
	// come from the exit code, so this counts as in-set even though the IP
	// string is absent from the output.
	r = &fakeRunner{out: "elements = { 5.9.0.0/16 }"}
	ok, _ = nftSetContainsWithRunner(r, "proxy_common4", "5.9.0.7")
	if !ok {
		t.Fatalf("CIDR-covered IP must count as in-set (interval lookup); ok=%v", ok)
	}
}
