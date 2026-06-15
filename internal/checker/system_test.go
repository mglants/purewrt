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
}
