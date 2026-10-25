package manager

import (
	"github.com/purewrt/purewrt/internal/config"
	"testing"
)

func TestLibraryValidation(t *testing.T) {
	good := config.ZapretCandidate{Name: "user_example", Protocols: []string{"tcp", "udp"}, TCPPorts: "443", UDPPorts: "443,50000-65535", Params: "--filter-tcp=443 --lua-desync=fake:blob=custom --new --filter-udp=443,50000-65535 --lua-desync=fake:blob=fake_default_quic", Blobs: []config.ZapretBlobRef{{Name: "custom", Hex: "0x010203"}}}
	if err := validateLibraryCandidate(good); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*config.ZapretCandidate)
	}{
		{"process flag", func(c *config.ZapretCandidate) { c.Params += " --daemon" }},
		{"missing blob", func(c *config.ZapretCandidate) { c.Blobs = nil }},
		{"traversal", func(c *config.ZapretCandidate) {
			c.Blobs = []config.ZapretBlobRef{{Name: "custom", File: "../bad.bin"}}
		}},
		{"bad hex", func(c *config.ZapretCandidate) { c.Blobs = []config.ZapretBlobRef{{Name: "custom", Hex: "0xzz"}} }},
		{"catalog name", func(c *config.ZapretCandidate) { c.Name = "catalog" }},
		{"protocol mismatch", func(c *config.ZapretCandidate) { c.Protocols = []string{"tcp"} }},
		{"invalid port", func(c *config.ZapretCandidate) { c.TCPPorts = "65536" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.change(&c)
			if validateLibraryCandidate(c) == nil {
				t.Fatal("accepted invalid candidate")
			}
		})
	}
}
func TestLibraryCRUD(t *testing.T) {
	c := config.ZapretCandidate{Name: "user_one"}
	list, err := updateUserLibrary(config.ZapretCandidateList{}, ZapretLibraryRequest{Action: "save", Candidate: c})
	if err != nil || len(list.Candidates) != 1 {
		t.Fatalf("create: %v", err)
	}
	if _, err = updateUserLibrary(list, ZapretLibraryRequest{Action: "save", Candidate: c}); err == nil {
		t.Fatal("overwrote existing name")
	}
	c.Name = "user_two"
	list, err = updateUserLibrary(list, ZapretLibraryRequest{Action: "save", OriginalName: "user_one", Candidate: c})
	if err != nil || list.Candidates[0].Name != "user_two" {
		t.Fatalf("rename: %v", err)
	}
	if _, err = updateUserLibrary(list, ZapretLibraryRequest{Action: "delete", OriginalName: "catalog"}); err == nil {
		t.Fatal("deleted non-user entry")
	}
	list, err = updateUserLibrary(list, ZapretLibraryRequest{Action: "delete", OriginalName: "user_two"})
	if err != nil || len(list.Candidates) != 0 {
		t.Fatalf("delete: %v", err)
	}
}
