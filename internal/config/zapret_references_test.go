package config

import (
	"testing"
)

func TestZapretLibraryReferences(t *testing.T) {
	c := Config{ZapretStrategies: []ZapretStrategy{{Name: "ref", Candidate: "user_test", Profile: "wan", Params: "stale", QueueNum: 205}, {Name: "custom", Params: "keep"}}, ZapretProfiles: []ZapretProfile{{Name: "wan"}}}
	list := ZapretCandidateList{Candidates: []ZapretCandidate{{Name: "user_test", Protocols: []string{"udp"}, UDPPorts: "50000-65535", Params: "first", Blobs: []ZapretBlobRef{{Name: "zero", Hex: "0x0000"}}}}}
	if err := c.ResolveZapretReferences(list); err != nil {
		t.Fatal(err)
	}
	if c.ZapretStrategies[0].Params != "first" || c.ZapretStrategies[0].UDPPorts != "50000-65535" || c.ZapretStrategies[0].QueueNum != 205 || c.ZapretStrategies[1].Params != "keep" {
		t.Fatal(c.ZapretStrategies)
	}
	if len(c.ZapretStrategies[0].LibraryBlobs) != 1 || c.ZapretStrategies[0].LibraryBlobs[0] != "zero:0x0000" {
		t.Fatal(c.ZapretProfiles)
	}
	list.Candidates[0].Params = "updated"
	if err := c.ResolveZapretReferences(list); err != nil || c.ZapretStrategies[0].Params != "updated" {
		t.Fatal("library edit not resolved", err)
	}
	if err := c.ResolveZapretReferences(ZapretCandidateList{}); err == nil {
		t.Fatal("missing reference silently accepted")
	}
}
