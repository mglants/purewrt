package proxyguard

import (
	"errors"
	"os"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestRoutingSignatureIgnoresMeasurements(t *testing.T) {
	s := NewState()
	s.Nodes["a"] = &NodeState{Name: "a", State: Quarantined, LastDownKbps: 100}
	s.Groups["g"] = &GroupState{Name: "g", Members: []string{"a"}, LastResorts: []string{"a"}}
	before := s.RoutingSignature()
	s.Nodes["a"].LastDownKbps = 900
	s.Nodes["a"].LastDelayMS = 20
	if after := s.RoutingSignature(); after != before {
		t.Fatalf("measurement changed routing signature: %q != %q", after, before)
	}
	s.Nodes["a"].State = Healthy
	if after := s.RoutingSignature(); after == before {
		t.Fatal("routing decision did not change signature")
	}
}

func TestLoadRejectsUnknownStateVersion(t *testing.T) {
	c := config.Default()
	c.Settings.RuntimeDir = t.TempDir()
	if err := os.WriteFile(Path(c), []byte(`{"version":999}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(c); !errors.Is(err, ErrStateVersion) {
		t.Fatalf("Load error = %v, want ErrStateVersion", err)
	}
}
