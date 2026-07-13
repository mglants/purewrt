package mesh

import (
	"strings"
	"testing"
)

func TestGenerateCodeRoundTrip(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	s := code.Encode()
	if !strings.HasPrefix(s, "PWMESH1-") {
		t.Fatalf("encoded code missing prefix: %q", s)
	}
	got, err := DecodeCode(s)
	if err != nil {
		t.Fatalf("DecodeCode: %v", err)
	}
	if got.PSK != code.PSK {
		t.Fatalf("PSK mismatch after round-trip")
	}
	if got.NetworkSecret != code.NetworkSecret {
		t.Fatalf("NetworkSecret mismatch after round-trip")
	}
	if got.NetworkName() != code.NetworkName() {
		t.Fatalf("NetworkName mismatch: %q vs %q", got.NetworkName(), code.NetworkName())
	}
}

func TestGenerateCodeUnique(t *testing.T) {
	a, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	if a.PSK == b.PSK || a.NetworkName() == b.NetworkName() {
		t.Fatal("two generated codes share secrets")
	}
}

func TestNetworkNameFormat(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	name := code.NetworkName()
	if !strings.HasPrefix(name, "pwmesh-") || len(name) != len("pwmesh-")+16 {
		t.Fatalf("unexpected network name %q", name)
	}
}

func TestDecodeCodeRejectsTamper(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	s := code.Encode()
	// Flip one payload character (skip the fixed prefix and avoid dashes).
	b := []byte(s)
	for i := len(b) - 1; i > len("PWMESH1-"); i-- {
		if b[i] == '-' {
			continue
		}
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		break
	}
	if _, err := DecodeCode(string(b)); err == nil {
		t.Fatal("tampered code accepted")
	}
}

func TestDecodeCodeRejectsGarbage(t *testing.T) {
	for _, s := range []string{
		"",
		"PWMESH1-",
		"PWMESH1-AAAA",
		"nonsense",
		"PWMESH9-AAAAAAAA", // unknown version prefix
	} {
		if _, err := DecodeCode(s); err == nil {
			t.Fatalf("garbage %q accepted", s)
		}
	}
}

func TestDecodeCodeCaseAndWhitespaceTolerant(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	s := code.Encode()
	sloppy := " " + strings.ToLower(s) + "\n"
	got, err := DecodeCode(sloppy)
	if err != nil {
		t.Fatalf("sloppy paste rejected: %v", err)
	}
	if got.PSK != code.PSK {
		t.Fatal("PSK mismatch after sloppy decode")
	}
}

func TestExtraPeersRoundTrip(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	code.ExtraPeers = []string{"tcp://relay.example.org:11010", "udp://1.2.3.4:11010"}
	got, err := DecodeCode(code.Encode())
	if err != nil {
		t.Fatalf("DecodeCode: %v", err)
	}
	if len(got.ExtraPeers) != 2 || got.ExtraPeers[0] != code.ExtraPeers[0] || got.ExtraPeers[1] != code.ExtraPeers[1] {
		t.Fatalf("ExtraPeers round-trip mismatch: %#v", got.ExtraPeers)
	}
}
