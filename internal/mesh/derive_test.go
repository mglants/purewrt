package mesh

import (
	"encoding/hex"
	"testing"
)

// RFC 5869 Appendix A test vectors validate the hand-rolled HKDF-SHA256.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

func TestHKDFRFC5869Case1(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	got := hkdfSHA256(ikm, salt, info, 42)
	if hex.EncodeToString(got) != want {
		t.Fatalf("HKDF case 1 mismatch:\n got %x\nwant %s", got, want)
	}
}

func TestHKDFRFC5869Case3EmptySaltInfo(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	want := "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
	got := hkdfSHA256(ikm, nil, nil, 42)
	if hex.EncodeToString(got) != want {
		t.Fatalf("HKDF case 3 mismatch:\n got %x\nwant %s", got, want)
	}
}

func TestDeriveSSPassword(t *testing.T) {
	psk := mustHex(t, "0000000000000000000000000000000000000000000000000000000000000001")
	saltA := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	saltB := mustHex(t, "0f0e0d0c0b0a09080706050403020100")

	a := DeriveSSPassword(psk, saltA)
	b := DeriveSSPassword(psk, saltB)
	if a == b {
		t.Fatal("different salts produced identical ss passwords")
	}
	if len(a) != 32 { // 16 bytes hex-encoded
		t.Fatalf("ss password length %d, want 32 hex chars", len(a))
	}
	if a != DeriveSSPassword(psk, saltA) {
		t.Fatal("derivation not deterministic")
	}
}

func TestDeriveAPIKey(t *testing.T) {
	psk := mustHex(t, "0000000000000000000000000000000000000000000000000000000000000001")
	k := DeriveAPIKey(psk)
	if len(k) != 32 {
		t.Fatalf("api key length %d, want 32", len(k))
	}
	pw := DeriveSSPassword(psk, nil)
	if hex.EncodeToString(k[:16]) == pw {
		t.Fatal("api key and ss password derivations not domain-separated")
	}
}
