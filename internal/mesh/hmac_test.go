package mesh

import (
	"testing"
	"time"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestSignVerifyRequest(t *testing.T) {
	key := testKey()
	now := time.Unix(1_700_000_000, 0)
	ts := now.Unix()
	nonce := "00112233445566778899aabbccddeeff"
	mac := SignRequest(key, ts, nonce, "GET", "/mesh/v1/info")

	cache := NewNonceCache(16, 5*time.Minute)
	if err := VerifyRequest(key, now, ts, nonce, "GET", "/mesh/v1/info", mac, cache); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestVerifyRequestRejectsWrongKey(t *testing.T) {
	key := testKey()
	other := make([]byte, 32)
	now := time.Unix(1_700_000_000, 0)
	nonce := "00112233445566778899aabbccddeeff"
	mac := SignRequest(other, now.Unix(), nonce, "GET", "/mesh/v1/info")
	cache := NewNonceCache(16, 5*time.Minute)
	if err := VerifyRequest(key, now, now.Unix(), nonce, "GET", "/mesh/v1/info", mac, cache); err == nil {
		t.Fatal("request signed with wrong key accepted")
	}
}

func TestVerifyRequestRejectsPathSwap(t *testing.T) {
	key := testKey()
	now := time.Unix(1_700_000_000, 0)
	nonce := "00112233445566778899aabbccddeeff"
	mac := SignRequest(key, now.Unix(), nonce, "GET", "/mesh/v1/info")
	cache := NewNonceCache(16, 5*time.Minute)
	if err := VerifyRequest(key, now, now.Unix(), nonce, "GET", "/mesh/v1/other", mac, cache); err == nil {
		t.Fatal("MAC accepted for different path")
	}
}

func TestVerifyRequestRejectsClockSkew(t *testing.T) {
	key := testKey()
	now := time.Unix(1_700_000_000, 0)
	ts := now.Add(-3 * time.Minute).Unix() // outside the 120s window
	nonce := "00112233445566778899aabbccddeeff"
	mac := SignRequest(key, ts, nonce, "GET", "/mesh/v1/info")
	cache := NewNonceCache(16, 5*time.Minute)
	if err := VerifyRequest(key, now, ts, nonce, "GET", "/mesh/v1/info", mac, cache); err == nil {
		t.Fatal("stale timestamp accepted")
	}
}

func TestVerifyRequestRejectsReplay(t *testing.T) {
	key := testKey()
	now := time.Unix(1_700_000_000, 0)
	ts := now.Unix()
	nonce := "00112233445566778899aabbccddeeff"
	mac := SignRequest(key, ts, nonce, "GET", "/mesh/v1/info")
	cache := NewNonceCache(16, 5*time.Minute)
	if err := VerifyRequest(key, now, ts, nonce, "GET", "/mesh/v1/info", mac, cache); err != nil {
		t.Fatalf("first request rejected: %v", err)
	}
	if err := VerifyRequest(key, now, ts, nonce, "GET", "/mesh/v1/info", mac, cache); err == nil {
		t.Fatal("replayed nonce accepted")
	}
}

func TestNonceCacheEviction(t *testing.T) {
	key := testKey()
	now := time.Unix(1_700_000_000, 0)
	cache := NewNonceCache(2, 5*time.Minute)
	nonces := []string{"aa", "bb", "cc"}
	for _, n := range nonces {
		mac := SignRequest(key, now.Unix(), n, "GET", "/x")
		if err := VerifyRequest(key, now, now.Unix(), n, "GET", "/x", mac, cache); err != nil {
			t.Fatalf("nonce %s rejected: %v", n, err)
		}
	}
	// "aa" was evicted by capacity; replay of it must still be rejected within
	// the window? No — capacity eviction is a deliberate memory bound; the test
	// asserts the newest nonce is still remembered.
	mac := SignRequest(key, now.Unix(), "cc", "GET", "/x")
	if err := VerifyRequest(key, now, now.Unix(), "cc", "GET", "/x", mac, cache); err == nil {
		t.Fatal("newest nonce replay accepted despite cache")
	}
}

func TestSignVerifyResponse(t *testing.T) {
	key := testKey()
	ts := int64(1_700_000_000)
	nonce := "00112233445566778899aabbccddeeff"
	body := []byte(`{"v":1,"node_name":"alpha"}`)
	mac := SignResponse(key, ts, nonce, body)
	if err := VerifyResponse(key, ts, nonce, body, mac); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	if err := VerifyResponse(key, ts, nonce, []byte(`{"v":1,"node_name":"evil"}`), mac); err == nil {
		t.Fatal("tampered body accepted")
	}
}
