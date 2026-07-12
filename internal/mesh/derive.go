package mesh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// hkdfSHA256 implements RFC 5869 extract-and-expand. Hand-rolled because the
// stdlib crypto/hkdf only exists from Go 1.24 and go.mod keeps a 1.22 floor;
// validated against the RFC Appendix A test vectors in derive_test.go.
func hkdfSHA256(secret, salt, info []byte, n int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)

	var out, block []byte
	for counter := byte(1); len(out) < n; counter++ {
		exp := hmac.New(sha256.New, prk)
		exp.Write(block)
		exp.Write(info)
		exp.Write([]byte{counter})
		block = exp.Sum(nil)
		out = append(out, block...)
	}
	return out[:n]
}

// DeriveSSPassword derives the shadowsocks password for the mesh listener of
// the router owning credSalt. Every router shares the group PSK but has its
// own salt, so listener passwords differ per host.
func DeriveSSPassword(psk, credSalt []byte) string {
	return hex.EncodeToString(hkdfSHA256(psk, credSalt, []byte("purewrt-mesh/ss-v1"), 16))
}

// DeriveAPIKey derives the shared HMAC key that authenticates mesh API
// requests between group members.
func DeriveAPIKey(psk []byte) []byte {
	return hkdfSHA256(psk, nil, []byte("purewrt-mesh/api-v1"), 32)
}

// DeriveCredSalt derives a router's credential salt from the group PSK and
// its node name, so the salt needs no storage or exchange: any group member
// can compute any other member's listener password from the name alone.
// Salts were public-by-design anyway; secrecy lives entirely in the PSK.
func DeriveCredSalt(psk []byte, nodeName string) string {
	return hex.EncodeToString(hkdfSHA256(psk, nil, append([]byte("purewrt-mesh/salt-v1:"), nodeName...), 16))
}
