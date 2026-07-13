package mesh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
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
// its hardware id (base MAC), so the salt needs no storage or exchange: any
// group member can compute any other member's listener password from the
// hwid alone. The hwid is immutable per device — unlike a node name, leaving
// and rejoining can never mint a new identity. Salts were public-by-design
// anyway; secrecy lives entirely in the PSK.
func DeriveCredSalt(psk []byte, hwid string) string {
	return hex.EncodeToString(hkdfSHA256(psk, nil, append([]byte("purewrt-mesh/salt-v1:"), hwid...), 16))
}

// DeriveOverlayIP deterministically maps a router's hwid into a static
// overlay address inside the group's subnet — stateless DHCP: zero config,
// no allocator to race, and the address never changes across restarts.
// attempt breaks the rare hash collision: when two hwids land on one host
// index, mesh-sync bumps the deterministic loser's attempt counter and the
// next derivation lands elsewhere. Returns "a.b.c.d/prefix" (easytier TOML
// ipv4 form). Host indexes stay in [1, hosts-2], skipping the network and
// broadcast addresses.
func DeriveOverlayIP(cidr, hwid string, attempt int) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("mesh: overlay subnet %q: %w", cidr, err)
	}
	base := ipnet.IP.To4()
	if base == nil {
		return "", fmt.Errorf("mesh: overlay subnet %q is not IPv4", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	if hostBits < 2 {
		return "", fmt.Errorf("mesh: overlay subnet %q too small", cidr)
	}
	hosts := uint64(1)<<uint(hostBits) - 2 // usable: excludes network + broadcast
	h := sha256.Sum256([]byte(fmt.Sprintf("purewrt-mesh/overlay-ip-v1:%s:%d", hwid, attempt)))
	idx := binary.BigEndian.Uint64(h[:8])%hosts + 1
	addr := binary.BigEndian.Uint32(base) + uint32(idx)
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], addr)
	return fmt.Sprintf("%d.%d.%d.%d/%d", out[0], out[1], out[2], out[3], ones), nil
}
