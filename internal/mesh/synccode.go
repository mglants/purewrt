// Package mesh implements the friend-to-friend mesh primitives: the
// copy-paste sync-code carrying the group secrets, HKDF credential
// derivation, HMAC request authentication for the mesh API, and the
// easytier-cli wrapper. The package is pure (no OpenWrt dependencies).
package mesh

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// CreatorSeedIPv4 is the static overlay address mesh-init assigns to the
// mesh CREATOR. easytier's DHCP allocates inside the subnet of already-used
// member IPs and only falls back to its hardwired 10.126.126.0/24 default
// when none exist — so one statically-seeded /16 member makes every joiner
// (plain DHCP) inherit the /16 (~65k members). Joiners never set a static
// address; the DHCP allocator keeps handling conflicts in-band.
const CreatorSeedIPv4 = "10.126.0.1/16"

const (
	codePrefix  = "PWMESH1-"
	codeVersion = 0x01

	flagExtraPeers = 0x01

	tlvExtraPeer = 0x01

	nameEntropyLen   = 8
	networkSecretLen = 24
	pskLen           = 32
	macLen           = 4
)

// Code is the decoded contents of a mesh sync-code. The code itself is the
// group secret: anyone holding it can join the overlay and derive every
// credential, so it must be treated like a password.
type Code struct {
	NameEntropy   [nameEntropyLen]byte
	NetworkSecret [networkSecretLen]byte
	PSK           [pskLen]byte
	ExtraPeers    []string // optional custom rendezvous/relay peer URLs
}

// NetworkName derives the easytier network name from the code entropy so
// that groups on shared public rendezvous nodes cannot collide by name.
func (c Code) NetworkName() string {
	return "pwmesh-" + hex.EncodeToString(c.NameEntropy[:])
}

// GenerateCode mints a fresh group code from crypto/rand.
func GenerateCode() (Code, error) {
	var c Code
	buf := make([]byte, nameEntropyLen+networkSecretLen+pskLen)
	if _, err := rand.Read(buf); err != nil {
		return Code{}, fmt.Errorf("mesh: generate code: %w", err)
	}
	copy(c.NameEntropy[:], buf[:nameEntropyLen])
	copy(c.NetworkSecret[:], buf[nameEntropyLen:nameEntropyLen+networkSecretLen])
	copy(c.PSK[:], buf[nameEntropyLen+networkSecretLen:])
	return c, nil
}

var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Encode serializes the code as PWMESH1-<base32>, dash-grouped every 8
// characters for readability. The trailing 4-byte HMAC detects typos and
// truncated pastes; it is not a secrecy mechanism.
func (c Code) Encode() string {
	payload := []byte{codeVersion, c.flags()}
	payload = append(payload, c.NameEntropy[:]...)
	payload = append(payload, c.NetworkSecret[:]...)
	payload = append(payload, c.PSK[:]...)
	for _, p := range c.ExtraPeers {
		payload = append(payload, tlvExtraPeer, byte(len(p)))
		payload = append(payload, p...)
	}
	payload = append(payload, codeMAC(c.PSK[:], payload)...)

	enc := codeEncoding.EncodeToString(payload)
	var b strings.Builder
	b.WriteString(codePrefix)
	for i := 0; i < len(enc); i += 8 {
		if i > 0 {
			b.WriteByte('-')
		}
		end := i + 8
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
	}
	return b.String()
}

func (c Code) flags() byte {
	if len(c.ExtraPeers) > 0 {
		return flagExtraPeers
	}
	return 0
}

func codeMAC(psk, payload []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(payload)
	return m.Sum(nil)[:macLen]
}

// DecodeCode parses a pasted sync-code. It tolerates case changes,
// surrounding whitespace, and dash regrouping.
func DecodeCode(s string) (Code, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, codePrefix) {
		return Code{}, errors.New("mesh: not a PWMESH1 sync-code")
	}
	enc := strings.ReplaceAll(strings.TrimPrefix(s, codePrefix), "-", "")
	payload, err := codeEncoding.DecodeString(enc)
	if err != nil {
		return Code{}, fmt.Errorf("mesh: malformed sync-code: %w", err)
	}
	const fixed = 2 + nameEntropyLen + networkSecretLen + pskLen
	if len(payload) < fixed+macLen {
		return Code{}, errors.New("mesh: sync-code too short")
	}
	if payload[0] != codeVersion {
		return Code{}, fmt.Errorf("mesh: unsupported sync-code version %d", payload[0])
	}

	var c Code
	off := 2
	off += copy(c.NameEntropy[:], payload[off:off+nameEntropyLen])
	off += copy(c.NetworkSecret[:], payload[off:off+networkSecretLen])
	off += copy(c.PSK[:], payload[off:off+pskLen])

	body, mac := payload[:len(payload)-macLen], payload[len(payload)-macLen:]
	if !bytes.Equal(codeMAC(c.PSK[:], body), mac) {
		return Code{}, errors.New("mesh: sync-code checksum mismatch (typo or truncated paste)")
	}

	tlvs := body[off:]
	for len(tlvs) > 0 {
		if len(tlvs) < 2 || len(tlvs) < 2+int(tlvs[1]) {
			return Code{}, errors.New("mesh: sync-code truncated extension")
		}
		typ, val := tlvs[0], string(tlvs[2:2+int(tlvs[1])])
		if typ == tlvExtraPeer {
			c.ExtraPeers = append(c.ExtraPeers, val)
		}
		// Unknown TLV types are skipped for forward compatibility.
		tlvs = tlvs[2+int(tlvs[1]):]
	}
	return c, nil
}
