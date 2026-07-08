package config

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
)

// embeddedZapretCandidates is the built-in baseline candidate list, always
// available (no network, no package file). The purewrt-lists fetch writes an
// updated copy to ZapretCandidatesPath which overrides this.
//
//go:embed zapret_candidates.json
var embeddedZapretCandidates []byte

// ZapretCandidatesPath is the on-disk override the purewrt-lists fetch writes
// (and users may hand-edit). Takes precedence over the embedded baseline.
const ZapretCandidatesPath = "/etc/purewrt/zapret_candidates.json"

// ZapretCandidatesDir is where fetched blob decoys are cached.
const ZapretBlobCacheDir = "/etc/purewrt/blobs"

// ZapretFakeDirs are the zapret package's shipped fake-payload directories,
// checked first when resolving a blob (most decoys ship with zapret). The
// manager's ResolveBlob and the generator's path canonicalization share this
// list so the emitted --blob path matches where the fetch lands.
var ZapretFakeDirs = []string{
	"/usr/libexec/zapret/files/fake",
	"/opt/zapret2/files/fake",
	"/opt/zapret/files/fake",
	"/usr/lib/zapret/fake",
}

// CanonicalBlobPath returns the filesystem path a blob .bin resolves to,
// WITHOUT fetching: a shipped copy if one exists, else the fetch cache path
// under ZapretBlobCacheDir. Pure + deterministic (only stat), so the generator
// can emit it and the fingerprint stays stable whether or not the fetch has
// run yet. The manager's ResolveBlob populates the cache path when missing.
func CanonicalBlobPath(file string) string {
	file = filepath.Base(file)
	for _, d := range ZapretFakeDirs {
		p := filepath.Join(d, file)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return filepath.Join(ZapretBlobCacheDir, file)
}

// ZapretCandidate is one strategy in the shared list — a superset of the LuCI
// preset shape (adds ISP + Blobs) so it drives the preset dropdown, the
// strategy tester, and Create-strategy staging from one source. Candidates are
// grouped by ISP; "common" is the cross-ISP default set.
type ZapretCandidate struct {
	Name      string          `json:"name"`
	ISP       string          `json:"isp"` // "common" | ISP label, e.g. "Rostelecom (RU)"
	Protocols []string        `json:"protocols"`
	TCPPorts  string          `json:"tcp_ports"`
	UDPPorts  string          `json:"udp_ports"`
	TCPPktOut int             `json:"tcp_pkt_out"`
	TCPPktIn  int             `json:"tcp_pkt_in"`
	UDPPktOut int             `json:"udp_pkt_out"`
	UDPPktIn  int             `json:"udp_pkt_in"`
	Params    string          `json:"params"`
	Blobs     []ZapretBlobRef `json:"blobs,omitempty"`
}

// ZapretBlobRef names an nfqws2 fake-payload blob a candidate's params
// reference (fake:blob=<Name> / seqovl_pattern=<Name>) and the .bin File to
// resolve for it. SHA256 (optional) is verified when the file is fetched.
type ZapretBlobRef struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	SHA256 string `json:"sha256,omitempty"`
}

// ZapretCandidateList is the zapret_candidates.json root.
type ZapretCandidateList struct {
	Candidates []ZapretCandidate `json:"candidates"`
}

// LoadZapretCandidates resolves the candidate list: the on-disk override at
// ZapretCandidatesPath (purewrt-lists fetch cache, or hand-edited) if present
// and non-empty, else the embedded baseline. Never fails — a missing or
// malformed override falls back to the embed.
func LoadZapretCandidates() ZapretCandidateList {
	if data, err := os.ReadFile(ZapretCandidatesPath); err == nil {
		var l ZapretCandidateList
		if json.Unmarshal(data, &l) == nil && len(l.Candidates) > 0 {
			return l
		}
	}
	return EmbeddedZapretCandidates()
}

// EmbeddedZapretCandidates returns just the built-in baseline (ignores the
// on-disk override) — used to seed/compare and as the guaranteed fallback.
func EmbeddedZapretCandidates() ZapretCandidateList {
	var l ZapretCandidateList
	_ = json.Unmarshal(embeddedZapretCandidates, &l)
	return l
}
