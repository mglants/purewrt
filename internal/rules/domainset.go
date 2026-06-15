package rules

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// ErrNotDomainBehavior is returned by ParseMRSDomainSet when the MRS payload
// declares an IPCIDR set rather than a domain set. Callers should fall back
// to the materialising ParseMRS path for IPCIDR providers.
var ErrNotDomainBehavior = errors.New("mrs: not a domain set")

// DomainSet is a non-materialising view of an MRS domain bitmap-trie. The
// underlying succinct trie answers DomainSuffix membership queries in
// O(len(domain)) without expanding the 81k+ entries of a large provider
// into Go strings — saving ~7-10x memory on the worst MRS file in the wild
// (blocked-refilter-domains.mrs) and dropping cold-parse from ~30-60s to
// ~50ms.
//
// Use ParseMRSDomainSet to construct. Lookup is allocation-free for misses
// and allocates only the matched-suffix string on a hit; safe for repeated
// queries from a single goroutine.
type DomainSet struct {
	name          string
	leaves        []uint64
	compactLeaves []uint64
	labelBitmap   []uint64
	labels        []byte
	prefixOnes    []int
	onesPositions []int
	bitsLen       int
}

// Name returns the provider name supplied at construction.
func (d *DomainSet) Name() string { return d.name }

// ParseMRSDomainSet decodes an MRS payload (zstd/gzip/plain) and returns a
// non-materialising DomainSet over its bitmap-trie. Returns
// ErrNotDomainBehavior for IPCIDR MRS files so the caller can fall back to
// the materialising ParseMRS path.
func ParseMRSDomainSet(name string, data []byte) (DomainSet, error) {
	var ds DomainSet
	payload, _, err := decodeMRSPayload(data)
	if err != nil {
		return ds, err
	}
	if len(payload) < 4 || !bytes.Equal(payload[:4], []byte{'M', 'R', 'S', 1}) {
		return ds, errors.New("mrs: unsupported non-native MRS format")
	}
	r := bytes.NewReader(payload)
	if _, err := r.Seek(4, io.SeekStart); err != nil {
		return ds, err
	}
	behavior, err := r.ReadByte()
	if err != nil {
		return ds, err
	}
	if behavior != 0 {
		return ds, ErrNotDomainBehavior
	}
	var count int64
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return ds, err
	}
	var extraLen int64
	if err := binary.Read(r, binary.BigEndian, &extraLen); err != nil {
		return ds, err
	}
	if extraLen < 0 || extraLen > int64(r.Len()) {
		return ds, errors.New("mrs: invalid MRS extra length")
	}
	if extraLen > 0 {
		if _, err := r.Seek(extraLen, io.SeekCurrent); err != nil {
			return ds, err
		}
	}
	t, err := readMRSTrieRaw(r)
	if err != nil {
		return ds, err
	}
	prefixOnes, onesPositions, bitsLen := t.buildRankSelect()
	ds = DomainSet{
		name:          name,
		leaves:        t.leaves,
		labelBitmap:   t.labelBitmap,
		labels:        t.labels,
		prefixOnes:    prefixOnes,
		onesPositions: onesPositions,
		bitsLen:       bitsLen,
	}
	ds.compactLeaves = buildCompactLeaves(t, prefixOnes, onesPositions, bitsLen)
	return ds, nil
}

// buildCompactLeaves walks the trie once and produces a bitmap that ORs each
// node N's original leaf bit with the leaf bit of the descendant reachable
// via the literal three-edge path "." -> "+" -> ".". This collapses the
// "+.example.com" wildcard form with the plain "example.com" form so that
// Lookup needs only one leaf check per visited node — matching the
// TrimPrefix("+.")-then-DomainSuffix semantics applied by the materialising
// path (see parse_mrs.go:226).
func buildCompactLeaves(t mrsTrie, prefixOnes, onesPositions []int, bitsLen int) []uint64 {
	// Upper bound on node count = 1 (root) + zeros in labelBitmap.
	maxNodes := max(1, 1+(bitsLen-len(onesPositions)))
	out := make([]uint64, (maxNodes+63)/64)
	countZeros := func(n int) int {
		if n < 0 {
			return 0
		}
		if n > bitsLen {
			n = bitsLen
		}
		return n - prefixOnes[n]
	}
	selectOne := func(idx int) int {
		if idx < 0 || idx >= len(onesPositions) {
			return -1
		}
		return onesPositions[idx]
	}
	nodeBmStart := func(n int) int {
		if n == 0 {
			return 0
		}
		p := selectOne(n - 1)
		if p < 0 {
			return -1
		}
		return p + 1
	}
	findChild := func(parentNodeID, startBmIdx int, target byte) (int, int, bool) {
		if startBmIdx < 0 {
			return 0, 0, false
		}
		for bmIdx := startBmIdx; bmIdx < bitsLen; bmIdx++ {
			if bitAt(t.labelBitmap, bmIdx) {
				return 0, 0, false
			}
			labelIdx := bmIdx - parentNodeID
			if labelIdx < 0 || labelIdx >= len(t.labels) {
				return 0, 0, false
			}
			if t.labels[labelIdx] == target {
				child := countZeros(bmIdx + 1)
				return child, nodeBmStart(child), true
			}
		}
		return 0, 0, false
	}
	// Enumerate via DFS so we only touch nodeIDs that are actually reachable.
	_ = walkMRSTrie(t, func(nodeID int, _ []byte) bool {
		if bitAt(t.leaves, nodeID) {
			setBit(out, nodeID)
			return true
		}
		bmStart := nodeBmStart(nodeID)
		if bmStart < 0 {
			return true
		}
		c1, c1bm, ok := findChild(nodeID, bmStart, '.')
		if !ok {
			return true
		}
		c2, c2bm, ok := findChild(c1, c1bm, '+')
		if !ok {
			return true
		}
		c3, _, ok := findChild(c2, c2bm, '.')
		if !ok {
			return true
		}
		if bitAt(t.leaves, c3) {
			setBit(out, nodeID)
		}
		return true
	})
	return out
}

func setBit(bm []uint64, i int) {
	if i < 0 {
		return
	}
	if i>>6 >= len(bm) {
		return
	}
	bm[i>>6] |= uint64(1) << uint(i&63)
}

func (d *DomainSet) countZeros(n int) int {
	if n < 0 {
		return 0
	}
	if n > d.bitsLen {
		n = d.bitsLen
	}
	return n - d.prefixOnes[n]
}

func (d *DomainSet) selectOne(idx int) int {
	if idx < 0 || idx >= len(d.onesPositions) {
		return -1
	}
	return d.onesPositions[idx]
}

func (d *DomainSet) nodeBmStart(n int) int {
	if n == 0 {
		return 0
	}
	p := d.selectOne(n - 1)
	if p < 0 {
		return -1
	}
	return p + 1
}

// findChildLabel walks the children list of parentNodeID starting at
// startBmIdx, returning the child node ID and its children-list start
// position for the edge labelled target — or (0, 0, false) if none.
func (d *DomainSet) findChildLabel(parentNodeID, startBmIdx int, target byte) (int, int, bool) {
	if startBmIdx < 0 {
		return 0, 0, false
	}
	for bmIdx := startBmIdx; bmIdx < d.bitsLen; bmIdx++ {
		if bitAt(d.labelBitmap, bmIdx) {
			return 0, 0, false
		}
		labelIdx := bmIdx - parentNodeID
		if labelIdx < 0 || labelIdx >= len(d.labels) {
			return 0, 0, false
		}
		if d.labels[labelIdx] == target {
			child := d.countZeros(bmIdx + 1)
			return child, d.nodeBmStart(child), true
		}
	}
	return 0, 0, false
}

// Lookup tests whether domain is matched by any DomainSuffix rule in the
// set. On a hit it returns the canonical matched suffix (the rule's
// Rule.Value with the "+." wildcard prefix already stripped — exactly the
// form produced by parseNativeMRSWithOptions). On a miss it returns
// ("", false) without allocating.
//
// Match semantics mirror mihomo's DomainSuffix: rule X matches domain D
// iff D == X or D ends with "." + X.
func (d *DomainSet) Lookup(domain string) (string, bool) {
	if domain == "" {
		return "", false
	}
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", false
	}
	// A leaf at the root encodes an empty-suffix rule that matches everything.
	if bitAt(d.compactLeaves, 0) {
		return "", true
	}
	rd := reverseBytes(domain)
	nodeID, bmIdx := 0, 0
	for k := range rd {
		child, childBm, ok := d.findChildLabel(nodeID, bmIdx, rd[k])
		if !ok {
			return "", false
		}
		nodeID, bmIdx = child, childBm
		if bitAt(d.compactLeaves, nodeID) {
			if k+1 == len(rd) || rd[k+1] == '.' {
				return reverseString(string(rd[:k+1])), true
			}
		}
	}
	return "", false
}

// reverseBytes returns a fresh byte slice with s reversed. Used inside
// Lookup so we can index without allocating a new string per char.
func reverseBytes(s string) []byte {
	b := make([]byte, len(s))
	for i, j := 0, len(s)-1; j >= 0; i, j = i+1, j-1 {
		b[i] = s[j]
	}
	return b
}
