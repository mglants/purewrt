package rules

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
)

type MRSInfo struct {
	Native     bool
	Compressed string
	Behavior   string
	Count      int
}

func ParseMRS(name string, data []byte) (Provider, error) {
	return ParseMRSWithOptions(name, data, MRSParseOptions{SortDomains: true})
}

type MRSParseOptions struct {
	SortDomains bool
}

// MRSStreamHandlers carries the per-entry callbacks for StreamMRS. The
// Domain callback receives the decoded forward-form domain as a `[]byte`
// (with any "+." wildcard prefix already stripped). The slice points into
// a reusable buffer owned by the walker — it's valid only for the
// duration of the call; copy with `string(b)` or `append(nil, b...)` if
// you need to retain it. Designed to give the hot dnsmasq-emission path
// in internal/generator/stream.go zero per-entry allocations.
//
// CIDR stays string-based because (a) it allocates inside netip anyway,
// and (b) the CIDR set sizes are 3+ orders of magnitude smaller than the
// big MRS domain providers in practice.
type MRSStreamHandlers struct {
	Domain func([]byte) error
	CIDR   func(string) error
}

func StreamMRS(data []byte, handlers MRSStreamHandlers) error {
	payload, _, err := decodeMRSPayload(data)
	if err != nil {
		return err
	}
	if len(payload) >= 4 && bytes.Equal(payload[:4], []byte{'M', 'R', 'S', 1}) {
		return streamNativeMRS(payload, handlers)
	}
	parsed := ParseText("mrs", payload)
	for _, r := range parsed.Rules {
		switch r.Type {
		case Domain, DomainSuffix:
			if handlers.Domain != nil {
				if err := handlers.Domain([]byte(r.Value)); err != nil {
					return err
				}
			}
		case IPCIDR, IPCIDR6:
			if handlers.CIDR != nil {
				if err := handlers.CIDR(r.Value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func streamNativeMRS(data []byte, handlers MRSStreamHandlers) error {
	r := bytes.NewReader(data)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return err
	}
	if !bytes.Equal(magic, []byte{'M', 'R', 'S', 1}) {
		return errors.New("invalid MRS magic")
	}
	behavior, err := r.ReadByte()
	if err != nil {
		return err
	}
	var count int64
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return err
	}
	var extraLen int64
	if err := binary.Read(r, binary.BigEndian, &extraLen); err != nil {
		return err
	}
	if extraLen < 0 || extraLen > int64(r.Len()) {
		return errors.New("invalid MRS extra length")
	}
	if extraLen > 0 {
		if _, err := r.Seek(extraLen, io.SeekCurrent); err != nil {
			return err
		}
	}
	switch behavior {
	case 0:
		return streamMRSDomains(r, handlers.Domain)
	case 1:
		return streamMRSCIDRs(r, handlers.CIDR)
	default:
		return errors.New("unsupported MRS behavior")
	}
}

func ParseMRSWithOptions(name string, data []byte, opt MRSParseOptions) (Provider, error) {
	p := Provider{Name: name, Format: "mrs", Action: "proxy"}
	payload, _, err := decodeMRSPayload(data)
	if err != nil {
		return p, err
	}
	if len(payload) >= 4 && bytes.Equal(payload[:4], []byte{'M', 'R', 'S', 1}) {
		return parseNativeMRSWithOptions(name, payload, opt)
	}
	text := string(payload)
	if !strings.Contains(text, ".") && !strings.Contains(text, "/") {
		return p, errors.New("unsupported MRS binary encoding; expected native MRS domain/ipcidr or mihomo-compatible exported text/yaml")
	}
	p = ParseText(name, payload)
	p.Format = "mrs"
	return p, nil
}

func AnalyzeMRS(data []byte) (MRSInfo, error) {
	payload, compressed, err := decodeMRSPayload(data)
	if err != nil {
		return MRSInfo{}, err
	}
	info := MRSInfo{Compressed: compressed}
	if len(payload) < 4 || !bytes.Equal(payload[:4], []byte{'M', 'R', 'S', 1}) {
		return info, errors.New("unsupported non-native MRS metadata")
	}
	r := bytes.NewReader(payload)
	if _, err := r.Seek(4, io.SeekStart); err != nil {
		return info, err
	}
	behavior, err := r.ReadByte()
	if err != nil {
		return info, err
	}
	var count int64
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return info, err
	}
	if count < 0 || count > int64(^uint(0)>>1) {
		return info, errors.New("invalid MRS count")
	}
	info.Native = true
	info.Count = int(count)
	switch behavior {
	case 0:
		info.Behavior = "domain"
	case 1:
		info.Behavior = "ipcidr"
	default:
		return info, errors.New("unsupported MRS behavior")
	}
	return info, nil
}

// maxMRSPayloadBytes caps the decompressed MRS payload. MRS files are
// downloaded from user-configured URLs and parsed on 128–512 MB routers —
// without this cap a small zstd/gzip bomb expands until the OOM killer
// takes out the manager. Real-world MRS payloads top out in the tens of MB.
const maxMRSPayloadBytes = 128 << 20

func decodeMRSPayload(data []byte) ([]byte, string, error) {
	payload := data
	if len(data) >= 4 && data[0] == 0x28 && data[1] == 0xb5 && data[2] == 0x2f && data[3] == 0xfd {
		zr, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxMRSPayloadBytes))
		if err != nil {
			return nil, "zstd", err
		}
		defer zr.Close()
		payload, err = zr.DecodeAll(data, nil)
		if err != nil {
			return nil, "zstd", err
		}
		if len(payload) > maxMRSPayloadBytes {
			return nil, "zstd", fmt.Errorf("MRS payload exceeds %d MB limit", maxMRSPayloadBytes>>20)
		}
		return payload, "zstd", nil
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, "gzip", err
		}
		defer func() { _ = zr.Close() }()
		payload, err = io.ReadAll(io.LimitReader(zr, maxMRSPayloadBytes+1))
		if err != nil {
			return nil, "gzip", err
		}
		if len(payload) > maxMRSPayloadBytes {
			return nil, "gzip", fmt.Errorf("MRS payload exceeds %d MB limit", maxMRSPayloadBytes>>20)
		}
		return payload, "gzip", nil
	}
	return payload, "", nil
}

func parseNativeMRSWithOptions(name string, data []byte, opt MRSParseOptions) (Provider, error) {
	p := Provider{Name: name, Format: "mrs", Action: "proxy"}
	r := bytes.NewReader(data)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return p, err
	}
	if !bytes.Equal(magic, []byte{'M', 'R', 'S', 1}) {
		return p, errors.New("invalid MRS magic")
	}
	behavior, err := r.ReadByte()
	if err != nil {
		return p, err
	}
	var count int64
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return p, err
	}
	var extraLen int64
	if err := binary.Read(r, binary.BigEndian, &extraLen); err != nil {
		return p, err
	}
	if extraLen < 0 || extraLen > int64(r.Len()) {
		return p, errors.New("invalid MRS extra length")
	}
	if extraLen > 0 {
		if _, err := r.Seek(extraLen, io.SeekCurrent); err != nil {
			return p, err
		}
	}
	switch behavior {
	case 0:
		p.Behavior = "domain"
		domains, err := readMRSDomainsWithOptions(r, opt)
		if err != nil {
			return p, err
		}
		for i, d := range domains {
			p.Rules = append(p.Rules, Rule{Type: DomainSuffix, Value: strings.TrimPrefix(d, "+."), SourceProvider: name, SourceLine: i + 1, SupportedOpenWrt: true, SupportedMihomo: true})
		}
	case 1:
		p.Behavior = "ipcidr"
		cidrs, err := readMRSCIDRs(r)
		if err != nil {
			return p, err
		}
		for i, c := range cidrs {
			typ := IPCIDR
			if strings.Contains(c, ":") {
				typ = IPCIDR6
			}
			p.Rules = append(p.Rules, Rule{Type: typ, Value: c, SourceProvider: name, SourceLine: i + 1, SupportedOpenWrt: true, SupportedMihomo: true})
		}
	default:
		return p, errors.New("unsupported MRS behavior")
	}
	if count >= 0 && int64(len(p.Rules)) == 0 && count > 0 {
		return p, errors.New("empty decoded MRS")
	}
	return p, nil
}

func readMRSCIDRs(r *bytes.Reader) ([]string, error) {
	version := make([]byte, 1)
	if _, err := io.ReadFull(r, version); err != nil {
		return nil, err
	}
	if version[0] != 1 {
		return nil, errors.New("invalid MRS CIDR version")
	}
	var length int64
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	// Each range is 32 bytes (two 16-byte addresses) — bound the declared
	// count against remaining input before preallocating.
	if length < 0 || length > int64(r.Len())/32 {
		return nil, errors.New("invalid MRS CIDR length")
	}
	out := make([]string, 0, length)
	for i := int64(0); i < length; i++ {
		var from16, to16 [16]byte
		if err := binary.Read(r, binary.BigEndian, &from16); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.BigEndian, &to16); err != nil {
			return nil, err
		}
		out = append(out, rangeToPrefixes(netip.AddrFrom16(from16).Unmap(), netip.AddrFrom16(to16).Unmap())...)
	}
	return out, nil
}

func streamMRSCIDRs(r *bytes.Reader, emit func(string) error) error {
	version := make([]byte, 1)
	if _, err := io.ReadFull(r, version); err != nil {
		return err
	}
	if version[0] != 1 {
		return errors.New("invalid MRS CIDR version")
	}
	var length int64
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}
	if length < 0 || length > int64(r.Len())/32 {
		return errors.New("invalid MRS CIDR length")
	}
	for i := int64(0); i < length; i++ {
		var from16, to16 [16]byte
		if err := binary.Read(r, binary.BigEndian, &from16); err != nil {
			return err
		}
		if err := binary.Read(r, binary.BigEndian, &to16); err != nil {
			return err
		}
		if emit == nil {
			continue
		}
		for _, cidr := range rangeToPrefixes(netip.AddrFrom16(from16).Unmap(), netip.AddrFrom16(to16).Unmap()) {
			if err := emit(cidr); err != nil {
				return err
			}
		}
	}
	return nil
}

func rangeToPrefixes(from, to netip.Addr) []string {
	if !from.IsValid() || !to.IsValid() || from.BitLen() != to.BitLen() {
		return nil
	}
	bitsLen := from.BitLen()
	var out []string
	cur := addrToUint(from)
	end := addrToUint(to)
	for cur[0] < end[0] || (cur[0] == end[0] && cur[1] <= end[1]) {
		maxSize := trailingZeros128(cur, bitsLen)
		remaining := sub128(end, cur)
		remaining = addOne128(remaining)
		maxByRemain := floorLog2_128(remaining)
		if maxSize > maxByRemain {
			maxSize = maxByRemain
		}
		prefixLen := bitsLen - maxSize
		addr := uintToAddr(cur, bitsLen)
		out = append(out, netip.PrefixFrom(addr, prefixLen).String())
		cur = addPow2(cur, maxSize)
		if cur[0] == 0 && cur[1] == 0 && bitsLen == 128 {
			break
		}
	}
	return out
}

// mrsTrie is the raw bitmap-trie payload of an MRS domain set, after the
// version byte has been validated. Both the materialising walker and the
// non-materialising DomainSet share this prologue.
type mrsTrie struct {
	leaves      []uint64
	labelBitmap []uint64
	labels      []byte
}

func readMRSTrieRaw(r *bytes.Reader) (mrsTrie, error) {
	var t mrsTrie
	version := make([]byte, 1)
	if _, err := io.ReadFull(r, version); err != nil {
		return t, err
	}
	if version[0] != 1 {
		return t, errors.New("invalid MRS domain version")
	}
	leaves, err := readUint64Slice(r)
	if err != nil {
		return t, err
	}
	labelBitmap, err := readUint64Slice(r)
	if err != nil {
		return t, err
	}
	var labelLen int64
	if err := binary.Read(r, binary.BigEndian, &labelLen); err != nil {
		return t, err
	}
	// Bound against remaining input before allocating — labelLen is
	// attacker-controlled in a downloaded file.
	if labelLen < 0 || labelLen > int64(r.Len()) {
		return t, errors.New("invalid MRS domain labels length")
	}
	labels := make([]byte, labelLen)
	if _, err := io.ReadFull(r, labels); err != nil {
		return t, err
	}
	return mrsTrie{leaves: leaves, labelBitmap: labelBitmap, labels: labels}, nil
}

// buildRankSelect derives the rank-select acceleration tables over t.labelBitmap.
func (t mrsTrie) buildRankSelect() (prefixOnes []int, onesPositions []int, bitsLen int) {
	bitsLen = len(t.labelBitmap) * 64
	prefixOnes = make([]int, bitsLen+1)
	onesPositions = make([]int, 0)
	for i := 0; i < bitsLen; i++ {
		prefixOnes[i+1] = prefixOnes[i]
		if bitAt(t.labelBitmap, i) {
			prefixOnes[i+1]++
			onesPositions = append(onesPositions, i)
		}
	}
	return
}

// walkMRSTrie visits every node of the trie in DFS order, invoking visit at
// each node before descending into its children. The visit callback can
// return false to skip the subtree rooted at this node. current carries the
// label bytes from the root in trie order (reverse-domain order); the slice
// is reused across calls and must not be retained.
func walkMRSTrie(t mrsTrie, visit func(nodeID int, current []byte) bool) error {
	prefixOnes, onesPositions, bitsLen := t.buildRankSelect()
	countZerosFast := func(n int) int {
		if n < 0 {
			return 0
		}
		if n > bitsLen {
			n = bitsLen
		}
		return n - prefixOnes[n]
	}
	selectOneFast := func(idx int) int {
		if idx < 0 || idx >= len(onesPositions) {
			return -1
		}
		return onesPositions[idx]
	}
	// Depth caps recursion: it grows by one per label byte, so real
	// domains stay under ~256. A crafted single-chain trie could otherwise
	// recurse once per payload byte and blow the stack.
	const maxTrieDepth = 1024
	var current []byte
	var walk func(nodeID, bmIdx, depth int) error
	walk = func(nodeID, bmIdx, depth int) error {
		if depth > maxTrieDepth {
			return errors.New("MRS domain trie exceeds depth limit")
		}
		if bmIdx < 0 || bmIdx >= bitsLen {
			return errors.New("invalid MRS domain bitmap index")
		}
		if !visit(nodeID, current) {
			return nil
		}
		for {
			if bitAt(t.labelBitmap, bmIdx) {
				return nil
			}
			labelIdx := bmIdx - nodeID
			if labelIdx < 0 || labelIdx >= len(t.labels) {
				return errors.New("invalid MRS domain label index")
			}
			current = append(current, t.labels[labelIdx])
			nextNodeID := countZerosFast(bmIdx + 1)
			nextBmIdx := selectOneFast(nextNodeID-1) + 1
			if err := walk(nextNodeID, nextBmIdx, depth+1); err != nil {
				return err
			}
			current = current[:len(current)-1]
			bmIdx++
		}
	}
	return walk(0, 0, 0)
}

func readMRSDomainsWithOptions(r *bytes.Reader, opt MRSParseOptions) ([]string, error) {
	t, err := readMRSTrieRaw(r)
	if err != nil {
		return nil, err
	}
	var out []string
	if err := walkMRSTrie(t, func(nodeID int, current []byte) bool {
		if bitAt(t.leaves, nodeID) {
			out = append(out, reverseString(string(current)))
		}
		return true
	}); err != nil {
		return nil, err
	}
	if opt.SortDomains {
		sort.Strings(out)
	}
	return out, nil
}

func streamMRSDomains(r *bytes.Reader, emit func([]byte) error) error {
	t, err := readMRSTrieRaw(r)
	if err != nil {
		return err
	}
	var emitErr error
	// rev is a reusable scratch buffer for the forward-form domain bytes.
	// Without this, each emit allocated a new ~25-byte string (the
	// `string(current)` in `reverseString`) — 80 k of those per big MRS
	// provider pinned a measurable chunk of CPU on GC + page faults.
	var rev []byte
	if err := walkMRSTrie(t, func(nodeID int, current []byte) bool {
		if emitErr != nil {
			return false
		}
		if !bitAt(t.leaves, nodeID) || emit == nil {
			return true
		}
		n := len(current)
		if cap(rev) < n {
			rev = make([]byte, n, n*2+32)
		}
		rev = rev[:n]
		for i, j := 0, n-1; j >= 0; i, j = i+1, j-1 {
			rev[i] = current[j]
		}
		// Strip leading "+." wildcard marker (mihomo MRS encodes
		// `+.example.com` to mean "example.com and any subdomain").
		// Matches strings.TrimPrefix("+.") semantics exactly.
		b := rev
		if len(b) >= 2 && b[0] == '+' && b[1] == '.' {
			b = b[2:]
		}
		if err := emit(b); err != nil {
			emitErr = err
			return false
		}
		return true
	}); err != nil {
		return err
	}
	return emitErr
}

// readUint64Slice takes *bytes.Reader (not io.Reader) so the declared
// length — an attacker-controlled int64 in a downloaded file — can be
// validated against the bytes actually remaining BEFORE allocating.
func readUint64Slice(r *bytes.Reader) ([]uint64, error) {
	var length int64
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length < 0 || length > int64(r.Len())/8 {
		return nil, errors.New("invalid MRS uint64 slice length")
	}
	out := make([]uint64, length)
	for i := range out {
		if err := binary.Read(r, binary.BigEndian, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func bitAt(bm []uint64, i int) bool {
	return i >= 0 && i>>6 < len(bm) && bm[i>>6]&(uint64(1)<<uint(i&63)) != 0
}

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func addrToUint(a netip.Addr) [2]uint64 {
	b := a.As16()
	return [2]uint64{binary.BigEndian.Uint64(b[0:8]), binary.BigEndian.Uint64(b[8:16])}
}

func uintToAddr(v [2]uint64, bitLen int) netip.Addr {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], v[0])
	binary.BigEndian.PutUint64(b[8:16], v[1])
	a := netip.AddrFrom16(b).Unmap()
	if bitLen == 32 && a.Is4() {
		return a
	}
	return netip.AddrFrom16(b)
}

func trailingZeros128(v [2]uint64, bitLen int) int {
	if bitLen == 32 {
		return bits.TrailingZeros32(uint32(v[1]))
	}
	if v[1] != 0 {
		return bits.TrailingZeros64(v[1])
	}
	return 64 + bits.TrailingZeros64(v[0])
}

func sub128(a, b [2]uint64) [2]uint64 {
	lo := a[1] - b[1]
	borrow := uint64(0)
	if a[1] < b[1] {
		borrow = 1
	}
	return [2]uint64{a[0] - b[0] - borrow, lo}
}

func addOne128(v [2]uint64) [2]uint64 {
	v[1]++
	if v[1] == 0 {
		v[0]++
	}
	return v
}

func floorLog2_128(v [2]uint64) int {
	if v[0] != 0 {
		return 64 + 63 - bits.LeadingZeros64(v[0])
	}
	if v[1] != 0 {
		return 63 - bits.LeadingZeros64(v[1])
	}
	return 0
}

func addPow2(v [2]uint64, pow int) [2]uint64 {
	if pow >= 64 {
		v[0] += 1 << uint(pow-64)
		return v
	}
	old := v[1]
	v[1] += 1 << uint(pow)
	if v[1] < old {
		v[0]++
	}
	return v
}
