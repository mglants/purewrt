package rules

import (
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// loadDecodedFixture reads a plain (already-decompressed) MRS payload —
// these pass straight through decodeMRSPayload, which makes them ideal for
// boundary-truncation tests where the corruption must reach the parser.
func loadDecodedFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/mrs/decoded/" + name)
	if err != nil {
		t.Skipf("decoded mrs fixture not available: %v", err)
	}
	return data
}

// TestMRSTruncationNeverPanics feeds prefixes of real payloads at every
// structurally interesting boundary — parse and stream must return an
// error (or succeed for the trivially-empty case), never panic or OOM.
func TestMRSTruncationNeverPanics(t *testing.T) {
	for _, fixture := range []string{"youtube.bin", "telegram-ips.bin"} {
		data := loadDecodedFixture(t, fixture)
		// Boundaries: mid-magic, behavior byte, mid-count, mid-extra-len,
		// just into the body, and a sweep of cuts through the first KB plus
		// a few deep cuts.
		cuts := []int{0, 1, 3, 4, 5, 9, 12, 13, 20, 21, 22, 30, 60, 100}
		for i := 128; i < len(data) && i < 1024; i += 64 {
			cuts = append(cuts, i)
		}
		cuts = append(cuts, len(data)/2, len(data)-1)
		for _, cut := range cuts {
			if cut > len(data) {
				continue
			}
			trunc := data[:cut]
			// Must not panic; error vs success is fixture-dependent.
			_, _ = ParseMRSWithOptions("trunc", trunc, MRSParseOptions{})
			_ = StreamMRS(trunc, MRSStreamHandlers{
				Domain: func([]byte) error { return nil },
				CIDR:   func(string) error { return nil },
			})
			_, _ = AnalyzeMRS(trunc)
			_, _ = ParseMRSDomainSet("trunc", trunc)
		}
	}
}

// TestMRSZstdBombRejected guards the decompression cap: a zstd frame
// expanding past maxMRSPayloadBytes must be rejected by the size limit,
// not allocated.
func TestMRSZstdBombRejected(t *testing.T) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		t.Fatal(err)
	}
	// 192 MB of zeros compresses to a few KB but exceeds the 128 MB cap.
	bomb := enc.EncodeAll(make([]byte, 192<<20), nil)
	_ = enc.Close()
	if _, _, err := decodeMRSPayload(bomb); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("zstd bomb must be rejected by the size cap, got err=%v", err)
	}
}

// TestMRSGzipEnvelope covers the gzip branch with native binary content —
// the existing fixtures are zstd, so gzip-wrap a decoded payload in-test.
func TestMRSGzipEnvelope(t *testing.T) {
	payload := loadDecodedFixture(t, "youtube.bin")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := ParseMRSWithOptions("gz", buf.Bytes(), MRSParseOptions{})
	if err != nil {
		t.Fatalf("gzip-wrapped native MRS must parse: %v", err)
	}
	if len(p.Rules) == 0 {
		t.Fatal("gzip-wrapped parse produced no rules")
	}
}

// FuzzStreamMRS exercises the full decode+stream path with mutated real
// payloads. Run with `go test -fuzz=FuzzStreamMRS ./internal/rules/`.
func FuzzStreamMRS(f *testing.F) {
	for _, name := range []string{"youtube.mrs", "telegram-ips.mrs"} {
		if data, err := os.ReadFile("../../testdata/mrs/" + name); err == nil {
			f.Add(data)
		}
	}
	for _, name := range []string{"youtube.bin", "telegram-ips.bin"} {
		if data, err := os.ReadFile("../../testdata/mrs/decoded/" + name); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = StreamMRS(data, MRSStreamHandlers{
			Domain: func([]byte) error { return nil },
			CIDR:   func(string) error { return nil },
		})
		_, _ = ParseMRSWithOptions("fuzz", data, MRSParseOptions{})
	})
}
