package mihomoapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestParseAssetVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, asset, arch, want string
	}{
		{"alpha-arm64", "mihomo-linux-arm64-alpha-d08c885.gz", "arm64", "alpha-d08c885"},
		{"alpha-amd64", "mihomo-linux-amd64-alpha-d08c885.gz", "amd64", "alpha-d08c885"},
		{"stable-semver", "mihomo-linux-arm64-v1.18.10.gz", "arm64", "v1.18.10"},
		{"compatible-suffix", "mihomo-linux-mipsle-alpha-d08c885-compatible.gz", "mipsle", "alpha-d08c885"},
		{"tgz-archive", "mihomo-linux-amd64-v1.18.10.tar.gz", "amd64", "v1.18.10"},
		{"arch-mismatch", "mihomo-linux-arm64-v1.18.10.gz", "amd64", ""},
		{"bogus-shape", "something-else.gz", "amd64", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAssetVersion(tc.asset, tc.arch)
			if got != tc.want {
				t.Fatalf("parseAssetVersion(%q,%q) = %q, want %q", tc.asset, tc.arch, got, tc.want)
			}
		})
	}
}

func TestSelectAsset(t *testing.T) {
	t.Parallel()

	assets := []ReleaseAsset{
		{Name: "mihomo-linux-arm64-compatible.gz", BrowserDownloadURL: "compatible"},
		{Name: "mihomo-linux-arm64.gz", BrowserDownloadURL: "native"},
		{Name: "mihomo-linux-amd64.gz", BrowserDownloadURL: "amd64"},
		{Name: "mihomo-linux-arm64.gz.sha256", BrowserDownloadURL: "sha"},
	}
	asset, sum := selectAsset(assets, "arm64")
	if asset.BrowserDownloadURL != "native" {
		t.Fatalf("asset = %+v", asset)
	}
	if sum.BrowserDownloadURL != "sha" {
		t.Fatalf("checksum = %+v", sum)
	}
}

func TestVerifySHA256(t *testing.T) {
	t.Parallel()

	data := []byte("binary")
	h := fmt.Sprintf("%x", sha256.Sum256(data))
	if err := verifySHA256(data, h+"  mihomo.gz", "mihomo.gz"); err != nil {
		t.Fatalf("verifySHA256 exact: %v", err)
	}
	if err := verifySHA256(data, "prefix "+h+" suffix", "other"); err != nil {
		t.Fatalf("verifySHA256 contains: %v", err)
	}
	if err := verifySHA256(data, "deadbeef  mihomo.gz", "mihomo.gz"); err == nil {
		t.Fatal("verifySHA256 mismatch returned nil")
	}
}

func TestExtractBinary(t *testing.T) {
	t.Parallel()

	raw, err := extractBinary([]byte("raw"), "mihomo")
	if err != nil || string(raw) != "raw" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}

	gz := gzipBytes(t, []byte("gzbin"))
	out, err := extractBinary(gz, "mihomo-linux.gz")
	if err != nil || string(out) != "gzbin" {
		t.Fatalf("gz=%q err=%v", out, err)
	}

	tarGz := tarGzipBytes(t, "dir/mihomo", []byte("tarbin"))
	out, err = extractBinary(tarGz, "mihomo-linux.tar.gz")
	if err != nil || string(out) != "tarbin" {
		t.Fatalf("tar=%q err=%v", out, err)
	}

	missing := tarGzipBytes(t, "dir/other", []byte("tarbin"))
	if _, err = extractBinary(missing, "mihomo-linux.tar.gz"); err == nil {
		t.Fatal("missing mihomo binary returned nil error")
	}
}

func TestEffectiveArchHint(t *testing.T) {
	t.Parallel()

	if got := effectiveArch("ARM64"); got != "arm64" {
		t.Fatalf("effectiveArch = %q", got)
	}
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarGzipBytes(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return gzipBytes(t, tarBuf.Bytes())
}
