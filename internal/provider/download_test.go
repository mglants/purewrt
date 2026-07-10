package provider

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/version"
)

func TestDownloadWithOptionsHTTP(t *testing.T) {
	t.Parallel()

	var gotUA, gotHWID, gotDevice, gotCustom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotHWID = r.Header.Get("X-HWID")
		gotDevice = r.Header.Get("X-Device-Name")
		gotCustom = r.Header.Get("X-Test")
		if r.URL.Query().Get("token") != "secret" {
			t.Fatalf("query token missing: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	res, err := DownloadWithOptions(srv.URL+"/sub?token=secret", DownloadOptions{
		IncludeHWID: true,
		UserAgent:   "PureWRT-Test",
		Headers:     []string{"X-Test: yes"},
	})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if string(res.Data) != "payload" {
		t.Fatalf("Data = %q, want payload", res.Data)
	}
	wantChecksum := fmt.Sprintf("%x", sha256.Sum256([]byte("payload")))
	if res.Checksum != wantChecksum {
		t.Fatalf("Checksum = %q, want %q", res.Checksum, wantChecksum)
	}
	if res.URLRedacted != srv.URL+"/sub?..." {
		t.Fatalf("URLRedacted = %q", res.URLRedacted)
	}
	if gotUA != "PureWRT-Test" || gotHWID == "" || gotDevice == "" || gotCustom != "yes" {
		t.Fatalf("unexpected headers: ua=%q hwid=%q device=%q custom=%q", gotUA, gotHWID, gotDevice, gotCustom)
	}
}

func TestDownloadWithOptionsHTTPError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTeapot)
	}))
	defer srv.Close()

	_, err := DownloadWithOptions(srv.URL, DownloadOptions{})
	if err == nil || !strings.Contains(err.Error(), "418") {
		t.Fatalf("error = %v, want status 418", err)
	}
}

func TestDownloadWithOptionsFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "data.txt")
	if err := os.WriteFile(path, []byte("local"), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := DownloadWithOptions("file://"+path, DownloadOptions{})
	if err != nil {
		t.Fatalf("DownloadWithOptions file: %v", err)
	}
	if string(res.Data) != "local" {
		t.Fatalf("Data = %q, want local", res.Data)
	}
}

// Panel-facing identity headers follow the Happ/v2board convention:
// x-device-os names the OS, x-ver-os carries the bare OS version (no
// "OpenWrt " prefix), and the default User-Agent embeds the purewrt
// package version instead of a hardcoded one.
func TestDownloadIdentityHeaderConvention(t *testing.T) {
	t.Parallel()
	var gotUA, gotDeviceOS, gotVerOS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotDeviceOS = r.Header.Get("x-device-os")
		gotVerOS = r.Header.Get("x-ver-os")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	if _, err := DownloadWithOptions(srv.URL, DownloadOptions{IncludeHWID: true}); err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if want := DefaultUserAgent(); gotUA != want {
		t.Fatalf("default User-Agent = %q, want %q", gotUA, want)
	}
	if !strings.HasPrefix(gotUA, "mihomo") || !strings.Contains(gotUA, "purewrt/"+version.Version) {
		t.Fatalf("default UA must be mihomo-prefixed with a purewrt/<version> comment (panel format gating, AGENTS.md), got %q", gotUA)
	}
	if gotDeviceOS != "OpenWrt" {
		t.Fatalf("x-device-os = %q, want OpenWrt", gotDeviceOS)
	}
	if gotVerOS == "" || strings.HasPrefix(gotVerOS, "OpenWrt") {
		t.Fatalf("x-ver-os must be the bare OS version, got %q", gotVerOS)
	}
}
