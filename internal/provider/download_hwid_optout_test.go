package provider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// HWID/device identity is a panel-facing fingerprint that only
// subscriptions and proxy providers need (their panels key downloads on
// it). Every other download — rule providers, geo data, native-list
// catalog, zapret candidates — must not carry router identity, so the
// injection is opt-in via IncludeHWID.
func TestHWIDNotSentByDefault(t *testing.T) {
	t.Parallel()
	var gotHWID, gotXHWID, gotXDevName, rawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHWID = r.Header.Get("x-hwid")
		gotXHWID = r.Header.Get("X-HWID")
		gotXDevName = r.Header.Get("X-Device-Name")
		rawQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	_, err := DownloadWithOptions(srv.URL+"/rules.txt?fmt=text", DownloadOptions{})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if gotHWID != "" || gotXHWID != "" || gotXDevName != "" {
		t.Fatalf("HWID headers sent without IncludeHWID: x-hwid=%q X-HWID=%q X-Device-Name=%q", gotHWID, gotXHWID, gotXDevName)
	}
	if strings.Contains(rawQuery, "hwid=") || strings.Contains(rawQuery, "device_name=") {
		t.Fatalf("HWID query injection without IncludeHWID: %q", rawQuery)
	}
	if rawQuery != "fmt=text" {
		t.Fatalf("user query mangled: %q, want fmt=text", rawQuery)
	}
}

func TestHWIDSentWhenIncluded(t *testing.T) {
	t.Parallel()
	var gotHWID string
	var rawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHWID = r.Header.Get("X-HWID")
		rawQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, err := DownloadWithOptions(srv.URL, DownloadOptions{IncludeHWID: true})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if gotHWID == "" {
		t.Fatal("expected X-HWID header with IncludeHWID=true, got empty")
	}
	if !strings.Contains(rawQuery, "hwid=") {
		t.Fatalf("expected hwid query injection with IncludeHWID=true, got %q", rawQuery)
	}
}

// SuppressHWID is the user's explicit opt-out and beats IncludeHWID —
// subscriptions/proxy providers with suppress_hwid stay identity-free.
func TestSuppressHWIDBeatsIncludeHWID(t *testing.T) {
	t.Parallel()
	var gotHWID, gotXHWID, gotXDevName, rawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHWID = r.Header.Get("x-hwid")
		gotXHWID = r.Header.Get("X-HWID")
		gotXDevName = r.Header.Get("X-Device-Name")
		rawQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	_, err := DownloadWithOptions(srv.URL+"/sub?format=clash", DownloadOptions{
		IncludeHWID:  true,
		SuppressHWID: true,
	})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if gotHWID != "" || gotXHWID != "" || gotXDevName != "" {
		t.Fatalf("HWID headers leaked with SuppressHWID=true: x-hwid=%q X-HWID=%q X-Device-Name=%q", gotHWID, gotXHWID, gotXDevName)
	}
	if strings.Contains(rawQuery, "hwid=") || strings.Contains(rawQuery, "device_name=") {
		t.Fatalf("HWID query injection leaked with SuppressHWID=true: %q", rawQuery)
	}
	if rawQuery != "format=clash" {
		t.Fatalf("user query mangled: %q, want format=clash", rawQuery)
	}
}
