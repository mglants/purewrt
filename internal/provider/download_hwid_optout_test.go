package provider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSuppressHWIDDropsHeadersAndQuery(t *testing.T) {
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

func TestHWIDStillSentWhenSuppressFalse(t *testing.T) {
	t.Parallel()
	var gotHWID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHWID = r.Header.Get("X-HWID")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, err := DownloadWithOptions(srv.URL, DownloadOptions{})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if gotHWID == "" {
		t.Fatalf("expected X-HWID header by default, got empty")
	}
}
