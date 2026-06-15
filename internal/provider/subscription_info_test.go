package provider

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseSubscriptionInfoFullHeader(t *testing.T) {
	t.Parallel()
	want := SubscriptionInfo{
		UploadBytes:   123,
		DownloadBytes: 456,
		TotalBytes:    1000000000,
		Expire:        time.Unix(1735689600, 0).UTC(), // 2025-01-01
	}
	got := parseSubscriptionInfo("upload=123; download=456; total=1000000000; expire=1735689600")
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseSubscriptionInfoTolerantOfMissingFields(t *testing.T) {
	t.Parallel()
	got := parseSubscriptionInfo("upload=10; total=200")
	if got.UploadBytes != 10 || got.TotalBytes != 200 || got.DownloadBytes != 0 || !got.Expire.IsZero() {
		t.Fatalf("partial parse failed: %+v", got)
	}
}

func TestParseSubscriptionInfoIgnoresGarbage(t *testing.T) {
	t.Parallel()
	got := parseSubscriptionInfo("upload=abc; expire=not-a-number")
	if got.UploadBytes != 0 || !got.Expire.IsZero() {
		t.Fatalf("garbage should be ignored, got %+v", got)
	}
}

func TestDownloadCapturesSubscriptionInfo(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=11; download=22; total=99; expire=1735689600")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, err := DownloadWithOptions(srv.URL, DownloadOptions{})
	if err != nil {
		t.Fatalf("DownloadWithOptions: %v", err)
	}
	if res.SubscriptionInfo.UploadBytes != 11 || res.SubscriptionInfo.TotalBytes != 99 || res.SubscriptionInfo.Expire.IsZero() {
		t.Fatalf("subscription-userinfo not captured: %+v", res.SubscriptionInfo)
	}
}
