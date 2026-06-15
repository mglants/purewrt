package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendWebhookFormat(t *testing.T) {
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotCT = r.Header.Get("Content-Type")
	}))
	defer srv.Close()
	ev := Event{Event: "update_failure", Detail: "2 provider(s) failed", Host: "router", TS: time.Unix(1700000000, 0).UTC()}
	if err := Send(srv.URL, "webhook", ev); err != nil {
		t.Fatal(err)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type = %q", gotCT)
	}
	var decoded Event
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Event != "update_failure" || decoded.Detail != "2 provider(s) failed" || decoded.Host != "router" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestSendNtfyFormat(t *testing.T) {
	var gotBody []byte
	var gotTitle string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotTitle = r.Header.Get("Title")
	}))
	defer srv.Close()
	if err := Send(srv.URL, "ntfy", Event{Event: "sub_expiry", Detail: "subscription main: 3.2 days remaining"}); err != nil {
		t.Fatal(err)
	}
	if string(gotBody) != "subscription main: 3.2 days remaining" {
		t.Fatalf("body = %q", gotBody)
	}
	if gotTitle != "purewrt: sub_expiry" {
		t.Fatalf("title = %q", gotTitle)
	}
}

func TestSendNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	if err := Send(srv.URL, "webhook", Event{Event: "x"}); err == nil {
		t.Fatal("expected error on 403")
	}
}
