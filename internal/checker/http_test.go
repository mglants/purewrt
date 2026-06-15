package checker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPGet(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	res := HTTPGet(srv.URL)
	if res.Error != "" || res.Status != "201 Created" || res.LatencyMS < 0 {
		t.Fatalf("HTTPGet = %+v", res)
	}

	res = HTTPGet("http://127.0.0.1:1")
	if res.Error == "" {
		t.Fatal("expected error for closed port")
	}
	if !strings.Contains(res.Error, "connect") {
		t.Fatalf("unexpected error: %+v", res)
	}
}
