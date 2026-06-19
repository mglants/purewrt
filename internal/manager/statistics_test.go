package manager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/provider"
)

func TestParseNFTJSONSetStats(t *testing.T) {
	t.Parallel()

	data := []byte(`{"nftables":[{"metainfo":{}},{"set":{"name":"dns_media4","elem":["1.1.1.1","2.2.2.2"]}},{"set":{"name":"dns_media6","elements":["2001:db8::1"]}}]}`)
	got := parseNFTJSONSetStats(data)
	if got["dns_media4"].Entries != 2 || got["dns_media6"].Entries != 1 {
		t.Fatalf("stats = %+v", got)
	}
	if got["dns_media4"].Bytes == 0 {
		t.Fatalf("expected byte count: %+v", got["dns_media4"])
	}
	if parseNFTJSONSetStats([]byte(`not-json`)) != nil {
		t.Fatal("malformed json returned non-nil stats")
	}
}

func TestParseNFTJSONCounters(t *testing.T) {
	t.Parallel()

	// Realistic shape from `nft -j list counters table inet purewrt`:
	// metainfo wrapper, then one object per declared counter.
	data := []byte(`{"nftables":[
		{"metainfo":{}},
		{"counter":{"family":"inet","table":"purewrt","name":"proxy_common4","handle":42,"packets":1234,"bytes":56789}},
		{"counter":{"family":"inet","table":"purewrt","name":"dns_proxy_common4","handle":43,"packets":7,"bytes":1024}},
		{"counter":{"name":"empty","packets":0,"bytes":0}}
	]}`)
	got := parseNFTJSONCounters(data)
	if got["proxy_common4"].Packets != 1234 || got["proxy_common4"].Bytes != 56789 {
		t.Fatalf("proxy_common4 = %+v", got["proxy_common4"])
	}
	if got["dns_proxy_common4"].Packets != 7 || got["dns_proxy_common4"].Bytes != 1024 {
		t.Fatalf("dns_proxy_common4 = %+v", got["dns_proxy_common4"])
	}
	if _, ok := got["empty"]; !ok {
		t.Fatal("zero-valued counter must still be present in map")
	}
	if parseNFTJSONCounters([]byte(`not-json`)) != nil {
		t.Fatal("malformed json must return nil")
	}
	// Missing name field — the entry should be dropped silently so a
	// malformed line doesn't poison the whole map.
	bad := []byte(`{"nftables":[{"counter":{"packets":1,"bytes":2}}]}`)
	if len(parseNFTJSONCounters(bad)) != 0 {
		t.Fatal("counter without name must be skipped")
	}
}

func TestParseDNSMasqNFTJSONSet(t *testing.T) {
	t.Parallel()

	data := []byte(`{"nftables":[{"set":{"elem":[{"elem":{"val":"1.1.1.1","expires":30}},"2.2.2.2",{"val":"3.3.3.3","expires":10}]}}]}`)
	items, count := parseDNSMasqNFTJSONSet(data, 2)
	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(items))
	}
	if items[0].Timeout > items[1].Timeout {
		t.Fatalf("items not sorted by timeout: %+v", items)
	}
	if items[0].IP == "" || items[1].IP == "" {
		t.Fatalf("items = %+v", items)
	}

	items, count = parseDNSMasqNFTJSONSet([]byte(`bad`), 2)
	if items != nil || count != 0 {
		t.Fatalf("malformed items=%+v count=%d", items, count)
	}
}

func TestParseDNSMasqNFTJSONElement(t *testing.T) {
	t.Parallel()

	tests := []json.RawMessage{
		json.RawMessage(`{"elem":{"val":"1.1.1.1","expires":30}}`),
		json.RawMessage(`{"val":"2.2.2.2","expires":10}`),
		json.RawMessage(`"3.3.3.3"`),
	}
	for _, tt := range tests {
		if got, ok := parseDNSMasqNFTJSONElement(tt); !ok || got.IP == "" {
			t.Fatalf("parseDNSMasqNFTJSONElement(%s) = %+v %v", tt, got, ok)
		}
	}
	if _, ok := parseDNSMasqNFTJSONElement(json.RawMessage(`{}`)); ok {
		t.Fatal("empty object parsed successfully")
	}
}

func TestProviderMetadataAndFormatTime(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "provider.rules")
	when := time.Date(2026, 5, 16, 3, 4, 0, 0, time.UTC)
	meta := provider.Metadata{EntryCount: 42, LastUpdate: when, LastSuccess: when, ErrorMessage: ""}
	if err := provider.WriteMetadata(path, meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}
	got, ok := readProviderMetadata(path)
	if !ok || got.EntryCount != 42 {
		t.Fatalf("metadata = %+v ok=%v", got, ok)
	}
	if got := formatTime(when); got != "16.05.2026-03:04" {
		t.Fatalf("formatTime = %q", got)
	}
	if got := formatTime(time.Time{}); got != "" {
		t.Fatalf("zero formatTime = %q", got)
	}
	if err := os.WriteFile(path+".meta.json", []byte(`bad`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readProviderMetadata(path); ok {
		t.Fatal("corrupt metadata parsed successfully")
	}
}

func TestEffectiveSectionAction(t *testing.T) {
	t.Parallel()

	c := config.Default()
	c.Sections = []config.Section{{Name: "media", Action: "direct"}}
	if got := effectiveSectionAction(c, "media"); got != "direct" {
		t.Fatalf("effectiveSectionAction = %q", got)
	}
	if got := effectiveSectionAction(c, "missing"); got != "" {
		t.Fatalf("missing action = %q", got)
	}
}
