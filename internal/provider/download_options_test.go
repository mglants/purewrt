package provider

import (
	"strings"
	"testing"
)

func TestApplyDownloadOptionsAddsDeviceFields(t *testing.T) {
	u := ApplyDownloadOptions("https://panel.example/sub/abc?format=clash", DownloadOptions{IncludeHWID: true, HWID: "router-1", DeviceName: "Cudy WR3000H"})
	if u == "" || !containsAll(u, []string{"format=clash", "hwid=router-1", "device_name=Cudy+WR3000H"}) {
		t.Fatalf("unexpected url: %s", u)
	}
}

func TestApplyDownloadOptionsWithoutIncludeHWIDLeavesURLAlone(t *testing.T) {
	raw := "https://lists.example/common.native?tag=v1"
	if u := ApplyDownloadOptions(raw, DownloadOptions{HWID: "router-1", DeviceName: "Cudy WR3000H"}); u != raw {
		t.Fatalf("identity must not be injected without IncludeHWID: %s", u)
	}
}

func TestDownloadWithInvalidProxyURL(t *testing.T) {
	_, err := DownloadWithOptions("https://example.com/sub.yaml", DownloadOptions{ProxyURL: "://bad"})
	if err == nil || !strings.Contains(err.Error(), "invalid update proxy url") {
		t.Fatalf("expected invalid proxy url error, got: %v", err)
	}
}

func containsAll(s string, xs []string) bool {
	for _, x := range xs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
