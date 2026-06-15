package provider

import "testing"

func TestAutomaticHWIDNotEmpty(t *testing.T) {
	if AutomaticHWID() == "" {
		t.Fatal("automatic hwid is empty")
	}
}

func TestEffectiveIgnoresManualOverrides(t *testing.T) {
	o := DownloadOptions{HWID: "manual", DeviceName: "router"}
	if o.EffectiveHWID() == "manual" || o.EffectiveDeviceName() == "router" {
		t.Fatal("manual hwid/device override must be ignored")
	}
}
