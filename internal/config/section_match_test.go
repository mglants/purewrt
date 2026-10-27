package config

import "testing"

func TestDestinationPortsValidation(t *testing.T) {
	for _, value := range []string{"0", "65536", "443; accept", "80,", "900-800", "-1", "1-2-3", "udp"} {
		if _, err := NormalizeDestinationPorts(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	got, err := NormalizeDestinationPorts("443, 10002-10004,10000-10003,443")
	if err != nil || got != "443, 10000-10004" {
		t.Fatalf("normalization: %q %v", got, err)
	}
}

func TestDestinationPortsIntersection(t *testing.T) {
	for _, tc := range []struct {
		a, b, want string
		ok         bool
	}{
		{"", "", "", true}, {"", "443", "443", true}, {"443", "", "443", true},
		{"443,10000-11000", "10500-12000", "10500-11000", true},
		{"443", "80", "", false}, {"invalid", "443", "", false},
	} {
		got, ok := IntersectDestinationPorts(tc.a, tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("intersection %+v: %q %v", tc, got, ok)
		}
	}
}
