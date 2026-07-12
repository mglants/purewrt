package provider

import "testing"

// Dashes are banned from generated names: they can't be UCI section ids, so
// keeping them would force the anonymous + `option name` legacy form on
// every import from a dash-named subscription.
func TestSafeNameProducesUCISectionIDs(t *testing.T) {
	cases := map[string]string{
		"my-sub":      "my_sub",
		"a.b-c":       "a_b_c",
		"ok_name":     "ok_name",
		"тест":        "_",
		"":            "main",
		"my - sub 42": "my_sub_42",
	}
	for in, want := range cases {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}
