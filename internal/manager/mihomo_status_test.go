package manager

import "testing"

// After a package upgrade the still-running old process's /proc/<pid>/exe
// resolves to "<path> (deleted)" — the matcher must strip that suffix or
// the status probe reports "not running" while mihomo is still serving.
func TestMihomoExeMatches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		exe  string
		want bool
	}{
		{"/usr/libexec/mihomo", true},
		{"/usr/bin/mihomo", true},
		{"/usr/libexec/mihomo (deleted)", true},
		{"/etc/purewrt/mihomo-bin/mihomo-Prerelease-Alpha", true},
		{"/etc/purewrt/mihomo-bin/mihomo-Prerelease-Alpha (deleted)", true},
		{"/usr/bin/mihomo.v2", true},
		{"/usr/bin/mihomonia", false},
		{"/usr/bin/sh", false},
		{"", false},
	}
	for _, c := range cases {
		if got := mihomoExeMatches(c.exe); got != c.want {
			t.Errorf("mihomoExeMatches(%q) = %v, want %v", c.exe, got, c.want)
		}
	}
}
