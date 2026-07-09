package manager

import (
	"path/filepath"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

// writeTempConfig serializes c to a temp UCI file and returns its path, so
// Manager.Load reads it back (ZapretStatus reads config from disk).
func writeTempConfig(t *testing.T, c config.Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "purewrt")
	if err := config.Save(path, c); err != nil {
		t.Fatalf("save temp config: %v", err)
	}
	return path
}

// stubZapretStatusSeams swaps the process/counter/error seams for fakes and
// restores them on cleanup. Not parallel-safe (package globals).
func stubZapretStatusSeams(t *testing.T, procs map[int]int, counters map[string]nftCounter) {
	t.Helper()
	op, oc, oe := zapretProcs, zapretCounters, zapretRecentError
	t.Cleanup(func() { zapretProcs, zapretCounters, zapretRecentError = op, oc, oe })
	zapretProcs = func() map[int]int { return procs }
	zapretCounters = func() map[string]nftCounter { return counters }
	zapretRecentError = func(livePIDs) string { return "" }
}

func zapretStatusTestConfig() config.Config {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, FwMark: "0x40000000", NFQWSBin: "/usr/bin/nfqws"}}
	c.ZapretStrategies = []config.ZapretStrategy{
		{Name: "yt", Enabled: true, Profile: "wan", QueueNum: 200, Params: "--filter-tcp=443"},
		{Name: "dc", Enabled: true, Profile: "wan", QueueNum: 201, Params: "--filter-udp=443"},
	}
	c.Sections = []config.Section{
		{Name: "Youtube", Enabled: true, Action: "zapret", IPv4Enabled: true, Priority: 10, ZapretStrategies: []string{"yt"}},
		{Name: "Discord", Enabled: true, Action: "zapret", IPv4Enabled: true, Priority: 20, ZapretStrategies: []string{"dc"}},
		{Name: "Media", Enabled: true, Action: "proxy", Priority: 30}, // not zapret — ignored
	}
	return c
}

func TestZapretStatusRunningInstances(t *testing.T) {
	// Only queue 200 has a live nfqws; 201 is down.
	stubZapretStatusSeams(t, map[int]int{200: 3415}, map[string]nftCounter{
		"dns_proxy_Youtube4": {Packets: 110, Bytes: 27306},
		"proxy_Youtube4":     {Packets: 5, Bytes: 200},
	})
	m := Manager{ConfigPath: writeTempConfig(t, zapretStatusTestConfig())}
	s := m.ZapretStatus()

	if !s.Running {
		t.Fatal("expected Running=true (queue 200 up)")
	}
	if s.RoutedSections != 2 || s.EnabledStrategies != 2 || s.EnabledProfiles != 1 {
		t.Fatalf("counts: routed=%d strat=%d prof=%d, want 2/2/1", s.RoutedSections, s.EnabledStrategies, s.EnabledProfiles)
	}
	byStrat := map[string]ZapretInstanceStatus{}
	for _, i := range s.Instances {
		byStrat[i.Strategy] = i
	}
	if yt := byStrat["yt"]; !yt.Running || yt.PID != 3415 || yt.Queue != 200 {
		t.Fatalf("yt instance = %+v, want running pid 3415 queue 200", yt)
	}
	if dc := byStrat["dc"]; dc.Running || dc.PID != 0 || dc.Queue != 201 {
		t.Fatalf("dc instance = %+v, want not-running queue 201", dc)
	}
	// Youtube section aggregates proxy_ + dns_proxy_ (110+5 packets).
	var ytPkts uint64
	for _, sec := range s.Sections {
		if sec.Section == "Youtube" {
			ytPkts = sec.Packets
		}
	}
	if ytPkts != 115 {
		t.Fatalf("Youtube packets = %d, want 115 (proxy 5 + dns 110)", ytPkts)
	}
	if s.TotalPackets != 115 {
		t.Fatalf("TotalPackets = %d, want 115", s.TotalPackets)
	}
}

func TestZapretStatusStopped(t *testing.T) {
	stubZapretStatusSeams(t, map[int]int{}, map[string]nftCounter{})
	m := Manager{ConfigPath: writeTempConfig(t, zapretStatusTestConfig())}
	s := m.ZapretStatus()
	if s.Running {
		t.Fatal("expected Running=false with no nfqws procs")
	}
	for _, i := range s.Instances {
		if i.Running {
			t.Fatalf("instance %s should be not-running", i.Strategy)
		}
	}
}
