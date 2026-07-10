package manager

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/system"
)

type fakeRunner struct {
	failContains    string
	timeoutContains string // commands matching this return a deadline-exceeded error
	calls           []string
	respond         func(call string) (string, bool) // canned stdout for specific calls (e.g. nft list set)
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	return f.RunWithTimeout(0, name, args...)
}

func (f *fakeRunner) RunWithTimeout(_ time.Duration, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.timeoutContains != "" && strings.Contains(call, f.timeoutContains) {
		return "udhcpc: no lease, failing", errors.New("command timed out after 2m0s")
	}
	if f.failContains != "" && strings.Contains(call, f.failContains) {
		return "forced failure", errors.New("forced failure")
	}
	if f.respond != nil {
		if out, ok := f.respond(call); ok {
			return out, nil
		}
	}
	return "ok", nil
}

func TestApplyMihomoValidationFailureBeforePromote(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	r := &fakeRunner{failContains: "mihomo -t"}
	live := applyTestLivePaths(dir)
	err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, r)
	if err == nil || !strings.Contains(err.Error(), "mihomo config validation failed") {
		t.Fatalf("expected mihomo validation error, got %v", err)
	}
	if _, err := os.Stat(live.MihomoConfig); !os.IsNotExist(err) {
		t.Fatalf("live mihomo config must not be promoted on validation failure, err=%v", err)
	}
}

func TestApplyNFTFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	original := []byte("original nft")
	if err := os.MkdirAll(filepath.Dir(live.NFTFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live.NFTFile, original, 0600); err != nil {
		t.Fatal(err)
	}
	backup[live.NFTFile] = filepath.Join(dir, "purewrt.nft.bak")
	if err := os.WriteFile(backup[live.NFTFile], original, 0600); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{failContains: "nft -f " + live.NFTFile}
	err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, r)
	if err == nil || !strings.Contains(err.Error(), "nft -f") {
		t.Fatalf("expected nft failure, got %v", err)
	}
	got, err := os.ReadFile(live.NFTFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("expected rollback to restore nft file, got %q", got)
	}
}

func TestApplyDNSMasqReloadFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	original := []byte("original dnsmasq")
	if err := os.MkdirAll(filepath.Dir(live.DNSMasqFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live.DNSMasqFile, original, 0600); err != nil {
		t.Fatal(err)
	}
	backup[live.DNSMasqFile] = filepath.Join(dir, "purewrt.conf.bak")
	if err := os.WriteFile(backup[live.DNSMasqFile], original, 0600); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{failContains: "/etc/init.d/dnsmasq restart"}
	err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, r)
	if err == nil || !strings.Contains(err.Error(), "dnsmasq") {
		t.Fatalf("expected dnsmasq reload failure, got %v", err)
	}
	got, err := os.ReadFile(live.DNSMasqFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("expected rollback to restore dnsmasq file, got %q", got)
	}
}

// A dnsmasq restart that *times out* (slow startup on a large nftset config)
// must NOT roll back: the config is already promoted + loaded, the daemon is
// just slow. Rolling back here re-ran the same slow restart and, because the
// fingerprint never committed, made update-if-needed re-apply every run (the
// restart-timeout loop). The apply must succeed and the new dnsmasq file stay.
func TestApplyDNSMasqRestartTimeoutDoesNotRollBack(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	original := []byte("original dnsmasq")
	if err := os.MkdirAll(filepath.Dir(live.DNSMasqFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live.DNSMasqFile, original, 0600); err != nil {
		t.Fatal(err)
	}
	backup[live.DNSMasqFile] = filepath.Join(dir, "purewrt.conf.bak")
	if err := os.WriteFile(backup[live.DNSMasqFile], original, 0600); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{timeoutContains: "/etc/init.d/dnsmasq restart"}
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, r); err != nil {
		t.Fatalf("dnsmasq restart timeout must be tolerated, got %v", err)
	}
	// A rollback would restart dnsmasq a second time (restoreAndReload); on the
	// tolerated-timeout path it is restarted exactly once and never rolled back.
	restarts := 0
	for _, call := range r.calls {
		if strings.Contains(call, "/etc/init.d/dnsmasq restart") {
			restarts++
		}
	}
	if restarts != 1 {
		t.Fatalf("expected exactly one dnsmasq restart (no rollback), got %d calls: %v", restarts, r.calls)
	}
}

func TestApplyUsesValidUCIImportSyntax(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	c.DNS.HijackLANDNS = true
	live := applyTestLivePaths(dir)
	r := &fakeRunner{}
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, r); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "uci -m -f "+live.FirewallFile+" import firewall") {
		t.Fatalf("expected uci import -m -f syntax, got calls:\n%s", joined)
	}
	if strings.Contains(joined, "uci import ") || strings.Contains(joined, "uci -m -f "+live.FirewallFile+" firewall") {
		t.Fatalf("must not use invalid uci import firewall <file> syntax, got calls:\n%s", joined)
	}
}

// Mihomo-only change with a reachable controller: hot-reload (PUT /configs),
// never a process restart — established proxy connections must survive.
func TestApplyMihomoOnlyChangeHotReloadsNotRestart(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	r := &fakeRunner{}
	reloaded := false
	m := Manager{
		mihomoReachable: func(config.Config) bool { return true },
		mihomoReload:    func(config.Config) error { reloaded = true; return nil },
	}
	gen := generator.GenerationResult{DirtyGroups: generator.GenerationGroups{Mihomo: true}, Reason: "test mihomo only"}
	if err := m.applyWithRunnerPaths(c, backup, staged, live, gen, r); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "mihomo -t") {
		t.Fatalf("expected mihomo validation, got calls:\n%s", joined)
	}
	if !reloaded {
		t.Fatalf("expected mihomo hot-reload to be invoked, got calls:\n%s", joined)
	}
	for _, unexpected := range []string{"/etc/init.d/mihomo restart", "nft -c", "nft -f", "/etc/init.d/dnsmasq restart", "/etc/init.d/mwan3 reload", "uci -m -f"} {
		if strings.Contains(joined, unexpected) {
			t.Fatalf("did not expect %q for mihomo hot-reload apply, got calls:\n%s", unexpected, joined)
		}
	}
}

// Controller unreachable (mihomo down, or external-controller/secret changed):
// fall back to a cold restart.
func TestApplyMihomoFallsBackToRestartWhenControllerDown(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	r := &fakeRunner{}
	m := Manager{
		mihomoReachable: func(config.Config) bool { return false },
		mihomoReload:    func(config.Config) error { t.Fatal("reload must not run when controller unreachable"); return nil },
	}
	gen := generator.GenerationResult{DirtyGroups: generator.GenerationGroups{Mihomo: true}, Reason: "test mihomo down"}
	if err := m.applyWithRunnerPaths(c, backup, staged, live, gen, r); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if joined := strings.Join(r.calls, "\n"); !strings.Contains(joined, "/etc/init.d/mihomo restart") {
		t.Fatalf("expected cold restart when controller unreachable, got calls:\n%s", joined)
	}
}

// Reachable but the hot reload errors: fall back to a cold restart.
func TestApplyMihomoFallsBackToRestartWhenReloadErrors(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	r := &fakeRunner{}
	m := Manager{
		mihomoReachable: func(config.Config) bool { return true },
		mihomoReload:    func(config.Config) error { return errors.New("reload boom") },
	}
	gen := generator.GenerationResult{DirtyGroups: generator.GenerationGroups{Mihomo: true}, Reason: "test reload err"}
	if err := m.applyWithRunnerPaths(c, backup, staged, live, gen, r); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if joined := strings.Join(r.calls, "\n"); !strings.Contains(joined, "/etc/init.d/mihomo restart") {
		t.Fatalf("expected restart fallback on reload error, got calls:\n%s", joined)
	}
}

// On an nft reload the atomic table replace wipes the dynamic dns_* sets;
// apply must snapshot their members first and re-inject them after, so
// cached-client domains keep routing. A set whose section doesn't exist in the
// new config is never queried or restored.
func TestApplyPreservesDynamicDNSSetMembers(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	r := &fakeRunner{respond: func(call string) (string, bool) {
		if strings.Contains(call, "list set inet purewrt dns_bypass4") {
			return "set dns_bypass4 {\n  type ipv4_addr\n  elements = { 1.2.3.4 expires 2h29m, 5.6.7.8 }\n}", true
		}
		// a set for a section that does not exist in the new config — must never
		// be queried (so this canned output is unreachable) nor restored.
		if strings.Contains(call, "dns_proxy_ghost4") {
			return "set x {\n  elements = { 9.9.9.9 }\n}", true
		}
		return "", false
	}}
	gen := generator.GenerationResult{DirtyGroups: generator.GenerationGroups{OpenWrtBundle: true}, Reason: "test dns-set preserve"}
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, gen, r); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "nft add element inet purewrt dns_bypass4 { 1.2.3.4, 5.6.7.8 }") {
		t.Fatalf("expected dns_bypass4 members restored, got:\n%s", joined)
	}
	if strings.Contains(joined, "dns_proxy_ghost4") {
		t.Fatalf("must not query/restore a non-existent section's set, got:\n%s", joined)
	}
	// Sets that returned no elements (default "ok") must not produce add-element calls.
	if strings.Contains(joined, "nft add element inet purewrt dns_direct4") {
		t.Fatalf("empty set must not be restored, got:\n%s", joined)
	}
}

func TestParseNFTSetElements(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"set s {\n type ipv4_addr\n elements = { 1.2.3.4 expires 2h29m, 5.6.7.8 }\n}", []string{"1.2.3.4", "5.6.7.8"}},
		{"set s {\n type ipv6_addr\n elements = { 2001:db8::1 }\n}", []string{"2001:db8::1"}},
		{"set s {\n type ipv4_addr\n}", nil}, // empty set, no elements block
		{"ok", nil},
	}
	for i, tc := range cases {
		got := parseNFTSetElements(tc.in)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("case %d: got %v want %v", i, got, tc.want)
		}
	}
}

func TestApplyOpenWrtBundleChangeReloadsNFTAndDNSMasqOnly(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	r := &fakeRunner{}
	gen := generator.GenerationResult{DirtyGroups: generator.GenerationGroups{OpenWrtBundle: true}, Reason: "test openwrt bundle"}
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, gen, r); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	for _, expected := range []string{"nft -c -f " + staged.NFTFile, "nft -f " + live.NFTFile, "nft -f " + live.NFTSetsFile, "/etc/init.d/dnsmasq restart"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected %q, got calls:\n%s", expected, joined)
		}
	}
	for _, unexpected := range []string{"mihomo -t", "/etc/init.d/mihomo restart", "/etc/init.d/mwan3 reload", "uci -m -f"} {
		if strings.Contains(joined, unexpected) {
			t.Fatalf("did not expect %q for openwrt bundle apply, got calls:\n%s", unexpected, joined)
		}
	}
}

func TestApplyFirewallOnlyChangeReloadsFirewallOnly(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	c.DNS.HijackLANDNS = true
	live := applyTestLivePaths(dir)
	r := &fakeRunner{}
	gen := generator.GenerationResult{DirtyGroups: generator.GenerationGroups{Firewall: true}, Reason: "test firewall only"}
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, gen, r); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	for _, expected := range []string{"uci show firewall", "uci -m -f " + live.FirewallFile + " import firewall", "uci commit firewall", "/etc/init.d/firewall reload"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected %q, got calls:\n%s", expected, joined)
		}
	}
	for _, unexpected := range []string{"mihomo -t", "nft -c", "nft -f", "/etc/init.d/dnsmasq restart", "/etc/init.d/mihomo restart", "/etc/init.d/mwan3 reload"} {
		if strings.Contains(joined, unexpected) {
			t.Fatalf("did not expect %q for firewall-only apply, got calls:\n%s", unexpected, joined)
		}
	}
}

func TestApplyNoDirtyGroupsSkipsCommands(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	r := &fakeRunner{}
	gen := generator.GenerationResult{DirtyGroups: generator.GenerationGroups{}, Reason: "all groups unchanged"}
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, gen, r); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("expected no commands for cache-hit apply, got calls:\n%s", strings.Join(r.calls, "\n"))
	}
}

func TestApplyBackupUsesTempAndSkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	c, _, _ := applyTestConfig(t, dir)
	c.Settings.ResourceProfile = "low"
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	paths := generator.DefaultGeneratedPaths(c)
	if err := os.MkdirAll(filepath.Dir(paths.NFTFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.DNSMasqFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.NFTFile, []byte("small nft"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.DNSMasqFile, []byte(strings.Repeat("x", 129*1024)), 0600); err != nil {
		t.Fatal(err)
	}
	backup, cleanup, err := (Manager{}).applyBackup(c)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, ok := backup[paths.NFTFile]; !ok {
		t.Fatalf("small nft file should be backed up: %+v", backup)
	}
	if _, ok := backup[paths.DNSMasqFile]; ok {
		t.Fatalf("large dnsmasq file should be skipped: %+v", backup)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(paths.NFTFile), "purewrt.nft.*.bak"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("apply backup must not create persistent generated backups: %#v", matches)
	}
}

func TestApplyBackupMaxBytesUsesExplicitConfig(t *testing.T) {
	c := config.Default()
	c.Settings.ResourceProfile = "low"
	c.Settings.ApplyBackupMaxBytes = 42
	if got := applyBackupMaxBytes(c); got != 42 {
		t.Fatalf("explicit apply backup max bytes not used: got %d", got)
	}
}

func TestApplyStagedGenerateForceMarksAllGroupsDirty(t *testing.T) {
	dir := t.TempDir()
	c, _, _ := applyTestConfig(t, dir)
	c.Settings.LANSourceZones = nil // DefaultGeneratedPaths writes firewall to real /etc/config; opt out
	if err := generator.WriteAllToWithOptions(c, generator.DefaultGeneratedPaths(c), generator.WriteOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	_, gen, cleanup, err := (Manager{}).applyStagedGenerate(c, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	want := generator.GenerationGroups{}.All()
	if gen.DirtyGroups != want || gen.Reason != "forced" {
		t.Fatalf("forced apply should regenerate all groups, got groups=%+v reason=%q", gen.DirtyGroups, gen.Reason)
	}
}

// The LuCI "config dirty" banner compares /etc/config/purewrt's mtime
// against <RuntimeDir>/.last_applied. Only the rpcd wrapper used to write
// the marker, so CLI-side applies (cron update-if-needed) left the banner
// stuck on "unapplied changes". Every successful apply — including the
// no-dirty-groups short-circuit — must refresh the marker; failures and
// dry runs must not.
func TestApplySuccessTouchesLastAppliedMarker(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	before := time.Now().Add(-time.Second)
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, &fakeRunner{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(c.RuntimeDir(), ".last_applied"))
	if err != nil {
		t.Fatalf("expected .last_applied marker after successful apply: %v", err)
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(got)), 10, 64)
	if err != nil {
		t.Fatalf("marker must hold unix seconds (rpcd config_state does shell -gt on it), got %q: %v", got, err)
	}
	if ts < before.Unix() || ts > time.Now().Unix() {
		t.Fatalf("marker timestamp %d outside test window", ts)
	}
}

func TestApplyNoDirtyGroupsStillTouchesLastAppliedMarker(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	gen := generator.GenerationResult{Reason: "fingerprint match"}
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, gen, &fakeRunner{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.RuntimeDir(), ".last_applied")); err != nil {
		t.Fatalf("no-op apply leaves config in applied state, marker must refresh: %v", err)
	}
}

func TestApplyFailureDoesNotTouchLastAppliedMarker(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	r := &fakeRunner{failContains: "mihomo -t"}
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, r); err == nil {
		t.Fatal("expected apply failure")
	}
	if _, err := os.Stat(filepath.Join(c.RuntimeDir(), ".last_applied")); !os.IsNotExist(err) {
		t.Fatalf("failed apply must not refresh marker, stat err=%v", err)
	}
}

func TestApplyDryRunDoesNotTouchLastAppliedMarker(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	if err := (Manager{DryRun: true}).applyWithRunnerPaths(c, backup, staged, live, &fakeRunner{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.RuntimeDir(), ".last_applied")); !os.IsNotExist(err) {
		t.Fatalf("dry-run apply must not refresh marker, stat err=%v", err)
	}
}

func applyTestConfig(t *testing.T, dir string) (config.Config, generator.GeneratedPaths, system.BackupSet) {
	t.Helper()
	c := config.Default()
	c.Settings.MihomoBin = "mihomo"
	c.Settings.MihomoConfig = filepath.Join(dir, "configured", "mihomo.yaml")
	c.Settings.GeneratedDir = filepath.Join(dir, "generated")
	c.Settings.DNSMasqIncludeDir = filepath.Join(dir, "dnsmasq.d")
	c.DNS.HijackLANDNS = false
	c.DNS.Enabled = false
	c.Settings.RollbackOnFail = true
	c.Settings.RuntimeDir = filepath.Join(dir, "run")
	stage := filepath.Join(dir, "stage")
	staged := generator.StagedGeneratedPaths(c, stage)
	if err := generator.WriteAllTo(c, staged); err != nil {
		t.Fatal(err)
	}
	return c, staged, system.BackupSet{}
}

func applyTestLivePaths(dir string) generator.GeneratedPaths {
	return generator.GeneratedPaths{
		MihomoConfig:       filepath.Join(dir, "live", "mihomo.yaml"),
		DNSMasqFile:        filepath.Join(dir, "live", "purewrt.conf"),
		DNSMasqFragmentDir: filepath.Join(dir, "live", "dnsmasq.d"),
		NFTFile:            filepath.Join(dir, "live", "purewrt.nft"),
		NFTSetsFile:        filepath.Join(dir, "live", "purewrt-sets.nft"),
		FirewallFile:       filepath.Join(dir, "live", "firewall.generated"),
		Mwan3File:          filepath.Join(dir, "live", "mwan3.generated"),
		ZapretEnv:          filepath.Join(dir, "live", "zapret.env"),
	}
}
