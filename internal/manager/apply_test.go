package manager

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/system"
)

type fakeRunner struct {
	failContains string
	calls        []string
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.failContains != "" && strings.Contains(call, f.failContains) {
		return "forced failure", errors.New("forced failure")
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

func TestApplyMihomoOnlyChangeRestartsOnlyMihomo(t *testing.T) {
	dir := t.TempDir()
	c, staged, backup := applyTestConfig(t, dir)
	live := applyTestLivePaths(dir)
	r := &fakeRunner{}
	gen := generator.GenerationResult{DirtyGroups: generator.GenerationGroups{Mihomo: true}, Reason: "test mihomo only"}
	if err := (Manager{}).applyWithRunnerPaths(c, backup, staged, live, gen, r); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "mihomo -t") || !strings.Contains(joined, "/etc/init.d/mihomo restart") {
		t.Fatalf("expected mihomo validation and restart, got calls:\n%s", joined)
	}
	for _, unexpected := range []string{"nft -c", "nft -f", "/etc/init.d/dnsmasq restart", "/etc/init.d/mwan3 reload", "uci -m -f"} {
		if strings.Contains(joined, unexpected) {
			t.Fatalf("did not expect %q for mihomo-only apply, got calls:\n%s", unexpected, joined)
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
	for _, expected := range []string{"uci -q delete firewall.purewrt_dns_hijack_udp", "uci -q delete firewall.purewrt_dns_hijack_tcp", "uci -m -f " + live.FirewallFile + " import firewall", "uci commit firewall", "/etc/init.d/firewall reload"} {
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
