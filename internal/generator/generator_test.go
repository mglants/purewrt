package generator

import (
	"bytes"
	"os"
	"path/filepath"

	"strings"
	"testing"

	"github.com/purewrt/purewrt/internal/config"
)

func TestNFTPreservesMarks(t *testing.T) {
	out := string(NFTables(config.Default()))
	if !strings.Contains(out, "meta mark set meta mark | 0x1") {
		t.Fatal("nft must preserve mark bits with OR")
	}
	if !strings.Contains(out, "tproxy ip to :") || !strings.Contains(out, "tproxy ip6 to :") {
		t.Fatal("nft tproxy rules must specify ip/ip6 family")
	}
	if strings.Contains(out, " tproxy to :") {
		t.Fatal("nft tproxy rules must not omit family")
	}
}

func TestNFTBlocksEncryptedDNSWhenEnabled(t *testing.T) {
	c := config.Default()
	out := string(NFTables(c))
	if !strings.Contains(out, "tcp dport 853 reject") {
		t.Fatal("DoT block must emit tcp/853 reject")
	}
	if !strings.Contains(out, "udp dport 853 reject") {
		t.Fatal("DoQ block must emit udp/853 reject")
	}
	if !strings.Contains(out, "udp dport 443 reject") {
		t.Fatal("DoH3 block must emit udp/443 reject for known DoH3 IPs")
	}
	if !strings.Contains(out, "1.1.1.1") {
		t.Fatal("DoH3 block must include the well-known DoH3 IP list")
	}
}

func TestNFTAllowsEncryptedDNSWhenDisabled(t *testing.T) {
	c := config.Default()
	c.DNS.BlockDoT = false
	c.DNS.BlockDoQ = false
	c.DNS.BlockDoH3 = false
	out := string(NFTables(c))
	if strings.Contains(out, "tcp dport 853") || strings.Contains(out, "udp dport 853") {
		t.Fatal("DoT/DoQ rejects must not appear when block_* options disabled")
	}
	if strings.Contains(out, "udp dport 443 reject") {
		t.Fatal("DoH3 reject must not appear when block_doh3 disabled")
	}
}

func TestIPv6ModeForcesOnEvenInLowResource(t *testing.T) {
	c := config.Default()
	c.Settings.ResourceProfile = "low"
	c.Settings.IPv6Mode = "on"
	out := string(NFTables(c))
	if !strings.Contains(out, "ip6 daddr") {
		t.Fatal("IPv6Mode=on must emit ip6 rules even with low resource profile")
	}
}

func TestIPv6ModeOffSuppressesV6Rules(t *testing.T) {
	c := config.Default()
	c.Settings.IPv6Mode = "off"
	out := string(NFTables(c))
	if strings.Contains(out, "ip6 daddr @proxy_") {
		t.Fatal("IPv6Mode=off must suppress section v6 rules")
	}
}

// TestNFTCountersAreEmittedForEverySet — sanity check that every set we
// declare also gets a named counter, AND that every rule that matches
// @<set> increments that set's counter. Without both, the Statistics page
// would silently report zero hits for the missing pair.
func TestNFTCountersAreEmittedForEverySet(t *testing.T) {
	c := config.Default()
	out := string(NFTables(c))
	// Declarations: each `set <name>` must be followed (somewhere in the
	// same table block) by a `counter <name>` of the same name.
	for _, want := range []string{
		"counter bypass4 {",
		"counter dns_bypass4 {",
		"counter proxy_common4 {",
		"counter dns_proxy_common4 {",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing counter declaration %q in:\n%s", want, out)
		}
	}
	// Every @<set> rule should include a `counter name "<set>"` reference.
	// Walk every line that contains "daddr @" and assert the counter is
	// present on that same line.
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, "daddr @")
		if idx < 0 {
			continue
		}
		// Extract the set name between "@" and the next space.
		rest := line[idx+len("daddr @"):]
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			continue
		}
		set := rest[:end]
		want := `counter name "` + set + `"`
		if !strings.Contains(line, want) {
			t.Fatalf("rule references @%s but is missing %q:\n  %s", set, want, line)
		}
	}
}

func TestNFTAtomicReplacePrologue(t *testing.T) {
	// The generated nft file must atomically delete-and-readd the table so
	// rule-shape changes (e.g., tightened prerouting guards, new chains)
	// actually replace the running ruleset on the next `nft -f` rather
	// than no-op-ing because nft would otherwise merge into the existing
	// table. The three lines must run in order — `add` ensures `delete`
	// has something to remove, `delete` clears it, then the full
	// `table { ... }` block follows.
	out := string(NFTables(config.Default()))
	idxAdd := strings.Index(out, "add table inet purewrt")
	idxDel := strings.Index(out, "delete table inet purewrt")
	idxTable := strings.Index(out, "table inet purewrt {")
	if idxAdd < 0 || idxDel < 0 || idxTable < 0 {
		t.Fatalf("atomic-replace prologue missing (add=%d delete=%d table=%d):\n%s", idxAdd, idxDel, idxTable, out[:min(400, len(out))])
	}
	if !(idxAdd < idxDel && idxDel < idxTable) {
		t.Fatalf("prologue order must be add → delete → table; got add=%d delete=%d table=%d", idxAdd, idxDel, idxTable)
	}
}

func TestNFTPreroutingLoopBreakerTightened(t *testing.T) {
	// The two top-of-PREROUTING guards must allow re-injected packets
	// (iifname=lo + our mark + non-local daddr) to fall through to the
	// section dispatch, while still skipping true router-self-loopback
	// and externally-marked traffic.
	out := string(NFTables(config.Default()))
	if !strings.Contains(out, `iifname "lo" fib daddr type local return`) {
		t.Fatalf("PREROUTING lo guard must be qualified with fib daddr type local; got:\n%s", out)
	}
	if !strings.Contains(out, `iifname != "lo" meta mark & 0xff == 0x1 return`) {
		t.Fatalf("PREROUTING mark guard must be qualified with iifname != lo; got:\n%s", out)
	}
	if strings.Contains(out, `iifname "lo" return`) {
		t.Fatal("PREROUTING must no longer emit unconditional iifname lo return — it'd block re-injected OUTPUT marks")
	}
}

func TestNFTRouterOutputProxyDefaultOn(t *testing.T) {
	// RouterOutputProxy now defaults on, so the OUTPUT chain is present.
	out := string(NFTables(config.Default()))
	if !strings.Contains(out, "chain output_mangle") {
		t.Fatal("output_mangle chain must appear with RouterOutputProxy=true (default)")
	}
	// ...and absent when explicitly disabled.
	c := config.Default()
	c.Settings.RouterOutputProxy = false
	if strings.Contains(string(NFTables(c)), "chain output_mangle") {
		t.Fatal("output_mangle chain must not appear with RouterOutputProxy=false")
	}
}

func TestNFTOONIExemption(t *testing.T) {
	// Enabled + resolved uid ⇒ skuid exemption in the OUTPUT chain.
	c := config.Default()
	c.OONI.Enabled = true
	c.OONI.UID = 8377
	out := string(NFTables(c))
	if !strings.Contains(out, "meta skuid 8377 return") {
		t.Fatalf("expected OONI skuid exemption, got:\n%s", out)
	}
	// Disabled ⇒ no exemption.
	c2 := config.Default()
	c2.OONI.Enabled = false
	c2.OONI.UID = 8377
	if strings.Contains(string(NFTables(c2)), "meta skuid") {
		t.Fatal("OONI exemption must not appear when disabled")
	}
	// Enabled but unresolved uid (0) ⇒ no exemption (don't break nft load).
	c3 := config.Default()
	c3.OONI.Enabled = true
	c3.OONI.UID = 0
	if strings.Contains(string(NFTables(c3)), "meta skuid") {
		t.Fatal("OONI exemption must not appear when uid unresolved")
	}
}

func TestNFTRouterOutputProxyEmitsChain(t *testing.T) {
	c := config.Default()
	c.Settings.RouterOutputProxy = true
	out := string(NFTables(c))
	for _, want := range []string{
		"chain output_mangle {",
		"type route hook output priority mangle",
		`socket cgroupv2 level 2 "services/mihomo" return`,
		"meta mark & 0x40000000 != 0 return",
		"fib daddr type { local, broadcast, anycast, multicast } return",
		"ct direction reply return",
		"meta l4proto != { tcp, udp } return",
		`ip daddr @bypass4 counter name "bypass4" return`,
		`ip daddr @proxy_server_bypass4 counter name "proxy_server_bypass4" return`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output_mangle missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "meta cgroup ") {
		t.Fatalf("cgroupv1 `meta cgroup` should no longer be emitted; got:\n%s", out)
	}
}

func TestNFTCgroupV2PathLevelAutoDerived(t *testing.T) {
	c := config.Default()
	c.Settings.RouterOutputProxy = true
	c.Settings.CgroupV2Path = "services/mihomo/instance1"
	out := string(NFTables(c))
	if !strings.Contains(out, `socket cgroupv2 level 3 "services/mihomo/instance1" return`) {
		t.Fatalf("expected level-3 match for 3-segment path; got:\n%s", out)
	}
}

func TestNFTRouterOutputProxyEmitsSectionMark(t *testing.T) {
	c := config.Default()
	c.Settings.RouterOutputProxy = true
	out := string(NFTables(c))
	// Default config has a "common" proxy section. In OUTPUT we mark but never
	// `tproxy` (PREROUTING does that on the re-injected packet).
	if !strings.Contains(out, `ip daddr @proxy_common4 meta l4proto tcp meta mark set meta mark | 0x1 counter name "proxy_common4" accept`) {
		t.Fatalf("proxy section must mark+accept (no tproxy) in OUTPUT; got:\n%s", out)
	}
	// Make sure the OUTPUT chain doesn't accidentally carry tproxy actions.
	if strings.Contains(extractOutputChain(out), "tproxy ") {
		t.Fatalf("output_mangle must not contain tproxy action; got chain:\n%s", extractOutputChain(out))
	}
}

func TestNFTRouterOutputProxyZapretSectionReturns(t *testing.T) {
	c := config.Default()
	c.Settings.RouterOutputProxy = true
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, FwMark: "0x40000000", QueueNum: 200}}
	c.ZapretStrategies = []config.ZapretStrategy{{Name: "quic", Enabled: true, Profile: "wan", Protocols: []string{"udp"}, UDPPorts: "443"}}
	c.Sections = append(c.Sections, config.Section{
		Name: "zap", Enabled: true, Action: "zapret", TPROXYPort: 7895,
		ZapretStrategies: []string{"quic"},
	})
	out := string(NFTables(c))
	chain := extractOutputChain(out)
	// Zapret claims only its strategy-covered ports in OUTPUT; other ports
	// fall through to the proxy mark rules (port-scoped claims design).
	if !strings.Contains(chain, `ip daddr @proxy_zap4 meta l4proto udp udp dport { 443 } counter name "proxy_zap4" return`) {
		t.Fatalf("zapret section must emit a port-scoped `return` in OUTPUT; got:\n%s", chain)
	}
	if strings.Contains(chain, "@proxy_zap4 meta mark set") {
		t.Fatalf("zapret section must not mark in OUTPUT; got:\n%s", chain)
	}
}

func TestNFTRouterOutputProxyRejectSectionRejects(t *testing.T) {
	c := config.Default()
	c.Settings.RouterOutputProxy = true
	c.Sections = append(c.Sections, config.Section{
		Name: "blk", Enabled: true, Action: "reject",
	})
	out := string(NFTables(c))
	chain := extractOutputChain(out)
	if !strings.Contains(chain, `ip daddr @reject4 counter name "reject4" reject`) {
		t.Fatalf("reject section must reject in OUTPUT; got:\n%s", chain)
	}
}

// extractOutputChain isolates the body of `chain output_mangle { ... }`
// from a full nft ruleset so per-chain assertions don't pick up unrelated
// PREROUTING text.
func extractOutputChain(nft string) string {
	const marker = "chain output_mangle {"
	i := strings.Index(nft, marker)
	if i < 0 {
		return ""
	}
	rest := nft[i+len(marker):]
	if j := strings.Index(rest, "\n  }"); j >= 0 {
		return rest[:j]
	}
	return rest
}

func TestIPv6RejectWhenOffEmitsBlanketReject(t *testing.T) {
	c := config.Default()
	c.Settings.IPv6Mode = "off"
	c.Settings.IPv6RejectWhenOff = true
	out := string(NFTables(c))
	if !strings.Contains(out, "ip6 daddr ::/0 reject") {
		t.Fatal("expected blanket v6 reject when IPv6Mode=off + IPv6RejectWhenOff=true")
	}
}

func TestMihomoAllowLANBinding(t *testing.T) {
	// Default: allow-lan false → mixed-port binds loopback only, so a LAN
	// scan can't detect/use the router as an open proxy.
	if out := string(Mihomo(config.Default())); !strings.Contains(out, "allow-lan: false") {
		t.Fatalf("default must bind mixed-port to loopback (allow-lan: false):\n%s", out)
	}
	c := config.Default()
	c.Settings.MihomoAllowLAN = true
	if out := string(Mihomo(c)); !strings.Contains(out, "allow-lan: true") {
		t.Fatalf("MihomoAllowLAN=true must emit allow-lan: true:\n%s", out)
	}
}

func TestMihomoCatchAllFallsToDirectWithoutCommon(t *testing.T) {
	// Default has a common/Common section → catch-all targets Common.
	if out := string(Mihomo(config.Default())); !strings.Contains(out, "  - MATCH,Common\n") {
		t.Fatalf("default catch-all must be MATCH,Common:\n%s", out)
	}
	// Remove the Common group (delete the common section) → catch-all must
	// degrade to DIRECT, never dangle on a non-existent Common group.
	c := config.Default()
	kept := c.Sections[:0]
	for _, s := range c.Sections {
		if s.ProxyGroup != "Common" {
			kept = append(kept, s)
		}
	}
	c.Sections = kept
	out := string(Mihomo(c))
	if !strings.Contains(out, "  - MATCH,DIRECT\n") {
		t.Fatalf("catch-all must fall to MATCH,DIRECT when no Common group:\n%s", out)
	}
	if strings.Contains(out, "MATCH,Common") {
		t.Fatalf("must not emit MATCH,Common when the Common group is absent:\n%s", out)
	}
	if strings.Contains(out, "name: Common\n") {
		t.Fatalf("no Common proxy group should be emitted:\n%s", out)
	}
}

func TestMihomoNetCheckProbePath(t *testing.T) {
	// Default config has proxy sections → the net-check probe path is emitted:
	// a loopback `mixed` listener, the NetCheckProbe select group, and the
	// IN-NAME rule routing the listener to that group.
	out := string(Mihomo(config.Default()))
	for _, want := range []string{
		"- name: netcheck-probe\n    type: mixed\n    port: 7899\n    listen: 127.0.0.1\n",
		"- name: NetCheckProbe\n    type: select\n",
		"  - IN-NAME,netcheck-probe,NetCheckProbe\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing net-check probe element %q in:\n%s", want, out)
		}
	}

	// No proxy section → no probe path (zapret-only / direct box).
	c := config.Default()
	for i := range c.Sections {
		c.Sections[i].Action = "direct"
	}
	out = string(Mihomo(c))
	if strings.Contains(out, "netcheck-probe") || strings.Contains(out, "NetCheckProbe") {
		t.Fatalf("probe path must be absent when no proxy section is enabled:\n%s", out)
	}
}

func TestMihomoDashboardEnabledByDefault(t *testing.T) {
	out := string(Mihomo(config.Default()))
	for _, want := range []string{
		"external-controller: 0.0.0.0:9090",
		"external-ui: /etc/purewrt/dashboard",
		"external-ui-url: \"https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip\"",
		"external-ui-name: metacubexd",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("dashboard must be enabled by default; missing %q in:\n%s", want, out)
		}
	}
}

func TestWriteAllDoesNotInjectDemoFallbackRules(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	paths := GeneratedPaths{
		MihomoConfig:       filepath.Join(dir, "mihomo.yaml"),
		DNSMasqFile:        filepath.Join(dir, "purewrt.conf"),
		DNSMasqFragmentDir: dir,
		NFTFile:            filepath.Join(dir, "purewrt.nft"),
		NFTSetsFile:        filepath.Join(dir, "purewrt-sets.nft"),
		FirewallFile:       filepath.Join(dir, "firewall.generated"),
		Mwan3File:          filepath.Join(dir, "mwan3.generated"),
		ZapretEnv:          filepath.Join(dir, "zapret.env"),
	}
	if err := WriteAllTo(c, paths); err != nil {
		t.Fatal(err)
	}
	fragments, err := filepath.Glob(filepath.Join(paths.DNSMasqFragmentDir, "purewrt-*.dnsmasq"))
	if err != nil {
		t.Fatal(err)
	}
	var dnsmasq []byte
	for _, path := range fragments {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		dnsmasq = append(dnsmasq, data...)
	}
	for _, bad := range []string{"youtube.com", "googlevideo.com", "chatgpt.com", "openai.com"} {
		if strings.Contains(string(dnsmasq), bad) {
			t.Fatalf("demo fallback rule %q must not be generated:\n%s", bad, dnsmasq)
		}
	}
}

func TestWriteAllWritesRuntimeDNSMasqSnippetDirectly(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	paths := GeneratedPaths{
		MihomoConfig:       filepath.Join(dir, "mihomo.yaml"),
		DNSMasqFile:        filepath.Join(dir, "runtime", "purewrt.conf"),
		DNSMasqFragmentDir: filepath.Join(dir, "dnsmasq.d"),
		NFTFile:            filepath.Join(dir, "purewrt.nft"),
		NFTSetsFile:        filepath.Join(dir, "purewrt-sets.nft"),
		FirewallFile:       filepath.Join(dir, "firewall.generated"),
		Mwan3File:          filepath.Join(dir, "mwan3.generated"),
		ZapretEnv:          filepath.Join(dir, "zapret.env"),
	}
	if err := WriteAllTo(c, paths); err != nil {
		t.Fatal(err)
	}
	fragments, err := filepath.Glob(filepath.Join(paths.DNSMasqFragmentDir, "purewrt-*.dnsmasq"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) != 0 {
		for _, path := range fragments {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("conf-file=")) {
				t.Fatalf("runtime fragments must contain direct dnsmasq rules, not conf-file wrapper:\n%s", data)
			}
		}
	}
	if _, err := os.Stat(paths.DNSMasqFile); !os.IsNotExist(err) {
		t.Fatalf("legacy runtime dnsmasq file should not be written for direct snippet mode, err=%v", err)
	}
}

func TestDNSMasqFragmentPathUsesSectionPriority(t *testing.T) {
	dir := t.TempDir()
	if got := filepath.Base(DNSMasqFragmentPath(dir, config.Section{Name: "direct"})); got != "purewrt-000001-direct.dnsmasq" {
		t.Fatalf("unexpected direct fragment name: %s", got)
	}
	if got := filepath.Base(DNSMasqFragmentPath(dir, config.Section{Name: "reject"})); got != "purewrt-000002-reject.dnsmasq" {
		t.Fatalf("unexpected reject fragment name: %s", got)
	}
	if got := filepath.Base(DNSMasqFragmentPath(dir, config.Section{Name: "Messengers", Priority: 100})); got != "purewrt-000100-messengers.dnsmasq" {
		t.Fatalf("unexpected custom fragment name: %s", got)
	}
}

func TestWriteDNSMasqFragmentsRemovesStaleFragments(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "purewrt-000999-stale.dnsmasq")
	if err := os.WriteFile(stale, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	fragments := map[string]*bytes.Buffer{"media": bytes.NewBufferString("nftset=/youtube.com/4#inet#purewrt#media4\n")}
	changed, err := WriteDNSMasqFragments(c, GeneratedPaths{DNSMasqFragmentDir: dir}, fragments)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected fragment write/removal to report changed")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale fragment should be removed, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "purewrt-000010-media.dnsmasq")); err != nil {
		t.Fatalf("expected media fragment to be written: %v", err)
	}
}

func TestStagedGeneratedPathsPromoteToLive(t *testing.T) {
	dir := t.TempDir()
	stage := filepath.Join(dir, "stage")
	c := config.Default()
	live := GeneratedPaths{
		MihomoConfig:       filepath.Join(dir, "live", "mihomo.yaml"),
		DNSMasqFile:        filepath.Join(dir, "live", "purewrt.conf"),
		DNSMasqFragmentDir: filepath.Join(dir, "live", "dnsmasq.d"),
		NFTFile:            filepath.Join(dir, "live", "purewrt.nft"),
		NFTSetsFile:        filepath.Join(dir, "live", "purewrt-sets.nft"),
		FirewallFile:       filepath.Join(dir, "live", "firewall.generated"),
		Mwan3File:          filepath.Join(dir, "live", "mwan3.generated"),
		ZapretEnv:          filepath.Join(dir, "live", "zapret.env"),
	}
	c.Settings.MihomoConfig = live.MihomoConfig
	c.Settings.GeneratedDir = filepath.Join(dir, "live")
	staged := StagedGeneratedPaths(c, stage)
	if filepath.Dir(staged.MihomoConfig) != stage || staged.MihomoConfig == live.MihomoConfig {
		t.Fatalf("staged mihomo path must be under stage dir: %#v", staged)
	}
	if err := WriteAllTo(c, staged); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live.MihomoConfig); !os.IsNotExist(err) {
		t.Fatalf("live path should not exist before promotion, err=%v", err)
	}
	if err := PromoteGeneratedPaths(staged, live); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{live.MihomoConfig, live.NFTFile, live.NFTSetsFile, live.ZapretEnv} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("expected promoted file %s: %v", path, err)
		}
		if len(data) == 0 {
			t.Fatalf("promoted file %s is empty", path)
		}
	}
	if info, err := os.Stat(live.DNSMasqFragmentDir); err != nil || !info.IsDir() {
		t.Fatalf("expected promoted dnsmasq fragment dir, err=%v", err)
	}
}

func TestDefaultGeneratedPathsUseHybridPersistentAndRuntimeFiles(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.GeneratedDir = ""
	c.Settings.MihomoConfig = ""

	paths := DefaultGeneratedPaths(c)
	if paths.MihomoConfig != config.DefaultMihomoConfig {
		t.Fatalf("mihomo config should default to persistent path, got %q", paths.MihomoConfig)
	}
	runtimeGeneratedDir := filepath.Join(c.Settings.RuntimeDir, "generated")
	for _, path := range []string{paths.DNSMasqFile, paths.NFTSetsFile} {
		if filepath.Dir(path) != runtimeGeneratedDir {
			t.Fatalf("large runtime generated file %q should be under %q", path, runtimeGeneratedDir)
		}
	}
	persistentGeneratedDir := filepath.Dir(config.DefaultMihomoConfig)
	for _, path := range []string{paths.NFTFile, paths.ZapretEnv} {
		if filepath.Dir(path) != persistentGeneratedDir {
			t.Fatalf("small persistent generated file %q should be under %q", path, persistentGeneratedDir)
		}
	}
	// Fingerprint deliberately lives under RuntimeDir (tmpfs by default) so
	// it's wiped on reboot — that drops the "all groups unchanged" cache and
	// forces the post-boot apply to actually reload nftables instead of
	// short-circuiting because kernel state and on-disk fingerprint disagree.
	if filepath.Dir(fingerprintPath(c)) != runtimeGeneratedDir {
		t.Fatalf("fingerprint %q should live under runtime generated dir %q", fingerprintPath(c), runtimeGeneratedDir)
	}
}

func TestGeneratedFingerprintSkipRequiresRuntimeFiles(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.GeneratedDir = ""
	c.Settings.MihomoConfig = filepath.Join(dir, "persistent", "mihomo.yaml")
	c.Settings.DNSMasqIncludeDir = filepath.Join(dir, "dnsmasq.d")
	c.DNS.HijackLANDNS = false
	c.Settings.LANSourceZones = nil // no PureWRT firewall write to /etc/config in this test
	c.Mwan3.IntegratedRules = false

	if err := WriteAll(c); err != nil {
		t.Fatal(err)
	}
	paths := DefaultGeneratedPaths(c)
	if !generatedPathsComplete(c, paths) {
		t.Fatal("generated paths should be complete after WriteAll")
	}
	if err := os.RemoveAll(dnsmasqFragmentDir(paths)); err != nil {
		t.Fatal(err)
	}
	if generatedPathsComplete(c, paths) {
		t.Fatal("missing runtime DNSMasq fragment dir must disable fingerprint skip")
	}
	if err := WriteAll(c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dnsmasqFragmentDir(paths)); err != nil {
		t.Fatalf("missing runtime DNSMasq fragment dir should be regenerated despite unchanged fingerprint: %v", err)
	}
}

func TestGenerationCacheStatusAndForce(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.GeneratedDir = filepath.Join(dir, "generated")
	c.Settings.MihomoConfig = filepath.Join(dir, "generated", "mihomo.yaml")
	c.Settings.DNSMasqIncludeDir = filepath.Join(dir, "dnsmasq.d")
	c.DNS.HijackLANDNS = false
	c.Settings.LANSourceZones = nil // no PureWRT firewall write to /etc/config in this test
	c.Mwan3.IntegratedRules = false

	if status := CacheStatus(c); !strings.Contains(status, "generation cache: miss") || !strings.Contains(status, "fingerprint missing") {
		t.Fatalf("expected initial cache miss, got:\n%s", status)
	}
	if status := CacheStatus(c); !strings.Contains(status, "  mihomo: miss reason=fingerprint missing") || !strings.Contains(status, "  openwrt_bundle: miss reason=fingerprint missing") {
		t.Fatalf("expected per-group initial cache miss, got:\n%s", status)
	}
	if err := WriteAll(c); err != nil {
		t.Fatal(err)
	}
	if status := CacheStatus(c); !strings.Contains(status, "generation cache: hit") || !strings.Contains(status, "outputs complete: true") || !strings.Contains(status, "  mihomo: hit reason=unchanged") || !strings.Contains(status, "  openwrt_bundle: hit reason=unchanged") {
		t.Fatalf("expected cache hit after WriteAll, got:\n%s", status)
	}
	if err := os.Remove(DefaultGeneratedPaths(c).NFTSetsFile); err != nil {
		t.Fatal(err)
	}
	if status := CacheStatus(c); !strings.Contains(status, "generation cache: miss") || !strings.Contains(status, "  openwrt_bundle: miss reason=nft sets missing") || !strings.Contains(status, "  mihomo: hit reason=unchanged") {
		t.Fatalf("expected per-group output-missing cache miss, got:\n%s", status)
	}
	if err := WriteAll(c); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(c.Settings.MihomoConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteAllToWithOptions(c, DefaultGeneratedPaths(c), WriteOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(c.Settings.MihomoConfig)
	if err != nil {
		t.Fatal(err)
	}
	if after.ModTime().Before(before.ModTime()) {
		t.Fatalf("forced generation should not move output timestamp backwards: before=%v after=%v", before.ModTime(), after.ModTime())
	}
}

func TestWriteAllResultDetectsMihomoOnlyChange(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.GeneratedDir = filepath.Join(dir, "generated")
	c.Settings.MihomoConfig = filepath.Join(dir, "generated", "mihomo.yaml")
	c.Settings.DNSMasqIncludeDir = filepath.Join(dir, "dnsmasq.d")
	c.DNS.HijackLANDNS = false
	c.Settings.LANSourceZones = nil // no PureWRT firewall write to /etc/config in this test
	c.Mwan3.IntegratedRules = false
	paths := DefaultGeneratedPaths(c)
	if err := WriteAllToWithOptions(c, paths, WriteOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	c.Sections[0].ProxyStrategy = "round-robin"
	res, err := WriteAllToResult(c, paths, WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.DirtyGroups.Mihomo || res.DirtyGroups.OpenWrtBundle || res.DirtyGroups.Firewall || res.DirtyGroups.Mwan3 || res.DirtyGroups.Zapret || res.DirtyGroups.Policy {
		t.Fatalf("expected mihomo-only dirty group, got %+v reason=%s", res.DirtyGroups, res.Reason)
	}
}

func TestWriteAllResultForceMarksAllGroups(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Settings.RuntimeDir = filepath.Join(dir, "runtime")
	c.Settings.GeneratedDir = filepath.Join(dir, "generated")
	c.Settings.MihomoConfig = filepath.Join(dir, "generated", "mihomo.yaml")
	c.Settings.DNSMasqIncludeDir = filepath.Join(dir, "dnsmasq.d")
	c.DNS.HijackLANDNS = false
	c.Settings.LANSourceZones = nil // no PureWRT firewall write to /etc/config in this test
	c.Mwan3.IntegratedRules = false
	res, err := WriteAllToResult(c, DefaultGeneratedPaths(c), WriteOptions{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	want := GenerationGroups{}.All()
	if res.DirtyGroups != want {
		t.Fatalf("force should mark all groups dirty, got %+v want %+v", res.DirtyGroups, want)
	}
}

func TestMihomoDashboardEnabled(t *testing.T) {
	c := config.Default()
	c.Settings.DashboardEnabled = true
	out := string(Mihomo(c))
	for _, want := range []string{
		"external-controller: 0.0.0.0:9090",
		"external-ui: /etc/purewrt/dashboard",
		"external-ui-url: \"https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip\"",
		"external-ui-name: metacubexd",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestMihomoDNSIncludesUDPBootstrapFallbacks(t *testing.T) {
	out := string(Mihomo(config.Default()))
	for _, want := range []string{
		"proxy-server-nameserver:\n    - 1.1.1.1\n    - 8.8.8.8\n    - 9.9.9.9",
		"default-nameserver:\n    - 1.1.1.1\n    - 8.8.8.8\n    - 9.9.9.9",
		"fallback:\n    - 1.1.1.1\n    - 8.8.8.8\n    - 9.9.9.9",
		"nameserver:\n    - https://dns.google/dns-query",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing DNS bootstrap fallback %q in:\n%s", want, out)
		}
	}
}

func TestDNSMasqIsOnlyDNSSetGenerator(t *testing.T) {
	c := config.Default()
	c.DNS.Backend = "smartdns"
	out := renderDNSMasqForTest(t, c, map[string][]string{"media": {"youtube.com"}})
	if !strings.Contains(out, "nftset=/youtube.com/4#inet#purewrt#dns_proxy_media4") {
		t.Fatalf("dnsmasq nftset output must remain available regardless of legacy backend setting:\n%s", out)
	}
}

func TestMihomoExportsEnabledProxyProviders(t *testing.T) {
	c := config.Default()
	c.ProxyProviders = []config.ProxyProvider{
		{Name: "disabled", Enabled: false, Type: "http", URL: "https://example.com/disabled.yaml", Path: "/etc/purewrt/providers/disabled.yaml", Interval: 86400, HealthCheck: true, HealthCheckURL: "https://www.gstatic.com/generate_204", HealthCheckInterval: 300},
		{Name: "default_nodes", Enabled: true, Type: "file", Path: "/etc/purewrt/providers/default_nodes.yaml", HealthCheck: true, HealthCheckURL: "https://www.gstatic.com/generate_204", HealthCheckInterval: 300},
	}
	out := string(Mihomo(c))
	for _, want := range []string{
		"proxy-providers:\n  default_nodes:",
		"type: file",
		"path: /etc/purewrt/providers/default_nodes.yaml",
		"      - default_nodes",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	for _, bad := range []string{"  main:\n", "  disabled:\n", "url: \"\""} {
		if strings.Contains(out, bad) {
			t.Fatalf("unexpected %q in:\n%s", bad, out)
		}
	}
}

func TestLowResourceProfileReducesRuntimeConfig(t *testing.T) {
	c := config.Default()
	c.Settings.ResourceProfile = "low"
	c.Settings.MihomoGeodataEnabled = true
	// Dashboard is now an explicit user opt-in even on the low profile; the
	// default config has it enabled. Clear it here so this case tests the
	// "low + user-disabled-dashboard" path (the most common low-resource
	// recipe); a separate sibling test below covers the override case.
	c.Settings.DashboardEnabled = false
	c.ProxyProviders = []config.ProxyProvider{{Name: "main", Enabled: true, Type: "file", Path: "/etc/purewrt/providers/main.yaml", HealthCheck: true, HealthCheckURL: "https://www.gstatic.com/generate_204", HealthCheckInterval: 300}}
	mihomo := string(Mihomo(c))
	for _, want := range []string{
		"find-process-mode: off",
		"ipv6: false",
		"health-check:\n      enable: false",
		"type: url-test",
		"geodata-mode: false\ngeo-auto-update: false",
	} {
		if !strings.Contains(mihomo, want) {
			t.Fatalf("low-resource mihomo config missing %q in:\n%s", want, mihomo)
		}
	}
	for _, bad := range []string{"external-ui:", "ipv6: true"} {
		if strings.Contains(mihomo, bad) {
			t.Fatalf("low-resource mihomo config should not contain %q in:\n%s", bad, mihomo)
		}
	}
	nft := string(NFTables(c))
	for _, bad := range []string{"set bypass6", "ip6 daddr", "tproxy ip6"} {
		if strings.Contains(nft, bad) {
			t.Fatalf("low-resource nft config should not contain %q in:\n%s", bad, nft)
		}
	}
	dnsmasq := renderDNSMasqForTest(t, c, map[string][]string{"common": {"example.com"}})
	if strings.Contains(dnsmasq, "/6#") {
		t.Fatalf("low-resource dnsmasq config should not emit IPv6 nftsets:\n%s", dnsmasq)
	}
}

// TestLowResourceWithDashboardOverride verifies a user can keep the
// dashboard on even when ResourceProfile=low. Prior to the wizard's
// explicit-opt-in UX, the apply path silently dropped external-ui in low
// mode which left the user staring at a checked "Dashboard" box that did
// nothing — see AGENTS.md / wizard step 6 wording for the rationale.
func TestLowResourceWithDashboardOverride(t *testing.T) {
	c := config.Default()
	c.Settings.ResourceProfile = "low"
	c.Settings.DashboardEnabled = true
	mihomo := string(Mihomo(c))
	for _, want := range []string{
		"external-ui: " + c.Settings.DashboardPath,
		"external-ui-name: " + c.Settings.DashboardName,
	} {
		if !strings.Contains(mihomo, want) {
			t.Fatalf("low+DashboardEnabled should emit %q in:\n%s", want, mihomo)
		}
	}
}

func TestMihomoGeodataDisabledByDefault(t *testing.T) {
	mihomo := string(Mihomo(config.Default()))
	if !strings.Contains(mihomo, "geodata-mode: false\ngeo-auto-update: false") {
		t.Fatalf("default Mihomo config should disable geodata:\n%s", mihomo)
	}
}

func TestMihomoGeodataCanBeEnabled(t *testing.T) {
	c := config.Default()
	c.Settings.MihomoGeodataEnabled = true
	mihomo := string(Mihomo(c))
	if !strings.Contains(mihomo, "geodata-mode: true") {
		t.Fatalf("Mihomo geodata setting should enable geodata-mode:\n%s", mihomo)
	}
	if strings.Contains(mihomo, "geo-auto-update: false") {
		t.Fatalf("enabled Mihomo geodata should not force geo-auto-update off:\n%s", mihomo)
	}
}

func TestMihomoProxyGroupOptions(t *testing.T) {
	c := config.Default()
	c.ProxyProviders = []config.ProxyProvider{{Name: "main", Enabled: true, Type: "file", Path: "/etc/purewrt/providers/main.yaml", HealthCheckURL: "https://www.gstatic.com/generate_204", HealthCheckInterval: 300}}
	c.DNS.ProxyGroupType = "load-balance"
	c.DNS.ProxyFilter = "(?i)dns|safe"
	c.DNS.ProxyExcludeFilter = "(?i)direct"
	c.DNS.ProxyStrategy = "sticky-sessions"
	c.Sections = []config.Section{{Name: "media", Enabled: true, Action: "proxy", TPROXYPort: 7894, ProxyGroup: "Media", ProxyGroupType: "url-test", ProxyFilter: "(?i)hk|sg", ProxyExcludeFilter: "(?i)game", ProxyHealthCheckURL: "https://cp.cloudflare.com/generate_204", ProxyHealthCheckInterval: 600, IPv4Enabled: true, IPv6Enabled: true}}
	out := string(Mihomo(c))
	for _, want := range []string{
		"- name: DNSProxy\n    type: load-balance",
		"filter: \"(?i)dns|safe\"",
		"exclude-filter: \"(?i)direct\"",
		"strategy: sticky-sessions",
		"- name: Media\n    type: url-test",
		"filter: \"(?i)hk|sg\"",
		"exclude-filter: \"(?i)game\"",
		"url: https://cp.cloudflare.com/generate_204",
		"interval: 600",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestNativeImportZeroParseNoDedup(t *testing.T) {
	dir := t.TempDir()
	rpPath := filepath.Join(dir, "common.native")
	// Marker format: bare domains (incl. a deliberate duplicate), @cidr, bare
	// CIDRs (v4+v6). native_import must emit verbatim — no dedup, no parse.
	body := "# purewrt-native v1\tcommon\tbuild=1\n" +
		"youtube.com\n" +
		"youtube.com\n" + // duplicate — must NOT be dropped (claimed-map bypassed)
		"blocked.ru\n" +
		"@cidr\n" +
		"203.0.113.0/24\n" +
		"2001:db8::/32\n"
	if err := os.WriteFile(rpPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Settings.Workdir = dir
	c.Settings.RuleDedupMode = "full" // even under full dedup, native_import skips it
	c.Sections = []config.Section{{Name: "common", Enabled: true, Action: "proxy", IPv4Enabled: true, IPv6Enabled: true}}
	c.RuleProviders = []config.RuleProvider{{Name: "native_common", Enabled: true, Format: "text", ParseMode: "native_import", Path: rpPath, Section: "common"}}

	var dns, nftsets bytes.Buffer
	if err := streamRuleOutputs(c, generationSinks{dns: &dns, nftset: &nftsets}); err != nil {
		t.Fatal(err)
	}
	d := dns.String()
	if strings.Count(d, "nftset=/youtube.com/4#inet#purewrt#dns_proxy_common4") != 2 {
		t.Fatalf("duplicate domain must be emitted verbatim (no dedup):\n%s", d)
	}
	if !strings.Contains(d, "nftset=/blocked.ru/4#inet#purewrt#dns_proxy_common4") {
		t.Fatalf("missing domain directive:\n%s", d)
	}
	n := nftsets.String()
	if !strings.Contains(n, "add element inet purewrt proxy_common4 { 203.0.113.0/24 }") {
		t.Fatalf("missing v4 element:\n%s", n)
	}
	if !strings.Contains(n, "add element inet purewrt proxy_common6 { 2001:db8::/32 }") {
		t.Fatalf("missing v6 element:\n%s", n)
	}
}

func TestLowResourceStreamSkipsIPv6CIDR(t *testing.T) {
	dir := t.TempDir()
	rpPath := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rpPath, []byte("IP-CIDR,203.0.113.0/24\nIP-CIDR6,2001:db8::/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Settings.ResourceProfile = "low"
	c.Settings.Workdir = dir
	c.Sections = []config.Section{{Name: "common", Enabled: true, Action: "proxy", IPv4Enabled: true, IPv6Enabled: true}}
	c.RuleProviders = []config.RuleProvider{{Name: "rules", Enabled: true, Format: "text", Path: rpPath, Section: "common"}}
	var nftsets bytes.Buffer
	if err := streamRuleOutputs(c, generationSinks{nftset: &nftsets}); err != nil {
		t.Fatal(err)
	}
	out := nftsets.String()
	if !strings.Contains(out, "add element inet purewrt proxy_common4 { 203.0.113.0/24 }") {
		t.Fatalf("low-resource mode should keep IPv4 CIDRs:\n%s", out)
	}
	if strings.Contains(out, "2001:db8::/32") || strings.Contains(out, "proxy_common6") {
		t.Fatalf("low-resource mode should skip IPv6 CIDRs:\n%s", out)
	}
}

func TestIPv6DisabledStreamSkipsIPv6CIDR(t *testing.T) {
	dir := t.TempDir()
	rpPath := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rpPath, []byte("IP-CIDR,203.0.113.0/24\nIP-CIDR6,2001:db8::/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Settings.IPv6 = false
	c.Settings.Workdir = dir
	c.Sections = []config.Section{{Name: "common", Enabled: true, Action: "proxy", IPv4Enabled: true, IPv6Enabled: true}}
	c.RuleProviders = []config.RuleProvider{{Name: "rules", Enabled: true, Format: "text", Path: rpPath, Section: "common"}}
	var nftsets bytes.Buffer
	if err := streamRuleOutputs(c, generationSinks{nftset: &nftsets}); err != nil {
		t.Fatal(err)
	}
	out := nftsets.String()
	if !strings.Contains(out, "add element inet purewrt proxy_common4 { 203.0.113.0/24 }") {
		t.Fatalf("IPv6 disabled mode should keep IPv4 CIDRs:\n%s", out)
	}
	if strings.Contains(out, "2001:db8::/32") || strings.Contains(out, "proxy_common6") {
		t.Fatalf("IPv6 disabled mode should skip IPv6 CIDRs and sets:\n%s", out)
	}
}

func TestDNSUCICommandsUsePureWRTServerOnly(t *testing.T) {
	c := config.Default()
	c.DNS.Listen = "127.0.0.1:7874"
	cmds := DNSUCIApplyCommands(c)
	joined := ""
	for _, cmd := range cmds {
		joined += strings.Join(cmd, " ") + "\n"
	}
	for _, want := range []string{
		"uci -q del_list dhcp.@dnsmasq[0].server=127.0.0.1#7874",
		"uci add_list dhcp.@dnsmasq[0].server=127.0.0.1#7874",
		"uci set dhcp.@dnsmasq[0].noresolv=1",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "peerdns") {
		t.Fatalf("static peerdns changes must be handled by multi-WAN helper, got:\n%s", joined)
	}
	disable := DNSUCIDisableCommands(c)
	if strings.Join(disable[0], " ") != "uci -q del_list dhcp.@dnsmasq[0].server=127.0.0.1#7874" {
		t.Fatalf("disable must remove only PureWRT server entry, got %#v", disable)
	}
}

func TestDNSMasqIPv6FilterCommands(t *testing.T) {
	c := config.Default()
	// IPv6 routed (default) → delete the filter option
	c.Settings.IPv6 = true
	c.Settings.IPv6Mode = "auto"
	got := DNSMasqIPv6FilterCommands(c)
	if got[0][1] != "-q" || got[0][2] != "delete" || got[0][3] != "dhcp.@dnsmasq[0].filter_aaaa" {
		t.Fatalf("IPv6 routed should issue uci -q delete, got %#v", got[0])
	}
	if got[len(got)-1][1] != "commit" || got[len(got)-1][2] != "dhcp" {
		t.Fatalf("must end with uci commit dhcp, got %#v", got)
	}
	// IPv6 routing explicitly off → set the filter option
	c.Settings.IPv6 = false
	c.Settings.IPv6Mode = "off"
	got = DNSMasqIPv6FilterCommands(c)
	if got[0][1] != "set" || got[0][2] != "dhcp.@dnsmasq[0].filter_aaaa=1" {
		t.Fatalf("IPv6 off should issue uci set filter_aaaa=1, got %#v", got[0])
	}
}

func TestProxyServerBypassSetsReturnBeforeProxy(t *testing.T) {
	c := config.Default()
	c.Bypass.ProxyServerCIDR4 = []string{"203.0.113.10/32"}
	c.Bypass.ProxyServerCIDR6 = []string{"2001:db8::10/128"}
	nft := string(NFTables(c))
	for _, want := range []string{
		`ip daddr @proxy_server_bypass4 counter name "proxy_server_bypass4" return`,
		`ip6 daddr @proxy_server_bypass6 counter name "proxy_server_bypass6" return`,
		"set proxy_server_bypass4",
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("missing %q in:\n%s", want, nft)
		}
	}
	var buf bytes.Buffer
	if err := streamRuleOutputs(c, generationSinks{nftset: &buf}); err != nil {
		t.Fatal(err)
	}
	sets := buf.String()
	if strings.Contains(sets, "table inet purewrt {") {
		t.Fatalf("nft set payload must use standalone commands, got:\n%s", sets)
	}
	for _, want := range []string{
		"flush set inet purewrt proxy_server_bypass4",
		"add element inet purewrt proxy_server_bypass4 { 203.0.113.10/32 }",
	} {
		if !strings.Contains(sets, want) {
			t.Fatalf("missing %q in:\n%s", want, sets)
		}
	}
	if strings.Contains(sets, "  flush set") || strings.Contains(sets, "  add element") {
		t.Fatalf("nft set payload commands must not be nested in table block:\n%s", sets)
	}
	if !strings.Contains(sets, "add element inet purewrt proxy_server_bypass4 { 203.0.113.10/32 }") {
		t.Fatalf("missing proxy server bypass payload in:\n%s", sets)
	}
}

func TestNFTSplitStaticAndDNSDynamicSets(t *testing.T) {
	c := config.Default()
	nft := string(NFTables(c))
	for _, want := range []string{
		"set proxy_media4",
		"set dns_proxy_media4",
		"flags interval",
		`ip daddr @dns_proxy_media4 meta l4proto tcp meta mark set meta mark | 0x1 counter name "dns_proxy_media4" tproxy ip to :7894 accept`,
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("missing %q in:\n%s", want, nft)
		}
	}
	if strings.Contains(nft, "flags interval,dynamic,timeout") || strings.Contains(nft, "timeout 1h") {
		t.Fatalf("dns nft sets must avoid dynamic timeout flags for OpenWrt compatibility:\n%s", nft)
	}
	if strings.Contains(nft, "elements =") {
		t.Fatalf("stable nft file must not contain set payload elements:\n%s", nft)
	}
}

func TestDNSMasqTargetsDynamicDNSSets(t *testing.T) {
	c := config.Default()
	out := renderDNSMasqForTest(t, c, map[string][]string{"media": {"youtube.com"}})
	for _, want := range []string{
		"nftset=/youtube.com/4#inet#purewrt#dns_proxy_media4",
		"nftset=/youtube.com/6#inet#purewrt#dns_proxy_media6",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestNFTablesNativeRule(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{Name: "games", Enabled: true, Action: "proxy", TPROXYPort: 7898, IPv4Enabled: true, IPv6Enabled: true, UDPMode: "proxy"}}
	nft := string(NFTablesWithNative(c, map[string][]string{"games": {"ip daddr 138.128.136.0/21 meta l4proto udp th dport 50000-50100"}}))
	want := "ip daddr 138.128.136.0/21 meta l4proto udp th dport 50000-50100 meta mark set meta mark | 0x1 tproxy ip to :7898 accept"
	if !strings.Contains(nft, want) {
		t.Fatalf("missing native nft rule %q in:\n%s", want, nft)
	}
}

func TestPolicyCommandsUsePortableRuleAdd(t *testing.T) {
	cmds := strings.Join(PolicyCommands(config.Default()), "\n")
	if strings.Contains(cmds, "rule replace") {
		t.Fatalf("ip rule replace is not supported by OpenWrt ip-tiny, got:\n%s", cmds)
	}
	for _, want := range []string{
		"ip rule del priority 100 fwmark 0x1/0xff table 100",
		"ip rule add priority 100 fwmark 0x1/0xff table 100",
		"ip -6 rule del priority 100 fwmark 0x1/0xff table 100",
		"ip -6 rule add priority 100 fwmark 0x1/0xff table 100",
	} {
		if !strings.Contains(cmds, want) {
			t.Fatalf("missing %q in:\n%s", want, cmds)
		}
	}
}

func TestZapretNFTablesAndEnv(t *testing.T) {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan_a", Enabled: true, Interfaces: []string{"wan_a"}, FwMark: "0x40000000", NFQWSBin: "/usr/bin/nfqws"}}
	c.ZapretStrategies = []config.ZapretStrategy{{Name: "media_tcp", Enabled: true, Profile: "wan_a", QueueNum: 200, Protocols: []string{"tcp"}, TCPPorts: "443", TCPPktOut: 15, TCPPktIn: 6, Params: "--strategy-a"}, {Name: "media_udp", Enabled: true, Profile: "wan_a", QueueNum: 201, Protocols: []string{"udp"}, UDPPorts: "443", UDPPktOut: 9, UDPPktIn: 3, Params: "--strategy-u"}}
	c.Sections = []config.Section{{Name: "media", Enabled: true, Action: "zapret", TPROXYPort: 7894, ProxyGroup: "Media", IPv4Enabled: true, IPv6Enabled: true, UDPMode: "proxy", Priority: 90, ZapretStrategies: []string{"media_tcp", "media_udp"}}}
	nft := string(NFTables(c))
	if !strings.Contains(nft, "hook postrouting priority srcnat + 1") || !strings.Contains(nft, `oifname "wan_a" meta mark & 0x40000000 == 0 meta l4proto tcp tcp dport { 443 } ct original packets >= 1 ct original packets <= 15 counter name "proxy_media4" queue num 200 bypass`) || !strings.Contains(nft, `iifname "wan_a" meta l4proto tcp tcp sport { 443 } ct reply packets >= 1 ct reply packets <= 6 counter name "proxy_media4" queue num 200 bypass`) {
		t.Fatalf("expected zapret nfqueue rule, got:\n%s", nft)
	}
	if !strings.Contains(nft, `meta l4proto udp udp dport { 443 } ct original packets >= 1 ct original packets <= 9 counter name "proxy_media4" queue num 201 bypass`) || !strings.Contains(nft, `meta l4proto udp udp sport { 443 } ct reply packets >= 1 ct reply packets <= 3 counter name "proxy_media4" queue num 201 bypass`) {
		t.Fatalf("expected zapret udp nfqueue rules, got:\n%s", nft)
	}
	if !strings.Contains(nft, `tcp flags & (fin | rst) != 0 counter name "proxy_media4" queue num 200 bypass`) {
		t.Fatalf("expected explicit tcp flags expression, got:\n%s", nft)
	}
	if strings.Contains(nft, "packets 1-") || strings.Contains(nft, "tcp flags fin,rst") {
		t.Fatalf("nft must avoid ambiguous packet range or tcp flags syntax, got:\n%s", nft)
	}
	env := string(ZapretEnv(c))
	if !strings.Contains(env, "PUREWRT_ZAPRET_INSTANCE_0_QUEUE=\"200\"") || !strings.Contains(env, "PUREWRT_ZAPRET_INSTANCE_1_QUEUE=\"201\"") || !strings.Contains(env, "PUREWRT_ZAPRET_INSTANCE_0_FWMARK=\"0x40000000\"") {
		t.Fatalf("unexpected zapret env:\n%s", env)
	}
}

// TestZapretEnvEmitsBlobs guards the fix for "LUA ERROR: blob unavailable":
// each per-instance env var must carry the --blob= declarations so the init
// script passes them to nfqws. Blobs are auto-derived from the params
// (blob=NAME), resolved via the candidate catalog — no profile decl needed —
// so it works no matter how the strategy was created.
func TestZapretEnvEmitsBlobs(t *testing.T) {
	c := config.Default()
	// No explicit profile blobs — must still resolve quic_google from params
	// via the embedded candidate catalog (youtube_combined declares it).
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, Interfaces: []string{"wan"}, FwMark: "0x40000000", NFQWSBin: "/usr/bin/nfqws"}}
	c.ZapretStrategies = []config.ZapretStrategy{{Name: "yt", Enabled: true, Profile: "wan", QueueNum: 200, Protocols: []string{"udp"}, UDPPorts: "443", Params: "--filter-udp=443 --lua-desync=fake:blob=quic_google"}}
	c.Sections = []config.Section{{Name: "Youtube", Enabled: true, Action: "zapret", IPv4Enabled: true, Priority: 10, ZapretStrategies: []string{"yt"}}}
	env := string(ZapretEnv(c))
	if !strings.Contains(env, "PUREWRT_ZAPRET_INSTANCE_0_BLOBS=\"") || !strings.Contains(env, "--blob=quic_google:@") {
		t.Fatalf("env missing param-derived --blob decl:\n%s", env)
	}
	// A strategy that references no blob (only built-ins would be fine too)
	// emits an empty BLOBS var.
	c.ZapretStrategies[0].Params = "--filter-tcp=443 --lua-desync=multisplit:pos=1"
	if env2 := string(ZapretEnv(c)); !strings.Contains(env2, "PUREWRT_ZAPRET_INSTANCE_0_BLOBS=\"\"") {
		t.Fatalf("no-blob strategy should emit empty BLOBS:\n%s", env2)
	}
	// A built-in blob reference needs no decl either.
	c.ZapretStrategies[0].Params = "--filter-tcp=443 --lua-desync=fake:blob=fake_default_tls"
	if env3 := string(ZapretEnv(c)); !strings.Contains(env3, "PUREWRT_ZAPRET_INSTANCE_0_BLOBS=\"\"") {
		t.Fatalf("built-in blob should not emit a decl:\n%s", env3)
	}
}

func TestZapretNFTablesInterfaceSet(t *testing.T) {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, Interfaces: []string{"pppoe-wan", "eth2"}, FwMark: "0x40000000", NFQWSBin: "/usr/bin/nfqws"}}
	c.ZapretStrategies = []config.ZapretStrategy{{Name: "media_tcp", Enabled: true, Profile: "wan", QueueNum: 200, Protocols: []string{"tcp"}, TCPPorts: "443", TCPPktOut: 15, TCPPktIn: 6, Params: "--strategy-a"}}
	c.Sections = []config.Section{{Name: "media", Enabled: true, Action: "zapret", IPv4Enabled: true, IPv6Enabled: true, Priority: 90, ZapretStrategies: []string{"media_tcp"}}}
	nft := string(NFTables(c))
	if !strings.Contains(nft, "oifname { \"pppoe-wan\", \"eth2\" } meta mark & 0x40000000 == 0 meta l4proto tcp") || !strings.Contains(nft, "iifname { \"pppoe-wan\", \"eth2\" } meta l4proto tcp") {
		t.Fatalf("expected zapret interface set rules, got:\n%s", nft)
	}
}

func TestBlockQUICRejectsIPv4AndIPv6(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{Name: "common", Enabled: true, Action: "proxy", TPROXYPort: 7893, ProxyGroup: "Common", IPv4Enabled: true, IPv6Enabled: true, UDPMode: "block_quic", Priority: 100}}
	nft := string(NFTables(c))
	if !strings.Contains(nft, `ip daddr @proxy_common4 counter name "proxy_common4" udp dport 443 reject`) || !strings.Contains(nft, `ip6 daddr @proxy_common6 counter name "proxy_common6" udp dport 443 reject`) {
		t.Fatalf("expected IPv4 and IPv6 QUIC rejects, got:\n%s", nft)
	}
}

func TestDirectSectionReturns(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{Name: "direct", Enabled: true, Action: "direct", IPv4Enabled: true, IPv6Enabled: true, Priority: 100}}
	nft := string(NFTables(c))
	if !strings.Contains(nft, `ip daddr @direct4 counter name "direct4" return`) || !strings.Contains(nft, `ip6 daddr @direct6 counter name "direct6" return`) {
		t.Fatalf("expected explicit direct returns, got:\n%s", nft)
	}
}

func TestStreamRuleOutputsIncludesBypassCIDRs(t *testing.T) {
	c := config.Default()
	c.Bypass.CIDR4 = []string{"198.51.100.0/24"}
	c.Bypass.CIDR6 = []string{"2001:db8:1::/48"}
	var buf bytes.Buffer
	if err := streamRuleOutputs(c, generationSinks{nftset: &buf}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"add element inet purewrt bypass4 { 198.51.100.0/24 }", "add element inet purewrt bypass6 { 2001:db8:1::/48 }"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRuleProviderPriorityClaimsDuplicateDomain(t *testing.T) {
	dir := t.TempDir()
	directPath := filepath.Join(dir, "direct.list")
	proxyPath := filepath.Join(dir, "proxy.list")
	if err := os.WriteFile(directPath, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxyPath, []byte("example.com\nmedia.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Settings.Workdir = dir
	c.Settings.RuleDedupMode = "full"
	c.Sections = append(c.Sections, config.Section{Name: "direct", Enabled: true, Action: "direct", IPv4Enabled: true, IPv6Enabled: true, Priority: 1000})
	c.RuleProviders = []config.RuleProvider{
		{Name: "proxy", Enabled: true, Format: "text", Path: proxyPath, Section: "media", Priority: 100},
		{Name: "direct", Enabled: true, Format: "text", Path: directPath, Section: "direct", RouteAction: "direct", Priority: 10},
	}
	var dns bytes.Buffer
	if err := streamRuleOutputs(c, generationSinks{dns: &dns}); err != nil {
		t.Fatal(err)
	}
	out := dns.String()
	if !strings.Contains(out, "nftset=/example.com/4#inet#purewrt#dns_direct4") {
		t.Fatalf("expected high-priority direct provider to claim example.com:\n%s", out)
	}
	if strings.Contains(out, "nftset=/example.com/4#inet#purewrt#dns_proxy_media4") {
		t.Fatalf("lower-priority media provider must not receive claimed duplicate:\n%s", out)
	}
	if !strings.Contains(out, "nftset=/media.example/4#inet#purewrt#dns_proxy_media4") {
		t.Fatalf("non-duplicate media rule must remain:\n%s", out)
	}
}

func TestLowResourceNoDedupAllowsDuplicateDomains(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.list")
	secondPath := filepath.Join(dir, "second.list")
	if err := os.WriteFile(firstPath, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Settings.Workdir = dir
	c.Settings.ResourceProfile = "low"
	c.Settings.RuleDedupMode = "auto"
	c.RuleProviders = []config.RuleProvider{
		{Name: "first", Enabled: true, Format: "text", Path: firstPath, Section: "common", Priority: 10},
		{Name: "second", Enabled: true, Format: "text", Path: secondPath, Section: "common", Priority: 20},
	}
	var dns bytes.Buffer
	if err := streamRuleOutputs(c, generationSinks{dns: &dns}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(dns.String(), "nftset=/example.com/4#inet#purewrt#dns_proxy_common4"); got != 2 {
		t.Fatalf("low-resource auto should not dedupe duplicate domains, got count=%d:\n%s", got, dns.String())
	}
}

func TestStandardSectionDedupAllowsCrossSectionDuplicate(t *testing.T) {
	dir := t.TempDir()
	mediaPath := filepath.Join(dir, "media.list")
	commonPath := filepath.Join(dir, "common.list")
	if err := os.WriteFile(mediaPath, []byte("example.com\nexample.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(commonPath, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Settings.Workdir = dir
	c.Settings.ResourceProfile = "standard"
	c.Settings.RuleDedupMode = "auto"
	c.RuleProviders = []config.RuleProvider{
		{Name: "media", Enabled: true, Format: "text", Path: mediaPath, Section: "media", Priority: 10},
		{Name: "common", Enabled: true, Format: "text", Path: commonPath, Section: "common", Priority: 20},
	}
	var dns bytes.Buffer
	if err := streamRuleOutputs(c, generationSinks{dns: &dns}); err != nil {
		t.Fatal(err)
	}
	out := dns.String()
	if got := strings.Count(out, "nftset=/example.com/4#inet#purewrt#dns_proxy_media4"); got != 1 {
		t.Fatalf("standard auto should dedupe inside media section, got count=%d:\n%s", got, out)
	}
	if got := strings.Count(out, "nftset=/example.com/4#inet#purewrt#dns_proxy_common4"); got != 1 {
		t.Fatalf("standard auto should keep cross-section duplicate, got count=%d:\n%s", got, out)
	}
}

// VPNs are mihomo `direct` outbounds selected per section, pooled with
// providers — no kernel marks/ip-rules/masquerade.
func TestVPNAsMihomoProxies(t *testing.T) {
	c := config.Default()
	c.VPNs = []config.VPN{
		{Name: "work", Enabled: true, Interface: "wg0"},
		{Name: "home", Enabled: true, Interface: "tun0"},
	}
	c.Sections = []config.Section{
		{Name: "common", Enabled: true, Action: "proxy", TPROXYPort: 7893, ProxyGroup: "Common", ProxyGroupType: "url-test", IPv4Enabled: true, IPv6Enabled: true, VPNs: []string{"work", "home"}},
	}
	mi := string(Mihomo(c))
	for _, want := range []string{
		"name: vpn_work\n    type: direct\n    interface-name: wg0",
		"name: vpn_home\n    type: direct\n    interface-name: tun0",
		"      - vpn_work\n",
		"      - vpn_home\n",
	} {
		if !strings.Contains(mi, want) {
			t.Fatalf("missing %q in mihomo.yaml:\n%s", want, mi)
		}
	}
	// Kernel VPN paths are gone.
	nft := string(NFTables(c))
	if strings.Contains(nft, "vpn_work") || strings.Contains(nft, "masquerade") {
		t.Fatalf("kernel VPN nft rules must be gone:\n%s", nft)
	}
	cmds := strings.Join(PolicyCommands(c), "\n")
	if strings.Contains(cmds, "dev wg0") || strings.Contains(cmds, "dev tun0") {
		t.Fatalf("per-VPN ip rules/routes must be gone:\n%s", cmds)
	}
}

func TestZapretAutoQueueGeneration(t *testing.T) {
	c := config.Default()
	c.ZapretProfiles = []config.ZapretProfile{{Name: "wan", Enabled: true, Interfaces: []string{"wan"}, FwMark: "0x40000000", NFQWSBin: "/usr/bin/nfqws"}}
	c.ZapretStrategies = []config.ZapretStrategy{
		{Name: "auto_tcp", Enabled: true, Profile: "wan", QueueNum: 0, Protocols: []string{"tcp"}, TCPPorts: "443", TCPPktOut: 15, TCPPktIn: 6, Params: "--a"},
		{Name: "auto_udp", Enabled: true, Profile: "wan", QueueNum: 0, Protocols: []string{"udp"}, UDPPorts: "443", UDPPktOut: 9, UDPPktIn: 0, Params: "--b"},
	}
	c.Sections = []config.Section{{Name: "media", Enabled: true, Action: "zapret", IPv4Enabled: true, IPv6Enabled: true, ZapretStrategies: []string{"auto_tcp", "auto_udp"}}}
	nft := string(NFTables(c))
	for _, want := range []string{"queue num 200 bypass", "queue num 201 bypass"} {
		if !strings.Contains(nft, want) {
			t.Fatalf("missing %q in:\n%s", want, nft)
		}
	}
	env := string(ZapretEnv(c))
	for _, want := range []string{"PUREWRT_ZAPRET_INSTANCE_0_QUEUE=\"200\"", "PUREWRT_ZAPRET_INSTANCE_1_QUEUE=\"201\""} {
		if !strings.Contains(env, want) {
			t.Fatalf("missing %q in:\n%s", want, env)
		}
	}
}

func TestVirtualDirectAndRejectProvidersExportToGlobalSets(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{Name: "common", Enabled: true, Action: "proxy", TPROXYPort: 7893, ProxyGroup: "Common", IPv4Enabled: true, IPv6Enabled: true}}
	dnsmasq := renderDNSMasqForTest(t, c, map[string][]string{"direct": {"example.org"}, "reject": {"ads.example"}})
	for _, want := range []string{
		"nftset=/example.org/4#inet#purewrt#dns_direct4",
		"nftset=/ads.example/4#inet#purewrt#dns_reject4",
	} {
		if !strings.Contains(dnsmasq, want) {
			t.Fatalf("missing %q in:\n%s", want, dnsmasq)
		}
	}
	nft := string(NFTables(c))
	for _, want := range []string{
		`ip daddr @dns_reject4 counter name "dns_reject4" reject`,
		`ip daddr @dns_direct4 counter name "dns_direct4" return`,
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("missing %q in:\n%s", want, nft)
		}
	}
}

func renderDNSMasqForTest(t *testing.T, c config.Config, domains map[string][]string) string {
	t.Helper()
	var b bytes.Buffer
	if err := WriteDNSMasqHeader(&b); err != nil {
		t.Fatal(err)
	}
	for sec, ds := range domains {
		s, ok := c.SectionByName(sec)
		if !ok {
			if sec == "direct" || sec == "reject" {
				s = config.Section{Name: sec, Action: sec, IPv4Enabled: true, IPv6Enabled: true}
			} else {
				continue
			}
		}
		for _, d := range ds {
			if err := WriteDNSMasqDomain(&b, c, s, d); err != nil {
				t.Fatal(err)
			}
		}
	}
	return b.String()
}

func TestSourceCIDRRoutingRules(t *testing.T) {
	c := config.Default()
	c.Settings.FwMark = "0x1"
	c.Sections = []config.Section{
		{Name: "common", Enabled: true, Action: "proxy", TPROXYPort: 7893, IPv4Enabled: true, SourceCIDR4: []string{"10.13.14.0/24", "172.16.10.11"}},
		{Name: "direct", Enabled: true, Action: "direct", IPv4Enabled: true, SourceCIDR4: []string{"10.13.15.3/32"}},
		{Name: "reject", Enabled: true, Action: "reject", IPv4Enabled: true, SourceCIDR4: []string{"172.16.20.0/24"}},
	}
	c.Bypass.SourceCIDR4 = []string{"10.13.13.0/24"}
	out := string(NFTables(c))
	for _, want := range []string{
		"ip saddr 10.13.13.0/24 return",
		"ip saddr { 10.13.14.0/24, 172.16.10.11/32 } meta l4proto tcp meta mark set meta mark | 0x1 tproxy ip to :7893 accept",
		"ip saddr 10.13.15.3/32 return",
		"ip saddr 172.16.20.0/24 reject",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "ip saddr 10.13.13.0/24 return") > strings.Index(out, "ip saddr { 10.13.14.0/24, 172.16.10.11/32 }") {
		t.Fatalf("source bypass must be emitted before source routing:\n%s", out)
	}
}

func TestExcludedDeviceBypass(t *testing.T) {
	c := config.Default()
	c.Sections = []config.Section{{Name: "common", Enabled: true, Action: "proxy", TPROXYPort: 7893, IPv4Enabled: true}}
	c.Devices = []config.Device{
		{MAC: "aa:bb:cc:dd:ee:ff", Enabled: true, Exclude: true},
		{MAC: "11:22:33:44:55:66", Enabled: true, Section: "common"},
	}
	out := string(NFTables(c))
	if !strings.Contains(out, "ether saddr { aa:bb:cc:dd:ee:ff } return") {
		t.Fatalf("excluded device must emit a MAC bypass return:\n%s", out)
	}
	// Exclude return must precede the section device rule (bypass outranks routing).
	if strings.Index(out, "ether saddr { aa:bb:cc:dd:ee:ff } return") > strings.Index(out, "ether saddr { 11:22:33:44:55:66 }") {
		t.Fatalf("excluded-device return must come before section device rules:\n%s", out)
	}
	// A disabled excluded device emits nothing.
	c.Devices = []config.Device{{MAC: "aa:bb:cc:dd:ee:ff", Enabled: false, Exclude: true}}
	if strings.Contains(string(NFTables(c)), "aa:bb:cc:dd:ee:ff") {
		t.Fatalf("disabled excluded device must not emit a rule")
	}
}

func TestMACBeatsCIDRDeterministic(t *testing.T) {
	// A MAC assignment (low-priority section) and a source CIDR (high-priority
	// section): the MAC rule must be emitted before the CIDR rule regardless of
	// section priority, so MAC always wins.
	c := config.Default()
	c.Sections = []config.Section{
		{Name: "hi", Enabled: true, Action: "proxy", TPROXYPort: 7801, IPv4Enabled: true, Priority: 10, SourceCIDR4: []string{"10.0.0.5/32"}},
		{Name: "lo", Enabled: true, Action: "proxy", TPROXYPort: 7802, IPv4Enabled: true, Priority: 90},
	}
	c.Devices = []config.Device{{MAC: "aa:bb:cc:dd:ee:ff", Enabled: true, Section: "lo"}}
	out := string(NFTables(c))
	macIdx := strings.Index(out, "aa:bb:cc:dd:ee:ff")
	cidrIdx := strings.Index(out, "10.0.0.5")
	if macIdx < 0 || cidrIdx < 0 {
		t.Fatalf("expected both MAC and CIDR rules:\n%s", out)
	}
	if macIdx > cidrIdx {
		t.Fatalf("MAC rule (idx %d) must precede CIDR rule (idx %d) — MAC beats CIDR:\n%s", macIdx, cidrIdx, out)
	}
}
