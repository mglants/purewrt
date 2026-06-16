package generator

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/logging"
	"github.com/purewrt/purewrt/internal/metrics"
	"github.com/purewrt/purewrt/internal/system"
)

type GeneratedPaths struct {
	MihomoConfig         string
	DNSMasqFile          string
	DNSMasqFragmentDir   string
	NFTFile              string
	NFTSetsFile          string
	FirewallFile         string
	Mwan3File            string
	ZapretEnv            string
	ZapretUpstreamConfig string // /opt/zapret2/config; empty disables
}

// uciConfigDir is the directory holding fw4/mwan3 UCI config files that
// PureWRT generates and `uci import`s — "/etc/config" in production. Tests
// override it via PUREWRT_UCI_DIR (t.Setenv) so full apply/update pipelines
// don't have to write the real /etc/config.
func uciConfigDir() string {
	if d := os.Getenv("PUREWRT_UCI_DIR"); d != "" {
		return d
	}
	return "/etc/config"
}

func DefaultGeneratedPaths(c config.Config) GeneratedPaths {
	runtimeDir := c.Settings.RuntimeDir
	if runtimeDir == "" {
		runtimeDir = config.DefaultRuntimeDir
	}
	runtimeGeneratedDir := c.Settings.GeneratedDir
	if runtimeGeneratedDir == "" {
		runtimeGeneratedDir = filepath.Join(runtimeDir, "generated")
	}
	mihomoConfig := c.Settings.MihomoConfig
	if mihomoConfig == "" {
		mihomoConfig = config.DefaultMihomoConfig
	}
	persistentGeneratedDir := filepath.Dir(mihomoConfig)
	dnsmasqFile := filepath.Join(runtimeGeneratedDir, "purewrt.conf")
	nftFile := filepath.Join(persistentGeneratedDir, "purewrt.nft")
	nftSetsFile := filepath.Join(runtimeGeneratedDir, "purewrt-sets.nft")
	return GeneratedPaths{MihomoConfig: mihomoConfig, DNSMasqFile: dnsmasqFile, DNSMasqFragmentDir: c.Settings.DNSMasqIncludeDir, NFTFile: nftFile, NFTSetsFile: nftSetsFile, FirewallFile: filepath.Join(uciConfigDir(), "purewrt-firewall.generated"), Mwan3File: filepath.Join(uciConfigDir(), "purewrt-mwan3.generated"), ZapretEnv: filepath.Join(persistentGeneratedDir, "zapret.env"), ZapretUpstreamConfig: c.Settings.ZapretUpstreamConfigPath}
}

func StagedGeneratedPaths(c config.Config, stageDir string) GeneratedPaths {
	live := DefaultGeneratedPaths(c)
	return GeneratedPaths{
		MihomoConfig:         filepath.Join(stageDir, "mihomo.yaml"),
		DNSMasqFile:          filepath.Join(stageDir, filepath.Base(live.DNSMasqFile)),
		DNSMasqFragmentDir:   filepath.Join(stageDir, "dnsmasq.d"),
		NFTFile:              filepath.Join(stageDir, filepath.Base(live.NFTFile)),
		NFTSetsFile:          filepath.Join(stageDir, filepath.Base(live.NFTSetsFile)),
		FirewallFile:         filepath.Join(stageDir, filepath.Base(live.FirewallFile)),
		Mwan3File:            filepath.Join(stageDir, filepath.Base(live.Mwan3File)),
		ZapretEnv:            filepath.Join(stageDir, filepath.Base(live.ZapretEnv)),
		ZapretUpstreamConfig: stagedOrEmpty(stageDir, live.ZapretUpstreamConfig, "zapret2.config"),
	}
}

// stagedOrEmpty returns a staged path next to stageDir for a live path that
// might be empty (e.g. the upstream zapret2 config is opt-out).
func stagedOrEmpty(stageDir, live, fallback string) string {
	if live == "" {
		return ""
	}
	base := filepath.Base(live)
	if base == "" || base == "." || base == "/" {
		base = fallback
	}
	return filepath.Join(stageDir, base)
}

func PromoteGeneratedPaths(staged, live GeneratedPaths) error {
	return PromoteGeneratedPathsForGroups(staged, live, GenerationGroups{}.All())
}

func PromoteGeneratedPathsForGroups(staged, live GeneratedPaths, groups GenerationGroups) error {
	for _, f := range []struct {
		from string
		to   string
		perm fs.FileMode
		ok   bool
	}{
		{staged.MihomoConfig, live.MihomoConfig, 0644, groups.Mihomo},
		{staged.NFTFile, live.NFTFile, 0644, groups.OpenWrtBundle},
		{staged.NFTSetsFile, live.NFTSetsFile, 0644, groups.OpenWrtBundle},
		{staged.FirewallFile, live.FirewallFile, 0600, groups.Firewall},
		{staged.Mwan3File, live.Mwan3File, 0600, groups.Mwan3},
		{staged.ZapretEnv, live.ZapretEnv, 0644, groups.Zapret},
		{staged.ZapretUpstreamConfig, live.ZapretUpstreamConfig, 0644, groups.Zapret},
	} {
		if !f.ok {
			continue
		}
		if f.from == "" || f.to == "" {
			// Path-disabled output (e.g. ZapretUpstreamConfig when the user
			// hasn't opted in via Settings.ZapretUpstreamConfigPath).
			continue
		}
		data, err := os.ReadFile(f.from)
		if err != nil {
			if os.IsNotExist(err) && (f.from == staged.FirewallFile || f.from == staged.Mwan3File || f.from == staged.ZapretUpstreamConfig) {
				continue
			}
			return err
		}
		if _, err := system.WriteIfChanged(f.to, data, f.perm); err != nil {
			return err
		}
	}
	if groups.OpenWrtBundle {
		if err := PromoteDNSMasqFragments(staged, live); err != nil {
			return err
		}
	}
	return nil
}

func PromoteDNSMasqFragments(staged, live GeneratedPaths) error {
	if live.DNSMasqFragmentDir == "" || staged.DNSMasqFragmentDir == "" {
		return nil
	}
	if err := os.MkdirAll(live.DNSMasqFragmentDir, 0755); err != nil {
		return err
	}
	expected := map[string]struct{}{}
	matches, err := filepath.Glob(filepath.Join(staged.DNSMasqFragmentDir, "purewrt-*.dnsmasq"))
	if err != nil {
		return err
	}
	for _, from := range matches {
		base := filepath.Base(from)
		expected[base] = struct{}{}
		data, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		if _, err := system.WriteIfChanged(filepath.Join(live.DNSMasqFragmentDir, base), data, 0644); err != nil {
			return err
		}
	}
	liveMatches, err := filepath.Glob(filepath.Join(live.DNSMasqFragmentDir, "purewrt-*.dnsmasq"))
	if err != nil {
		return err
	}
	for _, path := range liveMatches {
		if _, ok := expected[filepath.Base(path)]; !ok {
			_ = os.Remove(path)
		}
	}
	return nil
}

func WriteAll(c config.Config) error {
	return WriteAllTo(c, DefaultGeneratedPaths(c))
}

func WriteAllForce(c config.Config) error {
	return WriteAllToWithOptions(c, DefaultGeneratedPaths(c), WriteOptions{Force: true})
}

type WriteOptions struct {
	Force           bool
	CheckPaths      GeneratedPaths
	SkipFingerprint bool
}

type GenerationResult struct {
	DirtyGroups GenerationGroups
	Reason      string
	Changed     map[string]bool
}

func WriteAllTo(c config.Config, paths GeneratedPaths) error {
	return WriteAllToWithOptions(c, paths, WriteOptions{})
}

func WriteAllToWithOptions(c config.Config, paths GeneratedPaths, opt WriteOptions) error {
	_, err := WriteAllToResult(c, paths, opt)
	return err
}

func WriteAllToResult(c config.Config, paths GeneratedPaths, opt WriteOptions) (GenerationResult, error) {
	log := logging.New(c.Settings.LogLevel)
	defer log.DebugTimer("generate: WriteAllTo")()
	res := GenerationResult{Changed: map[string]bool{}}
	for _, dir := range outputDirs(c, paths) {
		if dir == "" || dir == "." {
			continue
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return res, err
		}
	}
	fp, err := currentGenerationFingerprint(c)
	checkPaths := opt.CheckPaths
	if checkPaths.MihomoConfig == "" {
		checkPaths = paths
	}
	if err == nil {
		groups, reason := generationDirtyGroups(c, fp, checkPaths, opt.Force)
		res.DirtyGroups, res.Reason = groups, reason
		if !groups.Any() {
			log.Info("generate: cache hit: %s; skipping writes", reason)
			return res, nil
		}
		log.Info("generate: dirty groups=%+v reason=%s", groups, reason)
	} else if opt.Force {
		res.DirtyGroups, res.Reason = GenerationGroups{}.All(), "forced"
		log.Info("generate: cache bypassed by force")
	} else {
		res.DirtyGroups, res.Reason = GenerationGroups{}.All(), err.Error()
		log.Info("generate: cache unavailable: %v", err)
	}
	groups := res.DirtyGroups
	if !groups.Any() {
		groups = GenerationGroups{}.All()
		res.DirtyGroups = groups
	}
	dnsmasqFragments := map[string]*bytes.Buffer{}
	var nftsets bytes.Buffer
	native := map[string][]string{}
	if groups.OpenWrtBundle {
		log.Info("generate: streaming rule outputs")
		if err := streamRuleOutputs(c, generationSinks{dnsBySection: dnsmasqFragments, nftset: &nftsets, native: native}); err != nil {
			return res, err
		}
	}
	if groups.Mihomo {
		t := time.Now()
		mihomoCfg := Mihomo(c)
		if changed, err := system.WriteIfChanged(paths.MihomoConfig, mihomoCfg, 0644); err != nil {
			return res, err
		} else {
			res.Changed["mihomo"] = changed
			logWrite(log, "generate: mihomo config", paths.MihomoConfig, changed, len(mihomoCfg), time.Since(t))
			metrics.GenerateDurationMS.Observe(float64(time.Since(t).Milliseconds()), "mihomo")
		}
	}
	if groups.OpenWrtBundle {
		t := time.Now()
		if changed, err := WriteDNSMasqFragments(c, paths, dnsmasqFragments); err != nil {
			return res, err
		} else {
			res.Changed["dnsmasq"] = changed
			log.Info("generate: dnsmasq fragments dir=%s fragments=%d changed=%v took=%v", dnsmasqFragmentDir(paths), len(dnsmasqFragments), changed, time.Since(t))
			metrics.GenerateDurationMS.Observe(float64(time.Since(t).Milliseconds()), "dnsmasq")
		}
		t = time.Now()
		nft := NFTablesWithNative(c, native)
		if changed, err := system.WriteIfChanged(paths.NFTFile, nft, 0644); err != nil {
			return res, err
		} else {
			res.Changed["nft"] = changed
			logWrite(log, "generate: nft main", paths.NFTFile, changed, len(nft), time.Since(t))
			metrics.GenerateDurationMS.Observe(float64(time.Since(t).Milliseconds()), "nft")
		}
		t = time.Now()
		if changed, err := system.WriteIfChanged(paths.NFTSetsFile, nftsets.Bytes(), 0644); err != nil {
			return res, err
		} else {
			res.Changed["nftsets"] = changed
			logWrite(log, "generate: nft sets", paths.NFTSetsFile, changed, nftsets.Len(), time.Since(t))
			metrics.GenerateDurationMS.Observe(float64(time.Since(t).Milliseconds()), "nftsets")
		}
	}
	if groups.Firewall {
		if data := FirewallRules(c); len(data) > 0 {
			t := time.Now()
			if changed, err := system.WriteIfChanged(paths.FirewallFile, data, 0600); err != nil {
				return res, err
			} else {
				res.Changed["firewall"] = changed
				logWrite(log, "generate: firewall config", paths.FirewallFile, changed, len(data), time.Since(t))
				metrics.GenerateDurationMS.Observe(float64(time.Since(t).Milliseconds()), "firewall")
			}
		} else {
			log.Debug("generate: firewall config skipped dns_hijack=0")
		}
	}
	if groups.Mwan3 {
		if data := Mwan3Rules(c); len(data) > 0 {
			t := time.Now()
			if changed, err := system.WriteIfChanged(paths.Mwan3File, data, 0600); err != nil {
				return res, err
			} else {
				res.Changed["mwan3"] = changed
				logWrite(log, "generate: mwan3 config", paths.Mwan3File, changed, len(data), time.Since(t))
				metrics.GenerateDurationMS.Observe(float64(time.Since(t).Milliseconds()), "mwan3")
			}
		} else {
			log.Debug("generate: mwan3 config skipped mode=%s", c.Mwan3.Mode)
		}
	}
	if groups.Zapret {
		zapret := ZapretEnv(c)
		t := time.Now()
		if changed, err := system.WriteIfChanged(paths.ZapretEnv, zapret, 0644); err != nil {
			return res, err
		} else {
			res.Changed["zapret"] = changed
			logWrite(log, "generate: zapret env", paths.ZapretEnv, changed, len(zapret), time.Since(t))
			metrics.GenerateDurationMS.Observe(float64(time.Since(t).Milliseconds()), "zapret")
		}
		if paths.ZapretUpstreamConfig != "" {
			upstream := ZapretUpstreamConfig(c)
			t = time.Now()
			if changed, err := system.WriteIfChanged(paths.ZapretUpstreamConfig, upstream, 0644); err != nil {
				// Don't fail apply on this — /opt/zapret2 may not exist yet on
				// devices that haven't adopted the upstream init script. Log
				// and move on.
				log.Warn("generate: zapret2 upstream config write failed (skipping): %v", err)
			} else {
				if changed {
					res.Changed["zapret"] = true
				}
				logWrite(log, "generate: zapret2 upstream config", paths.ZapretUpstreamConfig, changed, len(upstream), time.Since(t))
			}
		}
	}
	if err == nil && !opt.SkipFingerprint {
		_ = writeGenerationFingerprint(c, fp)
		log.Debug("generate: fingerprint updated")
	}
	return res, nil
}

func CommitGenerationFingerprint(c config.Config) error {
	fp, err := currentGenerationFingerprint(c)
	if err != nil {
		return err
	}
	return writeGenerationFingerprint(c, fp)
}

func CacheStatus(c config.Config) string {
	fp, err := currentGenerationFingerprint(c)
	if err != nil {
		return "generation cache: unavailable: " + err.Error()
	}
	unchanged, reason := generationFingerprintState(c, fp)
	paths := DefaultGeneratedPaths(c)
	complete := generatedPathsComplete(c, paths)
	status := "miss"
	if unchanged && complete {
		status = "hit"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "generation cache: %s\nreason: %s\noutputs complete: %v\ngroups:\n", status, reason, complete)
	for _, group := range generationGroupCacheStatuses(c, fp, paths) {
		fmt.Fprintf(&b, "  %s: %s", group.Name, group.Status)
		if group.Reason != "" {
			fmt.Fprintf(&b, " reason=%s", group.Reason)
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "fingerprint: %s\n", fingerprintPath(c))
	return b.String()
}

func dnsmasqFragmentDir(paths GeneratedPaths) string {
	if paths.DNSMasqFragmentDir != "" {
		return paths.DNSMasqFragmentDir
	}
	return filepath.Dir(paths.DNSMasqFile)
}

func DNSMasqFragmentPath(dir string, section config.Section) string {
	return filepath.Join(dir, fmt.Sprintf("purewrt-%06d-%s.dnsmasq", dnsmasqFragmentPriority(section), safeFragmentName(section.Name)))
}

func dnsmasqFragmentPriority(section config.Section) int {
	switch section.Name {
	case "direct":
		return 1
	case "reject":
		return 2
	}
	if section.Priority > 0 {
		return section.Priority
	}
	return 1000
}

func safeFragmentName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "section"
	}
	return out
}

func WriteDNSMasqFragments(c config.Config, paths GeneratedPaths, fragments map[string]*bytes.Buffer) (bool, error) {
	dir := dnsmasqFragmentDir(paths)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, err
	}
	changed := false
	expected := map[string]struct{}{}
	for _, section := range dnsmasqFragmentSections(c, fragments) {
		buf := fragments[section.Name]
		if buf == nil || buf.Len() == 0 {
			continue
		}
		var out bytes.Buffer
		if err := WriteDNSMasqHeader(&out); err != nil {
			return changed, err
		}
		if _, err := out.Write(buf.Bytes()); err != nil {
			return changed, err
		}
		path := DNSMasqFragmentPath(dir, section)
		expected[filepath.Base(path)] = struct{}{}
		fileChanged, err := system.WriteIfChanged(path, out.Bytes(), 0644)
		if err != nil {
			return changed, err
		}
		changed = changed || fileChanged
	}
	removed, err := cleanupDNSMasqFragments(dir, expected)
	return changed || removed, err
}

func dnsmasqFragmentSections(c config.Config, fragments map[string]*bytes.Buffer) []config.Section {
	out := make([]config.Section, 0, len(fragments))
	for name := range fragments {
		if sec, ok := c.SectionByName(name); ok {
			out = append(out, sec)
			continue
		}
		out = append(out, virtualSection(name))
	}
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := dnsmasqFragmentPriority(out[i]), dnsmasqFragmentPriority(out[j])
		if pi == pj {
			return out[i].Name < out[j].Name
		}
		return pi < pj
	})
	return out
}

func virtualSection(name string) config.Section {
	switch name {
	case "direct":
		return config.Section{Name: "direct", Action: "direct", IPv4Enabled: true, IPv6Enabled: true}
	case "reject":
		return config.Section{Name: "reject", Action: "reject", IPv4Enabled: true, IPv6Enabled: true}
	default:
		return config.Section{Name: name, Priority: 1000, IPv4Enabled: true, IPv6Enabled: true}
	}
}

func cleanupDNSMasqFragments(dir string, expected map[string]struct{}) (bool, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "purewrt-*.dnsmasq"))
	if err != nil {
		return false, err
	}
	removed := false
	for _, path := range matches {
		if _, ok := expected[filepath.Base(path)]; ok {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		removed = true
	}
	return removed, nil
}

func outputDirs(c config.Config, paths GeneratedPaths) []string {
	var dirs []string
	base := []string{paths.MihomoConfig, dnsmasqFragmentDir(paths), paths.NFTFile, paths.NFTSetsFile, paths.ZapretEnv}
	if len(FirewallRules(c)) > 0 {
		base = append(base, paths.FirewallFile)
	}
	if len(Mwan3Rules(c)) > 0 {
		base = append(base, paths.Mwan3File)
	}
	for _, path := range base {
		if path != "" {
			dirs = append(dirs, filepath.Dir(path))
		}
	}
	return dirs
}

// logWrite emits a single info line summarising a generated output: path,
// changed flag, byte size, and elapsed wall time. Pass took=0 to omit the
// timing field. Replaces the older split between Info "wrote/unchanged" and
// Debug "size=" — keeps one observable line at info level for operators
// watching apply progress, with the timing detail useful for diagnosing
// slow stages.
func logWrite(log logging.Logger, what, path string, changed bool, size int, took time.Duration) {
	status := "wrote"
	if !changed {
		status = "unchanged"
	}
	if took > 0 {
		log.Info("%s %s path=%s changed=%v bytes=%d took=%v", what, status, path, changed, size, took)
	} else {
		log.Info("%s %s path=%s changed=%v bytes=%d", what, status, path, changed, size)
	}
}

func generatedPathsComplete(c config.Config, paths GeneratedPaths) bool {
	for _, path := range []string{paths.MihomoConfig, paths.NFTFile, paths.NFTSetsFile, paths.ZapretEnv} {
		if path == "" {
			return false
		}
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return false
		}
	}
	if info, err := os.Stat(dnsmasqFragmentDir(paths)); err != nil || !info.IsDir() {
		return false
	}
	if len(FirewallRules(c)) > 0 {
		if info, err := os.Stat(paths.FirewallFile); err != nil || info.IsDir() {
			return false
		}
	}
	if len(Mwan3Rules(c)) > 0 {
		if info, err := os.Stat(paths.Mwan3File); err != nil || info.IsDir() {
			return false
		}
	}
	return true
}
