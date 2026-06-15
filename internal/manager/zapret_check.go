package manager

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/rules"
	"github.com/purewrt/purewrt/internal/system"
)

var zapretBlockcheckPaths = []string{
	"/usr/libexec/zapret/blockcheck2.sh",
	"/opt/zapret2/blockcheck2.sh",
	"/opt/zapret/blockcheck2.sh",
}

type ZapretCheckOptions struct {
	Interface string
	ScanLevel string
	Repeats   string
	HTTP      string
	TLS12     string
	TLS13     string
	HTTP3     string
	HTTPSGet  string
	SkipDNS   string
	SkipIP    string
}

func (m Manager) ZapretCheckStrategy(domain string, wanInterface ...string) (string, error) {
	opt := ZapretCheckOptions{}
	if len(wanInterface) > 0 {
		opt.Interface = wanInterface[0]
	}
	return m.ZapretCheckStrategyWithOptions(domain, opt)
}

func (m Manager) ZapretCheckStrategyWithOptions(domain string, opt ZapretCheckOptions) (string, error) {
	return m.zapretCheckStrategyWithOptions(domain, opt, nil)
}

func (m Manager) ZapretCheckStrategyWithOptionsWriter(domain string, opt ZapretCheckOptions, w io.Writer) error {
	_, err := m.zapretCheckStrategyWithOptions(domain, opt, w)
	return err
}

func (m Manager) zapretCheckStrategyWithOptions(domain string, opt ZapretCheckOptions, w io.Writer) (string, error) {
	domain = strings.TrimSpace(domain)
	iface := strings.TrimSpace(opt.Interface)
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}
	if strings.ContainsAny(domain, " \t\r\n;&|`$()<>\"'") {
		return "", fmt.Errorf("domain contains unsupported characters")
	}
	if iface != "" && strings.ContainsAny(iface, " \t\r\n;&|`$()<>\"'") {
		return "", fmt.Errorf("interface contains unsupported characters")
	}
	if iface != "" {
		if _, err := net.InterfaceByName(iface); err != nil {
			return "", fmt.Errorf("interface %q not found", iface)
		}
	}

	script := firstExisting(zapretBlockcheckPaths)
	if script == "" {
		return "", fmt.Errorf("zapret blockcheck2.sh not found; install zapret package with blockcheck2 support")
	}

	c, _ := m.Load()
	warning := zapretCheckRuleWarning(c, domain)
	excluded, excludeOut := m.temporarilyExcludeZapretCheckDomain(ctxForDNS(), domain)
	if excluded {
		defer m.removeTemporaryZapretCheckExclusion(domain)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, script)
	cmd.Env = append(os.Environ(),
		"BATCH=1",
		"DOMAINS="+domain,
		"CURL_CMD=1",
		"CURL_MAX_TIME=4",
		"CURL_MAX_TIME_QUIC=4",
		"CURL_MAX_TIME_DOH=4",
		"SCANLEVEL="+defaultChoice(opt.ScanLevel, "quick", "quick", "standard", "force"),
		"REPEATS="+defaultNumber(opt.Repeats, "1"),
		"SKIP_DNSCHECK="+defaultBool(opt.SkipDNS, "1"),
		"SKIP_IPBLOCK="+defaultBool(opt.SkipIP, "1"),
		"ENABLE_HTTP="+defaultBool(opt.HTTP, "0"),
		"ENABLE_HTTPS_TLS12="+defaultBool(opt.TLS12, "1"),
		"ENABLE_HTTPS_TLS13="+defaultBool(opt.TLS13, "1"),
		"ENABLE_HTTP3="+defaultBool(opt.HTTP3, "0"),
		"CURL_HTTPS_GET="+defaultBool(opt.HTTPSGet, "0"),
	)
	if iface != "" {
		cmd.Env = append(cmd.Env, "CURL_OPT=--interface "+iface+" --connect-timeout 2 --max-time 4")
	}
	if bin := firstZapretNFQWSBin(c); bin != "" {
		cmd.Env = append(cmd.Env, "PKTWSD="+bin)
	}

	prefix := zapretCheckInterfaceMessage(iface) + zapretCheckExclusionMessage(domain, excluded, excludeOut) + warning
	if w != nil && prefix != "" {
		_, _ = io.WriteString(w, prefix)
	}
	out := &limitedBuffer{limit: 512 * 1024}
	cmdOut := io.Writer(out)
	if w != nil {
		cmdOut = io.MultiWriter(out, w)
	}
	cmd.Stdout = cmdOut
	cmd.Stderr = cmdOut
	err := cmd.Run()
	raw := out.String()
	summary := zapretCheckStrategySummary(raw)
	if w != nil && summary != "" {
		_, _ = io.WriteString(w, summary)
	}
	result := prefix + raw + summary
	if ctx.Err() == context.DeadlineExceeded {
		return result, fmt.Errorf("zapret strategy check timed out")
	}
	if err != nil {
		return result, fmt.Errorf("zapret strategy check failed: %w", err)
	}
	return result, nil
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 || b.buf.Len() >= b.limit {
		b.truncated = true
		return len(p), nil
	}
	remain := b.limit - b.buf.Len()
	if len(p) > remain {
		_, _ = b.buf.Write(p[:remain])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	out := b.buf.String()
	if b.truncated {
		out += "\n[PureWRT: zapret-check output truncated]\n"
	}
	return out
}

func defaultChoice(v, d string, allowed ...string) string {
	v = strings.TrimSpace(v)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return d
}

func defaultBool(v, d string) string {
	v = strings.TrimSpace(v)
	if v == "0" || v == "1" {
		return v
	}
	return d
}

func defaultNumber(v, d string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return d
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return d
		}
	}
	return v
}

func zapretCheckStrategySummary(out string) string {
	strategies := parseZapretStrategies(out)
	if len(strategies) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\nPureWRT parsed working strategies:\n")
	for i, s := range strategies {
		b.WriteString(fmt.Sprintf("[%d] %s\n", i+1, s))
	}
	return b.String()
}

func parseZapretStrategies(out string) []string {
	var res []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "working strategy found") || !strings.Contains(line, "!!!!!") {
			continue
		}
		parts := strings.Split(line, " : ")
		if len(parts) < 2 {
			continue
		}
		strategy := strings.TrimSpace(parts[len(parts)-1])
		strategy = strings.TrimSuffix(strategy, "!!!!!")
		strategy = strings.TrimSpace(strategy)
		fields := strings.Fields(strategy)
		if len(fields) > 1 && !strings.HasPrefix(fields[0], "--") {
			strategy = strings.Join(fields[1:], " ")
		}
		if strategy == "" {
			continue
		}
		if _, ok := seen[strategy]; ok {
			continue
		}
		seen[strategy] = struct{}{}
		res = append(res, strategy)
	}
	return res
}

func firstZapretNFQWSBin(c config.Config) string {
	for _, p := range c.EnabledZapretProfiles() {
		if p.NFQWSBin != "" {
			return p.NFQWSBin
		}
	}
	return ""
}

func zapretCheckInterfaceMessage(iface string) string {
	if iface == "" {
		return ""
	}
	return fmt.Sprintf("Running Zapret check with curl bound to interface %s.\n\n", iface)
}

func ctxForDNS() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}

func (m Manager) temporarilyExcludeZapretCheckDomain(ctx context.Context, domain string) (bool, string) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil || len(ips) == 0 {
		if err != nil {
			return false, "DNS resolve failed for temporary bypass: " + err.Error() + "\n\n"
		}
		return false, "DNS resolve returned no addresses for temporary bypass.\n\n"
	}
	r := system.Runner{DryRun: m.DryRun, Timeout: 10 * time.Second}
	var notes []string
	added := false
	for _, ip := range ips {
		cmd := zapretCheckBypassAddCommand(ip.String())
		if len(cmd) == 0 {
			continue
		}
		out, err := r.Run(cmd[0], cmd[1:]...)
		if err != nil {
			notes = append(notes, strings.TrimSpace(out))
			continue
		}
		added = true
	}
	if !added {
		return false, strings.Join(notes, "\n")
	}
	return true, "Temporarily added resolved check-domain IPs to PureWRT bypass sets.\n\n"
}

func (m Manager) removeTemporaryZapretCheckExclusion(domain string) {
	ctx := ctxForDNS()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return
	}
	r := system.Runner{DryRun: m.DryRun, Timeout: 10 * time.Second}
	for _, ip := range ips {
		cmd := zapretCheckBypassDeleteCommand(ip.String())
		if len(cmd) > 0 {
			_, _ = r.Run(cmd[0], cmd[1:]...)
		}
	}
}

func zapretCheckBypassAddCommand(ip string) []string {
	set := "bypass4"
	if strings.Contains(ip, ":") {
		set = "bypass6"
	}
	return []string{"nft", "add", "element", "inet", "purewrt", set, "{", ip, "}"}
}

func zapretCheckBypassDeleteCommand(ip string) []string {
	set := "bypass4"
	if strings.Contains(ip, ":") {
		set = "bypass6"
	}
	return []string{"nft", "delete", "element", "inet", "purewrt", set, "{", ip, "}"}
}

func zapretCheckExclusionMessage(domain string, excluded bool, detail string) string {
	if detail != "" {
		return detail
	}
	if excluded {
		return "Temporarily bypassing current PureWRT routing for " + domain + ".\n\n"
	}
	return ""
}

func zapretCheckRuleWarning(c config.Config, domain string) string {
	for _, rp := range c.RuleProviders {
		if !rp.Enabled || rp.Path == "" || rp.Section == "" {
			continue
		}
		sec, ok := c.SectionByName(rp.Section)
		if !ok || sec.Action == "zapret" {
			continue
		}
		data, err := os.ReadFile(rp.Path)
		if err != nil {
			continue
		}
		provider := rules.ParseText(rp.Name, data)
		for _, r := range provider.Rules {
			if r.Type != rules.Domain && r.Type != rules.DomainSuffix {
				continue
			}
			if domain == r.Value || strings.HasSuffix(domain, "."+r.Value) {
				return fmt.Sprintf("Warning: %s matches rule provider %q in section %q with action %q. PureWRT will temporarily bypass resolved IPs during the check.\n\n", domain, rp.Name, rp.Section, sec.Action)
			}
		}
	}
	return ""
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
