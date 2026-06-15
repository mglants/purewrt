package manager

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/config"
)

var (
	osMkdirAll  = os.MkdirAll
	osWriteFile = os.WriteFile
)

// ZapretAutotuneOptions controls a single autotune run.
type ZapretAutotuneOptions struct {
	Hosts         []string      // canary domains; ≥1 required
	Timeout       time.Duration // 0 -> 15 minutes (blockcheck is slow)
	Binary        string        // override for /usr/libexec/zapret/blockcheck2.sh
	EnableHTTP    bool          // default true
	EnableTLS12   bool          // default true
	EnableTLS13   bool          // default true
	EnableHTTP3   bool          // default true
	ScanLevel     string        // standard|force, default standard
	WriteUCI      bool          // when true, materialize discovered strategies into UCI
	StrategyName  string        // base for generated UCI names (default "autotune")
	TranscriptDir string        // where to save the raw blockcheck stdout (default $RuntimeDir/zapret-autotune)
}

// ZapretAutotuneResult is the parsed outcome.
type ZapretAutotuneResult struct {
	Hosts         []string                `json:"hosts"`
	PerHost       []ZapretAutotuneStrategy `json:"per_host"`
	Common        []ZapretAutotuneStrategy `json:"common"`
	Strategies    []config.ZapretStrategy `json:"materialized,omitempty"`
	TranscriptPath string                 `json:"transcript_path,omitempty"`
	ExitCode      int                     `json:"exit_code"`
}

// ZapretAutotuneStrategy is one winning desync clause from blockcheck output.
type ZapretAutotuneStrategy struct {
	Host     string `json:"host,omitempty"`     // empty when this row came from the COMMON intersection
	IPVer    int    `json:"ip_version"`         // 4 or 6, 0 for COMMON
	Daemon   string `json:"daemon"`             // nfqws, dvtws, etc.
	TestFunc string `json:"test_func,omitempty"`
	Strategy string `json:"strategy"`           // the raw nfqws clause
	Protocol string `json:"protocol,omitempty"` // tcp | udp | "" (inferred from --filter-tcp/--filter-udp)
	Ports    string `json:"ports,omitempty"`    // value of --filter-tcp= / --filter-udp= when present
}

// ZapretAutotune runs blockcheck2.sh against opts.Hosts and parses its
// output. When WriteUCI is true, the COMMON intersection (preferred) or the
// per-host winners are converted into one config.ZapretStrategy per unique
// (protocol, ports) tuple and saved.
func (m Manager) ZapretAutotune(opts ZapretAutotuneOptions) (ZapretAutotuneResult, error) {
	if len(opts.Hosts) == 0 {
		return ZapretAutotuneResult{}, fmt.Errorf("zapret-autotune: at least one canary host is required")
	}
	c, err := m.Load()
	if err != nil {
		return ZapretAutotuneResult{}, err
	}
	bin := opts.Binary
	if bin == "" {
		bin = "/usr/libexec/zapret/blockcheck2.sh"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	log := newLog(c)
	log.Info("zapret-autotune: starting blockcheck=%s hosts=%v timeout=%s", bin, opts.Hosts, timeout)

	stdout, code, runErr := runBlockcheck(bin, opts, timeout)
	res := parseBlockcheckOutput(stdout, opts.Hosts)
	res.ExitCode = code
	if path, err := persistTranscript(c, opts, stdout); err == nil {
		res.TranscriptPath = path
	}
	if runErr != nil && len(res.Common) == 0 && len(res.PerHost) == 0 {
		return res, fmt.Errorf("zapret-autotune: blockcheck failed and produced no strategies: %w", runErr)
	}

	if opts.WriteUCI {
		strategies := chooseAutotuneStrategies(res, opts.StrategyName)
		if len(strategies) == 0 {
			return res, fmt.Errorf("zapret-autotune: no strategies survived parsing — check transcript %s", res.TranscriptPath)
		}
		c2 := applyAutotuneStrategiesToConfig(c, strategies)
		if err := config.Save(m.ConfigPath, c2); err != nil {
			return res, err
		}
		res.Strategies = strategies
	}
	return res, nil
}

// runBlockcheck executes blockcheck2.sh under a timeout, returning stdout,
// exit code, and any wrapper error. blockcheck prints progress as it runs;
// we don't tee to anywhere live — the transcript is persisted post-hoc.
func runBlockcheck(bin string, opts ZapretAutotuneOptions, timeout time.Duration) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", bin)
	cmd.Env = blockcheckEnv(opts)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout // blockcheck logs progress on stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	}
	return stdout.Bytes(), code, err
}

func blockcheckEnv(opts ZapretAutotuneOptions) []string {
	env := []string{
		"BATCH=1",
		"DOMAINS=" + strings.Join(opts.Hosts, " "),
	}
	if opts.ScanLevel != "" {
		env = append(env, "SCANLEVEL="+opts.ScanLevel)
	}
	if opts.EnableHTTP {
		env = append(env, "ENABLE_HTTP=1")
	}
	if opts.EnableTLS12 {
		env = append(env, "ENABLE_HTTPS_TLS12=1")
	}
	if opts.EnableTLS13 {
		env = append(env, "ENABLE_HTTPS_TLS13=1")
	}
	if opts.EnableHTTP3 {
		env = append(env, "ENABLE_HTTP3=1")
	}
	return env
}

// blockcheckWinningRE matches the `!!!!! <func>: working strategy found for
// ipv<N> <host> : <daemon> <strategy> !!!!!` line emitted by report_strategy.
var blockcheckWinningRE = regexp.MustCompile(
	`!!!!! ([A-Za-z0-9_]+): working strategy found for ipv(\d+) (\S+) : (\S+) (.+?) !!!!!`,
)

// parseBlockcheckOutput extracts per-host winners and the multi-host COMMON
// intersection from blockcheck2.sh stdout. The COMMON block is delimited by
// the "* COMMON" header and ends at "Please note this SUMMARY" or EOF.
func parseBlockcheckOutput(stdout []byte, hosts []string) ZapretAutotuneResult {
	res := ZapretAutotuneResult{Hosts: hosts}

	for _, m := range blockcheckWinningRE.FindAllStringSubmatch(string(stdout), -1) {
		ipv := 0
		fmt.Sscanf(m[2], "%d", &ipv)
		strat := strings.TrimSpace(m[5])
		entry := ZapretAutotuneStrategy{
			TestFunc: m[1],
			IPVer:    ipv,
			Host:     m[3],
			Daemon:   m[4],
			Strategy: strat,
		}
		entry.Protocol, entry.Ports = inferProtocolPorts(strat)
		res.PerHost = append(res.PerHost, entry)
	}

	if start := bytes.Index(stdout, []byte("* COMMON")); start >= 0 {
		tail := stdout[start:]
		end := bytes.Index(tail, []byte("Please note this SUMMARY"))
		if end < 0 {
			end = len(tail)
		}
		for _, line := range strings.Split(string(tail[:end]), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "--") {
				continue
			}
			entry := ZapretAutotuneStrategy{Strategy: line, Daemon: "nfqws"}
			entry.Protocol, entry.Ports = inferProtocolPorts(line)
			res.Common = append(res.Common, entry)
		}
	}
	return res
}

func inferProtocolPorts(strat string) (string, string) {
	if m := regexp.MustCompile(`--filter-tcp=(\S+)`).FindStringSubmatch(strat); m != nil {
		return "tcp", m[1]
	}
	if m := regexp.MustCompile(`--filter-udp=(\S+)`).FindStringSubmatch(strat); m != nil {
		return "udp", m[1]
	}
	return "", ""
}

// chooseAutotuneStrategies promotes either the COMMON intersection (when
// present — the multi-host blockcheck has found a strategy that worked for
// every canary) or, failing that, the first winning per-host entry per
// (protocol, ports) pair. Returns one config.ZapretStrategy per pair.
func chooseAutotuneStrategies(res ZapretAutotuneResult, baseName string) []config.ZapretStrategy {
	if baseName == "" {
		baseName = "autotune"
	}
	picks := res.Common
	if len(picks) == 0 {
		picks = res.PerHost
	}
	seen := map[string]bool{}
	out := []config.ZapretStrategy{}
	for _, p := range picks {
		key := p.Protocol + "|" + p.Ports
		if seen[key] {
			continue
		}
		seen[key] = true
		name := fmt.Sprintf("%s_%s_%s", baseName, p.Protocol, sanitizeName(p.Ports))
		zs := config.ZapretStrategy{
			Name:    name,
			Enabled: true,
			Profile: "wan",
			Preset:  "custom",
			Params:  p.Strategy,
		}
		if p.Protocol != "" {
			zs.Protocols = []string{p.Protocol}
		}
		switch p.Protocol {
		case "tcp":
			zs.TCPPorts = p.Ports
		case "udp":
			zs.UDPPorts = p.Ports
		}
		out = append(out, zs)
	}
	return out
}

func sanitizeName(s string) string {
	r := strings.NewReplacer(",", "_", "-", "_", "*", "any")
	out := r.Replace(s)
	if out == "" {
		return "all"
	}
	return out
}

// applyAutotuneStrategiesToConfig adds (or replaces by name) the discovered
// strategies into c. Existing strategies with the same name are overwritten;
// unrelated strategies are preserved.
func applyAutotuneStrategiesToConfig(c config.Config, strategies []config.ZapretStrategy) config.Config {
	byName := map[string]int{}
	for i, zs := range c.ZapretStrategies {
		byName[zs.Name] = i
	}
	for _, zs := range strategies {
		if idx, ok := byName[zs.Name]; ok {
			c.ZapretStrategies[idx] = zs
		} else {
			c.ZapretStrategies = append(c.ZapretStrategies, zs)
		}
	}
	return c
}

// persistTranscript writes the raw blockcheck stdout under the runtime dir so
// the user can review what blockcheck actually emitted. Path is timestamped
// so concurrent autotune runs don't clobber each other.
func persistTranscript(c config.Config, opts ZapretAutotuneOptions, stdout []byte) (string, error) {
	dir := opts.TranscriptDir
	if dir == "" {
		runtime := c.Settings.RuntimeDir
		if runtime == "" {
			runtime = config.DefaultRuntimeDir
		}
		dir = filepath.Join(runtime, "zapret-autotune")
	}
	if err := osMkdirAll(dir, 0700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("blockcheck-%s.log", time.Now().UTC().Format("20060102-150405"))
	path := filepath.Join(dir, name)
	return path, osWriteFile(path, stdout, 0600)
}
