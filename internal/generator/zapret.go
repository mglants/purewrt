package generator

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

func ZapretEnv(c config.Config) []byte {
	var b strings.Builder
	instances := zapretInstances(c)
	b.WriteString("PUREWRT_ZAPRET_ENABLED=")
	if len(instances) > 0 {
		b.WriteString("1\n")
	} else {
		b.WriteString("0\n")
	}
	var names []string
	for _, inst := range instances {
		names = append(names, shellQuote(inst.strategy.Name))
	}
	b.WriteString("PUREWRT_ZAPRET_INSTANCES=\"" + strings.Join(names, " ") + "\"\n")
	for i, inst := range instances {
		p := inst.profile
		zs := inst.strategy
		prefix := fmt.Sprintf("PUREWRT_ZAPRET_INSTANCE_%d_", i)
		b.WriteString(prefix + "NAME=\"" + shellEscape(zs.Name) + "\"\n")
		b.WriteString(prefix + "PROFILE=\"" + shellEscape(p.Name) + "\"\n")
		b.WriteString(prefix + "QUEUE=\"" + itoa(zs.QueueNum) + "\"\n")
		b.WriteString(prefix + "FWMARK=\"" + shellEscape(p.FwMark) + "\"\n")
		b.WriteString(prefix + "NFQWS=\"" + shellEscape(p.NFQWSBin) + "\"\n")
		b.WriteString(prefix + "PARAMS=\"" + shellEscape(zs.Params) + "\"\n")
	}
	b.WriteString("PUREWRT_ZAPRET_INSTANCE_COUNT=\"" + itoa(len(instances)) + "\"\n")
	return []byte(b.String())
}

type zapretInstance struct {
	profile  config.ZapretProfile
	strategy config.ZapretStrategy
}

func zapretInstances(c config.Config) []zapretInstance {
	seen := map[string]bool{}
	out := []zapretInstance{}
	for _, sec := range c.Sections {
		if !sec.Enabled || sec.Action != "zapret" {
			continue
		}
		for _, name := range sec.ZapretStrategies {
			if seen[name] {
				continue
			}
			zs, ok := c.ZapretStrategyByName(name)
			if !ok {
				continue
			}
			p, ok := c.ZapretProfileByName(zs.Profile)
			if !ok {
				continue
			}
			seen[name] = true
			out = append(out, zapretInstance{profile: p, strategy: zs})
		}
	}
	return out
}

func shellEscape(s string) string { return strings.ReplaceAll(s, "\"", "\\\"") }

func shellQuote(s string) string { return strings.ReplaceAll(s, " ", "_") }

// ZapretUpstreamConfig compiles the enabled UCI zapret_strategy sections into
// the single-NFQWS2_OPT shell file that upstream zapret2's init.d script
// (/etc/init.d/zapret2) expects to source from /opt/zapret2/config.
//
// Shape:
//
//	NFQWS2_ENABLE=1
//	NFQWS2_OPT="--lua-init=@<lua>/zapret-lib.lua --lua-init=@<lua>/zapret-antidpi.lua \
//	            --lua-init=@<lua>/zapret-auto.lua \
//	            <strategy-1 protocol/port + params> --new \
//	            <strategy-2 protocol/port + params> --new \
//	            ..."
//
// Each enabled strategy becomes one `--new`-separated profile. nfqws2
// evaluates profiles in order; PureWRT's nftables hook is what selects
// which traffic enters the NFQUEUE, so the per-profile filter only has to
// distinguish protocol/port — no --ipset= / --hostlist= clauses needed.
func ZapretUpstreamConfig(c config.Config) []byte {
	instances := zapretInstances(c)
	var b strings.Builder
	b.WriteString("# PureWRT generated file; do not edit.\n")
	b.WriteString("# Source from /etc/init.d/zapret2 to get the compiled NFQWS2_OPT.\n\n")
	if len(instances) == 0 {
		b.WriteString("NFQWS2_ENABLE=0\n")
		b.WriteString("NFQWS2_OPT=\"\"\n")
		return []byte(b.String())
	}

	luaDir := zapretLuaBundleDir(instances)
	// Global head (before the first --new): the mandatory --lua-init scripts
	// plus --ctrack-disable=0 to keep nfqws2's connection tracking ON. L7
	// detection (--filter-l7, MTProto) silently no-ops without ctrack, and
	// it's harmless for non-L7 strategies — so always enable it in the head.
	clauses := []string{
		zapretLuaInit(luaDir) + " --ctrack-disable=0" + zapretBlobFlags(instances),
	}
	for _, inst := range instances {
		clauses = append(clauses, zapretProfileClause(inst.strategy))
	}
	opt := strings.Join(filterEmpty(clauses), " --new ")

	b.WriteString("NFQWS2_ENABLE=1\n")
	fmt.Fprintf(&b, "NFQWS2_OPT=\"%s\"\n", shellEscape(opt))
	return []byte(b.String())
}

// zapretLuaBundleDir picks the Lua bundle dir from the first instance's
// profile. Mixed bundles across profiles aren't supported by upstream
// (one daemon, one set of --lua-init), so first-wins is correct.
func zapretLuaBundleDir(instances []zapretInstance) string {
	for _, inst := range instances {
		if inst.profile.LuaBundleDir != "" {
			return inst.profile.LuaBundleDir
		}
	}
	return "/opt/zapret2/lua"
}

// zapretLuaInit returns the leading --lua-init flags that make named blobs
// (fake_default_tls, fake_default_http, fake_default_quic) resolvable. The
// three scripts come from upstream zapret2; missing them silently breaks
// any strategy that references those blob names.
func zapretLuaInit(luaDir string) string {
	scripts := []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"}
	parts := make([]string, 0, len(scripts))
	for _, s := range scripts {
		parts = append(parts, "--lua-init=@"+filepath.Join(luaDir, s))
	}
	return strings.Join(parts, " ")
}

// zapretBlobFlags renders custom blob declarations for the global head. Blobs
// are global to the single nfqws2 daemon, so we union them across every enabled
// profile and dedup by name (the part before the first ':'). Each entry is the
// raw nfqws2 form "name:@/path" or "name:0xHEX". Entries that are empty, lack a
// name:value shape, or contain whitespace (which would split the --blob arg)
// are skipped. Returns a leading-space string ("" when there are none).
func zapretBlobFlags(instances []zapretInstance) string {
	seen := map[string]bool{}
	var parts []string
	for _, inst := range instances {
		for _, raw := range inst.profile.Blobs {
			entry := strings.TrimSpace(raw)
			if entry == "" || strings.ContainsAny(entry, " \t\r\n\"") {
				continue
			}
			name, value, ok := strings.Cut(entry, ":")
			if !ok || name == "" || seen[name] {
				continue
			}
			seen[name] = true
			// A file-backed blob ("name:@<path>") is rewritten to its canonical
			// resolved path (shipped fake dir, else the /etc fetch cache) so the
			// emitted --blob points where the manager's blob fetch lands — the
			// staged path (e.g. a hardcoded /usr/libexec/... from the LuCI editor)
			// is only a filename hint. Inline-hex ("name:0x…") passes through.
			if file, isFile := strings.CutPrefix(value, "@"); isFile {
				entry = name + ":@" + config.CanonicalBlobPath(file)
			}
			parts = append(parts, "--blob="+entry)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}

// ZapretRequiredBlobFiles returns the basenames of every file-backed blob that
// the enabled zapret instances will emit — the set the manager must ensure is
// present (fetching missing decoys) before generation. Inline-hex blobs are
// excluded. Pure; deduped by filename.
func ZapretRequiredBlobFiles(c config.Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, inst := range zapretInstances(c) {
		for _, raw := range inst.profile.Blobs {
			entry := strings.TrimSpace(raw)
			if entry == "" || strings.ContainsAny(entry, " \t\r\n\"") {
				continue
			}
			_, value, ok := strings.Cut(entry, ":")
			if !ok {
				continue
			}
			file, isFile := strings.CutPrefix(value, "@")
			if !isFile || file == "" {
				continue
			}
			base := filepath.Base(file)
			if seen[base] {
				continue
			}
			seen[base] = true
			out = append(out, base)
		}
	}
	return out
}

// zapretProfileClause turns one UCI strategy into the protocol/port filter
// + params clause that goes between --new separators. The strategy's own
// Params can already include filter flags; in that case we don't re-add
// them.
func zapretProfileClause(zs config.ZapretStrategy) string {
	if strings.Contains(zs.Params, "--filter-tcp") || strings.Contains(zs.Params, "--filter-udp") {
		return strings.TrimSpace(zs.Params)
	}
	var parts []string
	parts = append(parts, "--name="+shellSafeName(zs.Name))
	for _, p := range strategyPortFilters(zs) {
		parts = append(parts, p)
	}
	// Packet-count limit → --out-range=-d<N>. These fields were previously
	// stored but never emitted; render the relevant one for the strategy's
	// protocol so the desync only touches the first N data packets.
	if n := zapretOutRange(zs); n > 0 {
		parts = append(parts, "--out-range=-d"+itoa(n))
	}
	if zs.Params != "" {
		parts = append(parts, strings.TrimSpace(zs.Params))
	}
	return strings.Join(parts, " ")
}

// zapretOutRange picks the packet-count limit for the strategy's protocol. TCP
// takes precedence when both are set (rare); 0 means "no limit" (omit).
func zapretOutRange(zs config.ZapretStrategy) int {
	for _, proto := range zs.Protocols {
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "tcp":
			if zs.TCPPktOut > 0 {
				return zs.TCPPktOut
			}
		case "udp":
			if zs.UDPPktOut > 0 {
				return zs.UDPPktOut
			}
		}
	}
	return 0
}

// strategyPortFilters renders --filter-tcp / --filter-udp pairs from the
// UCI strategy's Protocols + ports, one filter per (protocol, ports) combo.
func strategyPortFilters(zs config.ZapretStrategy) []string {
	out := []string{}
	for _, proto := range zs.Protocols {
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "tcp":
			if zs.TCPPorts != "" {
				out = append(out, "--filter-tcp="+zs.TCPPorts)
			} else {
				out = append(out, "--filter-tcp=*")
			}
		case "udp":
			if zs.UDPPorts != "" {
				out = append(out, "--filter-udp="+zs.UDPPorts)
			} else {
				out = append(out, "--filter-udp=*")
			}
		}
	}
	return out
}

func shellSafeName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "profile"
	}
	return string(out)
}

func filterEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
