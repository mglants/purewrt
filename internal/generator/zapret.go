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
	if len(instances) == 0 {
		b.WriteString("PUREWRT_ZAPRET_INSTANCE_COUNT=\"0\"\n")
		return []byte(b.String())
	}
	p := instances[0].profile
	params, blobs := zapretSharedParams(instances)
	b.WriteString("PUREWRT_ZAPRET_INSTANCES=\"shared\"\nPUREWRT_ZAPRET_INSTANCE_COUNT=\"1\"\n")
	fields := [][2]string{{"NAME", "shared"}, {"PROFILE", "shared"}, {"QUEUE", itoa(config.ZapretQueueBase)}, {"FWMARK", p.FwMark}, {"NFQWS", p.NFQWSBin}, {"PARAMS", params}, {"BLOBS", blobs}}
	for _, field := range fields {
		fmt.Fprintf(&b, "PUREWRT_ZAPRET_INSTANCE_0_%s=\"%s\"\n", field[0], shellEscape(field[1]))
	}
	return []byte(b.String())
}

// Each assignment retains its own filters, including every TCP/UDP --new
// clause. Blob aliases are namespaced because nfqws declarations are global.
func zapretSharedParams(instances []zapretInstance) (string, string) {
	var profiles, blobs []string
	catalog := zapretCatalogBlobFiles()
	for _, inst := range instances {
		params := zapretProfileClause(inst.strategy)
		aliases := map[string]string{}
		for _, flag := range strings.Fields(zapretInstanceBlobFlags(inst, catalog)) {
			name, value, ok := strings.Cut(strings.TrimPrefix(flag, "--blob="), ":")
			if !ok {
				continue
			}
			alias := fmt.Sprintf("pw_%x_%s", inst.strategy.SelectorMark, name)
			aliases[name] = alias
			blobs = append(blobs, "--blob="+alias+":"+value)
		}
		tokens := strings.Fields(params)
		selector := fmt.Sprintf("--filter-mark=0x%x/0x%x", inst.strategy.SelectorMark, config.ZapretSelectorMask)
		out := []string{selector}
		for _, token := range tokens {
			// Classification belongs to PureWRT, never to a library entry.
			if strings.HasPrefix(token, "--filter-mark=") {
				continue
			}
			if token == "--new" {
				out = append(out, token, selector)
				continue
			}
			segments := strings.Split(token, ":")
			for i, segment := range segments {
				key, value, ok := strings.Cut(segment, "=")
				if ok && (key == "blob" || key == "seqovl_pattern") && aliases[value] != "" {
					segments[i] = key + "=" + aliases[value]
				}
			}
			out = append(out, strings.Join(segments, ":"))
		}
		profiles = append(profiles, strings.Join(out, " "))
	}
	return strings.Join(profiles, " --new "), strings.Join(blobs, " ")
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

// ZapretUpstreamConfig previews the shared daemon's profiles, selectors and
// namespaced blobs. The service launches the equivalent parameters from env.
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
	params, blobs := zapretSharedParams(instances)
	opt := zapretLuaInit(luaDir) + " --bind-fix4 --bind-fix6 --ctrack-disable=0 " + blobs + " " + params

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

// zapretInstanceBlobFlags renders the --blob= decls for ONE instance — used by
// the shared compiler before namespacing each assignment's blob aliases.
// Leading-space string ("" when none).
func zapretInstanceBlobFlags(inst zapretInstance, catalog map[string]string) string {
	parts := appendInstanceBlobFlags(nil, map[string]bool{}, inst, catalog)
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}

// appendInstanceBlobFlags emits the blobs one instance needs: explicit profile
// decls first (authoritative), then any fake blobs referenced in the strategy
// params (blob=NAME / seqovl_pattern=NAME) auto-resolved via the candidate
// catalog. Auto-derivation is why blobs work regardless of how the strategy was
// created — no UI path has to remember to declare them.
func appendInstanceBlobFlags(parts []string, seen map[string]bool, inst zapretInstance, catalog map[string]string) []string {
	parts = appendBlobFlags(parts, seen, inst.strategy.LibraryBlobs)
	parts = appendBlobFlags(parts, seen, inst.profile.Blobs)
	for _, name := range zapretParamBlobNames(inst.strategy.Params) {
		if seen[name] || zapretBuiltinBlobs[name] {
			continue
		}
		file := catalog[name]
		if file == "" {
			continue // unknown alias: nfqws built-in, or genuinely missing — nothing to point at
		}
		seen[name] = true
		parts = append(parts, "--blob="+name+":@"+config.CanonicalBlobPath(file))
	}
	return parts
}

// zapretBuiltinBlobs are nfqws2's always-available fakes — referencing them in
// params needs no --blob= declaration.
var zapretBuiltinBlobs = map[string]bool{
	"fake_default_tls": true, "fake_default_http": true, "fake_default_quic": true,
}

// zapretParamBlobNames extracts fake-blob aliases referenced in a strategy's
// params via blob=NAME and seqovl_pattern=NAME tokens (e.g.
// "--lua-desync=fake:blob=quic_google:repeats=6" → "quic_google").
func zapretParamBlobNames(params string) []string {
	var names []string
	for _, tok := range strings.Fields(params) {
		for _, seg := range strings.Split(tok, ":") {
			for _, key := range []string{"blob=", "seqovl_pattern="} {
				if v, ok := strings.CutPrefix(seg, key); ok && v != "" {
					names = append(names, v)
				}
			}
		}
	}
	return names
}

// zapretCatalogBlobFiles builds the blob alias→file map from the shared
// candidate list (/etc override or embed) — the source of truth for what file
// each named fake blob resolves to.
func zapretCatalogBlobFiles() map[string]string {
	m := map[string]string{}
	for _, cand := range config.LoadZapretCandidates().Candidates {
		for _, b := range cand.Blobs {
			if b.Name != "" && b.File != "" && m[b.Name] == "" {
				m[b.Name] = b.File
			}
		}
	}
	return m
}

// appendBlobFlags normalizes each "name:@path" / "name:0xHEX" blob into a
// --blob= flag, deduped by name via seen, file-backed entries rewritten to the
// canonical resolved path. Skips empty / malformed / whitespace-bearing entries
// (which would split the arg). Shared by the union (upstream) and per-profile
// (env) emitters.
func appendBlobFlags(parts []string, seen map[string]bool, blobs []string) []string {
	for _, raw := range blobs {
		entry := strings.TrimSpace(raw)
		if entry == "" || strings.ContainsAny(entry, " \t\r\n\"") {
			continue
		}
		name, value, ok := strings.Cut(entry, ":")
		if !ok || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if file, isFile := strings.CutPrefix(value, "@"); isFile {
			entry = name + ":@" + config.CanonicalBlobPath(file)
		}
		parts = append(parts, "--blob="+entry)
	}
	return parts
}

// ZapretRequiredBlobFiles returns the basenames of every file-backed blob that
// the enabled zapret instances will emit — the set the manager must ensure is
// present (fetching missing decoys) before generation. Inline-hex blobs are
// excluded. Pure; deduped by filename.
func ZapretRequiredBlobFiles(c config.Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(base string) {
		if base == "" || base == "." || seen[base] {
			return
		}
		seen[base] = true
		out = append(out, base)
	}
	catalog := zapretCatalogBlobFiles()
	for _, inst := range zapretInstances(c) {
		// Explicit profile decls (file-backed only).
		for _, raw := range append(append([]string(nil), inst.profile.Blobs...), inst.strategy.LibraryBlobs...) {
			entry := strings.TrimSpace(raw)
			if entry == "" || strings.ContainsAny(entry, " \t\r\n\"") {
				continue
			}
			if _, value, ok := strings.Cut(entry, ":"); ok {
				if file, isFile := strings.CutPrefix(value, "@"); isFile {
					add(filepath.Base(file))
				}
			}
		}
		// Param-referenced fake blobs, resolved through the candidate catalog —
		// so non-shipped decoys get fetched even when the strategy carries no
		// explicit profile decl.
		for _, name := range zapretParamBlobNames(inst.strategy.Params) {
			if zapretBuiltinBlobs[name] {
				continue
			}
			if file := catalog[name]; file != "" {
				add(filepath.Base(file))
			}
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
