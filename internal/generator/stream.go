package generator

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/logging"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/rules"
)

type generationSinks struct {
	dns          io.Writer
	dnsBySection map[string]*bytes.Buffer
	nftset       io.Writer
	native       map[string][]string
}

type streamStats struct {
	domains int
	cidr4   int
	cidr6   int
}

func streamRuleOutputs(c config.Config, sinks generationSinks) error {
	log := logging.New(c.Settings.LogLevel)
	defer log.DebugTimer("generate: stream rule outputs")()
	if sinks.native == nil {
		sinks.native = map[string][]string{}
	}
	// Pre-size dnsmasq fragment buffers from rule-provider source sizes to
	// avoid ~17 power-of-two reallocations as the buffer climbs from 0 to
	// ~5 MB. Each doubling triggers a Go allocator round-trip and (for the
	// big sizes) a kernel `mmap`/`brk` — that was visible as elevated
	// `stime` during apply. Sizing once up front turns it into a single
	// allocation per section. Estimates are rough on purpose; the buffer
	// can still grow if we under-shoot, but the common case lands in one
	// shot.
	if sinks.dnsBySection != nil {
		sectionEstimate := map[string]int64{}
		for _, rp := range c.RuleProviders {
			if !rp.Enabled || rp.Path == "" {
				continue
			}
			info, err := os.Stat(rp.Path)
			if err != nil {
				continue
			}
			size := info.Size()
			var entries int64
			if strings.EqualFold(rp.Format, "mrs") {
				// .mrs is zstd-compressed succinct trie; empirically ~0.14
				// domain entries per compressed byte (e.g. 585 KB → ~80 k).
				entries = size * 14 / 100
			} else {
				// text/list: ~one rule per ~25 bytes (`DOMAIN-SUFFIX,...`).
				entries = size / 25
			}
			// Each domain emits two nftset lines (v4 + v6) of ~60 bytes
			// each, so 130 bytes per entry is the right rule-of-thumb.
			sectionEstimate[rp.Section] += entries * 130
		}
		for sec, est := range sectionEstimate {
			if est <= 0 {
				continue
			}
			if est > 32*1024*1024 {
				est = 32 * 1024 * 1024 // cap at 32 MB per section just in case
			}
			buf := &bytes.Buffer{}
			buf.Grow(int(est))
			sinks.dnsBySection[sec] = buf
		}
		log.Debug("generate: dnsmasq buffers pre-sized sections=%d", len(sectionEstimate))
	}
	if sinks.dns != nil {
		if err := WriteDNSMasqHeader(sinks.dns); err != nil {
			return err
		}
	}
	if sinks.nftset != nil {
		if err := WriteNFTSetPayloadHeader(sinks.nftset, c); err != nil {
			return err
		}
		for _, cidr := range c.Bypass.CIDR4 {
			if err := WriteNFTSetElement(sinks.nftset, "bypass4", cidr); err != nil {
				return err
			}
		}
		if c.Settings.IPv6 && !c.LowResource() {
			for _, cidr := range c.Bypass.CIDR6 {
				if err := WriteNFTSetElement(sinks.nftset, "bypass6", cidr); err != nil {
					return err
				}
			}
		}
		for _, cidr := range c.Bypass.ProxyServerCIDR4 {
			if err := WriteNFTSetElement(sinks.nftset, "proxy_server_bypass4", cidr); err != nil {
				return err
			}
		}
		if c.Settings.IPv6 && !c.LowResource() {
			for _, cidr := range c.Bypass.ProxyServerCIDR6 {
				if err := WriteNFTSetElement(sinks.nftset, "proxy_server_bypass6", cidr); err != nil {
					return err
				}
			}
		}
	}
	// Deduplicate only within a section. Overlapping destinations must remain
	// available to later sections whose protocol/port predicates differ.
	domainSeen := map[string]map[string]struct{}{}
	cidr4Seen := map[string]map[string]struct{}{}
	cidr6Seen := map[string]map[string]struct{}{}
	nativeSeen := map[string]map[string]struct{}{}
	totalProviders, totalDomains, totalCIDR4, totalCIDR6, totalNative, totalDup := 0, 0, 0, 0, 0, 0
	for _, rp := range orderedRuleProviders(c.RuleProviders) {
		// Per-provider timing wrapper. The IIFE lets us `defer` a single
		// summary log line that fires no matter which exit path the body
		// takes (skipped, MRS-stream, native-fast, slow-parse, etc.). The
		// `path` variable tags which code path actually ran so we can see
		// at a glance which providers go down the slow materialising path.
		retErr := func() error {
			t0 := time.Now()
			path := "skipped"
			var bytes int64
			defer func() {
				log.Debug("generate: rp name=%s format=%s path=%s bytes=%d took=%v", rp.Name, rp.Format, path, bytes, time.Since(t0))
			}()
			if !rp.Enabled {
				path = "skipped-disabled"
				log.Debug("generate: rule-provider %s skipped disabled", rp.Name)
				return nil
			}
			if rp.Path == "" {
				path = "skipped-missing-path"
				log.Debug("generate: rule-provider %s skipped missing path", rp.Name)
				return nil
			}
			sec, ok := sectionForRuleProvider(c, rp)
			if !ok {
				path = "skipped-no-section"
				log.Debug("generate: rule-provider %s skipped missing section=%s", rp.Name, rp.Section)
				return nil
			}
			data, err := os.ReadFile(rp.Path)
			if err != nil {
				path = "read-failed"
				if provider.IsGeoFormat(rp.Format) {
					// Geo providers (geoip/geosite) are materialized from the
					// local v2ray .dat into rp.Path during update
					// (materializeGeoProvider). A missing file here is not a
					// broken download — geo data hasn't been fetched yet
					// (geo-refresh) or no update has run since the provider was
					// added. It self-heals on the next update once the .dat is
					// present; say so instead of an alarming "read failed".
					log.Warn("generate: geo rule-provider %s (%s/%s) not materialized yet — run geo-refresh then update; skipping", rp.Name, rp.Format, rp.GeoTarget)
				} else {
					log.Warn("generate: rule-provider %s skipped read failed path=%s", rp.Name, rp.Path)
				}
				return nil
			}
			bytes = int64(len(data))
			log.Debug("generate: rule-provider %s read path=%s", rp.Name, rp.Path)
			if strings.EqualFold(rp.Format, "mrs") {
				// MRS streaming uses section-local deduplication — the
				// section-local seen-sets are threaded into the walk handlers
				// so we can skip the materialising artifact-cache path even
				// when dedup is enabled. This is the difference between an
				// 80 k-entry provider taking 18 s (cache hit → iterate
				// []NeutralRule) and ~50 ms (single trie walk, no alloc).
				dedup := &streamDedup{domainSeen: domainSeen, cidr4Seen: cidr4Seen, cidr6Seen: cidr6Seen}
				stats, err := streamMRSData(c, sec, data, sinks, dedup)
				if err != nil {
					log.Warn("generate: rule-provider %s streaming MRS failed: %v", rp.Name, err)
				} else {
					path = "mrs-stream"
					totalProviders++
					totalDomains += stats.domains
					totalCIDR4 += stats.cidr4
					totalCIDR6 += stats.cidr6
					log.Debug("generate: rule-provider %s MRS streamed domains=%d cidr4=%d cidr6=%d", rp.Name, stats.domains, stats.cidr4, stats.cidr6)
					return nil
				}
			}
			if strings.EqualFold(rp.ParseMode, "native_import") {
				// Pre-built list in nftset-builder's marker format: import
				// without reparsing or validation. The builder
				// already normalized/deduped/collapsed/CDN-carved, so the
				// router deduplicates it within this section and wraps it into
				// its dnsmasq directives + nft set elements.
				stats, err := streamNativeImportData(c, sec, data, sinks, &streamDedup{domainSeen: domainSeen, cidr4Seen: cidr4Seen, cidr6Seen: cidr6Seen})
				if err != nil {
					return err
				}
				path = "native-import"
				totalProviders++
				totalDomains += stats.domains
				totalCIDR4 += stats.cidr4
				totalCIDR6 += stats.cidr6
				log.Debug("generate: rule-provider %s native-import domains=%d cidr4=%d cidr6=%d", rp.Name, stats.domains, stats.cidr4, stats.cidr6)
				return nil
			}
			checksum := provider.ArtifactChecksum(rp.Path)
			cacheDir := c.CacheDir()
			if _, err := provider.EnsureArtifact(cacheDir, rp.Name, rp.Format, checksum, data); err != nil {
				// Non-fatal — ReadArtifact below misses and we fall back to
				// the slow parse — but without this warning a broken cache
				// dir degrades every generation silently.
				log.Warn("generate: rule-provider %s artifact cache build failed: %v", rp.Name, err)
			}
			artifact, err := provider.ReadArtifact(provider.ArtifactPath(cacheDir, rp.Name, checksum))
			if err != nil {
				path = "artifact-cache-miss-parse"
				log.Debug("generate: rule-provider %s parsing file format=%s bytes=%d", rp.Name, rp.Format, len(data))
				parsed, perr := provider.ParseRuleProviderForGeneration(rp.Name, rp.Format, data)
				if perr != nil {
					log.Warn("generate: rule-provider %s parse failed format=%s: %v", rp.Name, rp.Format, perr)
					return nil
				}
				log.Debug("generate: rule-provider %s parsed rules=%d", rp.Name, len(parsed.Rules))
				for _, r := range parsed.Rules {
					if !r.SupportedOpenWrt {
						continue
					}
					if nr, ok := rules.RuleToNeutral(r); ok {
						artifact = append(artifact, nr)
					}
				}
			} else {
				path = "artifact-cache-hit"
			}
			totalProviders++
			domains, cidr4, cidr6, native, dup := 0, 0, 0, 0, 0
			for _, nr := range artifact {
				if (!c.Settings.IPv6 || c.LowResource()) && nr.Type == "cidr6" {
					continue
				}
				switch nr.Type {
				case "domain":
					if dns := dnsSinkForSection(sinks, sec.Name); dns != nil && shouldEmitSeen(nr.Value, seenFor(domainSeen, sec.Name)) {
						if err := WriteDNSMasqDomain(dns, c, sec, nr.Value); err != nil {
							return err
						}
						domains++
					}
				case "cidr4":
					set := sec.NFTSet4()
					if sinks.nftset != nil && shouldEmitSeen(nr.Value, seenFor(cidr4Seen, set)) {
						if err := WriteNFTSetElement(sinks.nftset, set, nr.Value); err != nil {
							return err
						}
						cidr4++
					}
				case "cidr6":
					set := sec.NFTSet6()
					if sinks.nftset != nil && shouldEmitSeen(nr.Value, seenFor(cidr6Seen, set)) {
						if err := WriteNFTSetElement(sinks.nftset, set, nr.Value); err != nil {
							return err
						}
						cidr6++
					}
				case "native":
					if shouldEmitSeen(nr.Value, seenFor(nativeSeen, sec.Name)) {
						sinks.native[sec.Name] = append(sinks.native[sec.Name], nr.Value)
						native++
					}
				}
			}
			totalDomains += domains
			totalCIDR4 += cidr4
			totalCIDR6 += cidr6
			totalNative += native
			totalDup += dup
			log.Debug("generate: rule-provider %s emitted domains=%d cidr4=%d cidr6=%d native=%d duplicates=%d", rp.Name, domains, cidr4, cidr6, native, dup)
			return nil
		}()
		if retErr != nil {
			return retErr
		}
	}
	log.Info("generate: rule output summary providers=%d domains=%d cidr4=%d cidr6=%d native=%d duplicates=%d", totalProviders, totalDomains, totalCIDR4, totalCIDR6, totalNative, totalDup)
	return nil
}

func dnsSinkForSection(sinks generationSinks, section string) io.Writer {
	if sinks.dnsBySection != nil {
		buf := sinks.dnsBySection[section]
		if buf == nil {
			buf = &bytes.Buffer{}
			sinks.dnsBySection[section] = buf
		}
		return buf
	}
	return sinks.dns
}

func sectionForRuleProvider(c config.Config, rp config.RuleProvider) (config.Section, bool) {
	sec, ok := c.SectionByName(rp.Section)
	if ok {
		return sec, true
	}
	if rp.RouteAction == "direct" || rp.Section == "direct" {
		return config.Section{Name: "direct", Action: "direct", IPv4Enabled: true, IPv6Enabled: true}, true
	}
	if rp.RouteAction == "reject" || rp.Section == "reject" {
		return config.Section{Name: "reject", Action: "reject", IPv4Enabled: true, IPv6Enabled: true}, true
	}
	return config.Section{}, false
}

// orderedRuleProviders provides deterministic output ordering. Routing precedence
// is determined by section priority and packet predicates, not provider ownership.
func orderedRuleProviders(in []config.RuleProvider) []config.RuleProvider {
	out := append([]config.RuleProvider(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func seenFor(m map[string]map[string]struct{}, key string) map[string]struct{} {
	if m == nil {
		return nil
	}
	seen, ok := m[key]
	if !ok {
		seen = map[string]struct{}{}
		m[key] = seen
	}
	return seen
}

func shouldEmitSeen(v string, seen map[string]struct{}) bool {
	if seen == nil {
		return strings.TrimSpace(v) != ""
	}
	return appendSeen(v, seen)
}

func appendSeen(v string, seen map[string]struct{}) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if _, ok := seen[v]; ok {
		return false
	}
	seen[v] = struct{}{}
	return true
}

// nativeImportCIDRMarker separates the domain section from the CIDR
// section in a native_import list (nftset-builder's marker format).
const nativeImportCIDRMarker = "@cidr"

// streamNativeImportData imports a pre-built native list verbatim: lines
// before the "@cidr" marker are bare domains, lines after are bare CIDRs.
// It does no parsing or validation — the builder already produced clean,
// collapsed, CDN-carved data. Section-local dedup also handles multiple providers.
// Domains are wrapped into this
// section's dnsmasq nftset directives (prefix precomputed once), CIDRs into
// nft set elements; v6 is skipped when IPv6 is off. This is the only native
// path on the router.
func streamNativeImportData(c config.Config, sec config.Section, data []byte, sinks generationSinks, dedup *streamDedup) (streamStats, error) {
	var stats streamStats
	dns := dnsSinkForSection(sinks, sec.Name)
	pfx := DNSMasqDomainPrefixes(c, sec)
	emitV6 := c.Settings.IPv6 && !c.LowResource()
	inCIDR := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if line == nativeImportCIDRMarker {
			inCIDR = true
			continue
		}
		if !inCIDR {
			if dns != nil && shouldEmitSeen(line, seenFor(dedup.domainSeen, sec.Name)) {
				if err := WriteDNSMasqDomainPrefixed(dns, pfx, line); err != nil {
					return stats, err
				}
				stats.domains++
			}
			continue
		}
		if sinks.nftset == nil {
			continue
		}
		if strings.IndexByte(line, ':') >= 0 {
			if !emitV6 || !shouldEmitSeen(line, seenFor(dedup.cidr6Seen, sec.NFTSet6())) {
				continue
			}
			if err := WriteNFTSetElement(sinks.nftset, sec.NFTSet6(), line); err != nil {
				return stats, err
			}
			stats.cidr6++
			continue
		}
		if !shouldEmitSeen(line, seenFor(dedup.cidr4Seen, sec.NFTSet4())) {
			continue
		}
		if err := WriteNFTSetElement(sinks.nftset, sec.NFTSet4(), line); err != nil {
			return stats, err
		}
		stats.cidr4++
	}
	return stats, sc.Err()
}

// streamDedup carries the same dedup state the slow-path uses, so the MRS
// streaming path preserves the same per-section semantics. All fields are
// optional; nil maps mean "don't dedup for this dimension".
type streamDedup struct {
	domainSeen map[string]map[string]struct{} // section -> seen
	cidr4Seen  map[string]map[string]struct{} // nft set name -> seen
	cidr6Seen  map[string]map[string]struct{}
}

// streamMRSData walks the MRS bitmap-trie without materialising and emits
// directly to dnsmasq + nft sinks, deduplicating only within each section.
//
// nft set name (s4/s6) is computed once per call instead of per-element —
// `sec.NFTSet4()`/`NFTSet6()` re-build a string from `s.Action + s.Name`
// every invocation, which adds up to hundreds of thousands of allocations
// for the big providers.
func streamMRSData(c config.Config, sec config.Section, data []byte, sinks generationSinks, dedup *streamDedup) (streamStats, error) {
	var stats streamStats
	s4 := sec.NFTSet4()
	s6 := sec.NFTSet6()
	ipv6Enabled := c.Settings.IPv6 && !c.LowResource()
	// Pre-compute the dnsmasq prefix/suffix pair once per provider call so
	// the per-domain handler avoids `s.NFTSet4()` + `dnsSetName(...)` +
	// concat-into-WriteString. For an 80 k-entry provider this cut per-emit
	// allocations from ~4-6 to ~0 inside the loop.
	pfx := DNSMasqDomainPrefixes(c, sec)
	// Resolve the dnsmasq sink once too — the map lookup inside
	// dnsSinkForSection isn't free at 160 k calls.
	dns := dnsSinkForSection(sinks, sec.Name)
	// Pre-resolve the section's section-mode seen set so we don't pay the
	// map-of-maps lookup per domain.
	var domainSeen map[string]struct{}
	if dedup != nil {
		domainSeen = seenFor(dedup.domainSeen, sec.Name)
	}
	return stats, rules.StreamMRS(data, rules.MRSStreamHandlers{
		Domain: func(domain []byte) error {
			if dns == nil {
				return nil
			}
			// `m[string(b)]` and `_, ok := m[string(b)]` are Go's
			// well-known zero-alloc map idioms — the runtime hashes the
			// byte slice without materialising a string. Only the
			// `m[string(b)] = ...` *insert* allocates the key string,
			// which is unavoidable since the map needs to retain it.
			// Net per-entry alloc drops from 2 (reverseString result +
			// dedup key) to 1 (dedup key only).
			if domainSeen != nil {
				if _, ok := domainSeen[string(domain)]; ok {
					return nil
				}
				domainSeen[string(domain)] = struct{}{}
			}
			if err := WriteDNSMasqDomainPrefixedBytes(dns, pfx, domain); err != nil {
				return err
			}
			stats.domains++
			return nil
		},
		CIDR: func(cidr string) error {
			if sinks.nftset == nil {
				return nil
			}
			set := s4
			isV6 := strings.Contains(cidr, ":")
			if isV6 {
				if !ipv6Enabled {
					return nil
				}
				set = s6
			}
			if dedup != nil {
				seen := dedup.cidr4Seen
				if isV6 {
					seen = dedup.cidr6Seen
				}
				if !shouldEmitSeen(cidr, seenFor(seen, set)) {
					return nil
				}
			}
			if err := WriteNFTSetElement(sinks.nftset, set, cidr); err != nil {
				return err
			}
			if isV6 {
				stats.cidr6++
			} else {
				stats.cidr4++
			}
			return nil
		},
	})
}
