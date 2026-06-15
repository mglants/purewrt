package generator

// Mihomo mixin merger. Adopted from the OpenWrt-nikki pattern: users
// drop a YAML file at <workdir>/mihomo-mixin.yaml that gets deep-merged
// into the generated mihomo.yaml on each apply. The merge semantics
// match nikki's `yq ireduce ({}; . * $item)` operator for objects, plus
// a `purewrt-<key>` prefix convention for array prepends.
//
// Why deep-merge and not whole-file overwrite: PureWRT auto-generates
// the bulk of mihomo.yaml (proxy expansion, rule providers, DNS plumbing
// wired to the per-section tproxy ports). Users who want to add one
// experimental setting, an extra outbound, or override DNS shouldn't
// have to redeclare hundreds of lines.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/purewrt/purewrt/internal/config"
)

// applyMihomoMixin reads the mixin file (when enabled + present),
// unmarshals both the generated base and the mixin into yaml.Node trees,
// deep-merges them, resolves `purewrt-<key>` prepend keys, and marshals
// the result. Returns base unchanged on a miss (no mixin file, mixin
// disabled, or workdir not configured). Returns an error only for hard
// problems — unparseable mixin YAML, unreadable file with the path set
// to something other than "doesn't exist". The apply pipeline should
// fall back to base on error so a malformed mixin doesn't take down the
// router.
func applyMihomoMixin(base []byte, c config.Config) ([]byte, error) {
	if !c.Settings.MihomoMixinEnabled {
		return base, nil
	}
	path := mihomoMixinPath(c)
	mixinBytes, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return base, nil
		}
		return base, fmt.Errorf("read mixin %s: %w", path, err)
	}
	merged, err := mergeMihomoYAML(base, mixinBytes)
	if err != nil {
		return base, fmt.Errorf("merge mixin: %w", err)
	}
	return merged, nil
}

// mihomoMixinPath resolves the canonical mixin path under the configured
// workdir. Exported via a small helper rather than hardcoded so the
// manager-side read/write/preview methods can compute the same path
// without going through the apply pipeline.
func mihomoMixinPath(c config.Config) string {
	workdir := c.Settings.Workdir
	if workdir == "" {
		workdir = "/etc/purewrt"
	}
	return filepath.Join(workdir, "mihomo-mixin.yaml")
}

// MihomoMixinPath is the public accessor for the manager-side methods.
func MihomoMixinPath(c config.Config) string { return mihomoMixinPath(c) }

// MergeMihomoYAMLPublic exposes the merge operator for the preview path
// in manager/mihomo_mixin.go. Same semantics as the internal merger —
// just promoted so callers outside this package can run a merge against
// an arbitrary mixin body without going through the file/UCI plumbing.
func MergeMihomoYAMLPublic(base, mixin []byte) ([]byte, error) {
	return mergeMihomoYAML(base, mixin)
}

// mergeMihomoYAML is the core merge. Both inputs are unmarshalled to
// generic maps so the merge can operate on any mihomo.yaml shape — we
// don't model the schema, just walk it. Output is re-marshalled YAML
// preserving the merged map order naturally.
func mergeMihomoYAML(base, mixin []byte) ([]byte, error) {
	var baseMap map[string]any
	if err := yaml.Unmarshal(base, &baseMap); err != nil {
		// Should never happen — base is what we just rendered ourselves.
		// Surface it loudly so a regression in generator.Mihomo doesn't
		// silently get masked by the mixin path.
		return nil, fmt.Errorf("base mihomo.yaml is not valid YAML: %w", err)
	}
	if baseMap == nil {
		baseMap = map[string]any{}
	}
	var mixinMap map[string]any
	if err := yaml.Unmarshal(mixin, &mixinMap); err != nil {
		return nil, fmt.Errorf("mixin is not valid YAML: %w", err)
	}
	if mixinMap == nil {
		// Empty mixin → identity merge.
		return base, nil
	}
	merged := deepMergeMaps(baseMap, mixinMap)
	resolvePrependKeys(merged)
	return yaml.Marshal(merged)
}

// deepMergeMaps merges src into dst, returning a new map. The merge
// is recursive for nested maps; for non-map types (including arrays
// and scalars) src wins outright. Array-prepend semantics are handled
// in a separate post-processing pass (resolvePrependKeys) once the
// merged tree exists — keeps this function focused on the structural
// merge without baking the prefix convention into every nested call.
func deepMergeMaps(dst, src map[string]any) map[string]any {
	out := make(map[string]any, len(dst)+len(src))
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		existing, ok := out[k]
		if !ok {
			out[k] = v
			continue
		}
		// Both sides have the key — recurse only when both are maps.
		// yaml.v3 unmarshals YAML objects as map[string]any (when the
		// target is map[string]any) or map[any]any (when interface{}).
		// We handle both because nested decoding through `any` produces
		// map[string]any only when the immediate target type is also
		// map[string]any.
		switch dv := existing.(type) {
		case map[string]any:
			if sv, ok := v.(map[string]any); ok {
				out[k] = deepMergeMaps(dv, sv)
				continue
			}
		case map[any]any:
			if sv, ok := v.(map[any]any); ok {
				out[k] = deepMergeAnyMaps(dv, sv)
				continue
			}
		}
		// Otherwise (scalar, array, mismatched types) — src replaces.
		out[k] = v
	}
	return out
}

// deepMergeAnyMaps is the map[any]any twin of deepMergeMaps. yaml.v3
// uses this shape when decoding into `any` (not into a typed map).
func deepMergeAnyMaps(dst, src map[any]any) map[any]any {
	out := make(map[any]any, len(dst)+len(src))
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		existing, ok := out[k]
		if !ok {
			out[k] = v
			continue
		}
		if dv, dvOk := existing.(map[any]any); dvOk {
			if sv, svOk := v.(map[any]any); svOk {
				out[k] = deepMergeAnyMaps(dv, sv)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// resolvePrependKeys walks the top-level merged map looking for keys
// prefixed with "purewrt-". For each match, prepends the value (must be
// a list) to the corresponding non-prefixed key (creating it if absent)
// then deletes the prefixed key. This is the nikki-style array-prepend
// convention; it's intentionally scoped to the top level only — nested
// proxies/rules don't exist in mihomo's schema anyway.
const prependPrefix = "purewrt-"

func resolvePrependKeys(m map[string]any) {
	for key, val := range m {
		if !strings.HasPrefix(key, prependPrefix) {
			continue
		}
		baseKey := strings.TrimPrefix(key, prependPrefix)
		prependList, ok := asList(val)
		if !ok {
			// Non-list value behind the prefix — caller meant a regular
			// override, just rename the key and let it act as replace.
			m[baseKey] = val
			delete(m, key)
			continue
		}
		baseList, _ := asList(m[baseKey])
		// Prepend prependList in front of baseList.
		combined := make([]any, 0, len(prependList)+len(baseList))
		combined = append(combined, prependList...)
		combined = append(combined, baseList...)
		m[baseKey] = combined
		delete(m, key)
	}
}

// asList returns v as []any if v is any list-shaped value yaml.v3 might
// produce. Returns (nil, false) when v isn't a list — callers fall back
// to replace semantics in that case.
func asList(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, true
	case nil:
		return nil, false
	default:
		return nil, false
	}
}
