package manager

// Read / write / preview the mihomo mixin file. The merger itself lives
// in internal/generator/mihomo_mixin.go; this file is the user-facing
// surface (LuCI textarea Save → MihomoMixinWrite; "Preview merged" →
// MihomoMixinPreview).
//
// Validation happens in Write before the atomic file swap so a malformed
// mixin never lands on disk — the user gets the YAML parse error in the
// toast and the previous file is untouched.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/system"
)

// MihomoMixinInfo describes the on-disk state of the mixin file. Returned
// by MihomoMixinRead so the LuCI page can show "enabled / disabled" +
// "last modified" alongside the body.
type MihomoMixinInfo struct {
	Path      string `json:"path"`
	Enabled   bool   `json:"enabled"`
	Exists    bool   `json:"exists"`
	SizeBytes int64  `json:"size_bytes"`
	ModTime   string `json:"mod_time,omitempty"`
	Body      string `json:"body"`
}

// MihomoMixinRead returns the current mixin contents + metadata. Empty
// body when the file doesn't exist — that's the "no mixin configured
// yet" state, the LuCI page renders the textarea empty with a hint.
func (m Manager) MihomoMixinRead() (MihomoMixinInfo, error) {
	c, _ := m.Load()
	path := generator.MihomoMixinPath(c)
	info := MihomoMixinInfo{Path: path, Enabled: c.Settings.MihomoMixinEnabled}
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return info, nil
		}
		return info, err
	}
	info.Exists = true
	info.SizeBytes = fi.Size()
	info.ModTime = fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	body, err := os.ReadFile(path)
	if err != nil {
		return info, err
	}
	info.Body = string(body)
	return info, nil
}

// MihomoMixinWrite validates the body as YAML, then atomically writes
// it to disk. Empty body deletes the file (cleanest "turn it off"
// gesture short of toggling the UCI flag).
func (m Manager) MihomoMixinWrite(body string) error {
	c, _ := m.Load()
	path := generator.MihomoMixinPath(c)
	if body == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	var probe map[string]any
	if err := yaml.Unmarshal([]byte(body), &probe); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return system.AtomicWrite(path, []byte(body), 0o644)
}

// MihomoMixinPreview returns the merge of the current generated base
// with the given mixin body — without writing the file. Lets the LuCI
// page show "what would this produce" before the user commits. Empty
// body falls back to the current on-disk mixin (so previewing without
// edits shows the current effective config).
func (m Manager) MihomoMixinPreview(body string) (string, error) {
	c, _ := m.Load()
	if body == "" {
		if existing, err := os.ReadFile(generator.MihomoMixinPath(c)); err == nil {
			body = string(existing)
		}
	}
	// Force-enable for the preview so the merger runs even when the user
	// hasn't flipped the UCI flag yet — they're explicitly asking to see
	// the merged shape, the live flag doesn't matter here.
	cfg := c
	cfg.Settings.MihomoMixinEnabled = true
	// Render the base from the config — same path as apply uses.
	base := generator.Mihomo(cfg) // already merges if enabled + file exists
	// But we want the merge to use the OPTIONAL body, not the on-disk file.
	// Easiest path: re-render base from a clone with mixin disabled, then
	// merge against `body` directly via the exported merger.
	cfg.Settings.MihomoMixinEnabled = false
	base = generator.Mihomo(cfg)
	merged, err := generator.MergeMihomoYAMLPublic(base, []byte(body))
	if err != nil {
		return "", err
	}
	return string(merged), nil
}
