package manager

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/provider"
)

func (m Manager) Preview(url string) (string, error) {
	c, err := m.Load()
	if err != nil {
		return "", err
	}
	a, err := m.Analyze(url)
	if err != nil {
		return "", err
	}
	plan := provider.PlanImport(c, url, "", "auto", "minimal", a)
	b, err := json.MarshalIndent(plan, "", "  ")
	return string(b), err
}

func (m Manager) RuleProviderStatusJSON() (string, error) {
	c, err := m.Load()
	if err != nil {
		return "", err
	}
	type status struct {
		Name        string `json:"name"`
		LastUpdate  string `json:"last_update,omitempty"`
		LastSuccess string `json:"last_success,omitempty"`
		EntryCount  int    `json:"entry_count,omitempty"`
		Error       string `json:"error,omitempty"`
	}
	out := make([]status, 0, len(c.RuleProviders))
	for _, rp := range c.RuleProviders {
		st := status{Name: rp.Name, Error: rp.LastError}
		if meta, ok := readRuleProviderMetadata(rp.Path); ok {
			st.LastUpdate = formatRuleProviderStatusTime(meta.LastUpdate)
			st.LastSuccess = formatRuleProviderStatusTime(meta.LastSuccess)
			st.EntryCount = meta.EntryCount
			st.Error = meta.ErrorMessage
		}
		out = append(out, st)
	}
	b, err := json.MarshalIndent(map[string]any{"rule_providers": out}, "", "  ")
	return string(b), err
}

func readRuleProviderMetadata(path string) (provider.Metadata, bool) {
	if path == "" {
		return provider.Metadata{}, false
	}
	b, err := os.ReadFile(path + ".meta.json")
	if err != nil {
		return provider.Metadata{}, false
	}
	var meta provider.Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return provider.Metadata{}, false
	}
	return meta, true
}

func formatRuleProviderStatusTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("02.01.2006-15:04")
}

func (m Manager) Classify(name, rawURL, behavior, format string) (string, error) {
	b, err := json.MarshalIndent(provider.ClassifyRuleProvider(name, rawURL, behavior, format, nil), "", "  ")
	return string(b), err
}

func (m Manager) OverrideRuleProvider(name string, args []string) error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	found := false
	for i := range c.RuleProviders {
		rp := &c.RuleProviders[i]
		if rp.Name != name {
			continue
		}
		found = true
		for _, arg := range args {
			k, v, ok := strings.Cut(arg, "=")
			if !ok {
				continue
			}
			switch k {
			case "section":
				rp.Section, rp.UserOverriddenSection = v, true
			case "action", "route_action":
				rp.RouteAction, rp.UserOverriddenAction = v, true
			case "enabled":
				rp.Enabled = truthy(v)
			case "reset":
				if truthy(v) {
					rp.UserOverriddenSection, rp.UserOverriddenAction = false, false
				}
			}
		}
	}
	if !found {
		return fmt.Errorf("rule provider %q not found", name)
	}
	_, _ = config.Backup(defaultConfigPath(&m))
	if err := config.Save(defaultConfigPath(&m), c); err != nil {
		return err
	}
	return m.Apply()
}

func defaultConfigPath(m *Manager) string {
	if m.ConfigPath == "" {
		m.ConfigPath = uciPurewrtPath
	}
	return m.ConfigPath
}

func truthy(v string) bool {
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") || strings.EqualFold(v, "on")
}
