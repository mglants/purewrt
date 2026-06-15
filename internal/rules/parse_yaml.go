package rules

import "gopkg.in/yaml.v3"

type ClashProfile struct {
	Proxies        []map[string]any `yaml:"proxies"`
	ProxyProviders map[string]any   `yaml:"proxy-providers"`
	ProxyGroups    []map[string]any `yaml:"proxy-groups"`
	RuleProviders  map[string]any   `yaml:"rule-providers"`
	Rules          []string         `yaml:"rules"`
}

func ParseYAMLProfile(data []byte) (ClashProfile, error) {
	var p ClashProfile
	return p, yaml.Unmarshal(data, &p)
}
