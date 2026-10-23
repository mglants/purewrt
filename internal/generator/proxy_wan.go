package generator

import (
	"fmt"
	"github.com/purewrt/purewrt/internal/config"
)

func validateProxyWANGeneration(c config.Config) error {
	if !c.Mwan3.ProxyWANEnabled {
		return nil
	}
	if len(c.Mwan3.ProxyWANs) == 0 {
		return fmt.Errorf("proxy WANs enabled without selected interfaces")
	}
	resolved := map[string]bool{}
	for _, w := range c.Mwan3.ResolvedProxyWANs {
		if w.Mark == 0 || w.Device == "" {
			return fmt.Errorf("proxy WAN %q has unresolved routing", w.Name)
		}
		resolved[w.Name] = true
	}
	for _, name := range c.Mwan3.ProxyWANs {
		if !resolved[name] {
			return fmt.Errorf("proxy WAN %q must be resolved before generation", name)
		}
	}
	return nil
}
