package generator

import (
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

func Mwan3Rules(c config.Config) []byte {
	if c.Mwan3.Mode != "integrated" || !c.Mwan3.IntegratedRules {
		return nil
	}
	var b strings.Builder
	b.WriteString("# PureWRT generated mwan3 rules; advanced integrated mode.\n")
	for _, p := range c.ProxyProviders {
		if p.Mwan3Policy == "" {
			continue
		}
		b.WriteString("config rule 'purewrt_proxy_" + p.Name + "'\n")
		b.WriteString("    option proto 'all'\n")
		b.WriteString("    option use_policy '" + p.Mwan3Policy + "'\n\n")
	}
	return []byte(b.String())
}
