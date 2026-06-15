package checker

import "github.com/purewrt/purewrt/internal/config"

type Mwan3Status struct {
	Installed     bool
	Enabled       bool
	Mode          string
	MMXMask       string
	DirectTraffic string
	ProxyOutbound string
}

func Mwan3(c config.Config) Mwan3Status {
	return Mwan3Status{Mode: c.Mwan3.Mode, DirectTraffic: "handled by mwan3/default routing", ProxyOutbound: "mwan3 default policy in coexist mode"}
}
