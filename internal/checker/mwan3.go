package checker

import (
	"os"

	"github.com/purewrt/purewrt/internal/config"
)

type Mwan3Status struct {
	Installed     bool
	Enabled       bool
	MMXMask       string
	DirectTraffic string
	ProxyOutbound string
}

// mwan3Markers are files present only when the mwan3 package is installed.
var mwan3Markers = []string{"/usr/sbin/mwan3", "/etc/init.d/mwan3", "/lib/mwan3/mwan3.sh"}

func Mwan3(c config.Config) Mwan3Status {
	installed := false
	for _, p := range mwan3Markers {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			installed = true
			break
		}
	}
	outbound := "existing mwan3/default routing"
	if c.Mwan3.ProxyWANEnabled {
		outbound = "WAN-specific subscription providers"
	}
	return Mwan3Status{
		Installed:     installed,
		DirectTraffic: "handled by mwan3/default routing",
		ProxyOutbound: outbound,
	}
}
