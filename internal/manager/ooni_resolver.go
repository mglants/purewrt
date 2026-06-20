package manager

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/purewrt/purewrt/internal/config"
)

// ResolveOONIUser fills c.OONI.UID by looking up c.OONI.User in /etc/passwd.
// The uid feeds the nft OUTPUT-chain `meta skuid` exemption that keeps OONI
// measurements direct. If OONI is disabled or the user can't be resolved, UID
// stays 0 and the generator omits the exemption (so a stale enable flag with
// no user present can't break ruleset load).
func ResolveOONIUser(c config.Config) config.Config {
	if !c.OONI.Enabled {
		c.OONI.UID = 0
		return c
	}
	o := c.OONISettings()
	c.OONI.UID = lookupUID(o.User, "/etc/passwd")
	return c
}

// lookupUID returns the uid for name from a passwd-format file, or 0 if absent.
// Reads the file directly (busybox has no getent and CGO is off, so os/user's
// cgo path is unavailable on the router).
func lookupUID(name, passwdPath string) int {
	if name == "" {
		return 0
	}
	f, err := os.Open(passwdPath)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 3 || fields[0] != name {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return 0
		}
		return uid
	}
	return 0
}
