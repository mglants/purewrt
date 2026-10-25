package manager

import (
	"fmt"
	"github.com/purewrt/purewrt/internal/config"
	"os"
	"strconv"
	"strings"
)

// Selector bits must be private even when multi-WAN proxy generation is off.
// No mwan3 dependency: inspect kernel policy rules only when Zapret is enabled.
func validateZapretRoutingMasks(c config.Config, r commandRunner) error {
	if len(c.EnabledZapretProfiles()) == 0 {
		return nil
	}
	if err := validateZapretProfileMarks(c); err != nil {
		return err
	}
	for _, family := range []string{"-4", "-6"} {
		if family == "-6" && !c.Settings.IPv6 {
			continue
		}
		output, err := r.Run("ip", family, "rule", "show")
		if err != nil {
			return fmt.Errorf("inspect %s routing marks for Zapret: %w", family, err)
		}
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] != "fwmark" {
					continue
				}
				_, value, masked := strings.Cut(fields[i+1], "/")
				mask := uint64(0xffffffff)
				if masked {
					mask, err = strconv.ParseUint(value, 0, 32)
					if err != nil {
						return fmt.Errorf("invalid routing mark mask in %q", line)
					}
				}
				if mask&uint64(config.ZapretSelectorMask) != 0 {
					return fmt.Errorf("routing rule %q overlaps reserved Zapret selector mask 0x%x", strings.TrimSpace(line), config.ZapretSelectorMask)
				}
			}
		}
	}
	return nil
}

// Restart also stops a formerly active instance when the generated env is disabled.
func (m Manager) restartZapret(c config.Config, r commandRunner, script string) error {
	if _, err := os.Stat(script); err != nil {
		if countEnabledZapretStrategies(c) > 0 {
			return fmt.Errorf("Zapret service unavailable: %w", err)
		}
		return nil
	}
	return m.runServiceRestart(c, r, script, "restart")
}
