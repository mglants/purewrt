package manager

import "github.com/purewrt/purewrt/internal/config"

// WizardReset flushes PureWRT config back to a clean Default() — the setup
// wizard's "start over" semantics — while preserving the laborious bits a
// reset must never destroy:
//   - VPN + Zapret section definitions (the user's explicit ask),
//   - the mihomo external-controller secret (resetting it breaks the live
//     API/dashboard),
//   - the mihomo binary selection (so a GitHub-installed binary isn't
//     swapped back to the packaged /usr/bin/mihomo),
//   - a custom default-lists repo URL,
//   - the auto-detected dnsmasq include dir (a runtime-probed path, not user
//     config — blanking it makes apply silently stop installing nftset
//     fragments, so manual rules never reach dnsmasq until the next service
//     start re-detects it).
//
// It only persists the reset config; the caller (wizard runApply / CLI)
// stages its choices and applies afterward.
func (m Manager) WizardReset() error {
	cur, err := m.Load()
	if err != nil {
		return err
	}
	fresh := config.Default()

	// Preserved section definitions.
	fresh.ZapretProfiles = cur.ZapretProfiles
	fresh.ZapretStrategies = cur.ZapretStrategies
	fresh.VPNs = cur.VPNs

	// Preserved settings — guarded on non-empty so an unset field keeps its
	// Default rather than being blanked.
	keep := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	keep(&fresh.Settings.Secret, cur.Settings.Secret)
	keep(&fresh.Settings.MihomoBin, cur.Settings.MihomoBin)
	keep(&fresh.Settings.MihomoVersion, cur.Settings.MihomoVersion)
	keep(&fresh.Settings.MihomoArch, cur.Settings.MihomoArch)
	keep(&fresh.Settings.MihomoAssetURL, cur.Settings.MihomoAssetURL)
	keep(&fresh.Settings.MihomoSHA256URL, cur.Settings.MihomoSHA256URL)
	keep(&fresh.Settings.DefaultListsBaseURL, cur.Settings.DefaultListsBaseURL)
	keep(&fresh.Settings.DNSMasqIncludeDir, cur.Settings.DNSMasqIncludeDir)

	path := defaultConfigPath(&m)
	_, _ = config.Backup(path)
	return config.Save(path, fresh)
}
