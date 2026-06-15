package manager

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/mihomoapi"
)

func (m Manager) MihomoCheckUpdate() (mihomoapi.UpdateInfo, error) {
	c, err := m.Load()
	if err != nil {
		return mihomoapi.UpdateInfo{}, err
	}
	if c.Settings.MihomoChannel != "" && c.Settings.MihomoChannel != "alpha" {
		return mihomoapi.UpdateInfo{}, fmt.Errorf("unsupported mihomo channel %q; currently alpha is supported", c.Settings.MihomoChannel)
	}
	primary, fallback := updaterClients(c, 30*time.Second)
	info, err := (mihomoapi.Updater{APIURL: c.Settings.MihomoReleaseAPI, HTTPClient: primary}).Check(c.Settings.MihomoVersion, c.Settings.MihomoArch)
	if err != nil && fallback != nil {
		info, err = (mihomoapi.Updater{APIURL: c.Settings.MihomoReleaseAPI, HTTPClient: fallback}).Check(c.Settings.MihomoVersion, c.Settings.MihomoArch)
	}
	return info, err
}

func (m Manager) MihomoDownload() (mihomoapi.UpdateInfo, error) {
	return m.MihomoPackageUpdate()
}

func (m Manager) MihomoPackageUpdate() (mihomoapi.UpdateInfo, error) {
	c, err := m.Load()
	if err != nil {
		return mihomoapi.UpdateInfo{}, err
	}
	info, err := m.MihomoCheckUpdate()
	if err != nil {
		return info, err
	}
	c.Settings.MihomoVersion = info.Version
	c.Settings.MihomoAssetURL = info.URL
	c.Settings.MihomoSHA256URL = info.SHA256URL
	if m.ConfigPath == "" {
		m.ConfigPath = uciPurewrtPath
	}
	_, _ = config.Backup(m.ConfigPath)
	return info, config.Save(m.ConfigPath, c)
}

func (m Manager) MihomoCheckUpdateJSON() (string, error) {
	i, err := m.MihomoCheckUpdate()
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(i, "", "  ")
	return string(b), nil
}
