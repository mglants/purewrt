package generator

import (
	"encoding/json"

	"github.com/purewrt/purewrt/internal/config"
)

// OONIConfigJSON renders ooniprobe's config.json (schema confirmed against
// probe-cli v3.29.1). It records informed consent so `run unattended` never
// prompts, and sets whether measurements are uploaded to OONI's public
// archive. There is intentionally no proxy key — the proxy is passed as the
// `--proxy` run flag (it is backend-only by design); home is set via the
// OONI_HOME env. The file lives on tmpfs and is regenerated before each run,
// so it never needs the atomic staging pipeline the other artifacts use.
func OONIConfigJSON(c config.Config) []byte {
	cfg := ooniConfig{
		Comment:         "managed by purewrt — do not edit",
		Version:         1,
		InformedConsent: true,
	}
	cfg.Sharing.UploadResults = c.OONI.Upload
	// Leave nettests/advanced at their zero values: `run unattended` is
	// check-in driven (the OONI backend selects the test set), so we don't
	// pin a website list or runtime here.
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return append(out, '\n')
}

type ooniConfig struct {
	Comment         string `json:"_"`
	Version         int    `json:"_version"`
	InformedConsent bool   `json:"_informed_consent"`
	Sharing         struct {
		UploadResults bool `json:"upload_results"`
	} `json:"sharing"`
	Nettests struct{} `json:"nettests"`
	Advanced struct{} `json:"advanced"`
}
