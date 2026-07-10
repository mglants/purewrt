package provider

import (
	"net/url"
	"strings"
)

type DownloadOptions struct {
	// IncludeHWID opts a download into router-identity injection (hwid /
	// device_name query params and the x-hwid / X-Device-* header family).
	// Only subscriptions and proxy providers set it — their panels key
	// responses on device identity. Every other download (rule providers,
	// geo data, native-list catalog, zapret candidates) stays anonymous.
	IncludeHWID      bool
	HWID             string
	DeviceName       string
	UserAgent        string
	Headers          []string
	ProxyURL         string
	Bootstrap        BootstrapConfig
	PriorETag        string
	PriorLastModified string
	// Mirrors are alternate URLs tried after the primary fails. Each retry
	// round cycles through primary + mirrors in order before backing off.
	Mirrors []string
	// FallbackProxyURL, when non-empty, is used for a single retry pass after
	// direct attempts to all candidate URLs have failed. Intended for routing
	// fetches through the local mihomo mixed-port once the proxy is up, so a
	// blocked subscription host can still be reached on subsequent updates.
	FallbackProxyURL string
	// PinSHA256, when set, is a comma-separated list of hex SHA-256 hashes
	// of the peer cert's SubjectPublicKeyInfo. At least one must match for
	// the TLS handshake to succeed. Defeats panel MITM via a leaf-cert pin.
	PinSHA256 string
	// SuppressHWID, when true, disables the router-derived HWID injection
	// (both query params and x-hwid/x-device-* HTTP headers). Lets users
	// opt out of panel-driven fingerprinting per subscription/provider —
	// e.g. when they don't trust the panel operator or want subscription
	// downloads to be indistinguishable across devices.
	SuppressHWID bool
	// MaxBytes caps the response body. 0 = the 32 MiB default that fits
	// subscriptions/rule lists; geo-data fetches pass a larger cap.
	MaxBytes int64
}

func ApplyDownloadOptions(raw string, opt DownloadOptions) string {
	if !opt.IncludeHWID || opt.SuppressHWID {
		// Identity injection is opt-in (subscriptions/proxy providers) and
		// the user's SuppressHWID opt-out always wins. Preserve whatever
		// the user typed verbatim.
		return raw
	}
	if opt.HWID == "" {
		opt.HWID = opt.EffectiveHWID()
	}
	if opt.DeviceName == "" {
		opt.DeviceName = opt.EffectiveDeviceName()
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "file" {
		return raw
	}
	q := u.Query()
	if opt.HWID != "" {
		for _, key := range hwidKeys() {
			if q.Get(key) == "" {
				q.Set(key, opt.HWID)
			}
		}
	}
	if opt.DeviceName != "" {
		for _, key := range deviceKeys() {
			if q.Get(key) == "" {
				q.Set(key, opt.DeviceName)
			}
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func hwidKeys() []string {
	return []string{"hwid"}
}

func deviceKeys() []string {
	return []string{"device_name"}
}

func ParseHeaderList(headers []string) map[string]string {
	out := map[string]string{}
	for _, h := range headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			k, v, ok = strings.Cut(h, "=")
		}
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}
