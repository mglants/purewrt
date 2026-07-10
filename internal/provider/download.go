package provider

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/purewrt/purewrt/internal/version"
)

type DownloadResult struct {
	Data         []byte
	Checksum     string
	URLRedacted  string
	NotModified  bool
	ETag         string
	LastModified string
	// SubscriptionInfo carries the parsed subscription-userinfo header (when
	// the upstream proxy panel emitted one). Zero values mean header absent.
	SubscriptionInfo SubscriptionInfo
}

// SubscriptionInfo is the parsed `subscription-userinfo` response header.
// Format per de-facto convention is `upload=NNN; download=NNN; total=NNN;
// expire=NNN` where NNN are byte counts or a Unix timestamp.
type SubscriptionInfo struct {
	UploadBytes   int64
	DownloadBytes int64
	TotalBytes    int64
	Expire        time.Time
}

func Download(url string) (DownloadResult, error) {
	return DownloadWithOptions(url, DownloadOptions{})
}

func DownloadWithOptions(url string, opt DownloadOptions) (DownloadResult, error) {
	url = ApplyDownloadOptions(url, opt)
	if strings.HasPrefix(url, "file://") {
		b, err := os.ReadFile(strings.TrimPrefix(url, "file://"))
		return result(url, b), err
	}
	res, err := downloadAttempt(url, opt)
	if err == nil {
		return res, nil
	}
	// One fallback pass through the local proxy, once direct + mirrors are
	// all exhausted. Skipped when the proxy URL is the same one we just
	// tried (avoids a tautological re-attempt) and when the caller did not
	// configure a fallback.
	if opt.FallbackProxyURL != "" && opt.FallbackProxyURL != opt.ProxyURL {
		fallback := opt
		fallback.ProxyURL = opt.FallbackProxyURL
		fallback.FallbackProxyURL = ""
		if res2, err2 := downloadAttempt(url, fallback); err2 == nil {
			return res2, nil
		}
	}
	return DownloadResult{}, err
}

// failClass buckets per-attempt failures so the aggregate error can say
// whether the rounds died on the network, on 5xx, or on terminal 4xx —
// otherwise only the very last error survives the retry loop and ops
// can't tell a DNS blackhole from a dead mirror.
type failClass int

const (
	classNetwork failClass = iota // dial/TLS/DoH/read errors
	classHTTP5xx                  // 5xx + 429 (retryable server side)
	classHTTP4xx                  // terminal client-side statuses
	classOther                    // request construction etc.
	classCount
)

var failClassNames = [classCount]string{"network", "http5xx", "http4xx", "other"}

func classSummary(counts [classCount]int) string {
	var parts []string
	for cls, n := range counts {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", failClassNames[cls], n))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " [" + strings.Join(parts, " ") + "]"
}

func downloadAttempt(url string, opt DownloadOptions) (DownloadResult, error) {
	client, err := ClientFromBootstrap(opt.Bootstrap, opt.ProxyURL, opt.PinSHA256)
	if err != nil {
		return DownloadResult{}, err
	}
	retryMax, initial, maxWait := retryParams(opt.Bootstrap)
	candidates := append([]string{url}, sanitizeMirrors(opt.Mirrors)...)
	var lastErr error
	var counts [classCount]int
	for round := 0; round <= retryMax; round++ {
		if round > 0 {
			time.Sleep(backoff(initial, maxWait, round-1))
		}
		var (
			roundErr        error
			anyRetryable    bool
			sawNonRetryOnly = len(candidates) > 0
		)
		for _, candidate := range candidates {
			res, class, err := doOnce(client, candidate, opt)
			if err == nil {
				return res, nil
			}
			counts[class]++
			roundErr = err
			if class == classNetwork || class == classHTTP5xx {
				anyRetryable = true
				sawNonRetryOnly = false
			}
		}
		lastErr = roundErr
		// If every candidate failed with a terminal (non-retryable) error
		// the next round won't help; give up early.
		if !anyRetryable && sawNonRetryOnly {
			return DownloadResult{}, lastErr
		}
	}
	return DownloadResult{}, fmt.Errorf("download failed after %d round(s) across %d candidate(s)%s: %w", retryMax+1, len(candidates), classSummary(counts), lastErr)
}

func sanitizeMirrors(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func doOnce(client *http.Client, url string, opt DownloadOptions) (DownloadResult, failClass, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return DownloadResult{}, classOther, err
	}
	setDownloadHeaders(req, opt)
	if opt.PriorETag != "" {
		req.Header.Set("If-None-Match", opt.PriorETag)
	}
	if opt.PriorLastModified != "" {
		req.Header.Set("If-Modified-Since", opt.PriorLastModified)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Network-level errors are always retryable: TCP RST, TLS handshake
		// failures, DoH lookup failures, timeouts.
		return DownloadResult{}, classNetwork, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		return DownloadResult{
			URLRedacted:  RedactURL(url),
			NotModified:  true,
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
		}, classOther, nil
	}
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return DownloadResult{}, classHTTP5xx, fmt.Errorf("download failed: %s", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return DownloadResult{}, classHTTP4xx, fmt.Errorf("download failed: %s", resp.Status)
	}
	maxBytes := opt.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return DownloadResult{}, classNetwork, err
	}
	r := result(url, b)
	r.ETag = resp.Header.Get("ETag")
	r.LastModified = resp.Header.Get("Last-Modified")
	r.SubscriptionInfo = parseSubscriptionInfo(resp.Header.Get("subscription-userinfo"))
	return r, classOther, nil
}

// parseSubscriptionInfo turns a `subscription-userinfo` header value into
// the structured SubscriptionInfo. Tolerates missing or unparseable fields —
// the only constraints are upload/download/total are byte counts and expire
// is a Unix timestamp. Empty input returns the zero value.
func parseSubscriptionInfo(h string) SubscriptionInfo {
	if h == "" {
		return SubscriptionInfo{}
	}
	var info SubscriptionInfo
	for _, raw := range strings.Split(h, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(raw), "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "upload":
			info.UploadBytes = n
		case "download":
			info.DownloadBytes = n
		case "total":
			info.TotalBytes = n
		case "expire":
			if n > 0 {
				info.Expire = time.Unix(n, 0).UTC()
			}
		}
	}
	return info
}

func retryParams(bc BootstrapConfig) (int, time.Duration, time.Duration) {
	retryMax := bc.RetryMax
	if retryMax <= 0 {
		retryMax = 3 // 4 attempts total (initial + 3 retries)
	}
	initial := bc.RetryInitial
	if initial <= 0 {
		initial = 500 * time.Millisecond
	}
	maxWait := bc.RetryMaxWait
	if maxWait <= 0 {
		maxWait = 8 * time.Second
	}
	return retryMax, initial, maxWait
}

// backoff returns an exponentially increasing delay with ±25% jitter, capped.
func backoff(initial, maxWait time.Duration, attempt int) time.Duration {
	wait := initial << attempt
	if wait <= 0 || wait > maxWait {
		wait = maxWait
	}
	jitter := jitterFrac()
	// Apply ±25% jitter without panicking on tiny durations.
	delta := time.Duration(float64(wait) * 0.25 * jitter)
	return wait + delta
}

// jitterFrac returns a random float in [-1, 1).
func jitterFrac() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	u := binary.LittleEndian.Uint64(b[:])
	// Map to [0, 1) then to [-1, 1).
	f := float64(u&((1<<53)-1)) / float64(1<<53)
	return f*2 - 1
}

func setDownloadHeaders(req *http.Request, opt DownloadOptions) {
	ua := opt.UserAgent
	if ua == "" {
		ua = "PureWRT/" + version.Version
	}
	req.Header.Set("User-Agent", ua)
	// HWID/device headers are panel-driven fingerprints. Only downloads
	// that opted in (IncludeHWID — subscriptions/proxy providers) carry
	// them, and the user's SuppressHWID opt-out always wins, so every
	// other request is indistinguishable across devices that share the
	// user-agent and any custom headers below.
	if opt.IncludeHWID && !opt.SuppressHWID {
		hwid := opt.EffectiveHWID()
		device := opt.EffectiveDeviceName()
		req.Header.Set("x-hwid", hwid)
		// Happ/v2board header convention: x-device-os names the OS,
		// x-ver-os carries the bare OS version.
		req.Header.Set("x-device-os", "OpenWrt")
		req.Header.Set("x-ver-os", AutomaticOSVersion())
		req.Header.Set("x-device-model", device)
		req.Header.Set("X-Device-HWID", hwid)
		req.Header.Set("X-HWID", hwid)
		req.Header.Set("X-Device-Name", device)
	}
	for k, v := range ParseHeaderList(opt.Headers) {
		req.Header.Set(k, v)
	}
}

func result(url string, b []byte) DownloadResult {
	h := sha256.Sum256(b)
	return DownloadResult{Data: b, Checksum: fmt.Sprintf("%x", h[:]), URLRedacted: RedactURL(url)}
}
func RedactURL(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i] + "?..."
	}
	return u
}

