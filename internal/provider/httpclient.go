package provider

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BootstrapConfig is the runtime view of Settings.Bootstrap* that the
// provider package consumes. Keeping it small lets us pass it through
// DownloadOptions without dragging the whole Config struct into provider.
type BootstrapConfig struct {
	DoHEnabled     bool
	DoHResolvers   []string
	DoHTimeout     time.Duration
	RetryMax       int           // 0 -> default (4 attempts total)
	RetryInitial   time.Duration // 0 -> default (500ms)
	RetryMaxWait   time.Duration // 0 -> default (8s)
	TLSFingerprint string        // "off" | "browser" (default browser)
	TOFUPath       string        // empty -> DefaultTOFUPath; "off" disables
	TOFUTTL        time.Duration // 0 -> DefaultTOFUTTL
	// Warn, when non-nil, receives operational warnings — currently the
	// DoH→system-resolver fallback, which silently downgrades to
	// unencrypted DNS and matters in censored environments. A func field
	// (rather than a logging import) keeps provider dependency-free.
	Warn func(format string, args ...any)
}

// ClientOptions configures the bootstrap-resilient HTTP client used for
// subscription downloads, mihomo updates, and any other fetch path that
// must survive censorship of system DNS.
type ClientOptions struct {
	Timeout   time.Duration
	ProxyURL  string
	Resolver  *DoHResolver
	TOFU      *TOFUCache // nil disables trust-on-first-use IP caching
	TLSConfig *tls.Config
	// PinSHA256, when non-empty, is a comma-separated list of hex SHA-256
	// SPKI hashes that the peer's certificate chain MUST contain at least
	// one of. Empty disables pinning.
	PinSHA256 string
	// Warn, when non-nil, is called for operational warnings (see
	// BootstrapConfig.Warn).
	Warn func(format string, args ...any)
}

// NewClient builds an http.Client whose Transport.DialContext routes
// hostname lookups through the provided DoHResolver (if any) and then
// dials each returned IP in order. Falls back to the stdlib resolver when
// DoH is disabled or when the host is already an IP literal.
//
// Returns an error only if ProxyURL is set but unparseable; this preserves
// the long-standing "invalid update proxy url" behaviour callers rely on.
func NewClient(opts ClientOptions) (*http.Client, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		TLSClientConfig:       opts.TLSConfig,
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if opts.Resolver == nil || net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		// TOFU fast path: if we resolved this host successfully before, dial
		// the cached IPs first. Bypasses DoH entirely on day-2 updates, which
		// matters when the DoH endpoints themselves are intermittently blocked.
		if opts.TOFU != nil {
			if cached, ok := opts.TOFU.Lookup(host); ok {
				if conn, err := dialIPs(ctx, dialer, network, port, cached); err == nil {
					return conn, nil
				}
				// Every cached IP failed — origin probably rotated. Drop the
				// stale entry so the next dial re-resolves via DoH.
				opts.TOFU.Invalidate(host)
			}
		}
		ips, err := opts.Resolver.LookupHost(ctx, host)
		if err != nil || len(ips) == 0 {
			// DoH failed; fall back to the system resolver so a misconfigured
			// resolver pool can't permanently brick the bootstrap path. Warn
			// loudly: in censored environments this downgrade means the
			// lookup goes out as plaintext DNS.
			if opts.Warn != nil {
				opts.Warn("bootstrap: DoH resolution failed for %s (err=%v); falling back to plaintext system resolver", host, err)
			}
			return dialer.DialContext(ctx, network, addr)
		}
		conn, dialErr := dialIPs(ctx, dialer, network, port, ips)
		if dialErr == nil && opts.TOFU != nil {
			opts.TOFU.Store(host, ips)
		}
		if dialErr != nil {
			return nil, fmt.Errorf("dial %s: %w", addr, dialErr)
		}
		return conn, nil
	}
	if opts.ProxyURL != "" {
		u, err := url.Parse(opts.ProxyURL)
		if err != nil || u.Scheme == "" {
			return nil, fmt.Errorf("invalid update proxy url: %v", opts.ProxyURL)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	if pins := parsePinList(opts.PinSHA256); len(pins) > 0 {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		applyPin(tr.TLSClientConfig, pins)
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// dialIPs tries each IP in order until one connects or the list is exhausted.
// Returns the first successful net.Conn or the last dial error.
func dialIPs(ctx context.Context, dialer *net.Dialer, network, port string, ips []net.IP) (net.Conn, error) {
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no usable IP")
	}
	return nil, lastErr
}

// parsePinList splits "sha256/aaa,bbb,..." or "aaa,bbb,..." into normalised
// lowercase hex strings. Anything that isn't 64 hex chars is dropped.
func parsePinList(spec string) []string {
	out := []string{}
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		raw = strings.TrimPrefix(raw, "sha256/")
		raw = strings.TrimPrefix(raw, "sha256:")
		raw = strings.ToLower(raw)
		if len(raw) == 64 {
			if _, err := hex.DecodeString(raw); err == nil {
				out = append(out, raw)
			}
		}
	}
	return out
}

// applyPin installs a VerifyPeerCertificate hook that fails the handshake
// unless at least one cert in the chain has an SPKI SHA-256 in pins. Stdlib
// certificate-chain verification is preserved; the pin is an additional
// constraint on top, not a replacement.
func applyPin(cfg *tls.Config, pins []string) {
	pinSet := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		pinSet[p] = struct{}{}
	}
	prior := cfg.VerifyPeerCertificate
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if prior != nil {
			if err := prior(rawCerts, verifiedChains); err != nil {
				return err
			}
		}
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				continue
			}
			h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if _, ok := pinSet[hex.EncodeToString(h[:])]; ok {
				return nil
			}
		}
		return errors.New("certificate pin mismatch: no peer SPKI hashes match pins")
	}
}

// ClientFromBootstrap is the single entry point download.go and the
// mihomo updater should use. perRequestProxy, when non-empty, overrides
// the proxy URL from BootstrapConfig. pinSHA256 is forwarded into the
// TLS verify hook unchanged.
func ClientFromBootstrap(bc BootstrapConfig, perRequestProxy string, pinSHA256 string) (*http.Client, error) {
	return ClientFromBootstrapTimeout(bc, perRequestProxy, pinSHA256, 30*time.Second)
}

// ClientFromBootstrapTimeout is ClientFromBootstrap with an explicit
// overall timeout — large transfers (the ~44 MB mihomo binary) need more
// than the 30 s that fits subscription fetches.
func ClientFromBootstrapTimeout(bc BootstrapConfig, perRequestProxy string, pinSHA256 string, timeout time.Duration) (*http.Client, error) {
	var resolver *DoHResolver
	if bc.DoHEnabled {
		resolver = NewDoHResolver(bc.DoHResolvers, bc.DoHTimeout)
	}
	var tofu *TOFUCache
	if bc.TOFUPath != "off" {
		tofu = NewTOFUCache(bc.TOFUPath, bc.TOFUTTL)
	}
	return NewClient(ClientOptions{
		Timeout:   timeout,
		ProxyURL:  perRequestProxy,
		Resolver:  resolver,
		TOFU:      tofu,
		TLSConfig: tlsConfigForFingerprint(bc.TLSFingerprint),
		PinSHA256: pinSHA256,
		Warn:      bc.Warn,
	})
}

// tlsConfigForFingerprint returns a *tls.Config tuned to look less like a
// Go stdlib client and more like a mainstream browser. Censors increasingly
// fingerprint TLS ClientHello (JA3/JA4); a full mimic requires utls but
// that bumps the toolchain past what OpenWrt 24.10 ships, so this stdlib
// pass tunes the cheaply-controllable signals: ALPN order, curve order,
// cipher suite order. A future enhancement could enable utls behind a
// "utls" build tag for 25.12+ targets.
func tlsConfigForFingerprint(mode string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch mode {
	case "", "browser":
		cfg.NextProtos = []string{"h2", "http/1.1"}
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
		// TLS 1.2 cipher order; TLS 1.3 ciphers are fixed by the stdlib.
		// Order chosen to match a Chrome-shaped preference list.
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
	case "off":
		// Stdlib defaults; useful for diagnosing whether the fingerprint
		// tuning itself causes a regression with some upstream.
	}
	return cfg
}
