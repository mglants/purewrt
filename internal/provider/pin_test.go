package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// makeSelfSignedTLSServer spins up an httptest TLS server with a fresh
// self-signed certificate and returns the server, its leaf cert SPKI
// SHA-256 (lowercase hex), and a *tls.Config that trusts the cert.
func makeSelfSignedTLSServer(t *testing.T) (*httptest.Server, string, *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "purewrt-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(spki[:])

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	trust := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return srv, pin, trust
}

func TestPinAcceptsMatchingSPKI(t *testing.T) {
	t.Parallel()
	srv, pin, trust := makeSelfSignedTLSServer(t)
	defer srv.Close()

	client, err := NewClient(ClientOptions{
		TLSConfig: trust,
		PinSHA256: pin,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestPinRejectsNonMatchingSPKI(t *testing.T) {
	t.Parallel()
	srv, _, trust := makeSelfSignedTLSServer(t)
	defer srv.Close()

	bogus := strings.Repeat("0", 64)
	client, err := NewClient(ClientOptions{
		TLSConfig: trust,
		PinSHA256: bogus,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("expected pin mismatch error, got %v", err)
	}
}

func TestPinAcceptsAnyOfMultiplePins(t *testing.T) {
	t.Parallel()
	srv, pin, trust := makeSelfSignedTLSServer(t)
	defer srv.Close()

	pins := strings.Repeat("0", 64) + ",sha256/" + pin
	client, err := NewClient(ClientOptions{
		TLSConfig: trust,
		PinSHA256: pins,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
}
