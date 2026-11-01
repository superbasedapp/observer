package e2b

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSPKIPin (lane SBX-UPD, SBX-GOV-4): with a pin, a server whose public
// key hashes to it is reached and any other key is refused, on top of the
// usual certificate checks.
func TestSPKIPin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	good := hex.EncodeToString(sum[:])

	ok := &http.Client{Transport: pinnedTransport(good, roots)}
	resp, err := ok.Get(srv.URL)
	if err != nil {
		t.Fatalf("the pinned key was refused: %v", err)
	}
	_ = resp.Body.Close()

	bad := &http.Client{Transport: pinnedTransport(strings.Repeat("0", 64), roots)}
	if _, err := bad.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "does not match the endpoint's pin") {
		t.Fatalf("another key was accepted: %v", err)
	}
	// A pin never replaces the certificate check: an unknown issuer fails.
	untrusted := &http.Client{Transport: pinnedTransport(good, x509.NewCertPool())}
	if _, err := untrusted.Get(srv.URL); err == nil {
		t.Fatal("a pinned key with an untrusted certificate was accepted")
	}
	if c, err := New(Options{Endpoint: "https://api.e2b.corp.example", APIKey: "k", SPKISHA256: good}); err != nil || c.http.Transport == nil {
		t.Fatalf("New with a pin: %v", err)
	}
}
