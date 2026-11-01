package netx

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
)

func clients(pool *x509.CertPool, debug bool) {
	// ruleid: go.tls-verify-off
	a := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	cfg := &tls.Config{}
	// ruleid: go.tls-verify-off
	cfg.InsecureSkipVerify = true
	// ok: go.tls-verify-off
	b := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	// ok: go.tls-verify-off
	c := &tls.Config{InsecureSkipVerify: false}
	_, _, _ = a, b, c
}

// The false-positive shapes of the 1.1.0 rule: an explicit opt-in flag
// and test code.
func optIn(insecure bool) *tls.Config {
	cfg := &tls.Config{}
	if insecure {
		// ok: go.tls-verify-off
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

func TestSelfSigned(t *testing.T) {
	// ok: go.tls-verify-off
	_ = &tls.Config{InsecureSkipVerify: true}
}

// Lane SEC-G4 audit finding 2: only a flag- or config-named condition is an
// opt-in; an error branch still matches.
func fallback(err error, opts struct{ SkipVerify bool }) *tls.Config {
	cfg := &tls.Config{}
	if err != nil {
		// ruleid: go.tls-verify-off
		cfg.InsecureSkipVerify = true
	}
	if opts.SkipVerify {
		// ok: go.tls-verify-off
		cfg.InsecureSkipVerify = true
	}
	return cfg
}
