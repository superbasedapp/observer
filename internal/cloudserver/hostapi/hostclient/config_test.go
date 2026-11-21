package hostclient_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
)

// pemFiles renders p's CA and client certificate and key as the three PEM
// files the worker reads.
func pemFiles(t *testing.T, p pki) (ca, cert, keyPEM []byte) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.client.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.client.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestClientTLSConfig(t *testing.T) {
	t.Parallel()
	ca, cert, k := pemFiles(t, newPKI(t))
	c, err := hostclient.ClientTLSConfig(ca, cert, k)
	if err != nil {
		t.Fatal(err)
	}
	if c.RootCAs == nil || len(c.Certificates) != 1 || c.MinVersion == 0 {
		t.Fatalf("config = %+v", c)
	}
	if _, err := hostclient.NewSender(hostclient.SenderConfig{TLS: c, Signer: hostclient.Ed25519Signer("cp-1", requestKey)}); err != nil {
		t.Fatalf("NewSender over the loaded config: %v", err)
	}
	for name, args := range map[string][3][]byte{
		"no CA":              {nil, cert, k},
		"CA is not PEM":      {[]byte("nope"), cert, k},
		"key does not match": {ca, cert, mustKeyPEM(t, newPKI(t))},
		"no certificate":     {ca, nil, k},
	} {
		if _, err := hostclient.ClientTLSConfig(args[0], args[1], args[2]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustKeyPEM(t *testing.T, p pki) []byte {
	t.Helper()
	_, _, k := pemFiles(t, p)
	return k
}

func TestParseHostsFile(t *testing.T) {
	t.Parallel()
	pubB64 := base64.StdEncoding.EncodeToString(pub(responseKey))
	good := `{"place_on":"host-1","hosts":[{"id":"host-1","base_url":"https://10.0.0.5:8443","response_keys":{"host-r1":"` + pubB64 + `"}}]}`
	d, err := hostclient.ParseHostsFile([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	h, ok := d.Host("host-1")
	if !ok || h.BaseURL != "https://10.0.0.5:8443" || !h.ResponseKeys["host-r1"].Equal(pub(responseKey)) {
		t.Fatalf("host = %+v, %v", h, ok)
	}
	if placed, err := d.Place(t.Context(), orgA); err != nil || placed != "host-1" {
		t.Fatalf("Place = %q, %v", placed, err)
	}
	cases := map[string]string{
		"unknown field":       strings.Replace(good, `"place_on"`, `"placeon":"x","place_on"`, 1),
		"trailing data":       good + `{}`,
		"no hosts":            `{"place_on":"host-1","hosts":[]}`,
		"placement not known": strings.Replace(good, `"place_on":"host-1"`, `"place_on":"host-2"`, 1),
		"http origin":         strings.Replace(good, "https://", "http://", 1),
		"origin with a path":  strings.Replace(good, ":8443", ":8443/x", 1),
		"key not base64":      strings.Replace(good, pubB64, "***", 1),
		"short key":           strings.Replace(good, pubB64, base64.StdEncoding.EncodeToString([]byte("short")), 1),
		"no key":              `{"place_on":"host-1","hosts":[{"id":"host-1","base_url":"https://10.0.0.5:8443","response_keys":{}}]}`,
		"not JSON":            `place_on=host-1`,
		"too large":           `{"place_on":"` + strings.Repeat("h", 1<<20) + `"}`,
	}
	for name, raw := range cases {
		if _, err := hostclient.ParseHostsFile([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
