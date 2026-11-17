package hostclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// config.go turns the worker's deployment files into the Sender's TLS
// configuration and the host directory, so cmd/observer-cloud only reads
// files and passes bytes (the parsing is here, tested without a filesystem).

// maxHostsFile bounds the hosts file.
const maxHostsFile = 1 << 20

// ClientTLSConfig is the mTLS client configuration of the host-API client
// (design 4.6): the platform CA is the ONLY root (never the system pool, so
// a public certificate can never stand in for a tenant host), and the
// client certificate and key identify the control plane to every host.
// TLS 1.2 is the floor (NewSender raises it again).
func ClientTLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("hostclient.ClientTLSConfig: the platform CA file holds no PEM certificate")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("hostclient.ClientTLSConfig: client certificate: %w", err)
	}
	return &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// HostsFile is the hosts file's shape: the tenant hosts the control plane
// knows and the one that receives new tenants.
//
//	{"place_on": "host-1",
//	 "hosts": [{"id": "host-1", "base_url": "https://10.0.0.5:8443",
//	            "response_keys": {"host-r1": "<base64 Ed25519 public key>"}}]}
type HostsFile struct {
	// PlaceOn is the id of the host new tenants are placed on.
	PlaceOn string `json:"place_on"`
	// Hosts lists every host.
	Hosts []HostsFileHost `json:"hosts"`
}

// HostsFileHost is one host in a HostsFile.
type HostsFileHost struct {
	// ID is the host id (orgs.host_id).
	ID string `json:"id"`
	// BaseURL is the host's private origin.
	BaseURL string `json:"base_url"`
	// ResponseKeys pins the host's response keys: key id -> standard base64
	// of the 32-byte Ed25519 public key.
	ResponseKeys map[string]string `json:"response_keys"`
}

// ParseHostsFile decodes a hosts file strictly (no unknown field, no
// trailing data) and builds the directory; every host is validated by
// NewStaticDirectory (https origin, no path, a pinned response key).
func ParseHostsFile(raw []byte) (*StaticDirectory, error) {
	if len(raw) > maxHostsFile {
		return nil, errors.New("hostclient.ParseHostsFile: the hosts file is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f HostsFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("hostclient.ParseHostsFile: %w", err)
	}
	if dec.More() {
		return nil, errors.New("hostclient.ParseHostsFile: trailing data")
	}
	if len(f.Hosts) == 0 {
		return nil, errors.New("hostclient.ParseHostsFile: no host listed")
	}
	hosts := make([]Host, 0, len(f.Hosts))
	for _, h := range f.Hosts {
		keys := make(map[string]ed25519.PublicKey, len(h.ResponseKeys))
		for id, b64 := range h.ResponseKeys {
			k, err := base64.StdEncoding.DecodeString(b64)
			if err != nil || len(k) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("hostclient.ParseHostsFile: host %s: response key %q is not a base64 Ed25519 public key", h.ID, id)
			}
			keys[id] = ed25519.PublicKey(k)
		}
		hosts = append(hosts, Host{ID: h.ID, BaseURL: h.BaseURL, ResponseKeys: keys})
	}
	d, err := NewStaticDirectory(hosts, f.PlaceOn)
	if err != nil {
		return nil, fmt.Errorf("hostclient.ParseHostsFile: %w", err)
	}
	return d, nil
}
