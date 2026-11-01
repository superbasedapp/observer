package sandboxremote

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// credential.go binds a provider credential to the endpoint identity it was
// issued for (sandbox plan v2 section 5.7, ledger row SBX-GOV-4). A stored
// credential records the API origin it was connected for and is sent only
// there; an environment-variable credential is bound to the vendor's
// default endpoint only. A mismatch refuses the launch with
// credential_endpoint_mismatch, never a silent send.
//
// A Credential never prints its values: String and GoString name only the
// provider and the source, so a credential that reaches a log line or an
// error leaks nothing (a test greps for a fake key). Redact scrubs a
// vendor's error text of every value before it is shown or stored.

// ErrCredentialEndpointMismatch refuses a send to another endpoint.
var ErrCredentialEndpointMismatch = errors.New("credential_endpoint_mismatch")

// ErrCredentialMissing reports no credential for the provider.
var ErrCredentialMissing = errors.New("credential_missing")

// The closed credential sources.
const (
	SourceKeystore = "keystore"
	SourceEnv      = "env"
)

// Credential is one provider credential, resolved at use time.
type Credential struct {
	Provider string
	// Fields maps each of the vendor's EnvCredential names to its value
	// (token, team id, ...).
	Fields map[string]string
	// Endpoint is the API origin the credential is bound to.
	Endpoint string
	// Source is SourceKeystore or SourceEnv.
	Source string
	// SPKISHA256 is the server key pin recorded when the credential was
	// connected for a pinned endpoint (lane SBX-UPD, SBX-GOV-4; "" for
	// none). The vendor client pins it.
	SPKISHA256 string
}

// String names the credential without its values.
func (c Credential) String() string { return "credential(" + c.Provider + ", " + c.Source + ")" }

// GoString is String (so %#v leaks nothing either).
func (c Credential) GoString() string { return c.String() }

// Format prints String for every verb, so no fmt verb reaches the map.
func (c Credential) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(c.String())) }

// Get returns one field.
func (c Credential) Get(name string) string { return c.Fields[name] }

// Secrets returns every non-empty value, for redaction.
func (c Credential) Secrets() []string {
	var out []string
	for _, v := range c.Fields {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Complete reports whether every field the vendor names is set.
func (c Credential) Complete(v Vendor) bool {
	for _, n := range v.EnvCredential {
		if strings.TrimSpace(c.Fields[n]) == "" {
			return false
		}
	}
	return true
}

// CredentialFromEnv builds the env credential from a lookup (os.LookupEnv
// in the cmd layer); ok is false when any of the vendor's names is unset.
// It is bound to the vendor's default endpoint.
func CredentialFromEnv(v Vendor, lookup func(string) (string, bool)) (Credential, bool) {
	c := Credential{Provider: v.ID, Fields: map[string]string{}, Endpoint: v.DefaultEndpoint, Source: SourceEnv}
	for _, n := range v.EnvCredential {
		val, ok := lookup(n)
		if !ok || strings.TrimSpace(val) == "" {
			return Credential{}, false
		}
		c.Fields[n] = strings.TrimSpace(val)
	}
	return c, true
}

// StoredCredential is the keystore value: the fields and the endpoint they
// were connected for.
type StoredCredential struct {
	Version  int               `json:"version"`
	Provider string            `json:"provider"`
	Endpoint string            `json:"endpoint"`
	Fields   map[string]string `json:"fields"`
	// SPKISHA256 is the endpoint's key pin at connect (omitted when none,
	// so a credential stored before the field reads the same).
	SPKISHA256 string `json:"spki_sha256,omitempty"`
}

// KeystoreName is the secret name a provider credential is stored under.
const KeystoreName = "credential"

// EncodeStored serializes a credential for the keystore.
func EncodeStored(c Credential) ([]byte, error) {
	return json.Marshal(StoredCredential{Version: 1, Provider: c.Provider, Endpoint: c.Endpoint, Fields: c.Fields, SPKISHA256: c.SPKISHA256})
}

// DecodeStored parses a keystore value; it never echoes the value in an
// error.
func DecodeStored(provider string, b []byte) (Credential, error) {
	var s StoredCredential
	if err := json.Unmarshal(b, &s); err != nil || s.Version != 1 || s.Provider != provider || s.Endpoint == "" {
		return Credential{}, fmt.Errorf("%w: the stored %s credential does not parse; reconnect it", ErrCredentialMissing, provider)
	}
	return Credential{Provider: provider, Fields: s.Fields, Endpoint: s.Endpoint, Source: SourceKeystore, SPKISHA256: s.SPKISHA256}, nil
}

// CheckBinding refuses sending c to endpoint unless it is bound there: a
// stored credential to the endpoint it was connected for, an env credential
// to the vendor's default endpoint only.
func CheckBinding(c Credential, v Vendor, endpoint string) error {
	want := c.Endpoint
	if c.Source == SourceEnv {
		want = v.DefaultEndpoint
	}
	if endpoint == "" || normalizeOrigin(endpoint) != normalizeOrigin(want) {
		return fmt.Errorf("%w: the %s credential (%s) is bound to %s, not %s", ErrCredentialEndpointMismatch, v.Name, c.Source, want, endpoint)
	}
	return nil
}

// CheckBindingPinned is CheckBinding for an endpoint that carries a server
// key pin (an org-published self-hosted endpoint, SBX-GOV-4): the
// credential must also have been connected with that same pin. spki ""
// asks nothing more than CheckBinding.
func CheckBindingPinned(c Credential, v Vendor, endpoint, spki string) error {
	if err := CheckBinding(c, v, endpoint); err != nil {
		return err
	}
	if spki != "" && !strings.EqualFold(c.SPKISHA256, spki) {
		return fmt.Errorf("%w: the %s credential was connected for %s without the server key pin the endpoint now names; reconnect it for this endpoint", ErrCredentialEndpointMismatch, v.Name, endpoint)
	}
	return nil
}

func normalizeOrigin(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "/")
}

// Redact replaces every secret in s (longest first) with [redacted].
func Redact(s string, secrets []string) string {
	sorted := append([]string(nil), secrets...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, sec := range sorted {
		if len(sec) >= 4 {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}
