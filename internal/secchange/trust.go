package secchange

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// trust.go is the verifier's side of key enrolment (security plan 7.10
// "Key enrolment" and "Key id, algorithm, rotation, revocation"), over
// data only: a TrustSet is decoded from a keys file the verifier names
// (outside the repository under test, hermetic like the F1 policy), and
// holds self-attested node keys, org root keys with the key certificates
// they signed, and a revocation list. Issuing certificates, the org's
// revocation list and the countersign are lane SEC-F2B; this file checks
// what they produce.

// TrustVersion is the keys file shape version.
const TrustVersion = 1

// certDomain separates a key certificate signature from every other
// signature.
const certDomain = "sbo-change-key-cert-v1"

// MaxTrustFileSize caps a keys file.
const MaxTrustFileSize = 4 << 20

// ErrCertificate is wrapped when a key certificate does not verify.
var ErrCertificate = errors.New("secchange: key certificate does not verify")

// TrustFile is the keys file's JSON shape.
type TrustFile struct {
	Version      int           `json:"version"`
	Keys         []TrustKey    `json:"keys"`
	OrgRoots     []TrustKey    `json:"org_roots"`
	Certificates []Certificate `json:"certificates"`
	Revoked      []Revocation  `json:"revoked"`
}

// TrustKey is one public key in a keys file. NotBefore and NotAfter are
// optional RFC 3339 bounds on the records it may sign.
type TrustKey struct {
	KeyID           string `json:"key_id"`
	PublicKey       string `json:"public_key"`
	MachineIdentity string `json:"machine_identity,omitempty"`
	OrgID           string `json:"org_id,omitempty"`
	NotBefore       string `json:"not_before,omitempty"`
	NotAfter        string `json:"not_after,omitempty"`
}

// Certificate is an org root's statement that a node key belongs to a
// machine identity in an org for a validity window.
type Certificate struct {
	KeyID           string `json:"key_id"`
	PublicKey       string `json:"public_key"`
	MachineIdentity string `json:"machine_identity"`
	OrgID           string `json:"org_id"`
	NotBefore       string `json:"not_before"`
	NotAfter        string `json:"not_after"`
	IssuerKeyID     string `json:"issuer_key_id"`
	Signature       string `json:"signature,omitempty"`
}

// Revocation is one revoked key.
type Revocation struct {
	KeyID     string `json:"key_id"`
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason,omitempty"`
}

// trustedKey is a resolved key of a TrustSet.
type trustedKey struct {
	ID          string
	Public      ed25519.PublicKey
	Attestation string
	OrgID       string
	Machine     string
	notBefore   time.Time
	notAfter    time.Time
}

// covers reports whether a record time lies in the key's validity.
func (k trustedKey) covers(recordedAt string) error {
	t, err := time.Parse(time.RFC3339, recordedAt)
	if err != nil {
		return fmt.Errorf("%w: recorded_at", ErrInvalid)
	}
	if (!k.notBefore.IsZero() && t.Before(k.notBefore)) || (!k.notAfter.IsZero() && t.After(k.notAfter)) {
		return ErrKeyExpired
	}
	return nil
}

// TrustSet is the decoded, checked keys file.
type TrustSet struct {
	keys    map[string]trustedKey
	revoked map[string]bool
	// Issues lists the entries the set dropped (a bad key, a certificate
	// that did not verify); a dropped entry never trusts anything.
	Issues []string
}

// NewTrustSet builds a TrustSet from a decoded keys file. A key whose id
// does not match its public key, and a certificate that does not verify
// against an org root, are dropped and named in Issues. A revoked key
// stays known so a record it signed reads as revoked, not unknown.
func NewTrustSet(f TrustFile) (TrustSet, error) {
	if f.Version != TrustVersion {
		return TrustSet{}, fmt.Errorf("secchange: keys file version %d, want %d", f.Version, TrustVersion)
	}
	ts := TrustSet{keys: map[string]trustedKey{}, revoked: map[string]bool{}}
	for _, r := range f.Revoked {
		if keyIDRE.MatchString(r.KeyID) {
			ts.revoked[r.KeyID] = true
		}
	}
	for _, k := range f.Keys {
		tk, err := resolveKey(k.KeyID, k.PublicKey, k.NotBefore, k.NotAfter)
		if err != nil {
			ts.Issues = append(ts.Issues, "key "+clip(k.KeyID)+": "+err.Error())
			continue
		}
		tk.Attestation, tk.OrgID, tk.Machine = AttestationSelf, k.OrgID, k.MachineIdentity
		ts.keys[tk.ID] = tk
	}
	roots := map[string]ed25519.PublicKey{}
	for _, k := range f.OrgRoots {
		tk, err := resolveKey(k.KeyID, k.PublicKey, "", "")
		if err != nil {
			ts.Issues = append(ts.Issues, "org root "+clip(k.KeyID)+": "+err.Error())
			continue
		}
		if !ts.revoked[tk.ID] {
			roots[tk.ID] = tk.Public
		}
	}
	for _, c := range f.Certificates {
		tk, err := verifyCertificate(c, roots)
		if err != nil {
			ts.Issues = append(ts.Issues, "certificate "+clip(c.KeyID)+": "+err.Error())
			continue
		}
		ts.keys[tk.ID] = tk
	}
	return ts, nil
}

// ParseTrustFile decodes and checks a keys file.
func ParseTrustFile(b []byte) (TrustSet, error) {
	if len(b) > MaxTrustFileSize {
		return TrustSet{}, fmt.Errorf("secchange: keys file over %d bytes", MaxTrustFileSize)
	}
	var f TrustFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return TrustSet{}, fmt.Errorf("secchange: keys file: %w", err)
	}
	return NewTrustSet(f)
}

// lookup returns the trusted key with id, or why it is not trusted.
func (ts TrustSet) lookup(id string) (trustedKey, error) {
	if ts.revoked[id] {
		return trustedKey{}, ErrRevoked
	}
	k, ok := ts.keys[id]
	if !ok {
		return trustedKey{}, ErrUnknownKey
	}
	return k, nil
}

// Len is the number of trusted keys.
func (ts TrustSet) Len() int { return len(ts.keys) }

func resolveKey(id, pub64, notBefore, notAfter string) (trustedKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(pub64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return trustedKey{}, errors.New("public key is not a base64 Ed25519 key")
	}
	pub := ed25519.PublicKey(raw)
	if KeyID(pub) != id {
		return trustedKey{}, errors.New("key id does not match the public key")
	}
	k := trustedKey{ID: id, Public: pub}
	for _, b := range []struct {
		v   string
		dst *time.Time
	}{{notBefore, &k.notBefore}, {notAfter, &k.notAfter}} {
		if b.v == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, b.v)
		if err != nil {
			return trustedKey{}, errors.New("validity is not RFC 3339")
		}
		*b.dst = t
	}
	return k, nil
}

// certificateMessage is what an org root signs for a certificate.
func certificateMessage(c Certificate) ([]byte, error) {
	c.Signature = ""
	body, err := Canonical(c)
	if err != nil {
		return nil, err
	}
	return append([]byte(certDomain+"\x00"), body...), nil
}

// SignCertificate signs a certificate with an org root key (used by tests
// and by lane SEC-F2B's issuer, which owns the org side).
func SignCertificate(c Certificate, root ed25519.PrivateKey) (Certificate, error) {
	pub, _ := root.Public().(ed25519.PublicKey)
	c.IssuerKeyID = KeyID(pub)
	msg, err := certificateMessage(c)
	if err != nil {
		return c, err
	}
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(root, msg))
	return c, nil
}

func verifyCertificate(c Certificate, roots map[string]ed25519.PublicKey) (trustedKey, error) {
	root, ok := roots[c.IssuerKeyID]
	if !ok {
		return trustedKey{}, fmt.Errorf("%w: issuer is not a trusted org root", ErrCertificate)
	}
	if c.NotBefore == "" || c.NotAfter == "" || c.OrgID == "" || c.MachineIdentity == "" {
		return trustedKey{}, fmt.Errorf("%w: org, machine identity and validity are required", ErrCertificate)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return trustedKey{}, fmt.Errorf("%w: signature encoding", ErrCertificate)
	}
	msg, err := certificateMessage(c)
	if err != nil {
		return trustedKey{}, err
	}
	if !ed25519.Verify(root, msg, sig) {
		return trustedKey{}, fmt.Errorf("%w: signature", ErrCertificate)
	}
	tk, err := resolveKey(c.KeyID, c.PublicKey, c.NotBefore, c.NotAfter)
	if err != nil {
		return trustedKey{}, fmt.Errorf("%w: %w", ErrCertificate, err)
	}
	tk.Attestation, tk.OrgID, tk.Machine = AttestationOrg, c.OrgID, c.MachineIdentity
	return tk, nil
}

// SelfKeyEntry is the keys file entry a node exports for its own key
// (`observer security provenance status --export-key`).
func SelfKeyEntry(pub ed25519.PublicKey, machine, org string) TrustKey {
	return TrustKey{KeyID: KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), MachineIdentity: machine, OrgID: org}
}

func clip(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	out := []byte(s)
	for i, c := range out {
		if c < 0x20 || c > 0x7e {
			out[i] = '?'
		}
	}
	return string(out)
}

// Merge is the union of two trust sets (an org's CI policy keys and a keys
// file the verifier names): a key revoked in either stays revoked, and a key
// both sets trust keeps the receiver's entry. The issues of both are kept.
func (ts TrustSet) Merge(o TrustSet) TrustSet {
	out := TrustSet{keys: map[string]trustedKey{}, revoked: map[string]bool{}}
	for _, s := range []TrustSet{o, ts} {
		for id, k := range s.keys {
			out.keys[id] = k
		}
		for id := range s.revoked {
			out.revoked[id] = true
		}
	}
	out.Issues = append(append([]string(nil), ts.Issues...), o.Issues...)
	return out
}
