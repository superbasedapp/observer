package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"sort"
	"strings"
)

// The closed asymmetric JWS algorithm vocabulary (RFC 7518 / RFC 8037).
const (
	// AlgEdDSA is Ed25519 (RFC 8037) - the DEFAULT algorithm, never a pinned one.
	AlgEdDSA = "EdDSA"
	// AlgES256 is ECDSA P-256 with SHA-256, used when a KMS lacks Ed25519.
	AlgES256 = "ES256"
	// AlgRS256 is RSASSA-PKCS1-v1_5 with SHA-256, used when a KMS lacks EC/Ed25519.
	AlgRS256 = "RS256"
)

// MinRSABits is the smallest RSA modulus accepted for RS256 keys.
const MinRSABits = 2048

// knownAlgs is the closed set every AlgSet is a subset of.
var knownAlgs = map[string]bool{AlgEdDSA: true, AlgES256: true, AlgRS256: true}

// AlgSet is a configured asymmetric algorithm allowlist. The zero value
// accepts nothing (fail closed); use DefaultAlgs or NewAlgSet.
type AlgSet struct {
	algs map[string]bool
}

// DefaultAlgs returns the full asymmetric allowlist {EdDSA, ES256, RS256}.
// EdDSA is the default SIGNING algorithm; verifiers accept all three unless
// an operator narrows the set.
func DefaultAlgs() AlgSet {
	s, _ := NewAlgSet(AlgEdDSA, AlgES256, AlgRS256)
	return s
}

// NewAlgSet builds an allowlist. Any algorithm outside the closed asymmetric
// vocabulary (including "none" and every HS*) is refused.
func NewAlgSet(algs ...string) (AlgSet, error) {
	out := AlgSet{algs: map[string]bool{}}
	for _, a := range algs {
		a = strings.TrimSpace(a)
		if !knownAlgs[a] {
			return AlgSet{}, fmt.Errorf("jose.NewAlgSet: algorithm %q is not in the asymmetric allowlist {EdDSA, ES256, RS256}", a)
		}
		out.algs[a] = true
	}
	return out, nil
}

// Allows reports whether alg is in the set. Matching is exact and
// case-sensitive (RFC 7515 §4.1.1).
func (s AlgSet) Allows(alg string) bool { return s.algs != nil && s.algs[alg] }

// List returns the sorted members, for metadata documents
// (dpop_signing_alg_values_supported etc.).
func (s AlgSet) List() []string {
	out := make([]string, 0, len(s.algs))
	for a := range s.algs {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Empty reports whether the set accepts nothing.
func (s AlgSet) Empty() bool { return len(s.algs) == 0 }

// AlgForPublicKey returns the one JWS algorithm this package pairs with a
// public key type: Ed25519 -> EdDSA, ECDSA P-256 -> ES256, RSA >= 2048 ->
// RS256. Anything else is an error.
func AlgForPublicKey(pub any) (string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return "", fmt.Errorf("jose: ed25519 public key is %d bytes", len(k))
		}
		return AlgEdDSA, nil
	case *ecdsa.PublicKey:
		if k == nil || k.Curve != elliptic.P256() {
			return "", fmt.Errorf("jose: only ECDSA P-256 keys are supported")
		}
		return AlgES256, nil
	case *rsa.PublicKey:
		if k == nil || k.N.BitLen() < MinRSABits {
			return "", fmt.Errorf("jose: RSA keys must be at least %d bits", MinRSABits)
		}
		return AlgRS256, nil
	default:
		return "", fmt.Errorf("jose: unsupported public key type %T", pub)
	}
}

// CheckKeyAlg verifies that alg is the algorithm paired with pub's key type.
// It is the guard against algorithm/key confusion.
func CheckKeyAlg(pub any, alg string) error {
	want, err := AlgForPublicKey(pub)
	if err != nil {
		return err
	}
	if want != alg {
		return fmt.Errorf("jose: algorithm %q does not match key type (want %q)", alg, want)
	}
	return nil
}
