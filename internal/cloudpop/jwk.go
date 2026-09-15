package cloudpop

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// b64 is the base64url encoding with no padding used throughout the JWS
// structure (RFC 7515 §2).
var b64 = base64.RawURLEncoding

// jwk is the RFC 8037 OKP (Ed25519) public-key JSON Web Key embedded in the
// proof's protected header. Field order is fixed by declaration order and is
// NOT the thumbprint preimage — see Thumbprint for the canonical member set.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// newJWK builds the OKP JWK for an Ed25519 public key.
func newJWK(pub ed25519.PublicKey) jwk {
	return jwk{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(pub)}
}

// publicKey decodes and validates the JWK back into an Ed25519 public key.
func (k jwk) publicKey() (ed25519.PublicKey, error) {
	if k.Kty != "OKP" {
		return nil, fmt.Errorf("cloudpop: jwk kty %q, want OKP", k.Kty)
	}
	if k.Crv != "Ed25519" {
		return nil, fmt.Errorf("cloudpop: jwk crv %q, want Ed25519", k.Crv)
	}
	raw, err := b64.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("cloudpop: decode jwk x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("cloudpop: jwk x is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Thumbprint returns the RFC 7638 JWK SHA-256 thumbprint of an Ed25519 public
// key, base64url-encoded (no padding). The preimage is the canonical JSON of
// the required members in lexicographic order: {"crv":...,"kty":...,"x":...}.
// It is the stable device-key identifier the server binds an API token to
// (the DPoP "jkt").
func Thumbprint(pub ed25519.PublicKey) string {
	// Hand-built to guarantee the exact canonical member ordering and spacing
	// RFC 7638 mandates (no reliance on map ordering).
	preimage := `{"crv":"Ed25519","kty":"OKP","x":"` + b64.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(preimage))
	return b64.EncodeToString(sum[:])
}

// encodeJSON marshals v and base64url-encodes it for a JWS segment.
func encodeJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(raw), nil
}
