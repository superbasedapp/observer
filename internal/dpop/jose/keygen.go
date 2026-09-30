package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"
)

// RSAKeyBits is the modulus size GenerateKey uses for RS256.
const RSAKeyBits = 3072

// GenerateKey creates a fresh in-memory private key for alg and returns it as
// a crypto.Signer. r is the entropy source (crypto/rand.Reader in
// production). It is used by the LocalSealed key provider, the node's
// agent-access key slot and tests - never for a KMS-held key.
func GenerateKey(r io.Reader, alg string) (crypto.Signer, error) {
	switch alg {
	case AlgEdDSA:
		_, priv, err := ed25519.GenerateKey(r)
		if err != nil {
			return nil, fmt.Errorf("jose.GenerateKey: %w", err)
		}
		return priv, nil
	case AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), r)
		if err != nil {
			return nil, fmt.Errorf("jose.GenerateKey: %w", err)
		}
		return priv, nil
	case AlgRS256:
		priv, err := rsa.GenerateKey(r, RSAKeyBits)
		if err != nil {
			return nil, fmt.Errorf("jose.GenerateKey: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("jose.GenerateKey: algorithm %q is not in the asymmetric allowlist", alg)
	}
}
