package attachgrant

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
)

// ProofDomain domain-separates the device proof from every other signature
// the device key makes (the cloud's proof-of-possession JWS, whose signing
// input is base64url text with no NUL byte).
const ProofDomain = "sbo-attach-proof-v1"

// Proof is what the machine sends beside the grant: its device public key
// and a signature, by that key, over ProofMessage. Both are base64url without
// padding.
type Proof struct {
	// DevicePublicKey is the raw 32-byte Ed25519 device key, base64url.
	DevicePublicKey string `json:"device_public_key"`
	// Signature is the Ed25519 signature over ProofMessage, base64url.
	Signature string `json:"signature"`
}

// ProofMessage is what the device key signs: the domain, the exact grant and
// the node key being enrolled (the enrol request's agent_public_key, as
// sent). Binding the node key means a proof copied off the wire cannot enrol
// any other key, and the grant's single use stops a replay of the whole
// request.
func ProofMessage(grant, agentPublicKey string) []byte {
	h := sha256.New()
	h.Write([]byte(ProofDomain))
	h.Write([]byte{0})
	h.Write([]byte(strings.TrimSpace(grant)))
	h.Write([]byte{0})
	h.Write([]byte(agentPublicKey))
	return h.Sum(nil)
}

// SignProof signs the proof for grant and agentPublicKey with the device key.
func SignProof(devicePriv ed25519.PrivateKey, grant, agentPublicKey string) (Proof, error) {
	if len(devicePriv) != ed25519.PrivateKeySize {
		return Proof{}, fmt.Errorf("attachgrant.SignProof: %w: not an Ed25519 private key", ErrBadProof)
	}
	pub, ok := devicePriv.Public().(ed25519.PublicKey)
	if !ok {
		return Proof{}, fmt.Errorf("attachgrant.SignProof: %w: not an Ed25519 private key", ErrBadProof)
	}
	sig := ed25519.Sign(devicePriv, ProofMessage(grant, agentPublicKey))
	return Proof{DevicePublicKey: b64.EncodeToString(pub), Signature: b64.EncodeToString(sig)}, nil
}

// VerifyProof checks p against the verified claims c: the device key it
// carries must be the one whose thumbprint the grant names, and its signature
// must verify over ProofMessage(grant, agentPublicKey).
func VerifyProof(c Claims, p Proof, grant, agentPublicKey string) error {
	raw, err := b64.DecodeString(strings.TrimSpace(p.DevicePublicKey))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("attachgrant.VerifyProof: %w: device key", ErrBadProof)
	}
	pub := ed25519.PublicKey(raw)
	if Thumbprint(pub) != c.DeviceThumbprint {
		return fmt.Errorf("attachgrant.VerifyProof: %w: another device key", ErrBadProof)
	}
	sig, err := b64.DecodeString(strings.TrimSpace(p.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("attachgrant.VerifyProof: %w: signature", ErrBadProof)
	}
	if !ed25519.Verify(pub, ProofMessage(grant, agentPublicKey), sig) {
		return fmt.Errorf("attachgrant.VerifyProof: %w", ErrBadProof)
	}
	return nil
}

// Thumbprint is the RFC 7638 JWK SHA-256 thumbprint of an Ed25519 public key,
// base64url without padding: the canonical members {"crv","kty","x"} in
// order. It equals internal/cloudpop.Thumbprint (pinned by a test), which the
// cloud stores for every connect request; this package keeps its own copy so
// the org server never links the cloud's proof package.
func Thumbprint(pub ed25519.PublicKey) string {
	preimage := `{"crv":"Ed25519","kty":"OKP","x":"` + b64.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(preimage))
	return b64.EncodeToString(sum[:])
}
