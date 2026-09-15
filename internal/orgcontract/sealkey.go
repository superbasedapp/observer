package orgcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Node seal-key advertisement (Plane B dual-mode gateway design 2026-08-29
// §4.2 rung 3; gap register 2026-09-02 G1-BREAKGLASS). A break-glass lease's
// SealedCredential is sealed to the TARGET NODE's own key so no one but that
// machine can open it. For the org server to seal, it must know the node's
// public seal key — this file is the contract by which a node publishes it.
//
// Delivery: the node sets HeaderSealKey on every signed push. Like the two
// existing advisory ACK headers it rides an already-authenticated push and
// can only describe the node's OWN key; but unlike them it is a trust input
// (the server seals a real credential to whatever key it records), so the
// value carries its own Ed25519 signature under the node's enrolment signing
// key, bound to (org, node, scheme, key). The server verifies that signature
// against the agent public key bound at enrolment before recording the key —
// a bearer-holding middlebox that rewrote the header could not substitute a
// key it controls without also holding the node's signing key.
//
// The private half is never on the wire: the node derives it from its
// enrolment signing seed (internal/sealbox.DeriveKeyPair).

// HeaderSealKey carries a SealKeyAdvertisement, encoded by
// (SealKeyAdvertisement).HeaderValue, on the node's push request.
const HeaderSealKey = "X-SBO-Seal-Key"

// sealKeySigningDomain domain-separates the advertisement signature from every
// other Ed25519 use of the agent key (push signing, policy-state reports).
const sealKeySigningDomain = "sbo-break-glass-seal-key-advert-v1"

// SealKeyAdvertisement is one node's published seal key.
type SealKeyAdvertisement struct {
	// Scheme is the sealbox scheme tag the key is for (sealbox.SchemeV1).
	Scheme string
	// PublicKey is the base64url (unpadded) X25519 public key.
	PublicKey string
	// Signature is base64url(Ed25519) over SealKeySigningMessage.
	Signature string
}

// SealKeySigningMessage is the canonical signed bytes: domain tag + org +
// node + scheme + key, NUL-separated so no field can shift into another.
func SealKeySigningMessage(orgID, userID, scheme, publicKey string) []byte {
	h := sha256.New()
	for _, s := range []string{sealKeySigningDomain, orgID, userID, scheme, publicKey} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// SignSealKeyAdvertisement builds a signed advertisement for (orgID, userID).
func SignSealKeyAdvertisement(priv ed25519.PrivateKey, orgID, userID, scheme, publicKey string) SealKeyAdvertisement {
	sig := ed25519.Sign(priv, SealKeySigningMessage(orgID, userID, scheme, publicKey))
	return SealKeyAdvertisement{
		Scheme: scheme, PublicKey: publicKey,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

// HeaderValue encodes the advertisement as "<scheme>:<public_key>:<signature>".
// The scheme tag contains no ':' by construction (it is a fixed vocabulary), and
// the two base64url fields never do, so the split is unambiguous.
func (a SealKeyAdvertisement) HeaderValue() string {
	return a.Scheme + ":" + a.PublicKey + ":" + a.Signature
}

// ParseSealKeyHeader decodes a HeaderSealKey value. An empty value (a node that
// predates break-glass) yields ok=false with no error; a malformed one is an
// error the server logs and ignores.
func ParseSealKeyHeader(v string) (adv SealKeyAdvertisement, ok bool, err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return SealKeyAdvertisement{}, false, nil
	}
	parts := strings.Split(v, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return SealKeyAdvertisement{}, false, errors.New("orgcontract.ParseSealKeyHeader: want <scheme>:<public_key>:<signature>")
	}
	return SealKeyAdvertisement{Scheme: parts[0], PublicKey: parts[1], Signature: parts[2]}, true, nil
}

// VerifySealKeyAdvertisement checks the advertisement's signature under the
// agent public key bound at enrolment for (orgID, userID). It returns a named
// error for every failure so the server can log why a key was not recorded.
func VerifySealKeyAdvertisement(pub ed25519.PublicKey, orgID, userID string, a SealKeyAdvertisement) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("orgcontract.VerifySealKeyAdvertisement: no agent key bound")
	}
	if a.Scheme == "" || a.PublicKey == "" {
		return errors.New("orgcontract.VerifySealKeyAdvertisement: advertisement carries no scheme/key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil {
		return fmt.Errorf("orgcontract.VerifySealKeyAdvertisement: decode signature: %w", err)
	}
	if !ed25519.Verify(pub, SealKeySigningMessage(orgID, userID, a.Scheme, a.PublicKey), sig) {
		return errors.New("orgcontract.VerifySealKeyAdvertisement: signature verification failed")
	}
	return nil
}
