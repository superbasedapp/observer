package platformcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SigningDomain domain-separates host-API signatures from every other
// signature in the repository.
const SigningDomain = "sbo-platform-host-api-v1"

// ReplayWindow is the maximum clock distance between an envelope's timestamp
// and the verifier's now, in either direction.
const ReplayWindow = 5 * time.Minute

// Header names carrying the envelope on the wire.
const (
	HeaderKeyID     = "X-SBO-Key-Id"
	HeaderTimestamp = "X-SBO-Timestamp"
	HeaderNonce     = "X-SBO-Nonce"
	HeaderDigest    = "X-SBO-Body-Digest"
	HeaderSignature = "X-SBO-Signature"
)

// Envelope is the signed-body envelope of one host-API request or response.
type Envelope struct {
	// KeyID names the signing key.
	KeyID string `json:"key_id"`
	// Timestamp is Unix seconds at signing.
	Timestamp int64 `json:"timestamp"`
	// Nonce is a unique per-request string; the verifier's replay cache (not
	// this package) rejects repeats within ReplayWindow.
	Nonce string `json:"nonce"`
	// BodyDigest is BodyDigest(body): lowercase hex sha256.
	BodyDigest string `json:"body_digest"`
	// Signature is the base64 ed25519 signature over SigningInput.
	Signature string `json:"signature"`
}

// Envelope errors.
var (
	// ErrStale means the timestamp is outside ReplayWindow.
	ErrStale = errors.New("platformcontract: envelope timestamp outside replay window")
	// ErrDigestMismatch means the body does not match the signed digest.
	ErrDigestMismatch = errors.New("platformcontract: body digest mismatch")
	// ErrBadSignature means signature verification failed or was malformed.
	ErrBadSignature = errors.New("platformcontract: bad signature")
)

// BodyDigest returns the lowercase hex sha256 of body.
func BodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// SigningInput returns the canonical signed bytes: the domain tag, method,
// request target (path plus raw query), timestamp, nonce, key id and body
// digest, newline-joined. No field may be empty or contain a newline.
func SigningInput(method, target string, e Envelope) ([]byte, error) {
	named := []struct{ name, v string }{
		{"domain", SigningDomain},
		{"method", strings.ToUpper(method)},
		{"target", target},
		{"timestamp", strconv.FormatInt(e.Timestamp, 10)},
		{"nonce", e.Nonce},
		{"key_id", e.KeyID},
		{"body_digest", e.BodyDigest},
	}
	parts := make([]string, 0, len(named))
	for _, f := range named {
		if f.v == "" {
			return nil, fmt.Errorf("platformcontract.SigningInput: %s is empty", f.name)
		}
		if strings.ContainsAny(f.v, "\n\r") {
			return nil, fmt.Errorf("platformcontract.SigningInput: %s contains a newline", f.name)
		}
		parts = append(parts, f.v)
	}
	return []byte(strings.Join(parts, "\n")), nil
}

// NewEnvelope builds and signs an envelope for body at now.
func NewEnvelope(priv ed25519.PrivateKey, keyID, nonce, method, target string, body []byte, now time.Time) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("platformcontract.NewEnvelope: %w", ErrBadSignature)
	}
	e := Envelope{KeyID: keyID, Timestamp: now.Unix(), Nonce: nonce, BodyDigest: BodyDigest(body)}
	in, err := SigningInput(method, target, e)
	if err != nil {
		return Envelope{}, fmt.Errorf("platformcontract.NewEnvelope: %w", err)
	}
	e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, in))
	return e, nil
}

// CheckFreshness reports ErrStale when e.Timestamp is more than ReplayWindow
// from now in either direction (the exact edge is accepted). now is injected.
func (e Envelope) CheckFreshness(now time.Time) error {
	d := now.Sub(time.Unix(e.Timestamp, 0))
	if d < 0 {
		d = -d
	}
	if d > ReplayWindow {
		return fmt.Errorf("platformcontract.Envelope.CheckFreshness: %w", ErrStale)
	}
	return nil
}

// Verify checks freshness, the body digest and the signature against pub.
func (e Envelope) Verify(pub ed25519.PublicKey, method, target string, body []byte, now time.Time) error {
	if err := e.CheckFreshness(now); err != nil {
		return fmt.Errorf("platformcontract.Envelope.Verify: %w", err)
	}
	if BodyDigest(body) != e.BodyDigest {
		return fmt.Errorf("platformcontract.Envelope.Verify: %w", ErrDigestMismatch)
	}
	in, err := SigningInput(method, target, e)
	if err != nil {
		return fmt.Errorf("platformcontract.Envelope.Verify: %w: %w", ErrBadSignature, err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, in, sig) {
		return fmt.Errorf("platformcontract.Envelope.Verify: %w", ErrBadSignature)
	}
	return nil
}
