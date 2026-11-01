package sandboxcred

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

// SentinelPrefix starts every sentinel: a value no provider issues, so a
// secret scanner never takes it for a real key and the proxy recognises
// it.
const SentinelPrefix = "obsbx-sentinel-v1-"

// TokenHeader carries the run's relay token from the home side of the
// run's relay to the proxy. The home side sets it (replacing any value the
// box sent), and the proxy strips it before anything goes upstream.
const TokenHeader = "X-Observer-Sandbox-Cred" //nolint:gosec // G101: a header name

// randomBytes is the entropy of a sentinel or a token.
const randomBytes = 32

// mint reads randomBytes from r and encodes them.
func mint(r io.Reader) (string, error) {
	b := make([]byte, randomBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MintSentinel mints a run's sentinel for provider. It is random, and bound
// to the run and the provider by the run's injection record (its hash is
// stored with both), so it is worthless anywhere else.
func MintSentinel(r io.Reader, provider string) (string, error) {
	if _, ok := ProviderFor(provider); !ok {
		return "", errors.New("sandboxcred: unknown provider")
	}
	s, err := mint(r)
	if err != nil {
		return "", err
	}
	return SentinelPrefix + provider + "-" + s, nil
}

// MintToken mints a run's relay token.
func MintToken(r io.Reader) (string, error) { return mint(r) }

// Hash is the stored form of a sentinel or a token.
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// equalHash compares a presented value with a stored hash in constant time.
func equalHash(presented, stored string) bool {
	if presented == "" || stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(Hash(presented)), []byte(stored)) == 1
}

// IsSentinel reports whether s has a sentinel's shape.
func IsSentinel(s string) bool { return strings.HasPrefix(s, SentinelPrefix) }
