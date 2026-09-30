package dpop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

// DefaultNonceWindow is the nonce time-bucket width.
const DefaultNonceWindow = 5 * time.Minute

// NonceIssuer mints and checks STATELESS server nonces (the RFC 9449 §8/§9
// `DPoP-Nonce` challenge): base64url(bucket || HMAC-SHA256(key, bucket)[:16]).
// Every STS/data-plane replica that shares Key agrees without shared state; a
// nonce is accepted in its own bucket and the one after it.
type NonceIssuer struct {
	// Key is the shared HMAC key (>= 32 bytes).
	Key []byte
	// Window is the bucket width (zero -> DefaultNonceWindow).
	Window time.Duration
}

func (n NonceIssuer) window() time.Duration {
	if n.Window > 0 {
		return n.Window
	}
	return DefaultNonceWindow
}

// Validate checks the key length.
func (n NonceIssuer) Validate() error {
	if len(n.Key) < 32 {
		return errors.New("dpop: nonce key must be at least 32 bytes")
	}
	return nil
}

func (n NonceIssuer) mac(bucket uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], bucket)
	m := hmac.New(sha256.New, n.Key)
	m.Write(b[:])
	return append(b[:], m.Sum(nil)[:16]...)
}

// Issue returns the nonce for now's bucket.
func (n NonceIssuer) Issue(now time.Time) string {
	return base64.RawURLEncoding.EncodeToString(n.mac(uint64(now.Unix()) / uint64(n.window()/time.Second)))
}

// Check reports whether nonce was issued for now's bucket or the previous one.
func (n NonceIssuer) Check(nonce string, now time.Time) bool {
	if n.Validate() != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(raw) != 24 {
		return false
	}
	cur := uint64(now.Unix()) / uint64(n.window()/time.Second)
	got := binary.BigEndian.Uint64(raw[:8])
	if got != cur && got+1 != cur {
		return false
	}
	return hmac.Equal(raw, n.mac(got))
}
