package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func claims(raw string, key []byte) {
	// ruleid: go.jwt-verification-off
	t, _, _ := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	// ruleid: go.jwt-verification-off
	u, _ := jwt.Parse(raw, func(*jwt.Token) (any, error) { return jwt.UnsafeAllowNoneSignatureType, nil })
	// ok: go.jwt-verification-off
	v, _ := jwt.Parse(raw, func(*jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"HS256"}))
	_, _, _ = t, u, v
}

// The false-positive shapes of the 1.1.0 rule: claims validation turned
// off with the signature still checked, and test code.
func signedNoExpiry(raw string, key []byte) {
	// ok: go.jwt-verification-off
	_, _ = jwt.Parse(raw, func(*jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
}

func TestNoneRejected(t *testing.T) {
	// ok: go.jwt-verification-off
	key := jwt.UnsafeAllowNoneSignatureType
	_ = key
}
