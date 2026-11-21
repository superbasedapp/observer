package openshellorg

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// Grant lifetime bounds (section 5.3, G1-A9).
const (
	GrantTTLDefault = 12 * time.Hour
	GrantTTLMin     = 1 * time.Hour
	GrantTTLMax     = 72 * time.Hour
)

// HandleBytes is the size of a grant handle (32 random bytes).
const HandleBytes = 32

// RevokedBy says who revoked a grant. Only an admin revocation makes the
// reaper delete the member's boxes; a member's own logout does not (G1-R40).
type RevokedBy string

// The closed revokers.
const (
	RevokedByNone   RevokedBy = ""
	RevokedByMember RevokedBy = "member"
	RevokedByAdmin  RevokedBy = "admin"
)

// ClampGrantTTL bounds grant_ttl_hours to [1 h, 72 h]; zero means 12 h.
func ClampGrantTTL(d time.Duration) time.Duration {
	switch {
	case d == 0:
		return GrantTTLDefault
	case d < GrantTTLMin:
		return GrantTTLMin
	case d > GrantTTLMax:
		return GrantTTLMax
	}
	return d
}

// NewSecret reads n random bytes from rand and answers them base64url
// (unpadded) for the holder and their SHA-256 hex for the store. The store
// keeps only the hash.
func NewSecret(rand io.Reader, n int) (secret, hash string, err error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand, b); err != nil {
		return "", "", fmt.Errorf("openshellorg.NewSecret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(b)
	return secret, HashSecret(secret), nil
}

// HashSecret is the stored form of a handle, device code or token id.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// GrantFacts is what the store knows about a grant at mint time.
type GrantFacts struct {
	Found     bool
	ID        string
	MemberID  string
	ExpiresAt time.Time
	RevokedAt time.Time
	RevokedBy RevokedBy
	// AgentKeyFP is orgcontract.AgentKeyFingerprint of the member's
	// registered agent key at approval.
	AgentKeyFP string
	// SessionGen and AuthEpoch are the member's session generation and the
	// org's auth epoch at approval.
	SessionGen int64
	AuthEpoch  int64
}

// MemberNow is the member's current state the grant is checked against.
type MemberNow struct {
	ID         string
	Active     bool
	Allowed    bool
	AgentKeyFP string
	SessionGen int64
	AuthEpoch  int64
}

// CheckGrant applies mint rules T3 and T4 (and the per-call check F0's grant
// half): the grant exists, is not expired or revoked, is the member's own,
// its agent key fingerprint equals the member's key now, and neither the
// member's session generation nor the org's auth epoch moved.
func CheckGrant(g GrantFacts, m MemberNow, now time.Time) (rule string, r Reason) {
	switch {
	case !g.Found:
		return "T3", ReasonSigninRequired
	case !g.RevokedAt.IsZero():
		return "T3", ReasonSigninRevoked
	case g.MemberID != m.ID:
		return "T3", ReasonSigninRequired
	case !now.Before(g.ExpiresAt):
		return "T3", ReasonSigninExpired
	case g.AgentKeyFP == "" || g.AgentKeyFP != m.AgentKeyFP:
		return "T3", ReasonSigninRevoked
	case g.SessionGen != m.SessionGen || g.AuthEpoch != m.AuthEpoch:
		return "T4", ReasonSigninRevoked
	}
	return "", ReasonNone
}

// PruneAfter is how long an expired or revoked grant or device code is kept
// before openshellctl prunes it (section 9.2: seven days).
const PruneAfter = 7 * 24 * time.Hour
