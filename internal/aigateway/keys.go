package aigateway

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// VirtualKeyPrefix is the human-visible prefix of every minted virtual key.
// It makes a leaked key greppable and unambiguous in logs and support
// tickets, exactly as `sk-` does for provider keys.
const VirtualKeyPrefix = "sbo-vk-"

// virtualKeyRandomBytes is the entropy behind a virtual key. 32 bytes
// (256 bits) is well past brute-force reach and matches the sealing-key size.
const virtualKeyRandomBytes = 32

// vkEncoding is unpadded lowercase base32 — url-safe, case-insensitive-proof
// against typo mangling, and free of the `+`/`/` that break shell copy-paste.
var vkEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// MintVirtualKey draws entropy from r and returns a new plaintext virtual key
// of the form "sbo-vk-<base32(32 random bytes)>". The plaintext is returned
// ONCE to the caller who hands it to the developer; the server persists only
// HashVirtualKey(plaintext). r is injected (crypto/rand.Reader in production)
// so the mint is deterministic under test.
func MintVirtualKey(r io.Reader) (string, error) {
	buf := make([]byte, virtualKeyRandomBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("aigateway.MintVirtualKey: read entropy: %w", err)
	}
	return VirtualKeyPrefix + strings.ToLower(vkEncoding.EncodeToString(buf)), nil
}

// HashVirtualKey returns the hex SHA-256 of a plaintext virtual key. This is
// the ONLY form the server stores or compares — the plaintext is never
// persisted, so a database read cannot recover a usable key. Lookups hash the
// presented key and match on the hash.
func HashVirtualKey(plaintext string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(plaintext)))
	return hex.EncodeToString(sum[:])
}

// ValidVirtualKeyFormat reports whether s has the shape MintVirtualKey
// produces: the prefix followed by a non-empty base32 body of the expected
// length. It is a cheap pre-filter — a well-formed key still has to match a
// stored hash — so the gateway can reject obviously-bogus input before any
// store round-trip.
func ValidVirtualKeyFormat(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, VirtualKeyPrefix) {
		return false
	}
	body := strings.TrimPrefix(s, VirtualKeyPrefix)
	wantLen := vkEncoding.EncodedLen(virtualKeyRandomBytes)
	if len(body) != wantLen {
		return false
	}
	if _, err := vkEncoding.DecodeString(strings.ToUpper(body)); err != nil {
		return false
	}
	return true
}

// VirtualKey is the stored record behind a minted key. The plaintext is never
// held here; Hash is the SHA-256 the store matches on. A key is bound to a
// single member (UserID) and a single machine (MachineFingerprint) so a
// leaked key cannot be silently reused from another host, and abuse
// attribution is exact.
type VirtualKey struct {
	KeyID              string
	OrgID              string
	UserID             string
	MachineFingerprint string
	Hash               string

	CreatedAt time.Time
	ExpiresAt time.Time // zero ⇒ no TTL

	// RevokedAt is non-zero once revoked. RevokedStrict records the per-
	// revocation choice (design §2.3, HG8): a routine rotation lets in-flight
	// streams complete, a compromised-key revocation aborts them.
	RevokedAt     time.Time
	RevokedStrict bool

	// ThinAllowed gates thin-mode use (tool → gateway directly, no node
	// daemon). Default false: the gateway rejects a key not flagged for thin
	// use (§3.2 default-DENIED), an admin enables it per key for CI/bring-up.
	ThinAllowed bool

	// RotatedFrom, when set, is the KeyID this key superseded — rotation is
	// mint-new + revoke-old, so the audit trail links the generations.
	RotatedFrom string
}

// KeyRejectReason enumerates why authentication of a presented key failed.
// The gateway maps each to a stable, agent-legible error; none echoes the key.
type KeyRejectReason string

const (
	// RejectNone means the key is valid for use.
	RejectNone KeyRejectReason = ""
	// RejectMalformed — the presented string is not a well-formed key.
	RejectMalformed KeyRejectReason = "malformed"
	// RejectUnknown — no stored key matches the presented hash.
	RejectUnknown KeyRejectReason = "unknown"
	// RejectExpired — the key's TTL has passed.
	RejectExpired KeyRejectReason = "expired"
	// RejectRevoked — the key was revoked.
	RejectRevoked KeyRejectReason = "revoked"
	// RejectMachineMismatch — the presented machine fingerprint differs from
	// the bound one.
	RejectMachineMismatch KeyRejectReason = "machine_mismatch"
	// RejectThinDenied — a thin-mode request against a key not flagged for it.
	RejectThinDenied KeyRejectReason = "thin_denied"
	// RejectStaleWatermark — a cached "active" verdict older than the observed
	// revocation watermark (Sol S9); the caller must re-fetch, never resurrect.
	RejectStaleWatermark KeyRejectReason = "stale_watermark"
)

// EvaluateKey applies the pure validity rules to a resolved key at time now,
// for the presented machine fingerprint and thin-mode flag. It does NOT
// consult the revocation watermark — that is the auth cache's job
// (see AuthCacheEntry.Verdict), because the watermark rule guards a race
// between a cache fill and a revocation, not the key's own fields.
func EvaluateKey(k VirtualKey, presentedMachine string, thin bool, now time.Time) KeyRejectReason {
	if !k.RevokedAt.IsZero() {
		return RejectRevoked
	}
	if !k.ExpiresAt.IsZero() && !now.Before(k.ExpiresAt) {
		return RejectExpired
	}
	if k.MachineFingerprint != "" && presentedMachine != k.MachineFingerprint {
		return RejectMachineMismatch
	}
	if thin && !k.ThinAllowed {
		return RejectThinDenied
	}
	return RejectNone
}

// AuthCacheEntry is one cached key resolution, stamped with the revocation
// watermark observed when it was filled (Sol S9). The gateway caches
// resolutions to keep authn off the hot DB path, but a cache must never
// resurrect a key a concurrent revocation has already invalidated.
type AuthCacheEntry struct {
	Key       VirtualKey
	Watermark int64     // the store's revocation watermark at fill time
	FilledAt  time.Time // for TTL expiry
}

// Verdict returns the reject reason for a cached entry at time now, given the
// cache TTL and the store's LATEST revocation watermark. It layers two
// independent freshness checks on top of EvaluateKey:
//
//   - TTL: an entry older than ttl is stale (RejectUnknown ⇒ re-fetch).
//   - Watermark (Sol S9): if the store's latest watermark has advanced past
//     the entry's stamp, some key was revoked since this entry was filled;
//     the entry might be that key, so it is rejected as RejectStaleWatermark
//     and the caller re-resolves against the store. This closes the
//     lookup-races-revocation window: a stale "active" can never win.
//
// ttl <= 0 disables the TTL check (every non-watermark-stale entry is fresh).
func (e AuthCacheEntry) Verdict(presentedMachine string, thin bool, now time.Time, ttl time.Duration, latestWatermark int64) KeyRejectReason {
	if latestWatermark > e.Watermark {
		return RejectStaleWatermark
	}
	if ttl > 0 && now.Sub(e.FilledAt) >= ttl {
		return RejectUnknown
	}
	return EvaluateKey(e.Key, presentedMachine, thin, now)
}
