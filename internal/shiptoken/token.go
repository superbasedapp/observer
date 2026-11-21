package shiptoken

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Prefix starts every ship token. It makes a ship token recognisable in a
// secret scanner and impossible to confuse with an Ed25519 node bearer
// ("<base64url payload>.<base64url signature>", which never contains "_").
const Prefix = "sbocs_"

// IDPrefix starts every public token id (the row key an admin or member
// revokes by). The id is not a secret.
const IDPrefix = "cst_"

// secretBytes is the random part of a token: 256 bits.
const secretBytes = 32

// idBytes is the random part of a public token id.
const idBytes = 12

// encodedSecretLen is the base64url (no padding) length of secretBytes.
var encodedSecretLen = base64.RawURLEncoding.EncodedLen(secretBytes)

// ErrMalformed is returned by Parse for a value that is not a ship token.
var ErrMalformed = errors.New("shiptoken: not a ship token")

// Minted is one freshly generated token: the secret shown once, its public
// id and the digest the destination stores.
type Minted struct {
	// Token is the secret. It is returned to the caller exactly once and
	// never stored.
	Token string
	// ID is the public token id.
	ID string
	// Hash is Hash(Token), the only form a destination keeps.
	Hash string
}

// Generate mints a token from rand (crypto/rand.Reader in production).
func Generate(rand io.Reader) (Minted, error) {
	secret := make([]byte, secretBytes)
	if _, err := io.ReadFull(rand, secret); err != nil {
		return Minted{}, fmt.Errorf("shiptoken.Generate: secret: %w", err)
	}
	id := make([]byte, idBytes)
	if _, err := io.ReadFull(rand, id); err != nil {
		return Minted{}, fmt.Errorf("shiptoken.Generate: id: %w", err)
	}
	tok := Prefix + base64.RawURLEncoding.EncodeToString(secret)
	return Minted{Token: tok, ID: IDPrefix + hex.EncodeToString(id), Hash: Hash(tok)}, nil
}

// Parse checks that raw is a well-formed ship token and returns it trimmed.
// It does not say whether the token exists; that is the destination's lookup
// of Hash(token).
func Parse(raw string) (string, error) {
	tok := strings.TrimSpace(raw)
	if !strings.HasPrefix(tok, Prefix) {
		return "", ErrMalformed
	}
	body := tok[len(Prefix):]
	if len(body) != encodedSecretLen {
		return "", ErrMalformed
	}
	if _, err := base64.RawURLEncoding.DecodeString(body); err != nil {
		return "", ErrMalformed
	}
	return tok, nil
}

// FromAuthorization extracts a ship token from an Authorization header value
// ("Bearer <token>", the scheme case-insensitive).
func FromAuthorization(header string) (string, error) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", ErrMalformed
	}
	return Parse(rest)
}

// Hash is the stored digest of a token: lowercase sha256 hex. A token has
// 256 random bits, so an unsalted fast hash is the right tool (the
// enrolment-token and SCIM-token precedent); lookups are by digest equality.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ValidID reports whether id has the public token id shape.
func ValidID(id string) bool {
	if !strings.HasPrefix(id, IDPrefix) || len(id) != len(IDPrefix)+2*idBytes {
		return false
	}
	_, err := hex.DecodeString(id[len(IDPrefix):])
	return err == nil && strings.ToLower(id) == id
}

// Lifetime bounds. A ship token is short-lived next to an enrolment
// credential: eight hours (a working session) by default since decision
// CA-D18, a week at most, so a token left in a cloud environment setting
// expires on its own. The expiry is shown on every list and every receipt.
const (
	DefaultLifetime = 8 * time.Hour
	MinLifetime     = 10 * time.Minute
	MaxLifetime     = 7 * 24 * time.Hour
)

// lifetimeRule is one row of the lifetime table.
type lifetimeRule struct {
	name  string
	match func(time.Duration) bool
	pick  func(time.Duration) time.Duration
}

// lifetimeRules is walked top-down; the first match decides.
var lifetimeRules = []lifetimeRule{
	{"unset uses the default", func(d time.Duration) bool { return d <= 0 }, func(time.Duration) time.Duration { return DefaultLifetime }},
	{"below the floor is raised", func(d time.Duration) bool { return d < MinLifetime }, func(time.Duration) time.Duration { return MinLifetime }},
	{"above the ceiling is lowered", func(d time.Duration) bool { return d > MaxLifetime }, func(time.Duration) time.Duration { return MaxLifetime }},
	{"in range is kept", func(time.Duration) bool { return true }, func(d time.Duration) time.Duration { return d }},
}

// ClampLifetime resolves a requested lifetime through the lifetime table.
func ClampLifetime(requested time.Duration) time.Duration {
	for _, r := range lifetimeRules {
		if r.match(requested) {
			return r.pick(requested)
		}
	}
	return DefaultLifetime
}

// Volume cap bounds (decision CA-D18): the most admitted rows one token may
// land over its whole life on the org route. A sandbox's capture is bounded
// by its session, so a token that keeps landing rows far past any session's
// size is a leaked token being replayed, and the cap stops it without a
// human noticing first. The default fits many long sessions; the ceiling
// bounds what a member may ask for.
const (
	DefaultRowCap int64 = 200_000
	MinRowCap     int64 = 1_000
	MaxRowCap     int64 = 2_000_000
)

// rowCapRule is one row of the volume-cap table.
type rowCapRule struct {
	name  string
	match func(int64) bool
	pick  func(int64) int64
}

// rowCapRules is walked top-down; the first match decides.
var rowCapRules = []rowCapRule{
	{"unset uses the default", func(n int64) bool { return n <= 0 }, func(int64) int64 { return DefaultRowCap }},
	{"below the floor is raised", func(n int64) bool { return n < MinRowCap }, func(int64) int64 { return MinRowCap }},
	{"above the ceiling is lowered", func(n int64) bool { return n > MaxRowCap }, func(int64) int64 { return MaxRowCap }},
	{"in range is kept", func(int64) bool { return true }, func(n int64) int64 { return n }},
}

// ClampRowCap resolves a requested volume cap through the cap table.
func ClampRowCap(requested int64) int64 {
	for _, r := range rowCapRules {
		if r.match(requested) {
			return r.pick(requested)
		}
	}
	return DefaultRowCap
}

// MaxLabelRunes bounds a token label.
const MaxLabelRunes = 64

// ValidLabel reports whether label is an acceptable token label: empty, or at
// most MaxLabelRunes printable runes with no control characters. A label is
// the member's own note ("claude-code web env"), shown back on the list.
func ValidLabel(label string) bool {
	if !utf8.ValidString(label) || utf8.RuneCountInString(label) > MaxLabelRunes {
		return false
	}
	for _, r := range label {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// ValidEnvironmentLabel reports whether label names a cloud environment:
// a non-blank ValidLabel. Since decision CA-D18 a ship token is minted PER
// CLOUD ENVIRONMENT, so the label is required; it is what the list, the
// audit row and the session tag point a human at.
func ValidEnvironmentLabel(label string) bool {
	return strings.TrimSpace(label) != "" && ValidLabel(label)
}

// EnvironmentKey is the comparison form of an environment label (trimmed,
// case-folded): two active tokens of one holder may not share it.
func EnvironmentKey(label string) string {
	return strings.ToLower(strings.TrimSpace(label))
}

// Status values a token row resolves to.
const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

// StatusAt resolves a token's status at now. Revocation wins over expiry so
// the list says what a human did, not what the clock did.
func StatusAt(now, expiresAt, revokedAt time.Time) string {
	switch {
	case !revokedAt.IsZero():
		return StatusRevoked
	case !now.Before(expiresAt):
		return StatusExpired
	default:
		return StatusActive
	}
}

// Error codes both destinations answer with (the JSON "error" field). A
// sandbox's flush reads them to set its coverage state; none of them says
// anything about a token the caller does not hold.
const (
	CodeMissing        = "ship_token_missing"
	CodeInvalid        = "ship_token_invalid"
	CodeExpired        = "ship_token_expired"
	CodeRevoked        = "ship_token_revoked"
	CodeMemberInactive = "ship_token_member_inactive"
	CodeNoNode         = "ship_token_no_enrolled_node"
	CodeTooLarge       = "payload_too_large"
	// CodeVolumeExhausted: the batch would take the token past its volume
	// cap (CA-D18). Mint a new token for the environment.
	CodeVolumeExhausted = "ship_token_volume_exhausted"
	CodeBadEnvelope     = "bad_envelope"
	CodeUnavailable     = "unavailable"
	// CodeDisabled: the org has turned cloud sessions (Rail S) off
	// (security ledger CLOUDSESS-13). Org destination only: every mint
	// route and the ingest route answer it with 403 while the switch is
	// off; tokens are kept and resume when it is turned back on. A node's
	// own ship-token rail has no such switch.
	CodeDisabled = "cloud_sessions_disabled"
)

// RefusalCode maps a token status to its refusal code ("" for active).
func RefusalCode(status string) string {
	switch status {
	case StatusActive:
		return ""
	case StatusExpired:
		return CodeExpired
	case StatusRevoked:
		return CodeRevoked
	default:
		return CodeInvalid
	}
}
