package sdkkeygrant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// SigningDomain domain-separates the key grant's signature from every other
// signature the platform makes (the attach grant, entitlements, availability,
// host-API envelopes, OIDC tokens, the org's own rails).
const SigningDomain = "sbo-sdk-key-grant-v1"

// Version is the claims version this package signs and accepts.
const Version = 1

// Lifetime is how long a grant is valid after it is issued (the approval). The
// SDK redeems it within seconds of the poll that delivers it; ten minutes
// covers a personal dashboard still being set up and a retried poll.
const Lifetime = 10 * time.Minute

// ClockSkew is how far in the future an issue time may be (the cloud's clock
// ahead of the tenant host's).
const ClockSkew = 60 * time.Second

// TokenPrefix starts every key grant: the format's own version, so a future
// format, or a grant of another kind, is told apart before any decoding.
const TokenPrefix = "sbsk1."

// MaxTokenBytes bounds a grant before any decoding (a real one is well under
// 1 KiB).
const MaxTokenBytes = 4096

// Dashboard kinds a grant names.
const (
	// KindPersonal is an account's own personal dashboard.
	KindPersonal = "personal"
	// KindTeam is a team dashboard.
	KindTeam = "team"
)

// RedeemSecretLen is the length of a redeem secret: 32 random bytes as
// unpadded base64url. A redeem hash has the same length (a SHA-256 digest).
const RedeemSecretLen = 43

// Claims is the signed content of a grant. Every field is required.
type Claims struct {
	// V is the claims version (Version).
	V int `json:"v"`
	// KeyID names the signing key (platformcontract.DocumentKeyID).
	KeyID string `json:"kid"`
	// OrgID is the dashboard's organization id: the tenant the grant is for.
	OrgID string `json:"org_id"`
	// Slug is the dashboard's slug (the tenant host's routing label).
	Slug string `json:"slug"`
	// Kind is KindPersonal or KindTeam.
	Kind string `json:"kind"`
	// AccountID is the SuperBased account that approved the request.
	AccountID string `json:"account_id"`
	// Subject is the account's identity-provider subject, the value a pooled
	// host binds its members by. The member the key is minted for is found by
	// it; nobody is created.
	Subject string `json:"sub"`
	// RequestID is the connect request the approval answered.
	RequestID string `json:"request_id"`
	// RedeemHash is RedeemHash(redeem secret): the SDK sent it at create and
	// keeps the secret, so a grant copied from a log or a proxy is useless
	// without it.
	RedeemHash string `json:"redeem_hash"`
	// IssuedAt and ExpiresAt are Unix seconds.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
	// JTI is the grant's single-use id, JTIFor(RequestID): every re-delivery
	// of one approval carries the same jti, so the tenant host mints one key
	// per approval.
	JTI string `json:"jti"`
}

// Reason is the closed vocabulary of Verify's refusals, for the tenant host's
// answer and its audit row.
type Reason string

// The reasons, one per check this package owns.
const (
	// ReasonNone is the zero Reason: no refusal.
	ReasonNone Reason = ""
	// ReasonShape: not a key grant, or a claim is missing or out of shape.
	ReasonShape Reason = "shape"
	// ReasonVersion: a claims version this build does not accept.
	ReasonVersion Reason = "version"
	// ReasonNoKey: the verifier pins no key at all (the host does not take
	// key grants).
	ReasonNoKey Reason = "no_key"
	// ReasonUnknownKey: the grant names a key the verifier does not pin.
	ReasonUnknownKey Reason = "unknown_key"
	// ReasonSignature: the signature does not verify under the named key.
	ReasonSignature Reason = "signature"
	// ReasonDomain: a document of another kind: an attach grant's prefix, or
	// a signature that verifies only under another domain tag.
	ReasonDomain Reason = "domain"
	// ReasonSkew: the grant was issued in the future, beyond ClockSkew.
	ReasonSkew Reason = "skew"
	// ReasonLifetime: the grant claims a lifetime longer than Lifetime, or
	// expires before it is issued.
	ReasonLifetime Reason = "lifetime"
	// ReasonExpired: now is at or past the grant's expiry.
	ReasonExpired Reason = "expired"
)

// Errors. Verify wraps exactly one of them; ReasonOf maps it to its Reason.
var (
	// ErrShape is ReasonShape.
	ErrShape = errors.New("sdkkeygrant: malformed grant")
	// ErrVersion is ReasonVersion.
	ErrVersion = errors.New("sdkkeygrant: unsupported grant version")
	// ErrNoKey is ReasonNoKey.
	ErrNoKey = errors.New("sdkkeygrant: no key grant key is pinned")
	// ErrUnknownKey is ReasonUnknownKey.
	ErrUnknownKey = errors.New("sdkkeygrant: grant signed by a key that is not pinned")
	// ErrSignature is ReasonSignature.
	ErrSignature = errors.New("sdkkeygrant: grant signature does not verify")
	// ErrDomain is ReasonDomain.
	ErrDomain = errors.New("sdkkeygrant: not an SDK key grant (another document kind)")
	// ErrSkew is ReasonSkew.
	ErrSkew = errors.New("sdkkeygrant: grant issued in the future")
	// ErrLifetime is ReasonLifetime.
	ErrLifetime = errors.New("sdkkeygrant: grant lifetime out of range")
	// ErrExpired is ReasonExpired.
	ErrExpired = errors.New("sdkkeygrant: grant expired")
)

// reasons maps each error to its Reason (one row per check).
var reasons = []struct {
	err    error
	reason Reason
}{
	{ErrShape, ReasonShape},
	{ErrVersion, ReasonVersion},
	{ErrNoKey, ReasonNoKey},
	{ErrUnknownKey, ReasonUnknownKey},
	{ErrSignature, ReasonSignature},
	{ErrDomain, ReasonDomain},
	{ErrSkew, ReasonSkew},
	{ErrLifetime, ReasonLifetime},
	{ErrExpired, ReasonExpired},
}

// ReasonOf returns the Reason of an error Verify or Sign returned: ReasonNone
// for nil, ReasonShape for an error that is none of this package's.
func ReasonOf(err error) Reason {
	if err == nil {
		return ReasonNone
	}
	for _, r := range reasons {
		if errors.Is(err, r.err) {
			return r.reason
		}
	}
	return ReasonShape
}

// b64 is base64url without padding, the encoding of every part.
var b64 = base64.RawURLEncoding

// JTIFor derives the grant id from the connect request id: one per approval.
// Its tag differs from the attach grant's, so the two kinds never share a jti.
func JTIFor(requestID string) string {
	sum := sha256.Sum256([]byte("sbo-sdk-key-grant-jti-v1\x00" + requestID))
	return b64.EncodeToString(sum[:16])
}

// RedeemHash is the redeem hash of a redeem secret: unpadded base64url of the
// SHA-256 of the secret's ASCII bytes exactly as sent on the wire. The hash is
// over the text, not over decoded bytes, so no base64 decoder's leniency can
// make two different secrets hash alike.
func RedeemHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return b64.EncodeToString(sum[:])
}

// RedeemSecretValid reports whether s has a redeem secret's shape: exactly
// RedeemSecretLen characters of the unpadded base64url alphabet.
func RedeemSecretValid(s string) bool {
	return isB64URL(s, RedeemSecretLen)
}

// signingMessage is the bytes a signature under domain covers.
func signingMessage(domain string, payload []byte) []byte {
	msg := make([]byte, 0, len(domain)+1+len(payload))
	msg = append(msg, domain...)
	msg = append(msg, 0)
	return append(msg, payload...)
}

// Sign signs c with priv and returns the grant. It sets V and KeyID itself and
// refuses claims Verify would refuse for shape or lifetime (so the cloud can
// never hand out a grant no host accepts). Ed25519 is deterministic: the same
// claims and key give the same grant, so every delivery of one approval is
// byte-identical.
func Sign(priv ed25519.PrivateKey, c Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("sdkkeygrant.Sign: %w: not an Ed25519 private key", ErrShape)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("sdkkeygrant.Sign: %w: not an Ed25519 private key", ErrShape)
	}
	c.V = Version
	c.KeyID = platformcontract.DocumentKeyID(pub)
	if err := checkShape(c); err != nil {
		return "", fmt.Errorf("sdkkeygrant.Sign: %w", err)
	}
	if badLifetime(c) {
		return "", fmt.Errorf("sdkkeygrant.Sign: %w", ErrLifetime)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("sdkkeygrant.Sign: encode: %w", err)
	}
	sig := ed25519.Sign(priv, signingMessage(SigningDomain, payload))
	return TokenPrefix + b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// prefixRule is one row of the token prefix table.
type prefixRule struct {
	prefix string
	err    error // nil: this package's format
}

// prefixRules decide on the token's first bytes, before any decoding. A grant
// of another kind is ReasonDomain, so a host that is handed the attach grant
// says so; anything else unknown is ReasonShape.
var prefixRules = []prefixRule{
	{prefix: TokenPrefix, err: nil},
	{prefix: "sbag1.", err: ErrDomain}, // internal/attachgrant's tokenPrefix
}

// foreignDomains are the other domain tags a pinned key may sign under. A
// signature that fails under SigningDomain but verifies under one of these is
// ReasonDomain (the right key, the wrong kind of document), never accepted.
var foreignDomains = []string{
	"sbo-attach-grant-v1", // internal/attachgrant.SigningDomain (pinned by a test)
}

// parse checks the prefix and splits a grant into its decoded payload and
// signature.
func parse(token string) (payload, sig []byte, err error) {
	if len(token) > MaxTokenBytes {
		return nil, nil, ErrShape
	}
	rest, known := "", false
	for _, r := range prefixRules {
		if strings.HasPrefix(token, r.prefix) {
			if r.err != nil {
				return nil, nil, r.err
			}
			rest, known = strings.TrimPrefix(token, r.prefix), true
			break
		}
	}
	if !known {
		return nil, nil, ErrShape
	}
	p, s, ok := strings.Cut(rest, ".")
	if !ok || p == "" || s == "" || strings.Contains(s, ".") {
		return nil, nil, ErrShape
	}
	if payload, err = b64.DecodeString(p); err != nil {
		return nil, nil, ErrShape
	}
	if sig, err = b64.DecodeString(s); err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, ErrShape
	}
	return payload, sig, nil
}

// keyIDOf reads only the kid of a payload, before the signature is checked.
// Nothing else in the payload is trusted until the signature verifies.
func keyIDOf(payload []byte) (string, error) {
	var h struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(payload, &h); err != nil || h.KeyID == "" {
		return "", ErrShape
	}
	return h.KeyID, nil
}

// decodeClaims decodes a verified payload strictly: unknown fields refused,
// one object only.
func decodeClaims(payload []byte) (Claims, error) {
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || dec.More() {
		return Claims{}, ErrShape
	}
	return c, nil
}

// Facts are what the verifier compares a grant against.
type Facts struct {
	// Keys are the pinned key grant verification keys (current, then the
	// rotation slot). Empty: the host takes no key grants (ReasonNoKey).
	Keys platformcontract.KeySet
	// Now is the verifier's clock.
	Now time.Time
}

// claimRule is one row of the claim table: when refuse is true the grant is
// refused with err.
type claimRule struct {
	name   string
	refuse func(c Claims, f Facts) bool
	err    error
}

// claimRules are the checks after the signature, walked top-down. One test
// case per row (sdkkeygrant_test.go). The organization, redeem secret, jti
// and member checks follow on the tenant host.
var claimRules = []claimRule{
	{name: "version", refuse: func(c Claims, _ Facts) bool { return c.V != Version }, err: ErrVersion},
	{name: "shape", refuse: func(c Claims, _ Facts) bool { return checkShape(c) != nil }, err: ErrShape},
	{name: "skew", refuse: func(c Claims, f Facts) bool {
		return time.Unix(c.IssuedAt, 0).After(f.Now.Add(ClockSkew))
	}, err: ErrSkew},
	{name: "lifetime", refuse: func(c Claims, _ Facts) bool { return badLifetime(c) }, err: ErrLifetime},
	{name: "expired", refuse: func(c Claims, f Facts) bool { return !f.Now.Before(time.Unix(c.ExpiresAt, 0)) }, err: ErrExpired},
}

// Verify checks a grant: its prefix and shape, the key it names among
// f.Keys, the signature under SigningDomain (a signature that verifies only
// under another tag is ReasonDomain), the strict claim decode, then the claim
// table. It returns the claims only when every check passes; on a refusal the
// error wraps exactly one of this package's errors (ReasonOf).
func Verify(token string, f Facts) (Claims, error) {
	payload, sig, err := parse(strings.TrimSpace(token))
	if err != nil {
		return Claims{}, fmt.Errorf("sdkkeygrant.Verify: %w", err)
	}
	if len(f.Keys) == 0 {
		return Claims{}, fmt.Errorf("sdkkeygrant.Verify: %w", ErrNoKey)
	}
	kid, err := keyIDOf(payload)
	if err != nil {
		return Claims{}, fmt.Errorf("sdkkeygrant.Verify: %w", err)
	}
	pub, ok := f.Keys.Lookup(kid)
	if !ok {
		return Claims{}, fmt.Errorf("sdkkeygrant.Verify: %w", ErrUnknownKey)
	}
	if !ed25519.Verify(pub, signingMessage(SigningDomain, payload), sig) {
		for _, d := range foreignDomains {
			if ed25519.Verify(pub, signingMessage(d, payload), sig) {
				return Claims{}, fmt.Errorf("sdkkeygrant.Verify: %w: signed as %s", ErrDomain, d)
			}
		}
		return Claims{}, fmt.Errorf("sdkkeygrant.Verify: %w", ErrSignature)
	}
	c, err := decodeClaims(payload)
	if err != nil {
		return Claims{}, fmt.Errorf("sdkkeygrant.Verify: %w", err)
	}
	for _, r := range claimRules {
		if r.refuse(c, f) {
			return Claims{}, fmt.Errorf("sdkkeygrant.Verify: %s: %w", r.name, r.err)
		}
	}
	return c, nil
}

// badLifetime reports a grant that expires at or before it is issued, or
// lives longer than Lifetime.
func badLifetime(c Claims) bool {
	return c.ExpiresAt <= c.IssuedAt || time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > Lifetime
}

// shapeRule is one row of the claim shape table.
type shapeRule struct {
	field string
	bad   func(c Claims) bool
}

// shapeRules are the claims every grant must carry, in a closed vocabulary
// where there is one.
var shapeRules = []shapeRule{
	{field: "kid", bad: func(c Claims) bool { return !printable(c.KeyID, 64) }},
	{field: "org_id", bad: func(c Claims) bool { return !printable(c.OrgID, 128) }},
	{field: "slug", bad: func(c Claims) bool { return !printable(c.Slug, 64) }},
	{field: "kind", bad: func(c Claims) bool { return c.Kind != KindPersonal && c.Kind != KindTeam }},
	{field: "account_id", bad: func(c Claims) bool { return !printable(c.AccountID, 128) }},
	{field: "sub", bad: func(c Claims) bool { return !printable(c.Subject, 256) }},
	{field: "request_id", bad: func(c Claims) bool { return !printable(c.RequestID, 64) }},
	{field: "redeem_hash", bad: func(c Claims) bool { return !isB64URL(c.RedeemHash, RedeemSecretLen) }},
	{field: "jti", bad: func(c Claims) bool { return c.JTI != JTIFor(c.RequestID) }},
	{field: "iat", bad: func(c Claims) bool { return c.IssuedAt <= 0 }},
}

// checkShape walks shapeRules.
func checkShape(c Claims) error {
	for _, r := range shapeRules {
		if r.bad(c) {
			return fmt.Errorf("%w: %s", ErrShape, r.field)
		}
	}
	return nil
}

// printable reports whether s is 1 to maxLen printable ASCII characters with
// no space.
func printable(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// isB64URL reports whether s is exactly n characters of the unpadded
// base64url alphabet.
func isB64URL(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
