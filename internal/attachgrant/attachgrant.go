package attachgrant

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

// SigningDomain domain-separates the attach grant's signature from every
// other signature the platform makes (entitlements, availability, host-API
// envelopes, OIDC tokens, the org's own rails).
const SigningDomain = "sbo-attach-grant-v1"

// Version is the claims version this package mints and accepts.
const Version = 1

// Lifetime is how long a grant is valid after it is issued. The machine uses
// it within seconds of the approval; ten minutes covers a slow personal
// dashboard set-up and a retried poll.
const Lifetime = 10 * time.Minute

// ClockSkew is how far in the future an issue time may be (the cloud's clock
// ahead of the org server's).
const ClockSkew = 60 * time.Second

// tokenPrefix starts every grant: the format's own version, so a future
// format is told apart before any decoding.
const tokenPrefix = "sbag1."

// MaxTokenBytes bounds a grant before any decoding (a real one is well under
// 2 KiB).
const MaxTokenBytes = 4096

// Dashboard kinds a grant names.
const (
	// KindPersonal is an account's own personal dashboard.
	KindPersonal = "personal"
	// KindTeam is a team dashboard.
	KindTeam = "team"
)

// Share levels a grant names (the cloud decides them from the kind).
const (
	// ShareSummary is "Summary only" (a personal dashboard).
	ShareSummary = "summary"
	// ShareFull is "Full detail" (a team).
	ShareFull = "full"
)

// Claims is the signed content of a grant.
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
	// AccountID is the SuperBased account that approved the connect request.
	AccountID string `json:"account_id"`
	// Subject is the account's identity-provider subject, the value a pooled
	// host binds its members to (org_member_auth_methods under the platform
	// issuer's subject binding kind).
	Subject string `json:"sub"`
	// Email is the account's provider-verified email; empty when the
	// provider did not verify one. Never used to find a member.
	Email string `json:"email,omitempty"`
	// DeviceThumbprint is the RFC 7638 thumbprint of the device key the
	// connect request was created with.
	DeviceThumbprint string `json:"device_thumbprint"`
	// RequestID is the connect request the approval answered.
	RequestID string `json:"request_id"`
	// ShareLevel is ShareSummary or ShareFull.
	ShareLevel string `json:"share_level"`
	// IssuedAt and ExpiresAt are Unix seconds.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
	// JTI is the grant's single-use id. It is derived from the request id
	// (JTIFor), so every re-delivery of one approval carries the same jti
	// and the org server admits one attach per approval.
	JTI string `json:"jti"`
}

// Errors. Verify wraps exactly one of them, so the org server answers on
// error identity and its audit reason cannot drift from the decision.
var (
	// ErrMalformed: not a grant, or a claim is missing or out of shape.
	ErrMalformed = errors.New("attachgrant: malformed grant")
	// ErrUnknownKey: the grant names a key the verifier does not pin.
	ErrUnknownKey = errors.New("attachgrant: grant signed by a key that is not pinned")
	// ErrBadSignature: the signature does not verify under the named key and
	// the attach-grant domain.
	ErrBadSignature = errors.New("attachgrant: grant signature does not verify")
	// ErrVersion: a claims version this build does not accept.
	ErrVersion = errors.New("attachgrant: unsupported grant version")
	// ErrExpired: now is at or past the grant's expiry.
	ErrExpired = errors.New("attachgrant: grant expired")
	// ErrNotYetValid: the grant was issued in the future (beyond ClockSkew).
	ErrNotYetValid = errors.New("attachgrant: grant issued in the future")
	// ErrLifetime: the grant claims a lifetime longer than Lifetime.
	ErrLifetime = errors.New("attachgrant: grant lifetime too long")
	// ErrWrongOrg: the grant is for another organization.
	ErrWrongOrg = errors.New("attachgrant: grant is for another organization")
	// ErrBadProof: the device proof is missing, names another device key, or
	// does not verify.
	ErrBadProof = errors.New("attachgrant: device proof does not verify")
)

// b64 is base64url without padding, the encoding of every part.
var b64 = base64.RawURLEncoding

// JTIFor derives the grant id from the connect request id: one per approval.
func JTIFor(requestID string) string {
	sum := sha256.Sum256([]byte("sbo-attach-grant-jti-v1\x00" + requestID))
	return b64.EncodeToString(sum[:16])
}

// signingMessage is the bytes the signature covers.
func signingMessage(payload []byte) []byte {
	msg := make([]byte, 0, len(SigningDomain)+1+len(payload))
	msg = append(msg, SigningDomain...)
	msg = append(msg, 0)
	return append(msg, payload...)
}

// Mint signs c with priv and returns the grant. It sets V and KeyID itself and
// refuses claims that Verify would refuse for shape (so the cloud can never
// hand out a grant no host accepts). Ed25519 is deterministic: the same
// claims and key give the same grant, so a re-delivered approval hands out
// byte-identical grants.
func Mint(priv ed25519.PrivateKey, c Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("attachgrant.Mint: %w: not an Ed25519 private key", ErrMalformed)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("attachgrant.Mint: %w: not an Ed25519 private key", ErrMalformed)
	}
	c.V = Version
	c.KeyID = platformcontract.DocumentKeyID(pub)
	if err := checkShape(c); err != nil {
		return "", fmt.Errorf("attachgrant.Mint: %w", err)
	}
	if c.ExpiresAt <= c.IssuedAt || time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > Lifetime {
		return "", fmt.Errorf("attachgrant.Mint: %w", ErrLifetime)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("attachgrant.Mint: encode: %w", err)
	}
	sig := ed25519.Sign(priv, signingMessage(payload))
	return tokenPrefix + b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// parse splits a grant into its decoded payload and signature.
func parse(token string) (payload, sig []byte, err error) {
	if len(token) > MaxTokenBytes || !strings.HasPrefix(token, tokenPrefix) {
		return nil, nil, ErrMalformed
	}
	p, s, ok := strings.Cut(strings.TrimPrefix(token, tokenPrefix), ".")
	if !ok || p == "" || s == "" || strings.Contains(s, ".") {
		return nil, nil, ErrMalformed
	}
	if payload, err = b64.DecodeString(p); err != nil {
		return nil, nil, ErrMalformed
	}
	if sig, err = b64.DecodeString(s); err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, ErrMalformed
	}
	return payload, sig, nil
}

// decodeClaims decodes the payload strictly: unknown fields refused, one
// object only.
func decodeClaims(payload []byte) (Claims, error) {
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || dec.More() {
		return Claims{}, ErrMalformed
	}
	return c, nil
}

// Facts are what the verifier compares a grant against.
type Facts struct {
	// Keys are the pinned verification keys (current, then rotation slot).
	Keys platformcontract.KeySet
	// OrgID is the organization the request reached (the tenant).
	OrgID string
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
// case per row (attachgrant_test.go).
var claimRules = []claimRule{
	{name: "version", refuse: func(c Claims, _ Facts) bool { return c.V != Version }, err: ErrVersion},
	{name: "shape", refuse: func(c Claims, _ Facts) bool { return checkShape(c) != nil }, err: ErrMalformed},
	{name: "not-yet-valid", refuse: func(c Claims, f Facts) bool {
		return time.Unix(c.IssuedAt, 0).After(f.Now.Add(ClockSkew))
	}, err: ErrNotYetValid},
	{name: "lifetime", refuse: func(c Claims, _ Facts) bool {
		return c.ExpiresAt <= c.IssuedAt || time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > Lifetime
	}, err: ErrLifetime},
	{name: "expired", refuse: func(c Claims, f Facts) bool { return !f.Now.Before(time.Unix(c.ExpiresAt, 0)) }, err: ErrExpired},
	{name: "org", refuse: func(c Claims, f Facts) bool { return f.OrgID == "" || c.OrgID != f.OrgID }, err: ErrWrongOrg},
}

// Verify checks a grant: its shape, the key it names among f.Keys, the
// signature under SigningDomain, then the claim table. It returns the claims
// only when every check passes.
func Verify(token string, f Facts) (Claims, error) {
	payload, sig, err := parse(strings.TrimSpace(token))
	if err != nil {
		return Claims{}, fmt.Errorf("attachgrant.Verify: %w", err)
	}
	c, err := decodeClaims(payload)
	if err != nil {
		return Claims{}, fmt.Errorf("attachgrant.Verify: %w", err)
	}
	pub, ok := f.Keys.Lookup(c.KeyID)
	if !ok {
		return Claims{}, fmt.Errorf("attachgrant.Verify: %w", ErrUnknownKey)
	}
	if !ed25519.Verify(pub, signingMessage(payload), sig) {
		return Claims{}, fmt.Errorf("attachgrant.Verify: %w", ErrBadSignature)
	}
	for _, r := range claimRules {
		if r.refuse(c, f) {
			return Claims{}, fmt.Errorf("attachgrant.Verify: %s: %w", r.name, r.err)
		}
	}
	return c, nil
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
	{field: "email", bad: func(c Claims) bool { return c.Email != "" && !printable(c.Email, 320) }},
	{field: "device_thumbprint", bad: func(c Claims) bool { return len(c.DeviceThumbprint) != 43 || !printable(c.DeviceThumbprint, 43) }},
	{field: "request_id", bad: func(c Claims) bool { return !printable(c.RequestID, 64) }},
	{field: "share_level", bad: func(c Claims) bool { return c.ShareLevel != shareLevelFor(c.Kind) }},
	{field: "jti", bad: func(c Claims) bool { return c.JTI != JTIFor(c.RequestID) }},
	{field: "iat", bad: func(c Claims) bool { return c.IssuedAt <= 0 }},
}

// shareLevelFor is the one share level each kind carries: a grant can never
// name Summary only for a team or Full detail for a personal dashboard.
func shareLevelFor(kind string) string {
	if kind == KindTeam {
		return ShareFull
	}
	return ShareSummary
}

// checkShape walks shapeRules.
func checkShape(c Claims) error {
	for _, r := range shapeRules {
		if r.bad(c) {
			return fmt.Errorf("%w: %s", ErrMalformed, r.field)
		}
	}
	return nil
}

// printable reports whether s is 1 to max printable ASCII characters with no
// space.
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
