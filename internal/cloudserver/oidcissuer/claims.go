package oidcissuer

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/tenantctx"
)

// Claims is the id_token claim set, in the order it is serialized. It is the
// whole vocabulary: a claim not named here cannot be signed (the signer
// decodes requests with unknown fields refused).
type Claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	// AuthTime is when the person authenticated to establish the portal
	// session the token was issued from (OIDC Core 2), never the mint time.
	// Omitted (zero) when that is not known, which the issuer allows only
	// for a request that asked for no freshness (no prompt=login, no
	// max_age); a relying party then treats the sign-in time as unknown.
	AuthTime int64  `json:"auth_time,omitempty"`
	Jti      string `json:"jti"`
	Nonce    string `json:"nonce,omitempty"`
	Org      string `json:"org"`
	// Email and EmailVerified are a member's verified address. A support
	// token (Support) carries neither: the signer refuses one that does, so
	// a tenant can never match a staff sign-in to a member or an invitation
	// by address.
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	AMR           []string `json:"amr,omitempty"`
	// Support marks a SuperBased staff member signing in to the org as
	// support (plan 06 5.8.7): sub is "staff:<staff_id>", there is no email,
	// and the tenant admits the sign-in only while one of its own grants
	// names that subject. Minted only from a support code the staff process
	// wrote (SupportAuthorizer); a member code can never carry it.
	Support bool `json:"support,omitempty"`
}

// Bounds the claim rules enforce.
const (
	maxSubLen   = 255
	maxEmailLen = 254
	maxNonceLen = 512
	maxAMR      = 8
	maxAMRLen   = 32
	minJTILen   = 16
	maxJTILen   = 128
)

// claimRule is one row of the signer's claim rules: the claims are refused
// when bad reports true. The first refusing row decides.
type claimRule struct {
	id  string
	bad func(c Claims, issuer string, now time.Time) bool
}

// claimRules is walked top-down by ValidateClaims. It is the signer's own
// statement of what it will sign (design 3.3): a compromised web process can
// still ask for a token for any member it names (RK-12), but never one with
// another issuer, another org's audience, a long life, or no jti.
var claimRules = []claimRule{
	{id: "iss-fixed", bad: func(c Claims, iss string, _ time.Time) bool { return iss == "" || c.Iss != iss }},
	{id: "org-uuid", bad: func(c Claims, _ string, _ time.Time) bool { return !tenantctx.IsCanonicalUUID(c.Org) }},
	{id: "aud-is-org-client", bad: func(c Claims, _ string, _ time.Time) bool { return c.Aud != ClientIDPrefix+c.Org }},
	{id: "sub-present", bad: func(c Claims, _ string, _ time.Time) bool { return !boundedText(c.Sub, maxSubLen) }},
	{id: "jti-present", bad: func(c Claims, _ string, _ time.Time) bool { return !validToken(c.Jti, minJTILen, maxJTILen) }},
	{id: "iat-present", bad: func(c Claims, _ string, _ time.Time) bool { return c.Iat <= 0 }},
	{id: "exp-after-iat", bad: func(c Claims, _ string, _ time.Time) bool { return c.Exp <= c.Iat }},
	{id: "lifetime-cap", bad: func(c Claims, _ string, _ time.Time) bool {
		return c.Exp-c.Iat > int64(MaxTokenLifetime/time.Second)
	}},
	{id: "iat-fresh", bad: func(c Claims, _ string, now time.Time) bool {
		d := now.Unix() - c.Iat
		if d < 0 {
			d = -d
		}
		return d > int64(MaxIATSkew/time.Second)
	}},
	// auth_time, when present, is a past authentication: positive, and not
	// after the token's own iat (both are the issuer's clock; a session
	// established on another replica may read up to MaxIATSkew ahead).
	// Absent (zero) means not known, and is allowed: OIDC Core 2 requires it
	// only when max_age was sent, which the issuer checks at authorize.
	{id: "auth-time-past", bad: func(c Claims, _ string, _ time.Time) bool {
		return c.AuthTime < 0 || c.AuthTime > c.Iat+int64(MaxIATSkew/time.Second)
	}},
	// The support split (M7a.2): a support token names a staff subject and
	// nothing a member token carries; a member token never names one.
	{id: "support-sub-staff", bad: func(c Claims, _ string, _ time.Time) bool { return c.Support && !ValidSupportSubject(c.Sub) }},
	{id: "member-sub-not-staff", bad: func(c Claims, _ string, _ time.Time) bool {
		return !c.Support && strings.HasPrefix(c.Sub, SupportSubPrefix)
	}},
	{id: "support-no-email", bad: func(c Claims, _ string, _ time.Time) bool { return c.Support && (c.Email != "" || c.EmailVerified) }},
	{id: "support-no-amr", bad: func(c Claims, _ string, _ time.Time) bool { return c.Support && len(c.AMR) > 0 }},
	{id: "support-auth-time", bad: func(c Claims, _ string, _ time.Time) bool { return c.Support && c.AuthTime <= 0 }},
	{id: "email-present", bad: func(c Claims, _ string, _ time.Time) bool {
		return !c.Support && (!boundedText(c.Email, maxEmailLen) || !strings.Contains(c.Email, "@"))
	}},
	{id: "email-verified", bad: func(c Claims, _ string, _ time.Time) bool { return !c.Support && !c.EmailVerified }},
	{id: "nonce-bounded", bad: func(c Claims, _ string, _ time.Time) bool {
		return c.Nonce != "" && !boundedText(c.Nonce, maxNonceLen)
	}},
	{id: "amr-bounded", bad: func(c Claims, _ string, _ time.Time) bool {
		if len(c.AMR) > maxAMR {
			return true
		}
		for _, a := range c.AMR {
			if !validToken(a, 1, maxAMRLen) {
				return true
			}
		}
		return false
	}},
}

// ValidateClaims applies the signer's claim rules to c for the fixed issuer
// at now. It returns nil, or an error wrapping ErrClaimsRefused that names
// the refusing rule.
func ValidateClaims(c Claims, issuer string, now time.Time) error {
	for _, r := range claimRules {
		if r.bad(c, issuer, now) {
			return fmt.Errorf("oidcissuer.ValidateClaims: %s: %w", r.id, ErrClaimsRefused)
		}
	}
	return nil
}

// BuildClaims assembles the id_token claims for a redeemed code: aud is the
// client id, email_verified is the identity provider's own flag as the member
// carried it (operator item A4; the member rules and the signer's claim rules
// both refuse a false one, so a signed token always says true, plan 06 5.4),
// exp is iat plus TokenLifetime, and auth_time is the code's (the portal
// session's authentication, not now).
func BuildClaims(issuer string, code CodeRecord, jti string, now time.Time) Claims {
	iat := now.Unix()
	var authTime int64
	if !code.AuthTime.IsZero() {
		authTime = code.AuthTime.Unix()
	}
	return Claims{
		Iss:           issuer,
		Sub:           code.Sub,
		Aud:           code.ClientID,
		Exp:           iat + int64(TokenLifetime/time.Second),
		Iat:           iat,
		AuthTime:      authTime,
		Jti:           jti,
		Nonce:         code.Nonce,
		Org:           code.OrgID,
		Email:         code.Email,
		EmailVerified: code.EmailVerified,
		AMR:           append([]string(nil), code.AMR...),
	}
}

// auditMirrorPayload is the oidc_audit_mirror payload: the facts the tenant's
// own audit row carries (design 4.8: the two must agree on jti). No email.
type auditMirrorPayload struct {
	JTI      string `json:"jti"`
	Sub      string `json:"sub"`
	OrgID    string `json:"org_id"`
	ClientID string `json:"client_id"`
	KID      string `json:"kid"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

// AuditMirrorPayload returns the outbox payload for iss (JSON, no secrets, no
// email).
func AuditMirrorPayload(iss Issuance) ([]byte, error) {
	b, err := json.Marshal(auditMirrorPayload{
		JTI: iss.JTI, Sub: iss.Sub, OrgID: iss.OrgID, ClientID: iss.ClientID, KID: iss.KID,
		IssuedAt: iss.IssuedAt.Unix(), Expires: iss.ExpiresAt.Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("oidcissuer.AuditMirrorPayload: %w", err)
	}
	return b, nil
}

// boundedText reports whether s is non-empty valid UTF-8 of at most max bytes
// with no control characters.
func boundedText(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validToken reports whether s is min..max characters of the base64url
// alphabet plus '.', '~' (the RFC 3986 unreserved set).
func validToken(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isUnreserved(s[i]) {
			return false
		}
	}
	return true
}

func isUnreserved(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '~'
}
