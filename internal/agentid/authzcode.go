package agentid

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// authzcode.go is the PURE half of the P5b OAuth 2.1 authorization server
// (doc3 §11.9b, R9.2): PKCE S256 (RFC 7636) with the downgrade refusal, the
// single-use authorization-code redemption decision as an ordered rule
// table, the redirect-URI validation + matching rules shared by DCR (RFC
// 7591) and CIMD, and the opaque-secret / domain-tagged hash helpers every
// stored code, refresh token, registration access token and state/nonce
// uses (R8.26.k: codes, tokens, state and nonce are stored as HASHES, never
// raw). No I/O, no clock of its own: time and entropy are injected.

// OAuth 2.1 grant types the AS serves beside F1/F5 (R9.2).
const (
	// GrantTypeAuthorizationCode is the RFC 6749 §4.1 grant (F2 thin clients).
	GrantTypeAuthorizationCode = "authorization_code"
	// GrantTypeRefreshToken is the RFC 6749 §6 refresh grant (rotated, R8.24.l/B8).
	GrantTypeRefreshToken = "refresh_token"
	// ResponseTypeCode is the only response_type the AS serves (OAuth 2.1).
	ResponseTypeCode = "code"
	// PKCEMethodS256 is the only code_challenge_method accepted: `plain`
	// (and an absent method, which RFC 7636 defaults to plain) is a
	// downgrade and is refused.
	PKCEMethodS256 = "S256"
)

// PKCE errors (errors.Is). All of them are invalid_request at authorize and
// invalid_grant at the token endpoint.
var (
	// ErrPKCEDowngrade: the method is absent, `plain` or anything but S256.
	ErrPKCEDowngrade = errors.New("agentid: PKCE method is not S256 (downgrade refused)")
	// ErrPKCEChallenge: the code_challenge is not a 43-char base64url S256 digest.
	ErrPKCEChallenge = errors.New("agentid: malformed code_challenge")
	// ErrPKCEVerifier: the code_verifier breaks RFC 7636 §4.1 (43-128 unreserved chars).
	ErrPKCEVerifier = errors.New("agentid: malformed code_verifier")
	// ErrPKCEMismatch: S256(code_verifier) != code_challenge.
	ErrPKCEMismatch = errors.New("agentid: code_verifier does not match the code_challenge")
)

// CheckCodeChallenge validates an authorize request's PKCE pair: the method
// must be exactly "S256" (RFC 7636 §4.3 is case-sensitive; an absent method
// defaults to plain, which is a downgrade) and the challenge the unpadded
// base64url of a SHA-256 digest (43 characters).
func CheckCodeChallenge(method, challenge string) error {
	if method != PKCEMethodS256 {
		return ErrPKCEDowngrade
	}
	if len(challenge) != 43 {
		return ErrPKCEChallenge
	}
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != sha256.Size {
		return ErrPKCEChallenge
	}
	return nil
}

// S256Challenge returns BASE64URL(SHA256(verifier)) (RFC 7636 §4.2).
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE checks a token request's code_verifier against the stored S256
// challenge in constant time.
func VerifyPKCE(verifier, challenge string) error {
	if n := len(verifier); n < 43 || n > 128 {
		return ErrPKCEVerifier
	}
	for i := 0; i < len(verifier); i++ {
		if !isUnreserved(verifier[i]) {
			return ErrPKCEVerifier
		}
	}
	if subtle.ConstantTimeCompare([]byte(S256Challenge(verifier)), []byte(challenge)) != 1 {
		return ErrPKCEMismatch
	}
	return nil
}

// isUnreserved is the RFC 3986 unreserved set RFC 7636 §4.1 allows.
func isUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// ---- single-use code redemption --------------------------------------------

// AuthzCode is the stored authorization code as the redemption decision
// sees it (the store holds only its hash; the raw code is never at rest).
type AuthzCode struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	ExpiresAt           time.Time
	// Consumed is true when the code was already redeemed (the store's
	// consumed_at CAS lost): a replay.
	Consumed bool
}

// CodeRedemption is the token request presenting a code.
type CodeRedemption struct {
	// ClientID is the AUTHENTICATED (or, for a public client, declared)
	// client id - never a value read off the code.
	ClientID     string
	RedirectURI  string
	CodeVerifier string
	// Resource is the token request's RFC 8707 resource ("" = none sent).
	Resource string
}

// Code redemption reasons (the CLOSED internal vocabulary; the client only
// ever sees invalid_grant / invalid_target).
const (
	CodeReasonAllowed          = "allowed"
	CodeReasonReplayed         = "code_replayed"
	CodeReasonExpired          = "code_expired"
	CodeReasonClientMismatch   = "client_mismatch"
	CodeReasonRedirectMismatch = "redirect_uri_mismatch"
	CodeReasonPKCEDowngrade    = "pkce_downgrade"
	CodeReasonPKCEMismatch     = "pkce_mismatch"
	CodeReasonResourceMismatch = "resource_mismatch"
)

// CodeDecision is the redemption outcome.
type CodeDecision struct {
	Allow  bool
	Reason string
	// Error is the external OAuth code (invalid_grant / invalid_target).
	Error OAuthError
	// RevokeFamily is true when the refusal is a REPLAY: RFC 6749 §4.1.2
	// says the AS SHOULD revoke every token already issued from that code.
	RevokeFamily bool
}

// CodeRule is one row of the redemption table: the first row whose When
// holds decides (walked top-down, one test case per row).
type CodeRule struct {
	Name         string
	When         func(c AuthzCode, r CodeRedemption, now time.Time) bool
	Reason       string
	Error        OAuthError
	RevokeFamily bool
}

// DefaultCodeRules is the redemption table (RFC 6749 §4.1.3, RFC 7636 §4.6,
// RFC 8707 §2.2, OAuth 2.1 §4.1.3).
func DefaultCodeRules() []CodeRule {
	return []CodeRule{
		{
			Name: "replay", When: func(c AuthzCode, _ CodeRedemption, _ time.Time) bool { return c.Consumed },
			Reason: CodeReasonReplayed, Error: OAuthInvalidGrant, RevokeFamily: true,
		},
		{
			Name: "expired", When: func(c AuthzCode, _ CodeRedemption, now time.Time) bool { return !now.Before(c.ExpiresAt) },
			Reason: CodeReasonExpired, Error: OAuthInvalidGrant,
		},
		{Name: "client", When: func(c AuthzCode, r CodeRedemption, _ time.Time) bool {
			return r.ClientID == "" || subtle.ConstantTimeCompare([]byte(c.ClientID), []byte(r.ClientID)) != 1
		}, Reason: CodeReasonClientMismatch, Error: OAuthInvalidGrant},
		// The authorize request always carried (or was resolved to) a
		// redirect_uri, so the token request must repeat it exactly.
		{
			Name: "redirect", When: func(c AuthzCode, r CodeRedemption, _ time.Time) bool { return c.RedirectURI != r.RedirectURI },
			Reason: CodeReasonRedirectMismatch, Error: OAuthInvalidGrant,
		},
		{
			Name: "pkce_method", When: func(c AuthzCode, _ CodeRedemption, _ time.Time) bool { return c.CodeChallengeMethod != PKCEMethodS256 },
			Reason: CodeReasonPKCEDowngrade, Error: OAuthInvalidGrant,
		},
		{Name: "pkce_verify", When: func(c AuthzCode, r CodeRedemption, _ time.Time) bool {
			return VerifyPKCE(r.CodeVerifier, c.CodeChallenge) != nil
		}, Reason: CodeReasonPKCEMismatch, Error: OAuthInvalidGrant},
		{Name: "resource", When: func(c AuthzCode, r CodeRedemption, _ time.Time) bool {
			return c.Resource != "" && r.Resource != "" && c.Resource != r.Resource
		}, Reason: CodeReasonResourceMismatch, Error: OAuthInvalidTarget},
	}
}

// DecideCodeRedemption walks rules (nil -> DefaultCodeRules) top-down; no
// row firing is an allow.
func DecideCodeRedemption(rules []CodeRule, c AuthzCode, r CodeRedemption, now time.Time) CodeDecision {
	if rules == nil {
		rules = DefaultCodeRules()
	}
	for _, row := range rules {
		if row.When(c, r, now) {
			return CodeDecision{Reason: row.Reason, Error: row.Error, RevokeFamily: row.RevokeFamily}
		}
	}
	return CodeDecision{Allow: true, Reason: CodeReasonAllowed}
}

// ---- opaque secrets + domain-tagged hashes ----------------------------------

// Hash domains: each stored hash is tagged with its use, so a value hashed
// for one purpose never matches a lookup for another.
const (
	HashDomainCode    = "sbo-oauth-code-v1"
	HashDomainRefresh = "sbo-oauth-refresh-v1"
	HashDomainRAT     = "sbo-oauth-registration-token-v1"
	HashDomainState   = "sbo-oauth-state-v1"
	HashDomainNonce   = "sbo-oauth-nonce-v1"
	HashDomainFamily  = "sbo-oauth-family-v1"
)

// OpaqueSecretBytes is the entropy behind every minted code / token (256 bit).
const OpaqueSecretBytes = 32

// NewOpaqueSecret mints prefix + base64url(32 random bytes). r nil ->
// crypto/rand.
func NewOpaqueSecret(r io.Reader, prefix string) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	buf := make([]byte, OpaqueSecretBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("agentid.NewOpaqueSecret: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashOpaque is the stored form of a high-entropy secret: hex(SHA-256(domain
// || 0x00 || v)). A 256-bit random value needs no slow hash; the domain tag
// separates uses. An empty v hashes to "" (nothing to store).
func HashOpaque(domain, v string) string {
	if v == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write([]byte(v))
	return hex.EncodeToString(h.Sum(nil))
}

// RefreshFamilyID derives the refresh-token family id from the code hash that
// started it, deterministically, so a REPLAYED code can revoke exactly the
// family its first redemption created (RFC 6749 §4.1.2) without a stored
// code->family link.
func RefreshFamilyID(codeHash string) string {
	return "rf_" + HashOpaque(HashDomainFamily, codeHash)[:32]
}

// ---- redirect URIs (RFC 6749 §3.1.2, RFC 8252, OAuth 2.1 §2.3) --------------

// Redirect URI errors (errors.Is).
var (
	// ErrRedirectURI: a registered or presented redirect URI breaks the rules.
	ErrRedirectURI = errors.New("agentid: invalid redirect_uri")
)

// forbiddenRedirectSchemes can never receive a code (script execution, local
// file / data smuggling, or a non-navigable scheme).
var forbiddenRedirectSchemes = map[string]bool{
	"javascript": true, "data": true, "file": true, "vbscript": true, "about": true, "blob": true,
	"ftp": true, "ws": true, "wss": true, "chrome": true, "view-source": true,
}

// ValidateRedirectURI checks one redirect URI for registration (DCR or a CIMD
// document): absolute, no fragment, no userinfo; https anywhere; http ONLY
// for a loopback host (RFC 8252 §7.3/§8.3: 127.0.0.1, [::1] or localhost);
// otherwise a private-use scheme (RFC 8252 §7.1, e.g. cursor:// or
// com.example.app:/cb) that is not one of the script/file/data schemes.
func ValidateRedirectURI(raw string) error {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, " \t\r\n\\") {
		return fmt.Errorf("%w: empty, oversized or containing whitespace/backslash", ErrRedirectURI)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRedirectURI, err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme == "":
		return fmt.Errorf("%w: not absolute", ErrRedirectURI)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return fmt.Errorf("%w: carries a fragment", ErrRedirectURI)
	case u.User != nil:
		return fmt.Errorf("%w: carries userinfo", ErrRedirectURI)
	case forbiddenRedirectSchemes[scheme]:
		return fmt.Errorf("%w: scheme %q is never a redirect target", ErrRedirectURI, scheme)
	case scheme == "https":
		if u.Hostname() == "" {
			return fmt.Errorf("%w: https without a host", ErrRedirectURI)
		}
	case scheme == "http":
		if !IsLoopbackRedirectHost(u.Hostname()) {
			return fmt.Errorf("%w: plain http is allowed only for a loopback host", ErrRedirectURI)
		}
	default:
		// A private-use scheme: RFC 8252 §7.1 recommends reverse-domain
		// names; any other non-forbidden scheme is accepted (market
		// consensus - e.g. cursor://, vscode://) and shown on consent.
		if u.Opaque == "" && u.Host == "" && u.Path == "" {
			return fmt.Errorf("%w: private-use scheme without a path", ErrRedirectURI)
		}
	}
	return nil
}

// IsLoopbackRedirectHost reports whether host is a loopback redirect host
// (RFC 8252 §7.3/§8.3).
func IsLoopbackRedirectHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsLoopbackRedirect reports whether raw is an http loopback redirect URI.
func IsLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.EqualFold(u.Scheme, "http") && IsLoopbackRedirectHost(u.Hostname())
}

// RedirectURIMatches reports whether presented is one of registered: an
// EXACT string match, with the single RFC 8252 §7.3 exception that an http
// loopback redirect matches a registered loopback URI on the same host and
// path whatever the PORT (a native app cannot know its ephemeral port in
// advance - the AS MUST allow any port there).
func RedirectURIMatches(registered []string, presented string) bool {
	if presented == "" {
		return false
	}
	for _, r := range registered {
		if r == presented {
			return true
		}
	}
	if !IsLoopbackRedirect(presented) {
		return false
	}
	p, err := url.Parse(presented)
	if err != nil {
		return false
	}
	for _, r := range registered {
		if !IsLoopbackRedirect(r) {
			continue
		}
		ru, err := url.Parse(r)
		if err != nil {
			continue
		}
		if strings.EqualFold(ru.Hostname(), p.Hostname()) && ru.EscapedPath() == p.EscapedPath() && ru.RawQuery == p.RawQuery {
			return true
		}
	}
	return false
}
