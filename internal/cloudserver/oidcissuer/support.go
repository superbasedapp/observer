package oidcissuer

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// support.go is the issuer's support path (managed-SaaS plan 07 M7a.2; plan
// 06 5.8.7; design m6.0 4.9 "The support claim"): a SuperBased staff member
// signs in to a tenant org as SUPPORT, never as a member.
//
//   - Authorize runs in the STAFF process (its own host, login and role), on
//     the staff console's route SupportAuthorizePath, behind the staff
//     session middleware, whose authorization table requires a recent passkey
//     assertion for the support sign-in action. SupportAuthorizer validates
//     the client and the exact redirect URI and the request shape with the
//     member path's own rule tables, applies the freshness rules to the staff
//     session's assertion time, and writes a SUPPORT code (oidc_support_codes)
//     naming the staff member. It holds no signer and reads no customer
//     table.
//   - Token runs in the serve process at the one token endpoint. A support
//     code is consumed like any other (one conditional UPDATE, first), bound
//     to the client, redirect URI and PKCE verifier by the same rules, then
//     re-checked through SupportTokenStore.SupportTarget (the staff member
//     still active, the org active with its platform rail on), signed with
//     support: true, sub SupportSubject(staff), no email and no amr, verified
//     against the published key, and recorded (oidc_support_issued) BEFORE it
//     is returned.
//
// The issuer never knows whether the org granted the staff member access: the
// grant lives in the tenant, which admits a support session only while one of
// its own grants names the subject. The claim says only "this is SuperBased
// staff member X, authenticated with a passkey at auth_time".

// SupportSubPrefix starts the sub of every support token, and no member
// token's (the signer's claim rules refuse both mistakes).
const SupportSubPrefix = "staff:"

// SupportAuthorizePath is the staff console's support authorize route, on
// the staff origin (internal/cloudserver/api staff routes).
const SupportAuthorizePath = "/staff/oauth2/authorize"

// SupportSubject returns the support token sub for a staff id.
func SupportSubject(staffID string) string { return SupportSubPrefix + staffID }

// ValidSupportSubject reports whether s is SupportSubPrefix followed by a
// canonical lowercase UUID.
func ValidSupportSubject(s string) bool {
	return strings.HasPrefix(s, SupportSubPrefix) && isCanonicalUUID(strings.TrimPrefix(s, SupportSubPrefix))
}

// StaffSession is what the staff process knows about the signed-in staff
// member asking for a support code.
type StaffSession struct {
	// StaffID is staff_users.staff_id.
	StaffID string
	// AssertedAt is the session's latest WebAuthn assertion: the support
	// token's auth_time.
	AssertedAt time.Time
}

// SupportCodeStore is the staff process's seam: the client lookup (shared
// with the member path) and the support code write. The store writes the
// staff action log row in the same transaction as the code.
type SupportCodeStore interface {
	// Client returns the client; ErrNotFound when there is none.
	Client(ctx context.Context, clientID string) (Client, error)
	// PutSupportCode stores a new support code (c.Support is true).
	PutSupportCode(ctx context.Context, c CodeRecord) error
}

// SupportTarget is the token endpoint's re-check of a support code.
type SupportTarget struct {
	// StaffActive: the staff member exists and is active.
	StaffActive bool
	// OrgStatus is orgs.status ("" when the org does not exist).
	OrgStatus string
	// RailEnabled is orgs.platform_rail_enabled.
	RailEnabled bool
}

// SupportIssuance is the oidc_support_issued row recorded before a support
// token is returned.
type SupportIssuance struct {
	JTI       string
	OrgID     string
	StaffID   string
	ClientID  string
	KID       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SupportTokenStore is the serve process's support seam.
type SupportTokenStore interface {
	// SupportTarget reads the staff member's and the org's state.
	SupportTarget(ctx context.Context, staffID, orgID string) (SupportTarget, error)
	// RecordSupportIssuance writes the issued-token row; a jti seen before
	// is an error.
	RecordSupportIssuance(ctx context.Context, iss SupportIssuance) error
}

// SupportAuthorizerConfig configures a SupportAuthorizer.
type SupportAuthorizerConfig struct {
	// Issuer is the issuer identifier (ValidateIssuerURL), the same one the
	// serve process's Issuer signs as.
	Issuer string
	Store  SupportCodeStore
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Rand is the entropy source for codes; nil means crypto/rand.
	Rand io.Reader
}

// SupportAuthorizer writes support codes for signed-in staff members. It
// holds no state between calls and no key.
type SupportAuthorizer struct {
	issuer string
	store  SupportCodeStore
	now    func() time.Time
	rand   io.Reader
}

// NewSupportAuthorizer validates cfg. It does no I/O.
func NewSupportAuthorizer(cfg SupportAuthorizerConfig) (*SupportAuthorizer, error) {
	iss, err := ValidateIssuerURL(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if cfg.Store == nil {
		return nil, errors.New("oidcissuer.NewSupportAuthorizer: Store is required")
	}
	a := &SupportAuthorizer{issuer: iss, store: cfg.Store, now: cfg.Now, rand: cfg.Rand}
	if a.now == nil {
		a.now = time.Now
	}
	if a.rand == nil {
		a.rand = rand.Reader
	}
	return a, nil
}

// staffRule is one row of the rules on the staff session, applied at
// support authorize.
type staffRule struct {
	id  string
	bad func(s StaffSession) bool
}

var staffSessionRules = []staffRule{
	{id: "staff-id", bad: func(s StaffSession) bool { return !isCanonicalUUID(s.StaffID) }},
	// A staff session exists only through a WebAuthn assertion, so its time
	// is always known; a zero one is a wiring fault, refused.
	{id: "staff-asserted", bad: func(s StaffSession) bool { return s.AssertedAt.IsZero() }},
}

// Authorize handles a support authorize request from the signed-in staff
// member s. The order is the member path's: the client and exact redirect
// URI first (answered in place), then the request shape (redirected to the
// verified client), then freshness, then the code.
func (a *SupportAuthorizer) Authorize(ctx context.Context, r AuthorizeRequest, s StaffSession) AuthorizeResult {
	var client Client
	found := false
	if _, ok := OrgFromClientID(r.ClientID); ok {
		c, err := a.store.Client(ctx, r.ClientID)
		switch {
		case err == nil:
			client, found = c, true
		case errors.Is(err, ErrNotFound):
		default:
			return AuthorizeResult{Outcome: OutcomeError, Err: unavailable("client-lookup")}
		}
	}
	if e := checkClient(r, client, found); e != nil {
		return AuthorizeResult{Outcome: OutcomeError, Err: e}
	}
	if e := checkAuthorizeRequest(r); e != nil {
		return redirectErrorFor(a.issuer, r, e)
	}
	for _, rule := range staffSessionRules {
		if rule.bad(s) {
			return AuthorizeResult{Outcome: OutcomeError, Err: &Error{
				Code: ErrCodeAccessDenied, Description: "the staff session cannot sign in as support", Status: 403, RuleID: rule.id,
			}}
		}
	}
	now := a.now()
	facts := factsFor(r, Session{AccountID: SupportSubject(s.StaffID), AuthTime: s.AssertedAt}, now)
	switch d, rule := decideAuthn(facts); d {
	case authnIssue:
	case authnLoginRequired:
		return redirectErrorFor(a.issuer, r, &Error{
			Code: ErrCodeLoginRequired, Description: "the staff member must assert their passkey again, and prompt=none forbids asking",
			Status: 302, RuleID: rule,
		})
	default:
		// A fresh sign-in for a staff member is a new passkey assertion in
		// the staff console; the console has no resume flow yet, so the
		// request is answered in place and the staff member retries.
		return AuthorizeResult{Outcome: OutcomeError, Err: &Error{
			Code: ErrCodeLoginRequired, Description: "assert your passkey again in the staff console, then start the support sign-in again",
			Status: 401, RuleID: "support-" + rule,
		}}
	}
	code, err := randomTokenFrom(a.rand, 32)
	if err != nil {
		return redirectErrorFor(a.issuer, r, serverError("code-entropy"))
	}
	rec := CodeRecord{
		CodeHash: HashCode(code), ClientID: client.ClientID, OrgID: client.OrgID,
		Nonce: r.Nonce, CodeChallenge: r.CodeChallenge, RedirectURI: r.RedirectURI,
		AuthTime: s.AssertedAt.UTC(), CreatedAt: now, ExpiresAt: now.Add(CodeTTL),
		Support: true, StaffID: s.StaffID,
	}
	if err := a.store.PutSupportCode(ctx, rec); err != nil {
		return redirectErrorFor(a.issuer, r, unavailable("support-code-store"))
	}
	return AuthorizeResult{Outcome: OutcomeRedirect, Location: redirectWithFor(a.issuer, r.RedirectURI, map[string]string{
		"code": code, "state": r.State,
	})}
}

// supportTargetRule is one row of the token endpoint's support re-check.
type supportTargetRule struct {
	id   string
	desc string
	bad  func(t SupportTarget) bool
}

var supportTargetRules = []supportTargetRule{
	{id: "staff-active", desc: "this staff member cannot sign in", bad: func(t SupportTarget) bool { return !t.StaffActive }},
	{id: "org-active", desc: "this organization is not active", bad: func(t SupportTarget) bool { return t.OrgStatus != "active" }},
	{id: "rail-enabled", desc: "this organization does not use platform sign-in", bad: func(t SupportTarget) bool { return !t.RailEnabled }},
}

// BuildSupportClaims assembles a support token's claims: sub is the staff
// subject, there is no email, email_verified or amr, and auth_time is the
// staff session's passkey assertion.
func BuildSupportClaims(issuer string, code CodeRecord, jti string, now time.Time) Claims {
	iat := now.Unix()
	return Claims{
		Iss: issuer, Sub: SupportSubject(code.StaffID), Aud: code.ClientID,
		Exp: iat + int64(TokenLifetime/time.Second), Iat: iat, AuthTime: code.AuthTime.Unix(),
		Jti: jti, Nonce: code.Nonce, Org: code.OrgID, Support: true,
	}
}

// supportToken finishes Token for a consumed, bound support code.
func (i *Issuer) supportToken(ctx context.Context, code CodeRecord, now time.Time) (TokenResponse, error) {
	if i.support == nil {
		return TokenResponse{}, unavailable("support-not-configured")
	}
	if !isCanonicalUUID(code.StaffID) || code.AuthTime.IsZero() {
		return TokenResponse{}, &Error{Code: ErrCodeInvalidGrant, Description: "the authorization code is invalid", Status: 400, RuleID: "support-code-shape"}
	}
	t, err := i.support.SupportTarget(ctx, code.StaffID, code.OrgID)
	if err != nil {
		return TokenResponse{}, unavailable("support-target")
	}
	for _, rule := range supportTargetRules {
		if rule.bad(t) {
			return TokenResponse{}, &Error{Code: ErrCodeInvalidGrant, Description: rule.desc, Status: 400, RuleID: rule.id}
		}
	}
	key, e := i.signingKey(ctx, now)
	if e != nil {
		return TokenResponse{}, e
	}
	jti, err := i.randomToken(24)
	if err != nil {
		return TokenResponse{}, serverError("jti-entropy")
	}
	claims := BuildSupportClaims(i.issuer, code, jti, now)
	token, err := i.signer.Sign(ctx, key.KID, claims)
	if err != nil {
		return TokenResponse{}, unavailable("signer")
	}
	if e := selfCheck(token, key, claims); e != nil {
		return TokenResponse{}, e
	}
	// Audit before act: no record, no token.
	if err := i.support.RecordSupportIssuance(ctx, SupportIssuance{
		JTI: jti, OrgID: code.OrgID, StaffID: code.StaffID, ClientID: code.ClientID, KID: key.KID,
		IssuedAt: time.Unix(claims.Iat, 0).UTC(), ExpiresAt: time.Unix(claims.Exp, 0).UTC(),
	}); err != nil {
		return TokenResponse{}, unavailable("record-support-issuance")
	}
	return TokenResponse{IDToken: token, TokenType: "Bearer", ExpiresIn: int(TokenLifetime / time.Second)}, nil
}

// validateSupportAuthorizeURL checks the advertised support authorize URL:
// absolute https (http only on loopback), path SupportAuthorizePath, no
// query, fragment or user info.
func validateSupportAuthorizeURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != SupportAuthorizePath {
		return fmt.Errorf("oidcissuer: support authorize URL %q must be an absolute URL whose path is %s", raw, SupportAuthorizePath)
	}
	// Reuse the issuer URL's scheme rule on the same host with the issuer
	// path, so http is allowed only on loopback here too.
	probe := *u
	probe.Path = IssuerPath
	if _, err := ValidateIssuerURL(probe.String()); err != nil {
		return fmt.Errorf("oidcissuer: support authorize URL %q: %w", raw, err)
	}
	return nil
}
