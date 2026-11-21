package oidcissuer

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/portalmfa"
)

// Config configures an Issuer.
type Config struct {
	// Issuer is the issuer identifier: the portal origin plus IssuerPath,
	// e.g. https://app.superbased.app/oauth2. https is required except on a
	// loopback host (local development and tests).
	Issuer string
	Store  Store
	Signer Signer
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Rand is the entropy source for codes and jtis; nil means crypto/rand.
	Rand io.Reader
	// Support, when set, lets Token redeem support codes (M7a.2); nil
	// answers every support code temporarily_unavailable.
	Support SupportTokenStore
	// SupportAuthorizeURL, when set, is advertised in discovery as the staff
	// console's support authorize endpoint (SupportAuthorizePath on the
	// staff origin).
	SupportAuthorizeURL string
}

// Issuer is the OIDC issuer service. It keeps no state between calls:
// codes, issued tokens and keys live behind Store, private keys behind
// Signer, so any number of replicas may serve one flow.
type Issuer struct {
	issuer     string
	store      Store
	signer     Signer
	now        func() time.Time
	rand       io.Reader
	support    SupportTokenStore
	supportURL string
}

// New validates cfg and returns an Issuer. It does no I/O.
func New(cfg Config) (*Issuer, error) {
	iss, err := ValidateIssuerURL(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if cfg.Store == nil || cfg.Signer == nil {
		return nil, errors.New("oidcissuer.New: Store and Signer are required")
	}
	if cfg.SupportAuthorizeURL != "" {
		if err := validateSupportAuthorizeURL(cfg.SupportAuthorizeURL); err != nil {
			return nil, err
		}
	}
	i := &Issuer{
		issuer: iss, store: cfg.Store, signer: cfg.Signer, now: cfg.Now, rand: cfg.Rand,
		support: cfg.Support, supportURL: cfg.SupportAuthorizeURL,
	}
	if i.now == nil {
		i.now = time.Now
	}
	if i.rand == nil {
		i.rand = rand.Reader
	}
	return i, nil
}

// ValidateIssuerURL checks an issuer identifier: absolute, https (http only
// on a loopback host), no query, fragment, user info or trailing slash, and
// its path exactly IssuerPath. It returns the identifier unchanged.
func ValidateIssuerURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("oidcissuer.ValidateIssuerURL: %q is not an absolute URL without query or fragment", raw)
	}
	if u.Path != IssuerPath {
		return "", fmt.Errorf("oidcissuer.ValidateIssuerURL: path %q, want %q", u.Path, IssuerPath)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip, perr := netip.ParseAddr(host)
		if host != "localhost" && (perr != nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("oidcissuer.ValidateIssuerURL: %q: http is allowed only on a loopback host", raw)
		}
	default:
		return "", fmt.Errorf("oidcissuer.ValidateIssuerURL: scheme %q, want https", u.Scheme)
	}
	return raw, nil
}

// Identifier returns the issuer identifier.
func (i *Issuer) Identifier() string { return i.issuer }

// Discovery returns the discovery document.
func (i *Issuer) Discovery() Discovery {
	d := DiscoveryFor(i.issuer)
	d.SupportAuthorizationEndpoint = i.supportURL
	return d
}

// JWKS returns the published key set.
func (i *Issuer) JWKS(ctx context.Context) (JWKSDocument, error) {
	keys, err := i.store.SigningKeys(ctx)
	if err != nil {
		return JWKSDocument{}, fmt.Errorf("oidcissuer.JWKS: %w", err)
	}
	return JWKSDocument{Keys: PublishedKeys(keys, i.now())}, nil
}

// RegisterSignerKeys asks the signer for its public keys and registers any
// the store does not know as staged (not published) for vmID. The serve
// process calls it at start; promotion stays an operator act.
func (i *Issuer) RegisterSignerKeys(ctx context.Context, vmID string) ([]PublicKey, error) {
	keys, err := i.signer.PublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("oidcissuer.RegisterSignerKeys: signer: %w", err)
	}
	for _, k := range keys {
		if _, err := RSAPublicKey(k.JWK); err != nil || k.KID != k.JWK.Kid {
			return nil, fmt.Errorf("oidcissuer.RegisterSignerKeys: signer reported an unusable key %q", k.KID)
		}
	}
	if err := i.store.StageSigningKeys(ctx, vmID, keys, i.now()); err != nil {
		return nil, fmt.Errorf("oidcissuer.RegisterSignerKeys: %w", err)
	}
	return keys, nil
}

// Outcome is what an authorize call asks the HTTP layer to do.
type Outcome int

// Authorize outcomes.
const (
	// OutcomeRedirect: send the browser to Location (the client's redirect
	// URI, carrying a code or a redirectable error).
	OutcomeRedirect Outcome = iota + 1
	// OutcomeLogin: the caller has no session; send them to sign in and back.
	OutcomeLogin
	// OutcomeError: answer Err in place; never redirect.
	OutcomeError
	// OutcomeSecondFactor: the session must complete the portal's passkey
	// second factor first (the account holds a passkey this session has not
	// used, or the org requires one); send the browser to the portal's
	// second-factor page and back (C2).
	OutcomeSecondFactor
)

// AuthorizeResult is the answer to an authorize request.
type AuthorizeResult struct {
	Outcome  Outcome
	Location string
	Err      *Error
	// FreshSignIn (OutcomeLogin only): the sign-in must be a fresh primary
	// authentication, not a reuse of the identity provider's own session,
	// and the request is resumed with ReauthParam set to ReauthAt
	// (ResumeQuery). False: an ordinary sign-in, resumed unchanged.
	FreshSignIn bool
	ReauthAt    time.Time
}

// Authorize handles an authorize request from the browser's portal session s
// (s.AccountID "" when there is none). Whether the session may be used as it
// is, or a (fresh) sign-in is needed first, is decided by the freshness rules
// (authn.go) from the request's prompt and max_age and s.AuthTime; the code
// carries s.AuthTime, which becomes the id_token's auth_time (none when it is
// zero, which the rules allow only when no freshness was asked).
func (i *Issuer) Authorize(ctx context.Context, r AuthorizeRequest, s Session) AuthorizeResult {
	// 1. The client and the exact redirect URI, before anything else.
	var client Client
	found := false
	if _, ok := OrgFromClientID(r.ClientID); ok {
		c, err := i.store.Client(ctx, r.ClientID)
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
	// 2. The request shape; refusals go back to the (verified) client.
	if e := checkAuthorizeRequest(r); e != nil {
		return i.redirectError(r, e)
	}
	// 3. A session, authenticated recently enough for what was asked.
	now := i.now()
	facts := factsFor(r, s, now)
	switch d, rule := decideAuthn(facts); d {
	case authnIssue:
		// Belt and braces under the table: a request that asked for
		// freshness is never answered with a token that cannot say when the
		// person authenticated (OIDC Core 3.1.2.1 makes auth_time REQUIRED
		// with max_age). No row issues that way; a future row that did is
		// stopped here rather than signed.
		if facts.freshnessAsked() && s.AuthTime.IsZero() {
			return i.redirectError(r, serverError("authn-issue-without-auth-time"))
		}
	case authnSignIn:
		return AuthorizeResult{Outcome: OutcomeLogin}
	case authnLoginRequired:
		return i.redirectError(r, &Error{
			Code:        ErrCodeLoginRequired,
			Description: "the end user must sign in again, and prompt=none forbids asking", Status: 302, RuleID: rule,
		})
	default:
		return AuthorizeResult{Outcome: OutcomeLogin, FreshSignIn: true, ReauthAt: now.UTC().Truncate(time.Second)}
	}
	accountID := s.AccountID
	// 4. The caller and the org.
	m, err := i.store.Member(ctx, accountID, client.OrgID)
	if err != nil {
		return i.redirectError(r, unavailable("member-lookup"))
	}
	if e := checkAccount(m, ErrCodeAccessDenied, 302); e != nil {
		return i.redirectError(r, e)
	}
	// 4b. The second factor (C2): portalmfa's issuer table. prompt=none
	// cannot ask for it, so it is interaction_required.
	if v, rule := portalmfa.IssueRule(portalmfa.IssueFacts{
		Pending: s.SecondFactorPending, MultiFactor: portalmfa.MultiFactor(s.AMR), OrgRequires: m.RequireSecondFactor,
	}); v != portalmfa.IssueAllowed {
		if hasPrompt(r.Prompt, PromptNone) {
			return i.redirectError(r, &Error{
				Code: ErrCodeInteractionRequired, Description: "the end user must sign in with a passkey, and prompt=none forbids asking",
				Status: 302, RuleID: rule,
			})
		}
		return AuthorizeResult{Outcome: OutcomeSecondFactor}
	}
	// 5. The code.
	code, err := i.randomToken(32)
	if err != nil {
		return i.redirectError(r, serverError("code-entropy"))
	}
	rec := CodeRecord{
		CodeHash: HashCode(code), ClientID: client.ClientID, OrgID: client.OrgID, AccountID: accountID,
		Sub: m.Sub, Email: m.Email, EmailVerified: m.EmailVerified, Nonce: r.Nonce, CodeChallenge: r.CodeChallenge,
		RedirectURI: r.RedirectURI, AMR: append([]string(nil), s.AMR...),
		CreatedAt: now, ExpiresAt: now.Add(CodeTTL),
	}
	if !s.AuthTime.IsZero() {
		rec.AuthTime = s.AuthTime.UTC()
	}
	if err := i.store.PutCode(ctx, rec); err != nil {
		return i.redirectError(r, unavailable("code-store"))
	}
	return AuthorizeResult{Outcome: OutcomeRedirect, Location: i.redirectWith(r.RedirectURI, map[string]string{
		"code": code, "state": r.State,
	})}
}

// TokenResponse is the body of a successful token response.
type TokenResponse struct {
	IDToken   string `json:"id_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

// Token redeems an authorization code. The error is always an *Error.
func (i *Issuer) Token(ctx context.Context, r TokenRequest) (TokenResponse, error) {
	if e := checkTokenRequest(r); e != nil {
		return TokenResponse{}, e
	}
	now := i.now()
	// Consume first: whatever is wrong below, this code is spent.
	code, err := i.store.ConsumeCode(ctx, HashCode(r.Code), now)
	if errors.Is(err, ErrNotFound) {
		return TokenResponse{}, &Error{Code: ErrCodeInvalidGrant, Description: "the authorization code is invalid", Status: 400, RuleID: "code-unused-unexpired"}
	}
	if err != nil {
		return TokenResponse{}, unavailable("code-consume")
	}
	if e := checkBinding(r, code); e != nil {
		return TokenResponse{}, e
	}
	if code.Support {
		return i.supportToken(ctx, code, now)
	}
	m, err := i.store.Member(ctx, code.AccountID, code.OrgID)
	if err != nil {
		return TokenResponse{}, unavailable("member-lookup")
	}
	if e := checkAccount(m, ErrCodeInvalidGrant, 400); e != nil {
		return TokenResponse{}, e
	}
	// The org's requirement is read again: one turned on between authorize
	// and token is taken (C2).
	if m.RequireSecondFactor && !portalmfa.MultiFactor(code.AMR) {
		return TokenResponse{}, &Error{Code: ErrCodeInvalidGrant, Description: "the org requires a second factor", Status: 400, RuleID: "org-requires-second-factor"}
	}
	key, e := i.signingKey(ctx, now)
	if e != nil {
		return TokenResponse{}, e
	}
	jti, err := i.randomToken(24)
	if err != nil {
		return TokenResponse{}, serverError("jti-entropy")
	}
	// The email, its verification flag and sub are re-read: a change between authorize and token
	// is taken, never the stale snapshot.
	code.Sub, code.Email, code.EmailVerified = m.Sub, m.Email, m.EmailVerified
	claims := BuildClaims(i.issuer, code, jti, now)
	token, err := i.signer.Sign(ctx, key.KID, claims)
	if err != nil {
		return TokenResponse{}, unavailable("signer")
	}
	if e := selfCheck(token, key, claims); e != nil {
		return TokenResponse{}, e
	}
	iss := Issuance{
		JTI: jti, OrgID: code.OrgID, AccountID: code.AccountID, Sub: claims.Sub, ClientID: code.ClientID,
		KID: key.KID, IssuedAt: time.Unix(claims.Iat, 0).UTC(), ExpiresAt: time.Unix(claims.Exp, 0).UTC(),
	}
	payload, err := AuditMirrorPayload(iss)
	if err != nil {
		return TokenResponse{}, serverError("mirror-payload")
	}
	iss.MirrorPayload = payload
	// Audit before act: no record, no token.
	if err := i.store.RecordIssuance(ctx, iss); err != nil {
		return TokenResponse{}, unavailable("record-issuance")
	}
	return TokenResponse{IDToken: token, TokenType: "Bearer", ExpiresIn: int(TokenLifetime / time.Second)}, nil
}

// signingKey picks the key to sign with: active, published since its
// not_before, and held by our signer.
func (i *Issuer) signingKey(ctx context.Context, now time.Time) (SigningKey, *Error) {
	keys, err := i.store.SigningKeys(ctx)
	if err != nil {
		return SigningKey{}, unavailable("keys")
	}
	held, err := i.signer.PublicKeys(ctx)
	if err != nil {
		return SigningKey{}, unavailable("signer-keys")
	}
	heldSet := make(map[string]bool, len(held))
	for _, k := range held {
		heldSet[k.KID] = true
	}
	key, ok := SelectSigningKey(keys, heldSet, now)
	if !ok {
		return SigningKey{}, unavailable("no-published-key")
	}
	return key, nil
}

// selfCheck verifies a freshly signed token under the PUBLISHED key for its
// kid, with exactly the claims asked for.
func selfCheck(token string, key SigningKey, claims Claims) *Error {
	got, err := VerifyRS256(token, key.JWK)
	if err != nil || !sameClaims(got, claims) {
		return unavailable("signer-self-check")
	}
	return nil
}

func sameClaims(a, b Claims) bool {
	if a.Iss != b.Iss || a.Sub != b.Sub || a.Aud != b.Aud || a.Exp != b.Exp || a.Iat != b.Iat || a.AuthTime != b.AuthTime ||
		a.Jti != b.Jti || a.Nonce != b.Nonce || a.Org != b.Org || a.Email != b.Email ||
		a.EmailVerified != b.EmailVerified || a.Support != b.Support || len(a.AMR) != len(b.AMR) {
		return false
	}
	for k := range a.AMR {
		if a.AMR[k] != b.AMR[k] {
			return false
		}
	}
	return true
}

// redirectError sends e back to the verified redirect URI with the state.
func (i *Issuer) redirectError(r AuthorizeRequest, e *Error) AuthorizeResult {
	return redirectErrorFor(i.issuer, r, e)
}

// redirectWith appends params and the iss parameter (RFC 9207) to the
// registered redirect URI.
func (i *Issuer) redirectWith(redirectURI string, params map[string]string) string {
	return redirectWithFor(i.issuer, redirectURI, params)
}

func (i *Issuer) randomToken(n int) (string, error) { return randomTokenFrom(i.rand, n) }

// redirectErrorFor is redirectError for any issuer identifier (the member
// and support authorize paths share it).
func redirectErrorFor(issuer string, r AuthorizeRequest, e *Error) AuthorizeResult {
	params := map[string]string{"error": e.Code, "error_description": e.Description}
	if boundedText(r.State, maxStateLen) {
		params["state"] = r.State
	}
	return AuthorizeResult{Outcome: OutcomeRedirect, Location: redirectWithFor(issuer, r.RedirectURI, params), Err: e}
}

// redirectWithFor is redirectWith for any issuer identifier.
func redirectWithFor(issuer, redirectURI string, params map[string]string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

func randomTokenFrom(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("oidcissuer: entropy: %w", err)
	}
	return b64.EncodeToString(b), nil
}

func unavailable(rule string) *Error {
	return &Error{Code: ErrCodeTemporarilyUnavailable, Description: "sign-in is temporarily unavailable", Status: 503, RuleID: rule}
}

func serverError(rule string) *Error {
	return &Error{Code: ErrCodeServerError, Description: "sign-in failed", Status: 500, RuleID: rule}
}

// LoginReturnPath returns the same-origin path (with query) the sign-in flow
// should return to so an interrupted authorize request resumes.
func LoginReturnPath(rawQuery string) string {
	if strings.TrimSpace(rawQuery) == "" {
		return AuthorizePath
	}
	return AuthorizePath + "?" + rawQuery
}
