package oidcissuer

import (
	"net/url"
	"strings"
)

// AuthorizeRequest is the parsed query of GET /oauth2/authorize.
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	ResponseMode        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Request             string
	RequestURI          string
	// Prompt is the space-separated prompt values (OIDC Core 3.1.2.1).
	Prompt string
	// MaxAge is max_age as sent: decimal seconds, "" when absent.
	MaxAge string
	// ReauthAt is ReauthParam as sent (the issuer's own marker on a request
	// it resumes after demanding a fresh sign-in; authn.go).
	ReauthAt string
	// Duplicated lists the parameters that appeared more than once (RFC
	// 6749 3.1: a parameter must not be sent twice).
	Duplicated []string
}

// authorizeParams are the parameters ParseAuthorizeQuery reads.
var authorizeParams = []string{
	"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
	"code_challenge", "code_challenge_method", "request", "request_uri",
	"prompt", "max_age", ReauthParam,
}

// ParseAuthorizeQuery reads an authorize request from its query.
func ParseAuthorizeQuery(q url.Values) AuthorizeRequest {
	return AuthorizeRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		ResponseMode:        q.Get("response_mode"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Request:             q.Get("request"),
		RequestURI:          q.Get("request_uri"),
		Prompt:              q.Get("prompt"),
		MaxAge:              q.Get("max_age"),
		ReauthAt:            q.Get(ReauthParam),
		Duplicated:          duplicated(q, authorizeParams),
	}
}

// TokenRequest is the parsed form of POST /oauth2/token.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	// ClientSecretSent is true when the form carried client_secret: these
	// are public clients, so a secret is refused rather than ignored.
	ClientSecretSent bool
	Duplicated       []string
}

// tokenParams are the parameters ParseTokenForm reads.
var tokenParams = []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier", "client_secret"}

// ParseTokenForm reads a token request from its form body.
func ParseTokenForm(f url.Values) TokenRequest {
	_, secret := f["client_secret"]
	return TokenRequest{
		GrantType:        f.Get("grant_type"),
		Code:             f.Get("code"),
		RedirectURI:      f.Get("redirect_uri"),
		ClientID:         f.Get("client_id"),
		CodeVerifier:     f.Get("code_verifier"),
		ClientSecretSent: secret,
		Duplicated:       duplicated(f, tokenParams),
	}
}

func duplicated(v url.Values, names []string) []string {
	var out []string
	for _, n := range names {
		if len(v[n]) > 1 {
			out = append(out, n)
		}
	}
	return out
}

// Maximum lengths of the opaque values the issuer stores or echoes.
const (
	maxStateLen  = 512
	maxCodeLen   = 128
	maxClientLen = 64
)

// clientRule is one row of the client and redirect URI rules, walked before
// anything is redirected: a refusal here is answered in place (RFC 6749
// 4.1.2.1), because redirecting to an unverified URI is an open redirect.
type clientRule struct {
	id   string
	code string
	desc string
	bad  func(r AuthorizeRequest, c Client, found bool) bool
}

var clientRules = []clientRule{
	{
		id: "client-id-present", code: ErrCodeInvalidRequest, desc: "client_id is required",
		bad: func(r AuthorizeRequest, _ Client, _ bool) bool {
			return r.ClientID == "" || len(r.ClientID) > maxClientLen
		},
	},
	{
		id: "client-id-shape", code: ErrCodeInvalidClient, desc: "client_id is not an org client",
		bad: func(r AuthorizeRequest, _ Client, _ bool) bool { _, ok := OrgFromClientID(r.ClientID); return !ok },
	},
	{
		id: "client-id-once", code: ErrCodeInvalidRequest, desc: "client_id or redirect_uri was sent more than once",
		bad: func(r AuthorizeRequest, _ Client, _ bool) bool {
			for _, d := range r.Duplicated {
				if d == "client_id" || d == "redirect_uri" {
					return true
				}
			}
			return false
		},
	},
	{
		id: "client-known", code: ErrCodeInvalidClient, desc: "unknown client",
		bad: func(_ AuthorizeRequest, _ Client, found bool) bool { return !found },
	},
	{
		id: "client-enabled", code: ErrCodeInvalidClient, desc: "this client is disabled",
		bad: func(_ AuthorizeRequest, c Client, _ bool) bool { return c.Disabled },
	},
	{
		id: "redirect-exact", code: ErrCodeInvalidRequest, desc: "redirect_uri does not match the registered URI",
		bad: func(r AuthorizeRequest, c Client, _ bool) bool {
			return !RedirectMatches(c.RedirectURIs, r.RedirectURI)
		},
	},
}

// requestRule is one row of the authorize request rules, walked once the
// client and redirect URI are known good: a refusal is redirected back to the
// client with error and state.
type requestRule struct {
	id   string
	code string
	desc string
	bad  func(r AuthorizeRequest) bool
}

var authorizeRequestRules = []requestRule{
	{
		id: "params-once", code: ErrCodeInvalidRequest, desc: "a parameter was sent more than once",
		bad: func(r AuthorizeRequest) bool { return len(r.Duplicated) > 0 },
	},
	{
		id: "no-request-object", code: ErrCodeRequestNotSupported, desc: "request objects are not supported",
		bad: func(r AuthorizeRequest) bool { return r.Request != "" || r.RequestURI != "" },
	},
	{
		id: "response-type-code", code: ErrCodeUnsupportedResponseType, desc: "response_type must be code",
		bad: func(r AuthorizeRequest) bool { return r.ResponseType != "code" },
	},
	{
		id: "response-mode-query", code: ErrCodeInvalidRequest, desc: "response_mode must be query",
		bad: func(r AuthorizeRequest) bool { return r.ResponseMode != "" && r.ResponseMode != "query" },
	},
	{
		id: "scope-openid", code: ErrCodeInvalidScope, desc: "scope must include openid",
		bad: func(r AuthorizeRequest) bool { return !hasScope(r.Scope, "openid") },
	},
	{
		id: "state-present", code: ErrCodeInvalidRequest, desc: "state is required",
		bad: func(r AuthorizeRequest) bool { return !boundedText(r.State, maxStateLen) },
	},
	{
		id: "nonce-present", code: ErrCodeInvalidRequest, desc: "nonce is required",
		bad: func(r AuthorizeRequest) bool { return !boundedText(r.Nonce, maxNonceLen) },
	},
	{
		id: "pkce-s256", code: ErrCodeInvalidRequest, desc: "PKCE with code_challenge_method=S256 is required; plain is refused",
		bad: func(r AuthorizeRequest) bool { return r.CodeChallengeMethod != ChallengeMethodS256 },
	},
	{
		id: "prompt-supported", code: ErrCodeInvalidRequest, desc: "prompt carries a value this issuer does not support (supported: none, login)",
		bad: func(r AuthorizeRequest) bool { return !promptSupported(r.Prompt) },
	},
	{
		id: "prompt-none-alone", code: ErrCodeInvalidRequest, desc: "prompt=none cannot be combined with another prompt value",
		bad: func(r AuthorizeRequest) bool { return promptNoneWithOthers(r.Prompt) },
	},
	{
		id: "max-age-shape", code: ErrCodeInvalidRequest, desc: "max_age must be a non-negative number of seconds",
		bad: func(r AuthorizeRequest) bool { _, _, ok := parseMaxAge(r.MaxAge); return !ok },
	},
	{
		id: "pkce-challenge-shape", code: ErrCodeInvalidRequest, desc: "code_challenge must be a base64url SHA-256 digest",
		bad: func(r AuthorizeRequest) bool { return !validChallenge(r.CodeChallenge) },
	},
}

// accountRule is one row of the rules on the caller and the org, applied at
// authorize and again at token time.
type accountRule struct {
	id   string
	desc string
	bad  func(m Member) bool
}

var accountRules = []accountRule{
	{id: "member", desc: "you are not a member of this organization", bad: func(m Member) bool { return !m.IsMember }},
	{id: "account-active", desc: "this account cannot sign in", bad: func(m Member) bool { return m.AccountStatus != "active" }},
	{id: "org-active", desc: "this organization is not active", bad: func(m Member) bool { return m.OrgStatus != "active" }},
	{id: "rail-enabled", desc: "this organization does not use platform sign-in", bad: func(m Member) bool { return !m.RailEnabled }},
	{id: "subject-known", desc: "this account has no identity-provider subject", bad: func(m Member) bool { return !boundedText(m.Sub, maxSubLen) }},
	{id: "email-known", desc: "this account has no verified email", bad: func(m Member) bool {
		return !boundedText(m.Email, maxEmailLen) || !strings.Contains(m.Email, "@")
	}},
	// A4: the identity provider must have verified the address at the
	// caller's latest sign-in. The issuer refuses rather than signing
	// email_verified=false or omitting the claim: the M6.0 note fixes
	// email_verified as always true (plan 06 5.4), tenants match invitations
	// by it, and the signer's own claim rules refuse a false flag too.
	{id: "email-verified", desc: "your identity provider has not verified this account's email; verify it and sign in again", bad: func(m Member) bool {
		return !m.EmailVerified
	}},
}

// tokenRule is one row of the token request rules, walked before the code is
// touched.
type tokenRule struct {
	id     string
	code   string
	desc   string
	status int
	bad    func(r TokenRequest) bool
}

var tokenRequestRules = []tokenRule{
	{
		id: "params-once", code: ErrCodeInvalidRequest, status: 400, desc: "a parameter was sent more than once",
		bad: func(r TokenRequest) bool { return len(r.Duplicated) > 0 },
	},
	{
		id: "grant-type", code: ErrCodeUnsupportedGrantType, status: 400, desc: "grant_type must be authorization_code",
		bad: func(r TokenRequest) bool { return r.GrantType != "authorization_code" },
	},
	{
		id: "public-client", code: ErrCodeInvalidClient, status: 401, desc: "this is a public client; do not send a client secret",
		bad: func(r TokenRequest) bool { return r.ClientSecretSent },
	},
	{
		id: "client-id", code: ErrCodeInvalidClient, status: 401, desc: "client_id is required",
		bad: func(r TokenRequest) bool { _, ok := OrgFromClientID(r.ClientID); return !ok },
	},
	{
		id: "code-present", code: ErrCodeInvalidRequest, status: 400, desc: "code is required",
		bad: func(r TokenRequest) bool { return !validToken(r.Code, 16, maxCodeLen) },
	},
	{
		id: "redirect-present", code: ErrCodeInvalidRequest, status: 400, desc: "redirect_uri is required",
		bad: func(r TokenRequest) bool { return r.RedirectURI == "" },
	},
	{
		id: "verifier-present", code: ErrCodeInvalidRequest, status: 400, desc: "code_verifier is required",
		bad: func(r TokenRequest) bool { return r.CodeVerifier == "" },
	},
}

// bindingRule is one row of the rules binding a CONSUMED code to the token
// request: every refusal is invalid_grant, and the code is already spent.
type bindingRule struct {
	id  string
	bad func(r TokenRequest, c CodeRecord) bool
}

var codeBindingRules = []bindingRule{
	{id: "code-client", bad: func(r TokenRequest, c CodeRecord) bool { return r.ClientID != c.ClientID }},
	{id: "code-redirect", bad: func(r TokenRequest, c CodeRecord) bool { return r.RedirectURI != c.RedirectURI }},
	{id: "pkce-verifier", bad: func(r TokenRequest, c CodeRecord) bool { return !VerifyPKCE(c.CodeChallenge, r.CodeVerifier) }},
	// No auth_time row: a code without one (a session whose authentication
	// time is not known, or a code minted before cloud migration 0083) yields
	// a token that carries none, never a filled-in time. Authorize issued such
	// a code only for a request that asked for no freshness.
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// checkClient walks clientRules; nil when the client and redirect URI pass.
func checkClient(r AuthorizeRequest, c Client, found bool) *Error {
	for _, rule := range clientRules {
		if rule.bad(r, c, found) {
			return &Error{Code: rule.code, Description: rule.desc, Status: 400, RuleID: rule.id}
		}
	}
	return nil
}

// checkAuthorizeRequest walks authorizeRequestRules.
func checkAuthorizeRequest(r AuthorizeRequest) *Error {
	for _, rule := range authorizeRequestRules {
		if rule.bad(r) {
			return &Error{Code: rule.code, Description: rule.desc, Status: 302, RuleID: rule.id}
		}
	}
	return nil
}

// checkAccount walks accountRules; code is the error code a refusal carries
// (access_denied at authorize, invalid_grant at token).
func checkAccount(m Member, code string, status int) *Error {
	for _, rule := range accountRules {
		if rule.bad(m) {
			return &Error{Code: code, Description: rule.desc, Status: status, RuleID: rule.id}
		}
	}
	return nil
}

// checkTokenRequest walks tokenRequestRules.
func checkTokenRequest(r TokenRequest) *Error {
	for _, rule := range tokenRequestRules {
		if rule.bad(r) {
			return &Error{Code: rule.code, Description: rule.desc, Status: rule.status, RuleID: rule.id}
		}
	}
	return nil
}

// checkBinding walks codeBindingRules.
func checkBinding(r TokenRequest, c CodeRecord) *Error {
	for _, rule := range codeBindingRules {
		if rule.bad(r, c) {
			return &Error{Code: ErrCodeInvalidGrant, Description: "the authorization code is invalid", Status: 400, RuleID: rule.id}
		}
	}
	return nil
}
