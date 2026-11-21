package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidchttp"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The WorkOS browser sign-in leg (plan §3 W1). It is a BFF flow: the browser
// never sees a WorkOS token, a client secret, or the PKCE verifier — it only
// carries an opaque transaction cookie across the AuthKit round-trip and comes
// back holding the same __Host-sbci session cookie the dev-auth login mints.
//
// Two cookies, with different lifetimes and purposes:
//
//   - the SESSION cookie is SameSite=Lax (operator ruling A7a,
//     portalCookieSameSite in portal.go): it rides a cross-site top-level GET
//     navigation, so every mutation is guarded by portalAuth's double-submit
//     CSRF header and exact-Origin check, never by SameSite;
//   - the TRANSACTION cookie is SameSite=Lax too, because the AuthKit callback
//     IS a cross-site top-level navigation and a Strict cookie would simply not
//     be sent (adversarial-review finding 5). It is pre-auth, single-use,
//     10-minute-lived, and is cleared the moment the callback reads it.
//
// The whole leg is DARK BY DEFAULT: without the SBCI_PORTAL_WORKOS activation
// gate every route here answers an honest 501, so R7's exposure gates decide
// when browser sign-in becomes reachable — not a deploy accident.
const (
	// portalTxnCookieSecure is the production transaction-cookie name. Same
	// __Host- hardening rationale as the session cookie.
	portalTxnCookieSecure = "__Host-sbci-txn"
	// portalTxnCookieDev is the plain-http dev fallback (the __Host- prefix
	// requires Secure, which a browser refuses over http).
	portalTxnCookieDev = "sbci_txn"
	// portalTxnCookieMaxAge bounds the transaction cookie to the same 30
	// minutes the auth_transactions row lives (store.DefaultAuthTransactionTTL).
	portalTxnCookieMaxAge = 1800

	// portalSignInErrorParam carries a recoverable callback failure to the
	// console sign-in page (callbackRefuse), which explains it.
	portalSignInErrorParam = "signin_error"

	// defaultPortalReturnTo is where a completed sign-in lands when the caller
	// asked for nothing specific.
	defaultPortalReturnTo = "/portal/"
	// portalReturnPrefix constrains the redirect allowlist to the portal SPA:
	// a same-origin path is necessary but not sufficient.
	portalReturnPrefix = "/portal/"

	// stepUpQueryParam carries the minted step-up authorization id back to the
	// SPA on the post-callback redirect. The id is single-use, ≤5 minutes old,
	// and bound to this browser session + action, so it is useless to anyone
	// else; the SPA replays it in the destructive request body.
	stepUpQueryParam = "step_up"
)

// workOSCallbackPath is the exact callback path; the redirect_uri is
// PortalBaseURL + this (which falls back to ExternalBaseURL on a single-host
// deployment), recorded on the transaction and re-checked at callback so a
// transaction minted for one origin cannot complete at another.
const workOSCallbackPath = "/portal/auth/workos/callback"

// workOSRedirectURI is the exact redirect_uri this deployment registers with
// WorkOS. It is anchored to the PORTAL origin, never the API origin: once R5
// splits the two names, the browser leg lives entirely on app.superbased.app
// and a redirect_uri carrying the API host would be both unregistered at the
// provider and cross-origin for the transaction cookie.
func (s *Server) workOSRedirectURI() string { return s.portalBaseURL + workOSCallbackPath }

// portalTxnCookieName returns the transaction-cookie name for this deployment,
// mirroring portalCookieName's stable server-level choice.
func (s *Server) portalTxnCookieName() string {
	if s.portalSecureCookie {
		return portalTxnCookieSecure
	}
	return portalTxnCookieDev
}

// setTxnCookie writes the pre-auth transaction cookie: HttpOnly, Path=/,
// SameSite=Lax (it MUST survive the cross-site AuthKit callback), Secure
// whenever the deployment uses the __Host- name.
func (s *Server) setTxnCookie(w http.ResponseWriter, raw string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: HttpOnly, SameSite=Lax for the AuthKit callback; Secure follows the deployment
		Name:     s.portalTxnCookieName(),
		Value:    raw,
		Path:     "/",
		MaxAge:   portalTxnCookieMaxAge,
		HttpOnly: true,
		Secure:   s.portalSecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearTxnCookie expires the transaction cookie. The callback calls it on EVERY
// outcome, so a failed attempt never leaves a reusable transaction cookie.
func (s *Server) clearTxnCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: HttpOnly, SameSite=Lax for the AuthKit callback; Secure follows the deployment
		Name:     s.portalTxnCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.portalSecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// randomSecret returns a 256-bit base64url secret (the same shape the store
// mints its own bearer secrets in).
func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cloudserver/api: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge is the S256 code challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// secretHash is the hex sha256 the store keys its hashed secrets by.
func secretHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// percentEncodedTraps are the percent-encodings that would let a return_to
// smuggle a path separator, an escape, or a dot segment PAST the checks below
// and have a browser (or a downstream proxy) decode it afterwards. They are
// rejected on the raw string, in either letter case, rather than decoded and
// re-inspected: "reject what we cannot fully reason about" is the whole point
// of an allowlist, and no legitimate portal route needs an encoded slash.
var percentEncodedTraps = []string{"%5c", "%2f", "%2e"}

// safeReturnPath is the redirect allowlist. It admits ONLY a canonical,
// same-origin, query-free PATH inside the portal SPA, plus the rows of
// returnTargets (today one: the OIDC authorize endpoint with its query,
// canonically re-encoded). Everything else — an
// absolute URL ("https://evil.example"), a protocol-relative one
// ("//evil.example"), a backslash trick ("/\evil"), a percent-encoded
// separator ("/portal/a%2f..%2f..%2fx"), a dot segment ("/portal/../x"), a
// control character, or anything carrying a scheme/host/query/fragment — is
// refused outright. There is deliberately no "host equals ours" branch: a path
// is the only accepted shape, so an open redirect cannot be introduced by a
// parsing subtlety.
//
// It is DECODE-AWARE and CANONICALIZING, which are two separate defenses:
//
//   - decode-aware, because the value arrives already percent-decoded once (it
//     is a query parameter), so a SECOND encoding layer left in the string is
//     an attempt to have someone downstream decode it again;
//   - canonicalizing, because the returned string is what a browser is later
//     told to visit — so the prefix check must hold on the CLEANED path, not on
//     a spelling of it that only looks like it is under /portal/.
//
// The returned path is the canonical form, and it is what the caller stores and
// later redirects to.
func safeReturnPath(raw string) (string, bool) {
	if raw == "" {
		return defaultPortalReturnTo, true
	}
	// 0) Split off a query. Only a returnTarget row that keeps one may have
	// it; every check below runs on the PATH alone, so a query can never
	// smuggle a separator or a dot segment into what is redirected to.
	rawPath, rawQuery, hasQuery := strings.Cut(raw, "?")
	// 1) Raw-string traps. A backslash is a path separator to some browsers and
	// URL parsers; a control character can split a header downstream; a
	// fragment is never accepted.
	if strings.ContainsAny(raw, "\\#") {
		return "", false
	}
	lower := strings.ToLower(rawPath)
	for _, trap := range percentEncodedTraps {
		if strings.Contains(lower, trap) {
			return "", false
		}
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	// 2) Shape. A path, and nothing but a path: no scheme, no authority, no
	// query, no fragment. A query is admitted only by a row that says so
	// (the OIDC authorize resume); for the portal SPA, accepting one would
	// mean reasoning about how it merges with the step-up parameter appended
	// later, and no portal route needs one on a return_to.
	if !strings.HasPrefix(rawPath, "/") || strings.HasPrefix(rawPath, "//") {
		return "", false
	}
	u, err := url.Parse(rawPath)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	// 3) No dot segments, in any spelling. (The encoded spellings are already
	// gone above; this catches the literal ones.)
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	// 4) Canonicalize, then re-check the prefix on the CLEANED path. path.Clean
	// drops the trailing slash, so restore it when the caller asked for a
	// directory-shaped route ("/portal/" must stay "/portal/", which is the
	// SPA's own root).
	cleaned := path.Clean(u.Path)
	if strings.HasSuffix(u.Path, "/") && cleaned != "/" {
		cleaned += "/"
	}
	// 5) The allow-list, top-down; the first row whose path matches decides.
	for _, t := range returnTargets {
		if !t.matches(cleaned) {
			continue
		}
		if !hasQuery {
			return cleaned, true
		}
		if !t.query {
			return "", false
		}
		// The query is re-encoded canonically: parsed (it must parse) and
		// written back, so what is stored and later redirected to is exactly
		// the parameters, never a spelling of them.
		q, err := url.ParseQuery(rawQuery)
		if err != nil {
			return "", false
		}
		if enc := q.Encode(); enc != "" {
			return cleaned + "?" + enc, true
		}
		return cleaned, true
	}
	return "", false
}

// returnTarget is one row of the return_to allow-list.
type returnTarget struct {
	// path is matched exactly, or as a prefix when prefix is set.
	path   string
	prefix bool
	// query admits (and canonically re-encodes) a query string.
	query bool
}

func (t returnTarget) matches(p string) bool {
	if t.prefix {
		return strings.HasPrefix(p, t.path)
	}
	return p == t.path
}

// returnTargets is the return_to allow-list, walked top-down by
// safeReturnPath. The portal SPA is the general case; the one exception is
// the OIDC authorize endpoint (managed-SaaS M6.2, design A5): an authorize
// request with no portal session sends the browser to sign in with
// return_to set to that same request, so it can resume. Its query (client,
// redirect URI, PKCE challenge, state, nonce) is the request itself, and the
// authorize endpoint re-validates every parameter, so keeping it cannot turn
// into an open redirect: the redirect lands on our own exact path.
var returnTargets = []returnTarget{
	// C2: the second-factor page carries its own return_to (the authorize
	// request it resumes); the page sends that back to the finish routes,
	// which validate it again here before answering it as "next".
	{path: secondFactorPagePath, query: true},
	{path: portalReturnPrefix, prefix: true},
	{path: oidcissuer.AuthorizePath, query: true},
}

// portalWorkOSReady reports whether the WorkOS browser leg may run, writing the
// honest 501 when it may not. Three independent reasons, each with its own
// copy: the activation gate is off (dark by default, R7), the deployment is
// running the dev-auth stub, or the WorkOS credentials are missing.
func (s *Server) portalWorkOSReady(w http.ResponseWriter) bool {
	if !s.portalWorkOSEnabled {
		writeErr(w, http.StatusNotImplemented, "provider_not_configured",
			"Browser sign-in with WorkOS is not enabled on this deployment. It stays dark until the exposure gates in the remediation plan (R7) are green; set SBCI_PORTAL_WORKOS=1 to activate it.")
		return false
	}
	if s.portalDevAuth() {
		writeErr(w, http.StatusNotImplemented, "dev_auth_mode",
			"This deployment runs the dev-auth identity stub, so the WorkOS sign-in leg is inactive. Sign in with POST /portal/auth/login instead.")
		return false
	}
	if s.workOSClientID == "" || s.workOSAPIKey == "" {
		writeErr(w, http.StatusNotImplemented, "provider_not_configured",
			"WorkOS is not fully configured on this deployment (WORKOS_CLIENT_ID and WORKOS_API_KEY are both required for the browser sign-in leg).")
		return false
	}
	return true
}

// optionalPortalPrincipal resolves the session cookie WITHOUT the portalAuth
// middleware, for the one endpoint whose authentication requirement depends on
// a query parameter (a step-up start needs a session; a login start must not).
// It is a GET-only path, so the middleware's other job — the double-submit CSRF
// check, which applies to mutations only — is not skipped by using this.
func (s *Server) optionalPortalPrincipal(r *http.Request) (portalPrincipal, bool) {
	c, err := r.Cookie(s.portalCookieName())
	if err != nil || c.Value == "" {
		return portalPrincipal{}, false
	}
	bp, err := s.store.IntrospectBrowserSession(r.Context(), c.Value, s.now(), store.WithIdleTTL(s.portalSessionIdleTTL))
	if err != nil || !bp.Valid {
		return portalPrincipal{}, false
	}
	return portalPrincipal{
		AccountID: bp.AccountID, SessionID: bp.SessionID, CSRFHash: bp.CSRFHash, Raw: c.Value,
	}, true
}

// handleWorkOSStart begins the AuthKit round-trip: it mints the state, nonce,
// and PKCE verifier, records the single-use transaction (verifier encrypted at
// rest), sets the Lax transaction cookie carrying the RAW state secret, and
// redirects to WorkOS.
//
// ?screen_hint=sign-up (login only) opens AuthKit on its sign-up screen: the
// console's "Create an account" (parseScreenHint).
//
// ?purpose=step_up&action=deletion|export|security additionally requires a live
// portal session and binds that session + account into the transaction, so the
// callback can prove the person who re-authenticated is the person already
// signed in on this browser.
func (s *Server) handleWorkOSStart(w http.ResponseWriter, r *http.Request) {
	if !s.portalWorkOSReady(w) {
		return
	}
	q := r.URL.Query()

	returnTo, ok := safeReturnPath(q.Get("return_to"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid_redirect",
			"return_to must be a same-origin path under /portal/")
		return
	}

	in := store.AuthTransactionInput{
		Purpose:     store.AuthPurposeLogin,
		ReturnTo:    returnTo,
		RedirectURI: s.workOSRedirectURI(),
		TTL:         store.DefaultAuthTransactionTTL,
		Now:         s.now(),
	}
	// forceReauth: make AuthKit authenticate the person again rather than
	// reuse its own session. Always for a step-up; for a login, when the
	// platform OIDC issuer asked for a fresh sign-in (reauth=1: its relying
	// party sent prompt=login, or a max_age the portal session cannot show it
	// meets). The transaction records it, and only a login whose transaction
	// says so mints a portal session with an authentication time (the
	// issuer's auth_time): the browser can drop reauth=1, but then the session
	// it gets has none, and the issuer asks again.
	// The sign-up choice (hosted sign-in fix, lane A): a closed enum, valid
	// on a login only. A step-up re-authenticates someone already signed
	// in, so asking it for the sign-up screen is refused rather than ignored.
	screenHint, ok := parseScreenHint(q)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid_screen_hint",
			"screen_hint must be sign-up or sign-in when present")
		return
	}
	forceReauth := false
	switch purpose := q.Get("purpose"); purpose {
	case "", store.AuthPurposeLogin:
		// Absent, or exactly one value "1"; anything else (an empty or
		// repeated parameter included) is refused rather than guessed at.
		switch vs, present := q[oidchttp.ReauthQueryParam]; {
		case !present:
		case len(vs) == 1 && vs[0] == "1":
			forceReauth = true
		default:
			writeErr(w, http.StatusBadRequest, "invalid_reauth", "reauth must be 1 when present")
			return
		}
	case store.AuthPurposeStepUp:
		if screenHint != "" {
			writeErr(w, http.StatusBadRequest, "invalid_screen_hint",
				"a step-up start cannot ask for the sign-up screen")
			return
		}
		forceReauth = true
		action := q.Get("action")
		switch action {
		case store.StepUpActionDeletion, store.StepUpActionExport, store.StepUpActionSecurity:
		default:
			writeErr(w, http.StatusBadRequest, "invalid_action",
				"a step-up start requires action=deletion|export|security")
			return
		}
		p, signedIn := s.optionalPortalPrincipal(r)
		if !signedIn {
			writeErr(w, http.StatusUnauthorized, "unauthorized",
				"sign in before re-authenticating for a destructive action")
			return
		}
		in.Purpose = store.AuthPurposeStepUp
		in.Action = action
		in.AccountID = p.AccountID
		in.SessionID = p.SessionID
	default:
		writeErr(w, http.StatusBadRequest, "invalid_purpose", "purpose must be login or step_up")
		return
	}

	rawState, err := randomSecret()
	if err != nil {
		s.log.Error("cloudserver/api: workos start rand", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start sign-in")
		return
	}
	rawNonce, err := randomSecret()
	if err != nil {
		s.log.Error("cloudserver/api: workos start rand", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start sign-in")
		return
	}
	verifier, err := randomSecret() // 43 base64url chars — a valid PKCE verifier
	if err != nil {
		s.log.Error("cloudserver/api: workos start rand", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start sign-in")
		return
	}
	in.StateHash = secretHash(rawState)
	in.NonceHash = secretHash(rawNonce)
	in.PKCEVerifier = verifier
	in.ForceReauth = forceReauth

	if _, err := s.store.CreateAuthTransaction(r.Context(), in); err != nil {
		s.log.Error("cloudserver/api: create auth transaction", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start sign-in")
		return
	}
	action := "portal_workos_start_" + in.Purpose
	if forceReauth && in.Purpose == store.AuthPurposeLogin {
		action += "_reauth"
	}
	if screenHint == workOSScreenSignUp {
		action += "_signup"
	}
	s.audit(r.Context(), in.AccountID, action)

	s.setTxnCookie(w, rawState)
	authorizeURL := s.workOSAuthorizeURLFor(in.RedirectURI, pkceChallenge(verifier), rawState, rawNonce, forceReauth, screenHint)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// screenHintParam is the start route's query parameter for the screen AuthKit
// opens on. It keeps WorkOS's own name so the console's link reads the same
// as the authorize request it becomes.
const screenHintParam = "screen_hint"

// workOSScreenSignUp is the authorize request's screen_hint for AuthKit's
// sign-up screen. WorkOS documents screen_hint (sign-up | sign-in) as valid
// only with provider=authkit, which workOSAuthorizeURLFor always sends.
const workOSScreenSignUp = "sign-up"

// screenHints is the closed set of screen_hint values the start route
// accepts, each mapped to what the authorize request carries. "sign-in" is
// AuthKit's default screen, so it is accepted and sends nothing: the
// authorize request carries screen_hint only for a sign-up.
var screenHints = map[string]string{
	"sign-in":          "",
	workOSScreenSignUp: workOSScreenSignUp,
}

// parseScreenHint reads the start route's screen_hint: absent is "" (the
// default screen); exactly one value from screenHints maps through it;
// anything else (an unknown, empty or repeated value) is refused, never
// guessed at.
func parseScreenHint(q url.Values) (string, bool) {
	vs, present := q[screenHintParam]
	if !present {
		return "", true
	}
	if len(vs) != 1 {
		return "", false
	}
	hint, ok := screenHints[vs[0]]
	return hint, ok
}

// workOSAuthorizeURLFor builds the AuthKit authorization URL. It mirrors the
// node-side builder in internal/cloudclient (same parameter set) but is
// implemented here because the server must not import the client package (the
// cloud egress pin). One deliberate difference: screenHint (the console's
// "Create an account") adds screen_hint, which the node-side builder never
// sends, because the CLI's own sign-in is never a sign-up entry point (a
// person creates the account in the browser console).
//
// forceReauth adds the two OIDC freshness parameters WorkOS's authorize
// endpoint accepts (both SDK-documented): `prompt=login` and `max_age=0`. They
// are set for a STEP-UP, and they are the whole point of a step-up — without
// them a live SSO session at the provider satisfies the re-authentication
// silently, and "re-authenticate to delete your account" degrades into a
// redirect the user never sees. A login start sets them only when the
// platform OIDC issuer asked for a fresh sign-in (reauth=1, handleWorkOSStart):
// forcing a fresh provider auth on every ordinary sign-in would be hostile.
func (s *Server) workOSAuthorizeURLFor(redirectURI, challenge, state, nonce string, forceReauth bool, screenHint string) string {
	u, err := url.Parse(s.workOSAuthorizeURL)
	if err != nil {
		// The URL comes from configuration validated at startup; fall back to the
		// raw value rather than failing the sign-in on an unreachable branch.
		return s.workOSAuthorizeURL
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", s.workOSClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("provider", "authkit")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("nonce", nonce)
	if forceReauth {
		q.Set("prompt", "login")
		q.Set("max_age", "0")
	}
	if screenHint != "" {
		q.Set(screenHintParam, screenHint)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// errWorkOSRejected marks a token exchange the provider refused (a bad, expired,
// or already-redeemed code): a CLIENT-caused state, answered 4xx. A refusal of
// this server's own client credentials is errWorkOSMisconfigured instead
// (workoserr.go, answered 503); any other exchange failure is a
// provider/transport fault and answered 502.
var errWorkOSRejected = errors.New("cloudserver/api: workos rejected the authorization code")

// exchangeWorkOSCode redeems the authorization code server-side. The client
// secret (WORKOS_API_KEY) never leaves this process.
//
// It returns the access token AND what the user object said about the person:
// the authenticate response is the ONE place WorkOS hands us the user's email,
// its `email_verified` flag and name (the AuthKit access token carries no email
// claim), so this is the only moment the server can learn them. The profile is
// display-only; the providerEmail is what the platform OIDC issuer signs
// (A4). The account is still resolved from the VERIFIED token's (provider,
// subject), never from anything in this `user` object.
func (s *Server) exchangeWorkOSCode(ctx context.Context, code, verifier string) (string, workOSUser, error) {
	status, body, err := s.postWorkOSToken(ctx, code, verifier)
	if err != nil {
		return "", workOSUser{}, fmt.Errorf("cloudserver/api.exchangeWorkOSCode: %w", err)
	}
	// Every non-200 is classified by workOSClassifyRules (T-964): 429 is
	// WorkOS's `slow_down` signal and stays a retryable provider fault (§10);
	// invalid_client / unauthorized_client / 401 are THIS server's
	// misconfiguration (a key from another WorkOS environment answered 400
	// invalid_client live); every other 4xx is the code's own fault.
	if status != http.StatusOK {
		wc, desc := parseWorkOSError(body)
		return "", workOSUser{}, &workOSTokenError{
			Outcome: classifyWorkOSStatus(status, wc), Status: status, Code: wc, Description: desc,
		}
	}
	var out struct {
		AccessToken string `json:"access_token"`
		// The user object AuthKit returns alongside the token. Absent on some
		// grant shapes and on any provider that does not send it — an omitted or
		// empty user simply yields an empty profile, never an error.
		User struct {
			Email string `json:"email"`
			// WorkOS's own verification of Email (the User object's
			// `email_verified`). A pointer: absent is NOT verified (A4).
			EmailVerified *bool  `json:"email_verified"`
			FirstName     string `json:"first_name"`
			LastName      string `json:"last_name"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", workOSUser{}, fmt.Errorf("cloudserver/api.exchangeWorkOSCode: decode: %w", err)
	}
	if out.AccessToken == "" {
		return "", workOSUser{}, fmt.Errorf("cloudserver/api.exchangeWorkOSCode: response carried no access_token")
	}
	return out.AccessToken, workOSUser{
		profile: newAccountProfile(out.User.Email, out.User.FirstName, out.User.LastName),
		email:   newProviderEmail(out.User.Email, out.User.EmailVerified),
	}, nil
}

// workOSUser is what one code exchange's user object said: the display
// profile (accountprofile.go) and the provider's statement about the address
// (verifiedemail.go). Both are consequences of a completed sign-in, never
// inputs to account resolution.
type workOSUser struct {
	profile accountProfile
	email   providerEmail
}

// callbackRecoverable are the callback refusals a person fixes by signing in
// again: the transaction this browser started is gone (expired, never set,
// already used, or another tab's), or they cancelled at the provider. A
// sign-up whose verification took longer than the transaction hit these with
// the account already created (L-142).
var callbackRecoverable = map[string]bool{
	"transaction_missing": true,
	"state_mismatch":      true,
	"transaction_invalid": true,
	"code_rejected":       true,
	"provider_error":      true,
}

// callbackRefuse answers a refused callback. A browser navigation (Accept
// names text/html) refused for a recoverable reason is sent to the console
// sign-in page, which explains it and offers the sign-in again, never a raw
// JSON error page; everything else, and every non-browser caller, gets the
// structured error as before. Nothing changes about WHAT is refused: the
// redirect starts no sign-in and carries only the fixed code.
func callbackRefuse(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	if callbackRecoverable[code] && acceptsHTML(r) {
		http.Redirect(w, r, defaultPortalReturnTo+"?"+portalSignInErrorParam+"="+code, http.StatusSeeOther)
		return
	}
	writeErr(w, status, code, msg)
}

// acceptsHTML reports whether the request is a browser navigation: its
// Accept header names text/html.
func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// handleWorkOSCallback completes the round-trip. Order matters and every step is
// fail-closed:
//
//  1. the transaction cookie must be present;
//  2. the `state` query parameter must equal the cookie's secret in constant
//     time — a forged state with a valid cookie, or a valid state with no
//     cookie, both stop here, and they stop here BEFORE anything is spent;
//  3. only now is the transaction cookie cleared: state matched, so this
//     request really is the continuation of this browser's own sign-in;
//  4. a provider `error=` is handled — consuming the matching transaction so
//     the cancelled attempt cannot be replayed;
//  5. the transaction row is consumed ATOMICALLY (replay or expiry ⇒ 4xx);
//  6. the recorded redirect_uri must still be this deployment's exact callback;
//  7. the code is exchanged server-side and the returned token verified by the
//     SAME identity.Verifier the device API uses.
//
// Steps 2 and 3 are in that order deliberately (F5). Clearing the cookie before
// the state check would hand any cross-site page a free denial-of-sign-in: a
// hidden <img src=".../callback?error=x"> rides the Lax cookie on a top-level
// navigation and would have killed a sign-in in progress. Nothing is cleared
// and no row is touched until the state proves the caller already knows this
// browser's own transaction secret.
//
// Client-caused states (mismatch, replay, expiry, a refused code) are 4xx with a
// structured body — never a 500.
func (s *Server) handleWorkOSCallback(w http.ResponseWriter, r *http.Request) {
	if !s.portalWorkOSReady(w) {
		return
	}
	ctx := r.Context()

	c, err := r.Cookie(s.portalTxnCookieName())
	if err != nil || c.Value == "" {
		callbackRefuse(w, r, http.StatusBadRequest, "transaction_missing",
			"this sign-in did not start on this browser (no transaction cookie)")
		return
	}

	q := r.URL.Query()
	state := q.Get("state")
	if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(c.Value)) != 1 {
		s.audit(ctx, "", "portal_workos_state_mismatch")
		callbackRefuse(w, r, http.StatusBadRequest, "state_mismatch",
			"the sign-in state did not match this browser's transaction")
		return
	}
	// The state matched this browser's own transaction secret, so from here on
	// the transaction cookie is spent, whatever happens.
	s.clearTxnCookie(w)

	if provErr := q.Get("error"); provErr != "" {
		// A genuine cancellation. Burn the transaction too, so the abandoned
		// state cannot later be presented with a code: ErrNotFound just means it
		// had already expired or been consumed, which is equally final.
		if _, err := s.store.ConsumeAuthTransaction(ctx, secretHash(state), s.now()); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			s.log.Warn("cloudserver/api: consume auth transaction after provider error", "err", err)
		}
		s.audit(ctx, "", "portal_workos_provider_error")
		callbackRefuse(w, r, http.StatusBadRequest, "provider_error", "the identity provider refused the sign-in")
		return
	}
	code := q.Get("code")
	if code == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "missing authorization code")
		return
	}

	txn, err := s.store.ConsumeAuthTransaction(ctx, secretHash(state), s.now())
	if errors.Is(err, store.ErrNotFound) {
		s.audit(ctx, "", "portal_workos_transaction_replay")
		callbackRefuse(w, r, http.StatusBadRequest, "transaction_invalid",
			"this sign-in link has expired or was already used")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: consume auth transaction", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not complete sign-in")
		return
	}
	if txn.RedirectURI != s.workOSRedirectURI() {
		s.audit(ctx, txn.AccountID, "portal_workos_redirect_mismatch")
		writeErr(w, http.StatusBadRequest, "redirect_mismatch",
			"this sign-in was started for a different origin")
		return
	}
	returnTo, ok := safeReturnPath(txn.ReturnTo)
	if !ok {
		returnTo = defaultPortalReturnTo
	}

	accessToken, user, err := s.exchangeWorkOSCode(ctx, code, txn.PKCEVerifier)
	var tokErr *workOSTokenError
	_ = errors.As(err, &tokErr)
	if errors.Is(err, errWorkOSMisconfigured) {
		// The provider refused THIS server's client credentials. No user action
		// can fix that, so it is an ERROR naming WorkOS's own error code and
		// description (never the key, never the code) and a 5xx that says so.
		s.log.Error("cloudserver/api: WorkOS refused this server's client credentials; browser sign-in is misconfigured",
			"workos_status", tokErr.Status, "workos_error", tokErr.Code,
			"workos_error_description", tokErr.Description, "workos_client_id", s.workOSClientID)
		s.audit(ctx, txn.AccountID, "portal_workos_misconfigured")
		writeErr(w, http.StatusServiceUnavailable, "signin_misconfigured",
			"sign-in is misconfigured on our side; this is not a problem with your account. Please try again later.")
		return
	}
	if errors.Is(err, errWorkOSRejected) {
		s.log.Warn("cloudserver/api: WorkOS rejected the authorization code",
			"workos_status", tokErr.Status, "workos_error", tokErr.Code,
			"workos_error_description", tokErr.Description)
		s.audit(ctx, txn.AccountID, "portal_workos_code_rejected")
		callbackRefuse(w, r, http.StatusBadRequest, "code_rejected",
			"the authorization code was rejected (it may have expired or already been used)")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: workos code exchange", "err", err)
		writeErr(w, http.StatusBadGateway, "provider_unavailable", "could not reach the identity provider")
		return
	}
	id, err := s.verifier.Verify(ctx, accessToken)
	if err != nil {
		s.audit(ctx, txn.AccountID, "portal_workos_token_invalid")
		writeErr(w, http.StatusUnauthorized, "unauthorized", "the identity provider's token did not verify")
		return
	}

	if txn.Purpose == store.AuthPurposeStepUp {
		s.completeStepUp(w, r, txn, id.Provider, id.Subject, returnTo, user)
		return
	}
	s.completeWorkOSLogin(w, r, id.Provider, id.Subject, returnTo, user, txn.ForceReauth)
}

// completeWorkOSLogin mints a FRESH browser session (a new cookie value every
// time — no fixation) and rotates its CSRF secret so the token that existed
// during the mint is not the one the SPA will later hold.
//
// It also records the display identity the exchange returned, AFTER the account
// is resolved and the session minted: the profile is a consequence of a
// completed sign-in, never an input to one, and a failed upsert never fails it
// (see rememberProfile). The provider's address and its `email_verified` flag
// are refreshed in the same place, but a failed write DOES fail the sign-in
// (before the cookie is set): the issuer signs that address, so a stale one
// must not survive a sign-in that did not record the latest statement (A4).
//
// forced is the transaction's ForceReauth: the leg sent AuthKit prompt=login
// and max_age=0, so the callback instant is a fresh authentication and the
// session records it (store.WithFreshAuthentication, the platform OIDC
// issuer's auth_time). An ordinary leg may have been answered from AuthKit's
// own session, so its session records no authentication time. The same
// contract caveat as completeStepUp applies: "fresh" holds to the extent
// AuthKit honours those parameters.
func (s *Server) completeWorkOSLogin(w http.ResponseWriter, r *http.Request, provider, subject, returnTo string, user workOSUser, forced bool) {
	ctx := r.Context()
	opts := []store.PortalLoginOption{store.WithIdleTTL(s.portalSessionIdleTTL)}
	if forced {
		opts = append(opts, store.WithFreshAuthentication())
	}
	sess, err := s.store.PortalLogin(ctx, provider, subject, s.portalSessionTTL, s.now(), opts...)
	if errors.Is(err, store.ErrAccountSuspended) {
		// The identity still verifies at the provider, but this account's access
		// has been revoked here (D18: a user.deleted lifecycle event suspends it).
		// Minting a fresh session would silently undo that revocation.
		s.audit(ctx, "", "portal_login_account_suspended")
		writeErr(w, http.StatusForbidden, "account_suspended",
			"this account is suspended and cannot sign in")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: workos portal login", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	if _, err := s.store.RotateBrowserCSRF(ctx, sess.AccountID, sess.RawSession, s.now()); err != nil {
		s.log.Error("cloudserver/api: rotate csrf after workos login", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	if err := s.rememberProviderEmail(ctx, sess.AccountID, user.email); err != nil {
		s.log.Error("cloudserver/api: record provider email after workos login", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	s.rememberProfile(ctx, sess.AccountID, user.profile)
	s.audit(ctx, sess.AccountID, "portal_login_ok")
	s.setSessionCookie(w, sess.RawSession, sess.ExpiresAt)
	s.ensurePersonalAfterSignIn(sess.AccountID)
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// completeStepUp records the re-authentication as a one-use authorization, but
// ONLY when the re-authenticated identity resolves to the very account the
// transaction was bound to. Signing in as somebody else mid-flow is a 403, not a
// step-up for the wrong account.
//
// On auth_time (the freshness claim this row makes, F2): it is the CALLBACK
// INSTANT of an authorization leg that was started with `prompt=login` and
// `max_age=0` (see workOSAuthorizeURLFor), i.e. of a provider authentication we
// asked the provider to perform afresh rather than satisfy from an existing SSO
// session. It is therefore a genuine "the human proved themselves just now"
// timestamp, not merely "a redirect completed just now" — but only to the
// extent the provider honours those parameters. That behaviour is contractual
// (both are standard OIDC authorization parameters WorkOS documents), and
// confirming it against the live provider is an explicit item in the operator's
// attended verification window, not something this code can assert for itself:
// the token this leg returns carries no auth_time claim to cross-check.
func (s *Server) completeStepUp(w http.ResponseWriter, r *http.Request, txn store.AuthTransaction, provider, subject, returnTo string, user workOSUser) {
	ctx := r.Context()
	account, err := s.store.AccountForIdentity(ctx, provider, subject)
	if err != nil || account != txn.AccountID {
		s.audit(ctx, txn.AccountID, "portal_step_up_account_mismatch")
		writeErr(w, http.StatusForbidden, "reauth_mismatch",
			"the credential you re-authenticated with does not match the signed-in account")
		return
	}
	// The re-authenticated identity has just been proven to resolve to THIS
	// account (the mismatch branch above is the only other outcome), so the
	// profile this exchange returned belongs to it. Refreshing it here is
	// trivially safe and keeps a long-lived session's chip current.
	s.rememberProfile(ctx, txn.AccountID, user.profile)
	// A step-up is a fresh provider sign-in too, so the provider's address
	// statement is refreshed, and a failed write fails it (A4).
	if err := s.rememberProviderEmail(ctx, txn.AccountID, user.email); err != nil {
		s.log.Error("cloudserver/api: record provider email after step-up", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not complete re-authentication")
		return
	}
	authz, err := s.store.CreateStepUpAuthorization(ctx, txn.AccountID, txn.SessionID, txn.Action, s.now())
	if err != nil {
		s.log.Error("cloudserver/api: create step-up authorization", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not complete re-authentication")
		return
	}
	s.audit(ctx, txn.AccountID, "portal_step_up_granted_"+txn.Action)
	http.Redirect(w, r, appendQueryParam(returnTo, stepUpQueryParam, authz.ID), http.StatusSeeOther)
}

// appendQueryParam adds one query parameter to an already-validated same-origin
// path. (The parameter is not named `path`: this file imports the path package.)
func appendQueryParam(rawPath, key, value string) string {
	u, err := url.Parse(rawPath)
	if err != nil {
		return rawPath
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// handlePortalSession is the SPA's reload bootstrap (E8). The store keeps only
// csrf_hash, so this endpoint cannot return the EXISTING CSRF token — it
// ROTATES the secret and returns the new raw token exactly once. A page reload
// therefore always leaves the tab holding a live token, and the previous one
// stops working immediately (last rotation wins; the fixation test pins it).
//
// It is a GET by design: the portalAuth middleware enforces the double-submit
// CSRF header on mutations only, which is precisely why this bootstrap can be
// reached by a freshly-loaded tab that holds no token yet.
// It is also the one GET that HANDS OUT a credential (the rotated CSRF token),
// which makes it the one GET a sibling origin would want to reach: same-site
// but cross-origin (say a compromised sub-domain of the portal host) is close
// enough for a Lax/Strict cookie to ride along on a top-level navigation. So it
// additionally enforces Sec-Fetch-Site when the browser sends it (F11) — see
// enforceSameOriginFetch for why an ABSENT header stays allowed.
func (s *Server) handlePortalSession(w http.ResponseWriter, r *http.Request) {
	if !enforceSameOriginFetch(w, r) {
		return
	}
	p, _ := portalPrincipalFrom(r.Context())
	rot, err := s.store.RotateBrowserCSRF(r.Context(), p.AccountID, p.Raw, s.now())
	if errors.Is(err, store.ErrNotFound) {
		s.clearSessionCookie(w)
		writeErr(w, http.StatusUnauthorized, "unauthorized", "session expired or invalid")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: rotate csrf", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not refresh the session")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	body := map[string]any{
		"account_id": p.AccountID,
		"csrf_token": rot.RawCSRFToken,
		"expires_at": rot.ExpiresAt.UTC().Format(time.RFC3339),
		"auth_mode":  s.portalAuthMode(),
		// The retirement switch (retired.go): the console hides the legacy
		// personal-plane links once it reads "retired".
		"personal_plane": s.personalPlane,
	}
	// The signed-in user's own display identity, so the SPA can render a name
	// instead of a UUID. The key is OMITTED when nothing is known — see
	// profileBody. This discloses the account's own email to the account's own
	// authenticated browser and nowhere else; the CSRF rotation above is
	// untouched by it.
	if prof := profileBody(s.lookupProfile(r.Context(), p.AccountID)); prof != nil {
		body["profile"] = prof
	}
	// C2: whether this session must still use its passkey (the SPA then
	// shows only the second-factor page).
	if st, ok := secondFactorFrom(r.Context()); ok {
		body["second_factor"] = secondFactorView(st)
	}
	writeJSON(w, http.StatusOK, body)
}

// portalAuthMode names the identity path this deployment signs browsers in
// with. It branches on the verifier's own provider label (the same capability
// portalDevAuth reads), never on a separate flag, so the answer cannot drift
// from what the sign-in endpoints actually do.
func (s *Server) portalAuthMode() string {
	if s.portalDevAuth() {
		return "dev"
	}
	return "workos"
}

// workOSBrowserReady reports whether the WorkOS browser sign-in leg would
// actually run — the exact conjunction portalWorkOSReady enforces per request,
// without writing a 501. It exists so the signed-out bootstrap below can tell
// the SPA the truth ("this button will work") instead of a flag that might be
// set while the credentials behind it are missing.
func (s *Server) workOSBrowserReady() bool {
	return s.portalWorkOSEnabled && !s.portalDevAuth() &&
		s.workOSClientID != "" && s.workOSAPIKey != ""
}

// handlePortalAuthConfig is the SIGNED-OUT bootstrap (F12): the minimum the SPA
// needs to render the right sign-in surface before it holds any session.
//
// It is unauthenticated by necessity — a browser with no cookie is precisely
// the caller — so it returns nothing account-scoped and nothing secret: only
// which identity path this deployment runs and whether the browser sign-in leg
// is live. Both facts are already observable by hitting the sign-in routes and
// reading the 501s; publishing them plainly saves the SPA from probing.
func (s *Server) handlePortalAuthConfig(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_mode":              s.portalAuthMode(),
		"workos_browser_enabled": s.workOSBrowserReady(),
		// Deployment-wide, not account-scoped (retired.go).
		"personal_plane": s.personalPlane,
	})
}

// enforceSameOriginFetch is the sibling-origin fence (F11) for the one portal
// GET that hands back a credential. Sec-Fetch-Site is set by the BROWSER, not
// by the page, so it cannot be forged by script on another origin:
//
//   - "same-origin" — the portal SPA calling its own BFF. Allowed.
//   - "none"        — a user-initiated navigation (typing the URL, a bookmark).
//     Allowed: there is no initiator origin to distrust.
//   - "same-site" / "cross-site" — SOMETHING ELSE initiated this, which for a
//     token-minting endpoint is never legitimate. Refused. "same-site" is
//     included deliberately: a sibling sub-domain is a different origin but
//     shares the cookie, which is exactly the gap a Strict cookie does not
//     close.
//
// An ABSENT header is allowed. Older browsers and every non-browser client
// (curl, the CLI, an integration test) send none, and refusing them would break
// real callers to defend against an attacker who, by construction, cannot
// suppress the header from inside a browser.
//
// It returns false when it has already written the refusal.
func enforceSameOriginFetch(w http.ResponseWriter, r *http.Request) bool {
	switch site := r.Header.Get("Sec-Fetch-Site"); site {
	case "", "same-origin", "none":
		return true
	default:
		writeErr(w, http.StatusForbidden, "cross_origin_refused",
			"this endpoint may only be called from the portal itself")
		return false
	}
}
