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
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The WorkOS browser sign-in leg (plan §3 W1). It is a BFF flow: the browser
// never sees a WorkOS token, a client secret, or the PKCE verifier — it only
// carries an opaque transaction cookie across the AuthKit round-trip and comes
// back holding the same __Host-sbci session cookie the dev-auth login mints.
//
// Two cookies, deliberately different:
//
//   - the SESSION cookie is SameSite=Strict — it must never ride a cross-site
//     request;
//   - the TRANSACTION cookie is SameSite=Lax, because the AuthKit callback IS a
//     cross-site top-level navigation and a Strict cookie would simply not be
//     sent (adversarial-review finding 5). It is pre-auth, single-use,
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
	// portalTxnCookieMaxAge bounds the transaction cookie to the same 10 minutes
	// the auth_transactions row lives.
	portalTxnCookieMaxAge = 600

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
	http.SetCookie(w, &http.Cookie{
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
	http.SetCookie(w, &http.Cookie{
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
// same-origin, query-free PATH inside the portal SPA. Everything else — an
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
	// 1) Raw-string traps. A backslash is a path separator to some browsers and
	// URL parsers; a control character can split a header downstream.
	if strings.Contains(raw, "\\") {
		return "", false
	}
	lower := strings.ToLower(raw)
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
	// query, no fragment. Accepting a query would mean reasoning about how it
	// merges with the step-up parameter appended later; refusing it is simpler
	// and costs nothing (no portal route needs one on a return_to).
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "?#") {
		return "", false
	}
	u, err := url.Parse(raw)
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
	if !strings.HasPrefix(cleaned, portalReturnPrefix) {
		return "", false
	}
	return cleaned, true
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
	switch purpose := q.Get("purpose"); purpose {
	case "", store.AuthPurposeLogin:
	case store.AuthPurposeStepUp:
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

	if _, err := s.store.CreateAuthTransaction(r.Context(), in); err != nil {
		s.log.Error("cloudserver/api: create auth transaction", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start sign-in")
		return
	}
	s.audit(r.Context(), in.AccountID, "portal_workos_start_"+in.Purpose)

	s.setTxnCookie(w, rawState)
	authorizeURL := s.workOSAuthorizeURLFor(in.RedirectURI, pkceChallenge(verifier), rawState, rawNonce,
		in.Purpose == store.AuthPurposeStepUp)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// workOSAuthorizeURLFor builds the AuthKit authorization URL. It mirrors the
// node-side builder in internal/cloudclient (same parameter set) but is
// implemented here because the server must not import the client package (the
// cloud egress pin).
//
// forceReauth adds the two OIDC freshness parameters WorkOS's authorize
// endpoint accepts (both SDK-documented): `prompt=login` and `max_age=0`. They
// are set for a STEP-UP only, and they are the whole point of a step-up —
// without them a live SSO session at the provider satisfies the
// re-authentication silently, and "re-authenticate to delete your account"
// degrades into a redirect the user never sees. A login start is deliberately
// left unchanged: forcing a fresh provider auth on every sign-in would be
// hostile, and there is nothing to step up from.
func (s *Server) workOSAuthorizeURLFor(redirectURI, challenge, state, nonce string, forceReauth bool) string {
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
	u.RawQuery = q.Encode()
	return u.String()
}

// errWorkOSRejected marks a token exchange the provider refused (a bad, expired,
// or already-redeemed code) — a CLIENT-caused state, answered 4xx. Any other
// exchange failure is a provider/transport fault and answered 502.
var errWorkOSRejected = errors.New("cloudserver/api: workos rejected the authorization code")

// exchangeWorkOSCode redeems the authorization code server-side. The client
// secret (WORKOS_API_KEY) never leaves this process.
//
// It returns the access token AND the display identity: the authenticate
// response is the ONE place WorkOS hands us the user's email and name (the
// AuthKit access token carries no email claim), so this is the only moment the
// portal can learn who the person is. The profile is display-only — the account
// is still resolved from the VERIFIED token's (provider, subject), never from
// anything in this `user` object.
func (s *Server) exchangeWorkOSCode(ctx context.Context, code, verifier string) (string, accountProfile, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {s.workOSClientID},
		"client_secret": {s.workOSAPIKey},
		"code":          {code},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.workOSTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", accountProfile{}, fmt.Errorf("cloudserver/api.exchangeWorkOSCode: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.workOSHTTP.Do(req)
	if err != nil {
		return "", accountProfile{}, fmt.Errorf("cloudserver/api.exchangeWorkOSCode: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// 429 is WorkOS's `slow_down` signal — a rate limit, not a rejected code
	// (§10). It is deliberately EXCLUDED from the "4xx ⇒ the code itself was
	// bad" branch below and falls through to the generic non-200 branch
	// instead, which the caller answers as a retryable 502
	// provider_unavailable: conflating the two would tell the user to restart
	// sign-in with a fresh authorization code when the right action is simply
	// "try again shortly" — the code itself was never the problem.
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return "", accountProfile{}, fmt.Errorf("%w: status %d", errWorkOSRejected, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", accountProfile{}, fmt.Errorf("cloudserver/api.exchangeWorkOSCode: token endpoint returned %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		// The user object AuthKit returns alongside the token. Absent on some
		// grant shapes and on any provider that does not send it — an omitted or
		// empty user simply yields an empty profile, never an error.
		User struct {
			Email     string `json:"email"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", accountProfile{}, fmt.Errorf("cloudserver/api.exchangeWorkOSCode: decode: %w", err)
	}
	if out.AccessToken == "" {
		return "", accountProfile{}, fmt.Errorf("cloudserver/api.exchangeWorkOSCode: response carried no access_token")
	}
	return out.AccessToken, newAccountProfile(out.User.Email, out.User.FirstName, out.User.LastName), nil
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
		writeErr(w, http.StatusBadRequest, "transaction_missing",
			"this sign-in did not start on this browser (no transaction cookie)")
		return
	}

	q := r.URL.Query()
	state := q.Get("state")
	if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(c.Value)) != 1 {
		s.audit(ctx, "", "portal_workos_state_mismatch")
		writeErr(w, http.StatusBadRequest, "state_mismatch",
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
		writeErr(w, http.StatusBadRequest, "provider_error", "the identity provider refused the sign-in")
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
		writeErr(w, http.StatusBadRequest, "transaction_invalid",
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

	accessToken, profile, err := s.exchangeWorkOSCode(ctx, code, txn.PKCEVerifier)
	if errors.Is(err, errWorkOSRejected) {
		s.audit(ctx, txn.AccountID, "portal_workos_code_rejected")
		writeErr(w, http.StatusBadRequest, "code_rejected",
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
		s.completeStepUp(w, r, txn, id.Provider, id.Subject, returnTo, profile)
		return
	}
	s.completeWorkOSLogin(w, r, id.Provider, id.Subject, returnTo, profile)
}

// completeWorkOSLogin mints a FRESH browser session (a new cookie value every
// time — no fixation) and rotates its CSRF secret so the token that existed
// during the mint is not the one the SPA will later hold.
//
// It also records the display identity the exchange returned, AFTER the account
// is resolved and the session minted: the profile is a consequence of a
// completed sign-in, never an input to one, and a failed upsert never fails it
// (see rememberProfile).
func (s *Server) completeWorkOSLogin(w http.ResponseWriter, r *http.Request, provider, subject, returnTo string, profile accountProfile) {
	ctx := r.Context()
	sess, err := s.store.PortalLogin(ctx, provider, subject, s.portalSessionTTL, s.now(), store.WithIdleTTL(s.portalSessionIdleTTL))
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
	s.rememberProfile(ctx, sess.AccountID, profile)
	s.audit(ctx, sess.AccountID, "portal_login_ok")
	s.setSessionCookie(w, sess.RawSession, sess.ExpiresAt)
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
func (s *Server) completeStepUp(w http.ResponseWriter, r *http.Request, txn store.AuthTransaction, provider, subject, returnTo string, profile accountProfile) {
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
	s.rememberProfile(ctx, txn.AccountID, profile)
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
	}
	// The signed-in user's own display identity, so the SPA can render a name
	// instead of a UUID. The key is OMITTED when nothing is known — see
	// profileBody. This discloses the account's own email to the account's own
	// authenticated browser and nowhere else; the CSRF rotation above is
	// untouched by it.
	if prof := profileBody(s.lookupProfile(r.Context(), p.AccountID)); prof != nil {
		body["profile"] = prof
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
