package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The transaction cookie name in dev mode (PortalSecureCookie=false). Must match
// internal/cloudserver/api/portalauth.go's portalTxnCookieDev.
const devTxnCookieName = "sbci_txn"

// --- fakes -----------------------------------------------------------------

// fakeWorkOSVerifier stands in for identity.WorkOSVerifier: same PROVIDER label
// (so the server is in "WorkOS mode", not dev-auth), but it validates a token of
// the shape "wtok:<subject>" instead of a JWT. The JWT/JWKS mechanics have their
// own suite in internal/cloudserver/identity; what matters here is that the
// browser leg uses the SAME verifier seam the device API uses.
type fakeWorkOSVerifier struct{}

func (fakeWorkOSVerifier) Provider() string { return "workos" }

func (fakeWorkOSVerifier) Verify(_ context.Context, raw string) (identity.Identity, error) {
	const prefix = "wtok:"
	if !strings.HasPrefix(raw, prefix) {
		return identity.Identity{}, identity.ErrInvalidToken
	}
	sub := strings.TrimPrefix(raw, prefix)
	if sub == "" {
		return identity.Identity{}, identity.ErrInvalidToken
	}
	return identity.Identity{Provider: "workos", Subject: sub}, nil
}

// fakeWorkOS is a stand-in AuthKit token endpoint. Codes are SINGLE-USE (WorkOS
// itself refuses a redeemed code), so the code-replay test exercises the real
// provider behaviour rather than a server-side assumption.
type fakeWorkOS struct {
	srv *httptest.Server

	mu       sync.Mutex
	redeemed map[string]bool
	// lastVerifier records the code_verifier the server presented, so a test can
	// assert PKCE actually round-tripped.
	lastVerifier string
	// requireSecret asserts the client_secret the server sends.
	requireSecret string
}

func newFakeWorkOS(t *testing.T, secret string) *fakeWorkOS {
	t.Helper()
	f := &fakeWorkOS{redeemed: map[string]bool{}, requireSecret: secret}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		code := r.PostForm.Get("code")
		f.mu.Lock()
		already := f.redeemed[code]
		f.redeemed[code] = true
		f.lastVerifier = r.PostForm.Get("code_verifier")
		f.mu.Unlock()

		switch {
		case r.PostForm.Get("grant_type") != "authorization_code",
			r.PostForm.Get("client_secret") != f.requireSecret,
			r.PostForm.Get("code_verifier") == "",
			!strings.HasPrefix(code, "code-"),
			already:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		// The code encodes the subject: "code-<subject>[@<nonce>]". The optional
		// @nonce suffix makes a code unique per exchange (WorkOS codes are
		// single-use) without changing which user it authenticates.
		subject := strings.TrimPrefix(code, "code-")
		if i := strings.IndexByte(subject, '@'); i >= 0 {
			subject = subject[:i]
		}
		// The authenticate response carries the USER object alongside the token —
		// the one place WorkOS hands the server an email and a name (the access
		// token itself has no email claim). Shaped exactly like the provider's:
		// snake_case first_name/last_name, plus fields the server ignores.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"wtok:` + subject + `",` +
			`"user":{"id":"user_` + subject + `","email":"` + subject + `@example.test",` +
			`"first_name":"Ada","last_name":"Lovelace","email_verified":true}}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

var codeCounter atomic.Int64

// newCode mints a FRESH single-use authorization code for subject. Tests that
// deliberately replay a code reuse the returned string.
func newCode(subject string) string {
	return fmt.Sprintf("code-%s@%d", subject, codeCounter.Add(1))
}

func (f *fakeWorkOS) verifier() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastVerifier
}

// --- harness ---------------------------------------------------------------

type workosHarness struct {
	*harness
	workos *fakeWorkOS
}

const testWorkOSSecret = "sk_test_secret"

// newWorkOSHarness builds a server in WorkOS mode with the browser sign-in leg
// ACTIVATED, pointed at a fake AuthKit. enabled=false leaves the activation gate
// off so the dark-by-default 501s can be asserted.
func newWorkOSHarness(t *testing.T, enabled bool) *workosHarness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	s.SetDeletionJournal(mustJournal(t))
	apiStore.SetDeletionJournal(mustJournal(t))
	fake := newFakeWorkOS(t, testWorkOSSecret)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()
	handler := api.New(api.Options{
		Store:               apiStore,
		Queue:               jobs.NewPGQueue(apiStore),
		Verifier:            fakeWorkOSVerifier{},
		ExternalBaseURL:     base,
		RateLimit:           &api.RateLimitConfig{},
		Attestor:            admAttestor{verified: true},
		Credentials:         jobs.StaticCredentials{Key: "test-key"},
		PortalWorkOSEnabled: enabled,
		WorkOSClientID:      "client_test",
		WorkOSAPIKey:        testWorkOSSecret,
		WorkOSAuthorizeURL:  fake.srv.URL + "/authorize",
		WorkOSTokenURL:      fake.srv.URL + "/token",
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &workosHarness{harness: &harness{srv: srv, store: s}, workos: fake}
}

// browser is a cookie-jar client that never follows redirects, so every 302/303
// (and the cookies it carries) can be inspected.
func newBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// startFlow performs GET /portal/auth/workos/start and returns the raw state
// secret it minted (read out of the transaction cookie) plus the response.
func (h *workosHarness) startFlow(t *testing.T, hc *http.Client, query string) (string, *http.Response) {
	t.Helper()
	resp, err := hc.Get(h.srv.URL + "/portal/auth/workos/start" + query)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	c := cookieNamed(resp, devTxnCookieName)
	if c == nil {
		return "", resp
	}
	return c.Value, resp
}

// signIn drives a complete WorkOS sign-in for subject and returns the browser
// client (holding the session cookie) plus its freshly-bootstrapped CSRF token.
func (h *workosHarness) signIn(t *testing.T, subject string) (*http.Client, string, string) {
	t.Helper()
	hc := newBrowser(t)
	state, resp := h.startFlow(t, hc, "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	if state == "" {
		t.Fatal("start set no transaction cookie")
	}
	cb := h.callback(t, hc, newCode(subject), state)
	if cb.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status=%d body=%s", cb.StatusCode, readAll(cb))
	}
	if cookieNamed(cb, devCookieName) == nil {
		t.Fatalf("callback set no session cookie; cookies=%v", cb.Cookies())
	}
	account, csrf := h.bootstrap(t, hc)
	return hc, csrf, account
}

func (h *workosHarness) callback(t *testing.T, hc *http.Client, code, state string) *http.Response {
	t.Helper()
	u := h.srv.URL + "/portal/auth/workos/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	resp, err := hc.Get(u)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return resp
}

// bootstrap calls the SPA reload endpoint and returns {account_id, csrf_token}.
func (h *workosHarness) bootstrap(t *testing.T, hc *http.Client) (string, string) {
	t.Helper()
	resp, err := hc.Get(h.srv.URL + "/portal/api/session")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var body struct {
		AccountID string `json:"account_id"`
		CSRF      string `json:"csrf_token"`
		ExpiresAt string `json:"expires_at"`
		AuthMode  string `json:"auth_mode"`
	}
	decode(t, resp, &body)
	if body.AccountID == "" || body.CSRF == "" || body.ExpiresAt == "" {
		t.Fatalf("session bootstrap incomplete: %+v", body)
	}
	if body.AuthMode != "workos" {
		t.Fatalf("auth_mode=%q, want workos", body.AuthMode)
	}
	return body.AccountID, body.CSRF
}

func mutate(t *testing.T, hc *http.Client, method, urlStr, csrf, body string) *http.Response {
	t.Helper()
	var r *http.Request
	if body == "" {
		r, _ = http.NewRequest(method, urlStr, http.NoBody)
	} else {
		r, _ = http.NewRequest(method, urlStr, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		r.Header.Set(csrfHeader, csrf)
	}
	resp, err := hc.Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", method, urlStr, err)
	}
	return resp
}

// --- activation gate -------------------------------------------------------

func TestWorkOSLegDarkByDefault(t *testing.T) {
	h := newWorkOSHarness(t, false)
	hc := newBrowser(t)
	for _, path := range []string{
		"/portal/auth/workos/start",
		"/portal/auth/workos/callback?code=code-x&state=y",
	} {
		resp, err := hc.Get(h.srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s status=%d, want 501 (dark by default)", path, resp.StatusCode)
		}
		var eb struct {
			Code string `json:"code"`
		}
		decode(t, resp, &eb)
		if eb.Code != "provider_not_configured" {
			t.Fatalf("%s code=%q, want provider_not_configured", path, eb.Code)
		}
	}
}

func TestWorkOSLegInactiveUnderDevAuth(t *testing.T) {
	// Dev-auth deployment with the gate flipped on: the dev stub still wins and
	// the WorkOS leg reports honestly rather than half-working.
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	s.SetDeletionJournal(mustJournal(t))
	apiStore.SetDeletionJournal(mustJournal(t))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()
	handler := api.New(api.Options{
		Store:               apiStore,
		Queue:               jobs.NewPGQueue(apiStore),
		Verifier:            identity.NewDevAuth(),
		ExternalBaseURL:     base,
		RateLimit:           &api.RateLimitConfig{},
		Attestor:            admAttestor{verified: true},
		Credentials:         jobs.StaticCredentials{Key: "test-key"},
		PortalWorkOSEnabled: true,
		WorkOSClientID:      "client_test",
		WorkOSAPIKey:        testWorkOSSecret,
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)

	resp, err := newBrowser(t).Get(srv.URL + "/portal/auth/workos/start")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("dev-auth start status=%d, want 501", resp.StatusCode)
	}
	var eb struct {
		Code string `json:"code"`
	}
	decode(t, resp, &eb)
	if eb.Code != "dev_auth_mode" {
		t.Fatalf("code=%q, want dev_auth_mode", eb.Code)
	}
}

// --- the happy path + cookie shapes ---------------------------------------

func TestWorkOSStartRedirectsAndSetsLaxTxnCookie(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc := newBrowser(t)
	state, resp := h.startFlow(t, hc, "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d, want 302", resp.StatusCode)
	}
	c := cookieNamed(resp, devTxnCookieName)
	if c == nil {
		t.Fatal("start set no transaction cookie")
	}
	// The transaction cookie MUST be Lax (Strict would not be sent on the
	// cross-site AuthKit callback) and HttpOnly, and it must not be the session.
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("txn cookie SameSite=%v, want Lax", c.SameSite)
	}
	if !c.HttpOnly {
		t.Fatal("txn cookie is not HttpOnly")
	}
	if c.MaxAge <= 0 || c.MaxAge > 600 {
		t.Fatalf("txn cookie MaxAge=%d, want 0<max_age<=600", c.MaxAge)
	}
	if cookieNamed(resp, devCookieName) != nil {
		t.Fatal("start minted a SESSION cookie before authentication")
	}

	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	q := loc.Query()
	if q.Get("state") != state {
		t.Fatal("authorize URL state does not match the transaction cookie")
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize URL missing PKCE: %v", q)
	}
	if q.Get("response_type") != "code" || q.Get("client_id") != "client_test" {
		t.Fatalf("authorize URL malformed: %v", q)
	}
	if got, want := q.Get("redirect_uri"), h.srv.URL+"/portal/auth/workos/callback"; got != want {
		t.Fatalf("redirect_uri=%q, want %q", got, want)
	}
	if q.Get("nonce") == "" {
		t.Fatal("authorize URL carries no nonce")
	}
}

func TestWorkOSCallbackMintsSessionAndClearsTxnCookie(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc := newBrowser(t)
	state, resp := h.startFlow(t, hc, "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d", resp.StatusCode)
	}
	cb := h.callback(t, hc, newCode("wanda"), state)
	if cb.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status=%d body=%s", cb.StatusCode, readAll(cb))
	}
	if got := cb.Header.Get("Location"); got != "/portal/" {
		t.Fatalf("callback Location=%q, want /portal/", got)
	}
	sess := cookieNamed(cb, devCookieName)
	if sess == nil {
		t.Fatal("callback set no session cookie")
	}
	if !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie attributes wrong: HttpOnly=%v SameSite=%v (want true/Strict)", sess.HttpOnly, sess.SameSite)
	}
	txn := cookieNamed(cb, devTxnCookieName)
	if txn == nil || txn.MaxAge >= 0 || txn.Value != "" {
		t.Fatalf("callback did not clear the transaction cookie: %+v", txn)
	}
	// PKCE really round-tripped: the server presented a verifier.
	if h.workos.verifier() == "" {
		t.Fatal("token exchange sent no code_verifier")
	}
	// The session works.
	if r := mustGet(t, hc, h.srv.URL+"/portal/api/overview"); r.StatusCode != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", r.StatusCode, readAll(r))
	}
}

func mustGet(t *testing.T, hc *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := hc.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	return resp
}

// --- adversarial: state, cookie, replay, expiry ---------------------------

func TestWorkOSCallbackAdversarialStates(t *testing.T) {
	h := newWorkOSHarness(t, true)

	t.Run("forged state with a valid cookie", func(t *testing.T) {
		hc := newBrowser(t)
		if _, resp := h.startFlow(t, hc, ""); resp.StatusCode != http.StatusFound {
			t.Fatalf("start status=%d", resp.StatusCode)
		}
		cb := h.callback(t, hc, newCode("forge"), "an-attacker-chosen-state")
		if cb.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", cb.StatusCode)
		}
		assertCode(t, cb, "state_mismatch")
		if cookieNamed(cb, devCookieName) != nil {
			t.Fatal("a forged state minted a session cookie")
		}
	})

	t.Run("valid state with no cookie", func(t *testing.T) {
		starter := newBrowser(t)
		state, resp := h.startFlow(t, starter, "")
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("start status=%d", resp.StatusCode)
		}
		// A DIFFERENT browser (no transaction cookie) presents the real state.
		victimless := newBrowser(t)
		cb := h.callback(t, victimless, "code-cookieless", state)
		if cb.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", cb.StatusCode)
		}
		assertCode(t, cb, "transaction_missing")
		if cookieNamed(cb, devCookieName) != nil {
			t.Fatal("a cookieless callback minted a session cookie")
		}
		// And the transaction is still unspent, so the honest browser finishes.
		if ok := h.callback(t, starter, "code-cookieless", state); ok.StatusCode != http.StatusSeeOther {
			t.Fatalf("honest completion status=%d body=%s", ok.StatusCode, readAll(ok))
		}
	})

	t.Run("state mismatch across two live transactions", func(t *testing.T) {
		a := newBrowser(t)
		b := newBrowser(t)
		stateA, _ := h.startFlow(t, a, "")
		if _, resp := h.startFlow(t, b, ""); resp.StatusCode != http.StatusFound {
			t.Fatalf("start B status=%d", resp.StatusCode)
		}
		// Browser B presents A's state: its own cookie does not match.
		cb := h.callback(t, b, newCode("crossed"), stateA)
		if cb.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", cb.StatusCode)
		}
		assertCode(t, cb, "state_mismatch")
	})

	t.Run("transaction replay after consume", func(t *testing.T) {
		hc := newBrowser(t)
		state, _ := h.startFlow(t, hc, "")
		if first := h.callback(t, hc, "code-replay-tom", state); first.StatusCode != http.StatusSeeOther {
			t.Fatalf("first callback status=%d body=%s", first.StatusCode, readAll(first))
		}
		// Re-present the same state on a browser that still holds the cookie
		// value (the real cookie was cleared, so put it back by hand — the
		// server must refuse on the CONSUMED ROW, not merely on the cookie).
		replayer := newBrowser(t)
		u, _ := url.Parse(h.srv.URL)
		replayer.Jar.SetCookies(u, []*http.Cookie{{Name: devTxnCookieName, Value: state}})
		cb := h.callback(t, replayer, "code-replay-tom", state)
		if cb.StatusCode != http.StatusBadRequest {
			t.Fatalf("replay status=%d body=%s, want 400", cb.StatusCode, readAll(cb))
		}
		assertCode(t, cb, "transaction_invalid")
		if cookieNamed(cb, devCookieName) != nil {
			t.Fatal("a replayed transaction minted a second session")
		}
	})

	t.Run("code replay is refused by the provider", func(t *testing.T) {
		hc := newBrowser(t)
		state, _ := h.startFlow(t, hc, "")
		if first := h.callback(t, hc, "code-burned", state); first.StatusCode != http.StatusSeeOther {
			t.Fatalf("first callback status=%d", first.StatusCode)
		}
		// A fresh transaction, but the SAME (already redeemed) code.
		hc2 := newBrowser(t)
		state2, _ := h.startFlow(t, hc2, "")
		cb := h.callback(t, hc2, "code-burned", state2)
		if cb.StatusCode != http.StatusBadRequest {
			t.Fatalf("code-replay status=%d body=%s, want 400", cb.StatusCode, readAll(cb))
		}
		assertCode(t, cb, "code_rejected")
		if cookieNamed(cb, devCookieName) != nil {
			t.Fatal("a replayed code minted a session")
		}
	})

	t.Run("missing code", func(t *testing.T) {
		hc := newBrowser(t)
		state, _ := h.startFlow(t, hc, "")
		resp, err := hc.Get(h.srv.URL + "/portal/auth/workos/callback?state=" + url.QueryEscape(state))
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", resp.StatusCode)
		}
	})

	t.Run("provider error is a 4xx not a 500", func(t *testing.T) {
		hc := newBrowser(t)
		state, _ := h.startFlow(t, hc, "")
		resp, err := hc.Get(h.srv.URL + "/portal/auth/workos/callback?error=access_denied&state=" + url.QueryEscape(state))
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", resp.StatusCode)
		}
		assertCode(t, resp, "provider_error")
	})
}

func assertCode(t *testing.T, resp *http.Response, want string) {
	t.Helper()
	var eb struct {
		Code string `json:"code"`
	}
	decode(t, resp, &eb)
	if eb.Code != want {
		t.Fatalf("error code=%q, want %q", eb.Code, want)
	}
}

// TestWorkOSTxnCookieIsNeverASession is the fixation guard: the pre-auth
// transaction cookie carries a high-entropy secret, and an attacker who can set
// cookies must not be able to promote it into a session. It also pins that a
// second sign-in produces a DIFFERENT session cookie value.
func TestWorkOSTxnCookieIsNeverASession(t *testing.T) {
	h := newWorkOSHarness(t, true)

	// A hand-planted transaction cookie authenticates nothing.
	hc := newBrowser(t)
	u, _ := url.Parse(h.srv.URL)
	state, _ := h.startFlow(t, hc, "")
	hc.Jar.SetCookies(u, []*http.Cookie{{Name: devCookieName, Value: state}})
	if r := mustGet(t, hc, h.srv.URL+"/portal/api/overview"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("txn-secret-as-session status=%d, want 401", r.StatusCode)
	}

	// Two sign-ins for the SAME subject mint two distinct session cookies.
	a := newBrowser(t)
	sa, _ := h.startFlow(t, a, "")
	ca := h.callback(t, a, newCode("fixation-fay"), sa)
	b := newBrowser(t)
	sb, _ := h.startFlow(t, b, "")
	cbresp := h.callback(t, b, newCode("fixation-fay"), sb)
	v1, v2 := cookieNamed(ca, devCookieName), cookieNamed(cbresp, devCookieName)
	if v1 == nil || v2 == nil {
		t.Fatal("a sign-in did not set a session cookie")
	}
	if v1.Value == v2.Value {
		t.Fatal("two sign-ins reused the same session cookie value (fixation)")
	}
}

// --- redirect allowlist ----------------------------------------------------

func TestWorkOSReturnToAllowlist(t *testing.T) {
	h := newWorkOSHarness(t, true)
	rejected := []string{
		"https://evil.example/steal",
		"//evil.example/steal",
		"http://" + strings.TrimPrefix(h.srv.URL, "http://") + "/portal/", // absolute, even same-origin
		"/\\evil.example",
		"/evil",        // same-origin but outside the portal SPA
		"javascript:1", // scheme
		"/portal",      // outside the /portal/ prefix
		"////evil.example",
		// F3: traversal and re-encoding. Each of these LOOKS like it is under
		// /portal/ until something downstream resolves or decodes it.
		"/portal/../x",                 // literal dot segments
		"/portal/%2e%2e/x",             // the same, percent-encoded
		"/portal/%5cevil",              // encoded backslash
		"/portal/a%2f..%2f..%2fx",      // encoded separators around a traversal
		"/portal/%2E%2E/x",             // case does not help
		"/portal/x\r\nSet-Cookie: a=b", // control characters
		"/portal/x?next=//evil.example",
		"/portal/x#frag",
		"/portal/./x",
	}
	for _, bad := range rejected {
		t.Run(bad, func(t *testing.T) {
			hc := newBrowser(t)
			_, resp := h.startFlow(t, hc, "?return_to="+url.QueryEscape(bad))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("return_to=%q status=%d, want 400", bad, resp.StatusCode)
			}
			assertCode(t, resp, "invalid_redirect")
			if cookieNamed(resp, devTxnCookieName) != nil {
				t.Fatal("a rejected return_to still minted a transaction")
			}
		})
	}

	accepted := []struct{ in, want string }{
		{"/portal/privacy", "/portal/privacy"},
		{"/portal/", "/portal/"},
		// Canonicalized, then re-checked: the redirect emits the CLEAN path, not
		// the spelling that was handed in.
		{"/portal//settings", "/portal/settings"},
		{"/portal/settings/", "/portal/settings/"},
	}
	for _, tc := range accepted {
		t.Run("accepted "+tc.in, func(t *testing.T) {
			hc := newBrowser(t)
			state, resp := h.startFlow(t, hc, "?return_to="+url.QueryEscape(tc.in))
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("return_to=%q status=%d, want 302 body=%s", tc.in, resp.StatusCode, readAll(resp))
			}
			cb := h.callback(t, hc, newCode("returner"), state)
			if got := cb.Header.Get("Location"); got != tc.want {
				t.Fatalf("return_to=%q ⇒ Location=%q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// --- CSRF bootstrap (E8) ---------------------------------------------------

func TestPortalSessionRotatesCSRF(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc, csrf1, account := h.signIn(t, "csrf-cora")
	if account == "" {
		t.Fatal("no account id")
	}

	// A reload rotates: a new token, and the OLD one no longer authorizes a
	// mutation.
	resp := mustGet(t, hc, h.srv.URL+"/portal/api/session")
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", got)
	}
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	decode(t, resp, &body)
	if body.CSRF == "" || body.CSRF == csrf1 {
		t.Fatalf("session reload did not rotate the CSRF token (%q vs %q)", body.CSRF, csrf1)
	}

	// Stale token ⇒ 403.
	if r := mutate(t, hc, "POST", h.srv.URL+"/portal/api/deletion-requests", csrf1, `{}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("stale-CSRF mutation status=%d, want 403", r.StatusCode)
	}
	// No token ⇒ 403.
	if r := mutate(t, hc, "POST", h.srv.URL+"/portal/api/deletion-requests", "", `{}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("missing-CSRF mutation status=%d, want 403", r.StatusCode)
	}
	// Current token ⇒ past CSRF (and into the step-up requirement).
	r := mutate(t, hc, "POST", h.srv.URL+"/portal/api/deletion-requests", body.CSRF, `{}`)
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("no-step-up deletion status=%d, want 403", r.StatusCode)
	}
	assertCode(t, r, "step_up_required")
}

func TestPortalSessionRequiresSession(t *testing.T) {
	h := newWorkOSHarness(t, true)
	if r := mustGet(t, newBrowser(t), h.srv.URL+"/portal/api/session"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated session bootstrap status=%d, want 401", r.StatusCode)
	}
}

// --- step-up ---------------------------------------------------------------

// stepUp drives the step-up leg for an already-signed-in browser and returns the
// authorization id the callback handed back.
func (h *workosHarness) stepUp(t *testing.T, hc *http.Client, subject, action string) string {
	t.Helper()
	state, resp := h.startFlow(t, hc, "?purpose=step_up&action="+action)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("step-up start status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	cb := h.callback(t, hc, newCode(subject), state)
	if cb.StatusCode != http.StatusSeeOther {
		t.Fatalf("step-up callback status=%d body=%s", cb.StatusCode, readAll(cb))
	}
	loc, err := url.Parse(cb.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse step-up Location: %v", err)
	}
	id := loc.Query().Get("step_up")
	if id == "" {
		t.Fatalf("step-up callback returned no authorization id (Location=%q)", loc)
	}
	if cookieNamed(cb, devCookieName) != nil {
		t.Fatal("a step-up minted a new session cookie")
	}
	return id
}

func TestStepUpStartRequiresSignIn(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc := newBrowser(t)
	_, resp := h.startFlow(t, hc, "?purpose=step_up&action=deletion")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous step-up start status=%d, want 401", resp.StatusCode)
	}
	if cookieNamed(resp, devTxnCookieName) != nil {
		t.Fatal("an anonymous step-up minted a transaction")
	}
}

func TestStepUpStartRejectsUnknownActionAndPurpose(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc, _, _ := h.signIn(t, "action-andy")
	for _, q := range []string{"?purpose=step_up", "?purpose=step_up&action=teleport", "?purpose=sideways"} {
		_, resp := h.startFlow(t, hc, q)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("start%s status=%d, want 400", q, resp.StatusCode)
		}
	}
}

func TestStepUpWrongAccountRefused(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc, _, _ := h.signIn(t, "stepup-sara")
	// Start a step-up as sara, then complete it with MALLORY's code: the
	// re-authenticated identity does not match the bound account.
	state, resp := h.startFlow(t, hc, "?purpose=step_up&action=deletion")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("step-up start status=%d", resp.StatusCode)
	}
	cb := h.callback(t, hc, newCode("mallory"), state)
	if cb.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong-account step-up status=%d body=%s, want 403", cb.StatusCode, readAll(cb))
	}
	assertCode(t, cb, "reauth_mismatch")
}

func TestDeletionRequiresStepUpAndConsumesItOnce(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc, csrf, _ := h.signIn(t, "del-dana")
	authz := h.stepUp(t, hc, "del-dana", "deletion")

	// A step-up for the WRONG action does not authorize deletion.
	exportAuthz := h.stepUp(t, hc, "del-dana", "export")
	if r := mutate(t, hc, "POST", h.srv.URL+"/portal/api/deletion-requests", csrf,
		`{"step_up_authorization_id":"`+exportAuthz+`"}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("export-step-up deletion status=%d, want 403", r.StatusCode)
	} else {
		assertCode(t, r, "step_up_invalid")
	}

	// An unknown id is refused.
	if r := mutate(t, hc, "POST", h.srv.URL+"/portal/api/deletion-requests", csrf,
		`{"step_up_authorization_id":"00000000-0000-0000-0000-000000000000"}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown-step-up deletion status=%d, want 403", r.StatusCode)
	}
	// A malformed id is a refusal, not a 500.
	if r := mutate(t, hc, "POST", h.srv.URL+"/portal/api/deletion-requests", csrf,
		`{"step_up_authorization_id":"not-a-uuid"}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("malformed-step-up deletion status=%d, want 403", r.StatusCode)
	}

	// The right authorization works exactly once.
	r := mutate(t, hc, "POST", h.srv.URL+"/portal/api/deletion-requests", csrf,
		`{"step_up_authorization_id":"`+authz+`"}`)
	if r.StatusCode != http.StatusAccepted {
		t.Fatalf("deletion status=%d body=%s, want 202", r.StatusCode, readAll(r))
	}
	var dr struct {
		State string `json:"state"`
	}
	decode(t, r, &dr)
	if dr.State != "done" {
		t.Fatalf("deletion state=%q, want done", dr.State)
	}
	// The deletion purged every session, so this cookie is dead — which is also
	// why the authorization can never be replayed from this browser.
	if resp := mustGet(t, hc, h.srv.URL+"/portal/api/overview"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-deletion overview status=%d, want 401", resp.StatusCode)
	}
}

// TestStepUpNotSharedAcrossSessions pins the session binding: an authorization
// minted in one browser cannot be spent by another browser signed into the SAME
// account.
func TestStepUpNotSharedAcrossSessions(t *testing.T) {
	h := newWorkOSHarness(t, true)
	first, _, _ := h.signIn(t, "share-sid")
	authz := h.stepUp(t, first, "share-sid", "deletion")

	second, csrf2, _ := h.signIn(t, "share-sid")
	r := mutate(t, second, "POST", h.srv.URL+"/portal/api/deletion-requests", csrf2,
		`{"step_up_authorization_id":"`+authz+`"}`)
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-session step-up status=%d body=%s, want 403", r.StatusCode, readAll(r))
	}
	assertCode(t, r, "step_up_invalid")

	// And nothing was deleted: the first browser's session still works.
	if resp := mustGet(t, first, h.srv.URL+"/portal/api/overview"); resp.StatusCode != http.StatusOK {
		t.Fatalf("overview after refused deletion status=%d, want 200", resp.StatusCode)
	}
}

// TestDevAuthDeletionPathUnchanged pins that the dev-auth body-reauth flow is
// untouched by the WorkOS branch (the existing portal_test.go coverage stays
// valid); this asserts the WorkOS-shaped body does NOT work there.
func TestDevAuthDeletionPathUnchanged(t *testing.T) {
	h := newHarness(t)
	c := h.portalLogin(t, "devmode-dora")
	if r := c.mutate("POST", "/portal/api/deletion-requests",
		[]byte(`{"step_up_authorization_id":"00000000-0000-0000-0000-000000000000"}`), c.csrf); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("dev-auth deletion with a step-up body status=%d, want 401 (broker reauth still required)", r.StatusCode)
	}
	resp := c.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:devmode-dora"}`), c.csrf)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("dev-auth deletion status=%d body=%s, want 202", resp.StatusCode, readAll(resp))
	}
}

// TestWorkOSSessionEndpointNotOnDeviceAPI pins the mutual-rejection posture at
// the surface level: the portal session cookie is not a device credential.
func TestWorkOSSessionEndpointRejectsBearerOnly(t *testing.T) {
	h := newWorkOSHarness(t, true)
	req, _ := http.NewRequest("GET", h.srv.URL+"/portal/api/session", http.NoBody)
	req.Header.Set("Authorization", "Bearer not-a-cookie")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer-only session status=%d, want 401", resp.StatusCode)
	}
	var eb json.RawMessage
	decode(t, resp, &eb)
}
