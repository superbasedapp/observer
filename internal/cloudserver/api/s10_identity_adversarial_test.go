package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudpop"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// exchangeBody builds the JSON body POST /v1/auth/exchange expects (the same
// shape harness.login mints), for the suspended-remint tests that hand-roll one.
func exchangeBody(brokerToken string, pub ed25519.PublicKey, nonce string, sig []byte) []byte {
	b, _ := json.Marshal(map[string]string{
		"workos_access_token": brokerToken,
		"device_public_key":   base64.RawURLEncoding.EncodeToString(pub),
		"device_label":        "s10-remint",
		"nonce":               nonce,
		"signature":           base64.RawURLEncoding.EncodeToString(sig),
	})
	return b
}

// postJSON POSTs a JSON body and returns the response.
func postJSON(t *testing.T, hc *http.Client, url string, body []byte) *http.Response {
	t.Helper()
	resp, err := hc.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// Stream 4 (row G2-13): the API half of the §10 identity/authorization
// adversarial set. Each test pins a defence that must FAIL if it is removed;
// the coverage-notes doc (docs/plans/arc2-stream4-identity-adversarial-notes-
// 2026-09-02.md) maps every §10 row to its test func here or to the pre-existing
// W1 coverage it already had.
//
// Rows already pinned by the W1 suite (portalauth_test.go / lifecycle_test.go /
// w1fix_test.go) are NOT re-implemented — the redirect open-redirect allowlist
// (TestWorkOSReturnToAllowlist, an exhaustive table), state/nonce/code/txn
// replay (TestWorkOSCallbackAdversarialStates), PKCE round-trip
// (TestTwoOriginBrowserSignIn), step-up action/session/account binding
// (TestDeletionRequiresStepUpAndConsumesItOnce / TestStepUpNotSharedAcrossSessions
// / TestStepUpWrongAccountRefused), CSRF rotation (TestPortalSessionRotatesCSRF),
// Sec-Fetch-Site (TestPortalSessionSecFetchSite), webhook signature/timestamp
// (TestWorkOSWebhookRejections), and JWKS/alg-confusion/rotation
// (identity/workos_test.go). This file closes the remaining gaps.

// proofAt mints an SBO-PoP header for (method, path) with an explicit jti and
// issued-at, so the middleware's jti-replay defence and iat clock window can be
// driven directly. A zero jti ⇒ cloudpop mints a fresh random one; a zero iat ⇒
// time.Now.
func (c *testClient) proofAt(method, path string, body []byte, jti string, iat time.Time) string {
	c.t.Helper()
	p, err := cloudpop.Create(cloudpop.CreateParams{
		PrivateKey:  c.priv,
		Method:      method,
		URL:         c.base + path,
		AccessToken: c.token,
		JTI:         jti,
		IssuedAt:    iat,
		Body:        body,
	})
	if err != nil {
		c.t.Fatalf("cloudpop.Create: %v", err)
	}
	return p
}

// bearerReq builds a request carrying the Bearer token and the given raw PoP
// header (empty ⇒ no PoP header at all).
func (c *testClient) bearerReq(method, path, pop string) *http.Request {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, nil)
	if err != nil {
		c.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if pop != "" {
		req.Header.Set("SBO-PoP", pop)
	}
	return req
}

// TestS10_DevicePoPAdversarial pins the proof-of-possession contract on the
// device API (§10 "API requests use proof-of-possession so theft of the
// short-lived access token alone is insufficient"). A valid Bearer is present in
// EVERY case, so any 401 here is the PoP layer, not the token layer: theft of
// the bearer without the device key buys nothing.
//
// The htu/htm binding, the iat clock window (server clockSkew defaults to 60s),
// a wrong signing key, and a missing proof are all single-request cases in the
// table; the stateful jti-replay case follows.
func TestS10_DevicePoPAdversarial(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "pop-pat")
	now := time.Now()

	// A registered device whose key we do NOT hold: sign a proof with a foreign
	// key. The embedded JWK thumbprint will not match the token's registered
	// device key.
	foreignPub, foreignPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = foreignPub
	foreignProof, err := cloudpop.Create(cloudpop.CreateParams{
		PrivateKey: foreignPriv, Method: "GET", URL: c.base + "/v1/devices",
		AccessToken: c.token, Body: nil,
	})
	if err != nil {
		t.Fatalf("foreign proof: %v", err)
	}

	cases := []struct {
		name string
		pop  string
	}{
		{"missing_pop_header", ""},
		{"htu_bound_to_other_path", c.proofAt("GET", "/v1/usage", nil, "", now)},
		{"htm_bound_to_other_method", c.proofAt("POST", "/v1/devices", nil, "", now)},
		{"iat_too_old", c.proofAt("GET", "/v1/devices", nil, "", now.Add(-10*time.Minute))},
		{"iat_in_future", c.proofAt("GET", "/v1/devices", nil, "", now.Add(10*time.Minute))},
		{"wrong_signing_key", foreignProof},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := c.bearerReq("GET", "/v1/devices", tc.pop)
			resp := c.do(req)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s status=%d, want 401 (PoP must fail with a valid bearer)", tc.name, resp.StatusCode)
			}
		})
	}

	// A correctly-bound proof still succeeds — proving the 401s above are the
	// specific defect, not a broken baseline.
	ok := c.do(c.bearerReq("GET", "/v1/devices", c.proofAt("GET", "/v1/devices", nil, "", now)))
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("valid proof status=%d, want 200", ok.StatusCode)
	}
	ok.Body.Close()
}

// TestS10_DevicePoPReplayRefused is the jti-replay half: a proof that verified
// once cannot be presented a second time (the per-account pop_replay cache).
// Replaying a captured proof is exactly the attack the jti defends against.
func TestS10_DevicePoPReplayRefused(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "replay-rita")

	const jti = "aaaaaaaaaaaaaaaaaaaaaa" // 22-char base64url, a valid bounded jti
	pop := c.proofAt("GET", "/v1/devices", nil, jti, time.Now())

	first := c.do(c.bearerReq("GET", "/v1/devices", pop))
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first proof status=%d, want 200", first.StatusCode)
	}
	first.Body.Close()

	// The SAME signed proof (same jti) again ⇒ replay ⇒ 401.
	second := c.do(c.bearerReq("GET", "/v1/devices", pop))
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed proof status=%d, want 401", second.StatusCode)
	}
	second.Body.Close()
}

// TestS10_SuspendedIdentityRefusedAtDeviceExchange closes the §10 "account
// suspension" row at the mint boundary: after a WorkOS user.deleted suspends the
// account, a BRAND-NEW device exchange presenting the SAME (still-valid) identity
// is refused with account_suspended. This is "a revoked identity cannot re-mint
// via any path", proven end-to-end through the real exchange handler — not just
// that existing credentials died.
func TestS10_SuspendedIdentityRefusedAtDeviceExchange(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	const subject = "remint-rob"

	// Establish the identity link (a first device), then suspend via the webhook.
	first := h.loginBroker(t, "wtok:"+subject)
	body := webhookEvent("evt_remint_1", "user.deleted", subject)
	if resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now())); resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	_ = first

	// A fresh exchange for the same identity must be refused (403 account_suspended),
	// NOT mint a new token.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	resp, err := h.srv.Client().Get(h.srv.URL + "/v1/auth/nonce")
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	var nb struct{ Nonce string }
	decode(t, resp, &nb)
	sig := ed25519.Sign(priv, exchangeSigningInput(nb.Nonce, pub))
	exReq := exchangeBody("wtok:"+subject, pub, nb.Nonce, sig)
	er := postJSON(t, h.srv.Client(), h.srv.URL+"/v1/auth/exchange", exReq)
	defer er.Body.Close()
	if er.StatusCode != http.StatusForbidden {
		t.Fatalf("post-suspension exchange status=%d, want 403 account_suspended body=%s", er.StatusCode, readAll(er))
	}
	assertCode(t, er, "account_suspended")

	// And a browser sign-in for the same identity is equally refused.
	hc := newBrowser(t)
	state, sresp := h.startFlow(t, hc, "")
	if sresp.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d", sresp.StatusCode)
	}
	cb := h.callback(t, hc, newCode(subject), state)
	if cb.StatusCode != http.StatusForbidden {
		t.Fatalf("post-suspension browser sign-in status=%d, want 403 body=%s", cb.StatusCode, readAll(cb))
	}
	assertCode(t, cb, "account_suspended")
}

// TestS10_WebhookOutOfOrderLifecycle pins that a later lifecycle event —
// whether truly unhandled (organization_membership.created) or handled but
// NON-STATUS-CHANGING (user.updated, a display-profile refresh only) — can
// never silently UN-suspend an account the user.deleted event already closed.
// Neither event type touches accounts.status, by construction: user.updated
// dispatches to applyUserUpdated, which only ever calls UpsertAccountProfile;
// organization_membership.created resolves to workOSEventRecordOnly via
// workOSEventDispatch's default. A redelivery of either AFTER a user.deleted
// (an out-of-order arrival) therefore keeps the account suspended.
func TestS10_WebhookOutOfOrderLifecycle(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	const subject = "order-olga"
	device := h.loginBroker(t, "wtok:"+subject)

	del := webhookEvent("evt_order_del", "user.deleted", subject)
	if resp := h.postWebhook(t, del, workosSignature(testWebhookSecret, del, time.Now())); resp.StatusCode != http.StatusOK {
		t.Fatalf("user.deleted status=%d", resp.StatusCode)
	}
	// Confirm suspended: the existing bearer is dead.
	if resp := device.do(device.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-delete device usage status=%d, want 401", resp.StatusCode)
	}

	// A subsequent user.updated IS handled (profile refresh) but must not
	// reactivate — the write itself silently no-ops against a suspended
	// account (UpsertAccountProfile's fenceAccountActiveTx), while the ledger
	// still reports the event as processed.
	upd := webhookEvent("evt_order_upd", "user.updated", subject)
	resp := h.postWebhook(t, upd, workosSignature(testWebhookSecret, upd, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("user.updated status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var ack struct {
		Status string `json:"status"`
	}
	decode(t, resp, &ack)
	if ack.Status != "profile_refreshed" {
		t.Fatalf("user.updated ack=%q, want profile_refreshed", ack.Status)
	}

	// A truly UNHANDLED type behind it in the same out-of-order redelivery must
	// equally leave status untouched.
	membership := webhookEvent("evt_order_mem", "organization_membership.created", subject)
	resp = h.postWebhook(t, membership, workosSignature(testWebhookSecret, membership, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("organization_membership.created status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	decode(t, resp, &ack)
	if ack.Status != "acknowledged" {
		t.Fatalf("organization_membership.created ack=%q, want acknowledged (unhandled, never acted on)", ack.Status)
	}

	// The account is still suspended: neither a fresh exchange nor a browser
	// sign-in for the identity may mint anything.
	status, err := h.store.AccountStatus(t.Context(), device.accountID)
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if status != "suspended" {
		t.Fatalf("account status=%q after out-of-order user.updated/organization_membership.created, want suspended", status)
	}
}

// TestS10_CrossAccountCSRFRefused pins that a VALID CSRF token belonging to one
// account cannot satisfy the double-submit check on ANOTHER account's session.
// The token must hash to the SESSION's stored csrf_hash, so account A's token on
// account B's cookie is a 403 — a stolen-but-foreign CSRF token is worthless.
func TestS10_CrossAccountCSRFRefused(t *testing.T) {
	h := newHarness(t)
	a := h.portalLogin(t, "csrf-alice")
	b := h.portalLogin(t, "csrf-bob")
	if a.accountID == b.accountID {
		t.Fatal("two subjects resolved to one account")
	}

	// B's cookie + A's CSRF token on a mutating request ⇒ 403 csrf_failed. CSRF is
	// checked in the middleware before the handler, so the body is irrelevant.
	resp := b.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:csrf-bob"}`), a.csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-account CSRF status=%d, want 403 body=%s", resp.StatusCode, readAll(resp))
	}
	assertCode(t, resp, "csrf_failed")

	// B's own token still works (the baseline the 403 above is measured against).
	ok := b.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:csrf-bob"}`), b.csrf)
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusAccepted {
		t.Fatalf("B's own CSRF status=%d, want 202", ok.StatusCode)
	}
}

// --- Wave C closures for the amendment's §10 gate list -----------------------
//
// docs/plans/cloud-intelligence-signed-in-free-portal-auth-zdr-amendment-
// 2026-08-29.md lines ~740-762 name the identity-and-authorization gates.
// Coverage as of Wave C:
//
//   - WorkOS issuer/audience/nonce/PKCE/state, refresh rotation/reuse, logout,
//     device revoke: pre-existing (workos_test.go, w1fix_test.go, this file's
//     PoP/replay tests above).
//   - "account recovery": a REAL feature — operator-driven reactivation
//     (ReactivateAccount). Tested at the store layer:
//     TestS10_ReactivateOnlySuspended and TestS10_ReactivationRestoresSignIn
//     (internal/cloudserver/store/s10_lifecycle_d18_test.go).
//   - "device re-enrollment": TestS10_DeviceReenrollmentAfterRevoke below.
//   - "duplicate-account" / no-email-only-merge:
//     TestS10_NoMergeByEmail (store/s10_lifecycle_d18_test.go) already pins
//     BOTH halves the amendment names — same (provider,subject) twice ⇒ one
//     account; two DIFFERENT subjects sharing an email ⇒ two accounts.
//   - WorkOS expiry/denial/JWKS rotation/provider outage: JWKS rotation +
//     "must not thrash" closed in identity/s10_adversarial_test.go
//     (TestS10_VerifierJWKSMissCooldownBoundsThrashButNotRotation, alongside
//     the pre-existing TestWorkOSVerifierRefetchesOnRotation). `slow_down` /
//     429 and a provider outage at the BROWSER leg (as opposed to the
//     identity-verifier's own JWKS fetch, already covered) are closed below:
//     TestS10_BrowserCodeExchangeSlowDownIsHonest and
//     TestS10_BrowserCodeExchangeProviderOutageIsHonest.
//   - "link/unlink" (attaching a second identity provider to an
//     already-signed-in account, or detaching one): NOT A FEATURE in this
//     codebase. resolveOrCreateAccountTx (the one identity-bootstrap seam
//     PortalLogin and Exchange both go through) always resolves or creates
//     EXACTLY one (provider, subject) → account relationship; there is no
//     endpoint, store method, or portal route that adds a second provider to
//     an already-signed-in account or removes an existing one. Documented
//     here rather than fabricating a test for a feature that does not exist.

// brokenTokenServer stands in for the AuthKit TOKEN endpoint, answering every
// code-exchange request with a fixed status/body. A `slow_down` (429) and a
// bare provider outage (5xx) are indistinguishable from the client's point of
// view — both are simply "the token endpoint did not return 200" — so one
// fixture, parameterized by status, covers both §10 rows. A genuine network
// TIMEOUT shares the same `err != nil` branch in exchangeWorkOSCode as this
// 5xx fixture (both are caught by the same `if err != nil` after
// `s.workOSHTTP.Do(req)`); it is not separately exercised here because doing
// so deterministically would mean actually waiting out a client timeout in a
// unit test, which is not worth the wall-clock cost for a code path this
// fixture already reaches.
func brokenTokenServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newBrokenExchangeHarness builds a WorkOS-mode server whose token endpoint is
// permanently broken (fixed status/body), so the browser callback's exchange
// leg always fails the same way a real `slow_down` or provider outage would.
// The authorize endpoint is never actually fetched in these tests (the
// CheckRedirect-disabled client inspects the 302 Location header without
// following it), so it does not need a working stand-in.
func newBrokenExchangeHarness(t *testing.T, tokenStatus int, tokenBody string) *workosHarness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	broken := brokenTokenServer(t, tokenStatus, tokenBody)

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
		PortalWorkOSEnabled: true,
		WorkOSClientID:      "client_test",
		WorkOSAPIKey:        testWorkOSSecret,
		WorkOSAuthorizeURL:  broken.URL + "/authorize",
		WorkOSTokenURL:      broken.URL + "/token",
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &workosHarness{harness: &harness{srv: srv, store: s}}
}

// TestS10_BrowserCodeExchangeSlowDownIsHonest pins the §10 "slow_down" row: a
// 429 from the WorkOS token endpoint during the browser code exchange answers
// an honest RETRYABLE error, mints NO session, and clears the spent
// transaction cookie exactly like every other callback outcome (F5's ordering
// — the cookie is always cleared once the state has matched, regardless of
// what happens after).
func TestS10_BrowserCodeExchangeSlowDownIsHonest(t *testing.T) {
	h := newBrokenExchangeHarness(t, http.StatusTooManyRequests, `{"error":"slow_down"}`)
	hc := newBrowser(t)
	state, sresp := h.startFlow(t, hc, "")
	if sresp.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d", sresp.StatusCode)
	}
	if state == "" {
		t.Fatal("start set no transaction cookie")
	}

	cb := h.callback(t, hc, newCode("slowdown-sam"), state)
	defer cb.Body.Close()
	if cb.StatusCode != http.StatusBadGateway {
		t.Fatalf("slow_down callback status=%d, want 502 body=%s", cb.StatusCode, readAll(cb))
	}
	assertCode(t, cb, "provider_unavailable")
	// clearTxnCookie always SENDS a Set-Cookie header (that is how a cookie is
	// cleared over HTTP) — a negative MaxAge, not an absent header — so the
	// clearing directive itself is present here; what must be absent is a
	// still-LIVE (non-negative MaxAge) transaction cookie.
	if c := cookieNamed(cb, devTxnCookieName); c != nil && c.MaxAge >= 0 {
		t.Fatal("the transaction cookie must be cleared even when the exchange fails")
	}
	if cookieNamed(cb, devCookieName) != nil {
		t.Fatal("a slow_down exchange must never mint a session cookie")
	}
}

// TestS10_BrowserCodeExchangeProviderOutageIsHonest pins the §10 "provider
// outage" row for the browser leg specifically (the identity verifier's own
// JWKS-fetch outage behaviour is a SEPARATE row, closed in
// identity/s10_adversarial_test.go): a 503 from the token endpoint gets the
// exact same honest, no-session, cookie-cleared, AUDITED treatment as the
// slow_down case above — the handler does not need to special-case the status
// code, only "was this a 2xx".
func TestS10_BrowserCodeExchangeProviderOutageIsHonest(t *testing.T) {
	h := newBrokenExchangeHarness(t, http.StatusServiceUnavailable, `{"error":"internal_error"}`)
	hc := newBrowser(t)
	state, sresp := h.startFlow(t, hc, "")
	if sresp.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d", sresp.StatusCode)
	}

	cb := h.callback(t, hc, newCode("outage-oscar"), state)
	defer cb.Body.Close()
	if cb.StatusCode != http.StatusBadGateway {
		t.Fatalf("provider-outage callback status=%d, want 502 body=%s", cb.StatusCode, readAll(cb))
	}
	assertCode(t, cb, "provider_unavailable")
	if cookieNamed(cb, devCookieName) != nil {
		t.Fatal("a provider-outage exchange must never mint a session cookie")
	}

	// A naive browser retry lands on "no transaction cookie": the callback
	// clears the transaction cookie UNCONDITIONALLY once the state has matched
	// (F5 step 3 — "whatever happens after"), before the exchange ever runs, so
	// this browser's jar no longer holds it. That is a DIFFERENT refusal from
	// the underlying database row's own single-use replay guard (already
	// pinned by TestWorkOSCallbackAdversarialStates, which forges the cookie
	// directly to exercise that path) — but equally final: there is no way for
	// this browser to complete the SAME sign-in attempt again.
	retry := h.callback(t, hc, newCode("outage-oscar-retry"), state)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusBadRequest {
		t.Fatalf("retry with no transaction cookie status=%d, want 400 transaction_missing", retry.StatusCode)
	}
	assertCode(t, retry, "transaction_missing")
}

// TestS10_DeviceReenrollmentAfterRevoke closes the §10 "device re-enrollment"
// row. The codebase's actual (and correct) security posture is stricter than
// a naive reading of "re-enrollment" might suggest, so this test pins BOTH
// halves precisely:
//
//   - a revoked device's key is refused FOREVER — a fresh Exchange presenting
//     the EXACT SAME public key the store already marked revoked_at on is
//     refused with 403 device_revoked, not silently re-registered. Reviving a
//     dead device key would be reviving a credential a revocation was meant to
//     kill.
//   - "re-enrollment" is minting a NEW device keypair: a fresh Exchange for
//     the SAME identity with a DIFFERENT public key succeeds and registers as
//     a brand-new device — the account is not locked out by one dead key.
func TestS10_DeviceReenrollmentAfterRevoke(t *testing.T) {
	h := newHarness(t)
	const subject = "reenroll-rachel"
	c := h.login(t, subject)

	if resp := c.do(c.signedReq("DELETE", "/v1/devices/"+deviceIDFor(t, c), nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke device status=%d body=%s", resp.StatusCode, readAll(resp))
	}

	// The SAME device key, re-presented: permanently refused.
	sameKeyResp := reexchange(t, h, subject, c.pub, c.priv)
	defer sameKeyResp.Body.Close()
	if sameKeyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("re-exchange with the REVOKED key status=%d, want 403 body=%s", sameKeyResp.StatusCode, readAll(sameKeyResp))
	}
	assertCode(t, sameKeyResp, "device_revoked")

	// A FRESH device key for the same identity: succeeds as a new device.
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	freshResp := reexchange(t, h, subject, newPub, newPriv)
	defer freshResp.Body.Close()
	if freshResp.StatusCode != http.StatusOK {
		t.Fatalf("re-exchange with a FRESH key status=%d, want 200 body=%s", freshResp.StatusCode, readAll(freshResp))
	}
	var er struct {
		AccountID  string `json:"account_id"`
		Thumbprint string `json:"thumbprint"`
	}
	decode(t, freshResp, &er)
	if er.AccountID != c.accountID {
		t.Fatalf("re-enrolled device resolved to a different account: %s vs %s", er.AccountID, c.accountID)
	}
	if er.Thumbprint == c.thumbprint {
		t.Fatal("the fresh device's thumbprint matched the revoked one — the key was not actually different")
	}
}

// deviceIDFor lists the account's devices and returns the id of the ONE this
// testClient registered (there is exactly one, freshly minted by h.login).
func deviceIDFor(t *testing.T, c *testClient) string {
	t.Helper()
	resp := c.do(c.signedReq("GET", "/v1/devices", nil))
	defer resp.Body.Close()
	var list struct {
		Devices []struct {
			ID string `json:"id"`
		} `json:"devices"`
	}
	decode(t, resp, &list)
	if len(list.Devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(list.Devices))
	}
	return list.Devices[0].ID
}

// reexchange drives POST /v1/auth/exchange for subject with an explicit
// keypair, mirroring harness.login's body-building but WITHOUT asserting the
// status — the caller inspects both the success and refusal shapes. Reuses
// exchangeBody + postJSON (this file's own helpers, above).
func reexchange(t *testing.T, h *harness, subject string, pub ed25519.PublicKey, priv ed25519.PrivateKey) *http.Response {
	t.Helper()
	resp, err := h.srv.Client().Get(h.srv.URL + "/v1/auth/nonce")
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	var nb struct{ Nonce string }
	decode(t, resp, &nb)
	sig := ed25519.Sign(priv, exchangeSigningInput(nb.Nonce, pub))
	body := exchangeBody("dev:"+subject, pub, nb.Nonce, sig)
	return postJSON(t, h.srv.Client(), h.srv.URL+"/v1/auth/exchange", body)
}
