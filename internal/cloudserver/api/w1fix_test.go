package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// Regression suite for the W1 adversarial-review fixes (F1, F2, F5, F7, F8,
// F11, F12). Each test names the property the review found missing, not the
// code that implements it.

// --- F1: the two-origin deployment -----------------------------------------

const (
	twoOriginPortalHost = "app.example"
	twoOriginAPIHost    = "cloud.example"
)

// twoOriginHarness is a server configured the way R5 describes production:
// /portal/* fenced to the portal host, /v1/* fenced to the API host, and the
// browser sign-in leg anchored to the PORTAL origin (PortalBaseURL) while
// proof-of-possession stays anchored to the API origin (ExternalBaseURL).
type twoOriginHarness struct {
	*workosHarness
	portalBase string
	apiBase    string
}

func newTwoOriginHarness(t *testing.T) *twoOriginHarness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	fake := newFakeWorkOS(t, testWorkOSSecret)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	// Two DIFFERENT origins over one listener: the requests below carry an
	// explicit Host header, which is exactly what a real two-name deployment
	// puts in front of this process.
	apiBase := "http://" + twoOriginAPIHost + ":" + port
	portalBase := "http://" + twoOriginPortalHost + ":" + port

	handler := api.New(api.Options{
		Store:               apiStore,
		Queue:               jobs.NewPGQueue(apiStore),
		Verifier:            fakeWorkOSVerifier{},
		ExternalBaseURL:     apiBase,
		PortalBaseURL:       portalBase,
		RateLimit:           &api.RateLimitConfig{},
		Attestor:            admAttestor{verified: true},
		Credentials:         jobs.StaticCredentials{Key: "test-key"},
		PortalWorkOSEnabled: true,
		WorkOSClientID:      "client_test",
		WorkOSAPIKey:        testWorkOSSecret,
		WorkOSAuthorizeURL:  fake.srv.URL + "/authorize",
		WorkOSTokenURL:      fake.srv.URL + "/token",
		PortalHost:          twoOriginPortalHost,
		APIHost:             twoOriginAPIHost,
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &twoOriginHarness{
		workosHarness: &workosHarness{harness: &harness{srv: srv, store: s}, workos: fake},
		portalBase:    portalBase,
		apiBase:       apiBase,
	}
}

// getAs issues a GET to the listener with an explicit Host, through hc (so a
// cookie jar keyed on the loopback URL still works across the whole flow).
func getAs(t *testing.T, hc *http.Client, base, path, host string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, http.NoBody)
	if err != nil {
		t.Fatalf("build request %s: %v", path, err)
	}
	req.Host = host
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("GET %s (Host %s): %v", path, host, err)
	}
	return resp
}

// TestTwoOriginBrowserSignIn is the F1 headline: with the portal and the API on
// two names, the whole browser sign-in leg lives on the PORTAL host, the
// redirect_uri handed to the provider carries the PORTAL origin (not the API
// origin it used to be built from), and each surface refuses the other's paths.
func TestTwoOriginBrowserSignIn(t *testing.T) {
	h := newTwoOriginHarness(t)
	hc := newBrowser(t)

	// 1) Start, on the portal host.
	resp := getAs(t, hc, h.srv.URL, "/portal/auth/workos/start", twoOriginPortalHost)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start on the portal host: status=%d body=%s, want 302", resp.StatusCode, readAll(resp))
	}
	txn := cookieNamed(resp, devTxnCookieName)
	if txn == nil {
		t.Fatal("start set no transaction cookie")
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	wantRedirect := h.portalBase + "/portal/auth/workos/callback"
	if got := loc.Query().Get("redirect_uri"); got != wantRedirect {
		t.Fatalf("redirect_uri=%q, want the PORTAL origin %q", got, wantRedirect)
	}
	if strings.Contains(loc.Query().Get("redirect_uri"), twoOriginAPIHost) {
		t.Fatal("redirect_uri carries the API host; the browser leg must be anchored to the portal origin")
	}

	// 2) Callback, on the portal host, completes the flow against the fake
	// provider — proving the recorded redirect_uri round-trips (the callback
	// re-checks it) rather than merely being written correctly.
	cbPath := "/portal/auth/workos/callback?code=" + url.QueryEscape(newCode("two-origin-tess")) +
		"&state=" + url.QueryEscape(txn.Value)
	cb := getAs(t, hc, h.srv.URL, cbPath, twoOriginPortalHost)
	if cb.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback on the portal host: status=%d body=%s, want 303", cb.StatusCode, readAll(cb))
	}
	if cookieNamed(cb, devCookieName) == nil {
		t.Fatalf("callback minted no session cookie; cookies=%v", cb.Cookies())
	}
	// And the session works — on the portal host.
	if r := getAs(t, hc, h.srv.URL, "/portal/api/overview", twoOriginPortalHost); r.StatusCode != http.StatusOK {
		t.Fatalf("overview on the portal host: status=%d body=%s, want 200", r.StatusCode, readAll(r))
	}

	// 3) The fence, both directions.
	for _, tc := range []struct{ name, path, host string }{
		{"portal start on the api host", "/portal/auth/workos/start", twoOriginAPIHost},
		{"portal callback on the api host", "/portal/auth/workos/callback?code=x&state=y", twoOriginAPIHost},
		{"portal api on the api host", "/portal/api/session", twoOriginAPIHost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := getAs(t, newBrowser(t), h.srv.URL, tc.path, tc.host)
			if r.StatusCode != http.StatusMisdirectedRequest {
				t.Fatalf("status=%d, want 421 body=%s", r.StatusCode, readAll(r))
			}
			assertCode(t, r, "wrong_host")
		})
	}
	for _, path := range []string{"/v1/auth/nonce", "/v1/usage"} {
		t.Run("api path on the portal host: "+path, func(t *testing.T) {
			r := getAs(t, newBrowser(t), h.srv.URL, path, twoOriginPortalHost)
			if r.StatusCode != http.StatusMisdirectedRequest {
				t.Fatalf("status=%d, want 421 body=%s", r.StatusCode, readAll(r))
			}
			assertCode(t, r, "wrong_host")
		})
	}
}

// TestSingleHostPortalBaseFallback pins the compatibility half of F1: with
// PortalBaseURL unset the portal origin IS the external base, so the staging
// deployment behaves exactly as it did before the option existed.
func TestSingleHostPortalBaseFallback(t *testing.T) {
	h := newWorkOSHarness(t, true) // no PortalBaseURL
	hc := newBrowser(t)
	state, resp := h.startFlow(t, hc, "")
	if resp.StatusCode != http.StatusFound || state == "" {
		t.Fatalf("start status=%d state=%q", resp.StatusCode, state)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got, want := loc.Query().Get("redirect_uri"), h.srv.URL+"/portal/auth/workos/callback"; got != want {
		t.Fatalf("redirect_uri=%q, want %q (the external base, unchanged)", got, want)
	}
	if cb := h.callback(t, hc, newCode("fallback-fred"), state); cb.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status=%d body=%s", cb.StatusCode, readAll(cb))
	}
}

// --- F2: step-up forces a FRESH provider authentication --------------------

// TestStepUpAuthorizeURLForcesReauth pins that a step-up asks the provider to
// re-authenticate the human (prompt=login + max_age=0) rather than accepting a
// live SSO session, and that an ordinary login start is left alone.
func TestStepUpAuthorizeURLForcesReauth(t *testing.T) {
	h := newWorkOSHarness(t, true)

	t.Run("login start does not force reauth", func(t *testing.T) {
		hc := newBrowser(t)
		_, resp := h.startFlow(t, hc, "")
		q := authorizeQuery(t, resp)
		if q.Get("prompt") != "" || q.Get("max_age") != "" {
			t.Fatalf("a plain sign-in must not force re-authentication: prompt=%q max_age=%q",
				q.Get("prompt"), q.Get("max_age"))
		}
	})

	t.Run("step-up start forces reauth", func(t *testing.T) {
		hc, _, _ := h.signIn(t, "fresh-freya")
		for _, action := range []string{"deletion", "export", "security"} {
			_, resp := h.startFlow(t, hc, "?purpose=step_up&action="+action)
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("step-up start (%s) status=%d body=%s", action, resp.StatusCode, readAll(resp))
			}
			q := authorizeQuery(t, resp)
			if q.Get("prompt") != "login" {
				t.Fatalf("step-up (%s) prompt=%q, want login", action, q.Get("prompt"))
			}
			if q.Get("max_age") != "0" {
				t.Fatalf("step-up (%s) max_age=%q, want 0", action, q.Get("max_age"))
			}
			// The rest of the authorization request is unchanged.
			if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" {
				t.Fatalf("step-up (%s) authorize URL malformed: %v", action, q)
			}
		}
	})
}

func authorizeQuery(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", resp.Header.Get("Location"), err)
	}
	return loc.Query()
}

// --- F5: a cross-site error= must not cancel a live sign-in ----------------

// TestCrossSiteErrorDoesNotCancelTransaction is the F5 regression. A page on
// another origin can navigate the browser to our callback, and the Lax
// transaction cookie rides along. If the handler spent that cookie before
// checking `state`, any such page could kill a sign-in in progress. Nothing may
// be cleared or consumed until the state proves the caller knows this browser's
// own transaction secret.
func TestCrossSiteErrorDoesNotCancelTransaction(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc := newBrowser(t)
	state, resp := h.startFlow(t, hc, "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d", resp.StatusCode)
	}

	// The drive-by: an error callback with a state the attacker cannot know.
	drive := mustGet(t, hc, h.srv.URL+"/portal/auth/workos/callback?error=access_denied&state=attacker-guess")
	if drive.StatusCode != http.StatusBadRequest {
		t.Fatalf("cross-site error status=%d, want 400", drive.StatusCode)
	}
	assertCode(t, drive, "state_mismatch")
	if c := cookieNamed(drive, devTxnCookieName); c != nil {
		t.Fatalf("a cross-site error callback cleared the transaction cookie: %+v", c)
	}

	// Same, with no state at all.
	drive2 := mustGet(t, hc, h.srv.URL+"/portal/auth/workos/callback?error=access_denied")
	if drive2.StatusCode != http.StatusBadRequest {
		t.Fatalf("stateless error status=%d, want 400", drive2.StatusCode)
	}
	assertCode(t, drive2, "state_mismatch")
	if c := cookieNamed(drive2, devTxnCookieName); c != nil {
		t.Fatalf("a stateless error callback cleared the transaction cookie: %+v", c)
	}

	// The honest sign-in still completes: neither the cookie nor the row moved.
	cb := h.callback(t, hc, newCode("survivor-sam"), state)
	if cb.StatusCode != http.StatusSeeOther {
		t.Fatalf("honest completion after a cross-site error: status=%d body=%s", cb.StatusCode, readAll(cb))
	}
	if cookieNamed(cb, devCookieName) == nil {
		t.Fatal("honest completion minted no session")
	}
}

// TestGenuineProviderErrorBurnsTheTransaction is the other half of F5: a
// cancellation the user really made (matching state) IS final — the cookie is
// cleared and the transaction consumed, so the abandoned state cannot later be
// presented with a code.
func TestGenuineProviderErrorBurnsTheTransaction(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc := newBrowser(t)
	state, resp := h.startFlow(t, hc, "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d", resp.StatusCode)
	}

	cancel := mustGet(t, hc, h.srv.URL+"/portal/auth/workos/callback?error=access_denied&state="+url.QueryEscape(state))
	if cancel.StatusCode != http.StatusBadRequest {
		t.Fatalf("cancel status=%d, want 400", cancel.StatusCode)
	}
	assertCode(t, cancel, "provider_error")
	txn := cookieNamed(cancel, devTxnCookieName)
	if txn == nil || txn.MaxAge >= 0 || txn.Value != "" {
		t.Fatalf("a genuine cancellation did not clear the transaction cookie: %+v", txn)
	}

	// Re-present the (now consumed) state with a real code, cookie restored by
	// hand so the refusal must come from the ROW, not from the missing cookie.
	replayer := newBrowser(t)
	u, _ := url.Parse(h.srv.URL)
	replayer.Jar.SetCookies(u, []*http.Cookie{{Name: devTxnCookieName, Value: state}})
	after := h.callback(t, replayer, newCode("cancelled-cara"), state)
	if after.StatusCode != http.StatusBadRequest {
		t.Fatalf("cancelled transaction reused: status=%d body=%s, want 400", after.StatusCode, readAll(after))
	}
	assertCode(t, after, "transaction_invalid")
	if cookieNamed(after, devCookieName) != nil {
		t.Fatal("a cancelled transaction minted a session")
	}
}

// --- F7: webhook intake is retry-safe --------------------------------------

// setDeviceUpdateGrant flips the SERVER role's (sbci_api — the role the
// harness binds the API to, exactly as `observer-cloud serve` does) UPDATE
// privilege on device_registrations so a revocation can be made to fail for
// real (rather than through a mock), then restored. The pool connects as the
// table owner, which is what a schema change like this needs.
func setDeviceUpdateGrant(t *testing.T, h *workosHarness, granted bool) {
	t.Helper()
	stmt := `REVOKE UPDATE ON device_registrations FROM sbci_api`
	if granted {
		stmt = `GRANT UPDATE ON device_registrations TO sbci_api`
	}
	if _, err := h.store.Pool().Exec(context.Background(), stmt); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}

// TestWebhookRetriesAfterAFailedRevocation is the F7 regression: an event whose
// handling FAILED must not be treated as handled on redelivery. Before the fix,
// intake keyed on "did this call insert the row?" — so the retry WorkOS sends
// after a 5xx was acknowledged as a duplicate and the revocation was lost
// permanently. The failure here is a real store error (the privilege the
// revocation needs is withdrawn), not an injected mock.
func TestWebhookRetriesAfterAFailedRevocation(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	const subject = "retry-rita"
	device := h.loginBroker(t, "wtok:"+subject)

	body := webhookEvent("event_retry_1", "user.deleted", subject)

	// 1) Delivery during the outage: 500, and NOTHING is stamped processed.
	setDeviceUpdateGrant(t, h, false)
	resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("failed revocation status=%d body=%s, want 500 (so WorkOS redelivers)", resp.StatusCode, readAll(resp))
	}
	ev, err := h.store.GetWorkOSEvent(t.Context(), "event_retry_1")
	if err != nil {
		t.Fatalf("the event was not recorded at all: %v", err)
	}
	if ev.ProcessedAt != nil {
		t.Fatal("a failed handling stamped the event processed")
	}
	// The account is untouched: the device still authenticates.
	if r := device.do(device.signedReq("GET", "/v1/usage", nil)); r.StatusCode != http.StatusOK {
		t.Fatalf("device usage status=%d during the outage, want 200 (nothing was revoked)", r.StatusCode)
	}

	// 2) WorkOS retries the SAME event id once the store is healthy again.
	setDeviceUpdateGrant(t, h, true)
	resp = h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry status=%d body=%s, want 200", resp.StatusCode, readAll(resp))
	}
	var ack struct {
		Status string `json:"status"`
	}
	decode(t, resp, &ack)
	if ack.Status != "revoked" {
		t.Fatalf("retry status=%q, want revoked (the retry must RE-PROCESS, not ack a duplicate)", ack.Status)
	}
	if r := device.do(device.signedReq("GET", "/v1/usage", nil)); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("device usage status=%d after the retry, want 401", r.StatusCode)
	}

	// 3) A THIRD delivery is now the duplicate ack — the settled event is not
	// re-processed on every subsequent retry.
	resp = h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	decode(t, resp, &ack)
	if ack.Status != "duplicate" {
		t.Fatalf("third delivery status=%q, want duplicate", ack.Status)
	}
}

// --- F8: revocation must be durable ----------------------------------------

// TestUserDeletedSuspendsAccountSoCredentialsCannotBeReminted is the F8
// regression. Revoking every credential is not enough: they are all re-mintable
// from the same identity link, so before the fix the very next device exchange
// or browser sign-in handed the "deleted" user a working credential again. The
// account must be suspended, and both identity entry points must refuse it.
func TestUserDeletedSuspendsAccountSoCredentialsCannotBeReminted(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	const subject = "durable-dee"
	device := h.loginBroker(t, "wtok:"+subject)

	body := webhookEvent("event_durable_1", "user.deleted", subject)
	resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook status=%d body=%s", resp.StatusCode, readAll(resp))
	}

	// The existing credential is dead (pinned elsewhere too; asserted here as
	// the precondition for the interesting part).
	if r := device.do(device.signedReq("GET", "/v1/usage", nil)); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-webhook device usage status=%d, want 401", r.StatusCode)
	}

	t.Run("the device exchange refuses to mint a new token", func(t *testing.T) {
		resp := h.exchangeRaw(t, "wtok:"+subject)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("post-revocation exchange status=%d body=%s, want 403", resp.StatusCode, readAll(resp))
		}
		assertCode(t, resp, "account_suspended")
	})

	t.Run("the browser sign-in refuses to mint a new session", func(t *testing.T) {
		hc := newBrowser(t)
		state, start := h.startFlow(t, hc, "")
		if start.StatusCode != http.StatusFound {
			t.Fatalf("start status=%d", start.StatusCode)
		}
		cb := h.callback(t, hc, newCode(subject), state)
		if cb.StatusCode != http.StatusForbidden {
			t.Fatalf("post-revocation browser sign-in status=%d body=%s, want 403", cb.StatusCode, readAll(cb))
		}
		assertCode(t, cb, "account_suspended")
		if cookieNamed(cb, devCookieName) != nil {
			t.Fatal("a suspended account was handed a session cookie")
		}
	})

	t.Run("an unrelated account still signs in", func(t *testing.T) {
		bystander := h.loginBroker(t, "wtok:durable-bystander")
		if r := bystander.do(bystander.signedReq("GET", "/v1/usage", nil)); r.StatusCode != http.StatusOK {
			t.Fatalf("bystander usage status=%d, want 200", r.StatusCode)
		}
	})
}

// --- F11: the CSRF-minting GET is same-origin only -------------------------

// TestPortalSessionSecFetchSite pins the sibling-origin fence on the one portal
// GET that hands back a credential. The header is browser-set and cannot be
// forged by script, so trusting it is sound; an ABSENT header stays allowed
// because every non-browser client sends none.
func TestPortalSessionSecFetchSite(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc, _, _ := h.signIn(t, "fetch-fiona")

	cases := []struct {
		name, header string
		want         int
	}{
		{"same-origin (the SPA)", "same-origin", http.StatusOK},
		{"none (typed URL or bookmark)", "none", http.StatusOK},
		{"same-site (a sibling sub-domain)", "same-site", http.StatusForbidden},
		{"cross-site", "cross-site", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/portal/api/session", http.NoBody)
			req.Header.Set("Sec-Fetch-Site", tc.header)
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			if resp.StatusCode != tc.want {
				t.Fatalf("Sec-Fetch-Site=%s status=%d, want %d body=%s", tc.header, resp.StatusCode, tc.want, readAll(resp))
			}
			if tc.want == http.StatusForbidden {
				assertCode(t, resp, "cross_origin_refused")
			}
		})
	}

	t.Run("absent header is allowed", func(t *testing.T) {
		if r := mustGet(t, hc, h.srv.URL+"/portal/api/session"); r.StatusCode != http.StatusOK {
			t.Fatalf("no Sec-Fetch-Site: status=%d, want 200 (older browsers and CLI clients send none)", r.StatusCode)
		}
	})
}

// --- F12: the signed-out bootstrap -----------------------------------------

// TestPortalAuthConfig pins the signed-out bootstrap: it answers WITHOUT a
// session, says which sign-in surface to render, and reports the browser leg as
// enabled only when it would actually work.
func TestPortalAuthConfig(t *testing.T) {
	type cfg struct {
		AuthMode string `json:"auth_mode"`
		WorkOS   bool   `json:"workos_browser_enabled"`
	}

	t.Run("workos mode with the browser leg active", func(t *testing.T) {
		h := newWorkOSHarness(t, true)
		resp := mustGet(t, newBrowser(t), h.srv.URL+"/portal/api/auth-config")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d, want 200 (it must answer while signed out)", resp.StatusCode)
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control=%q, want no-store", got)
		}
		var c cfg
		decode(t, resp, &c)
		if c.AuthMode != "workos" || !c.WorkOS {
			t.Fatalf("config=%+v, want {workos true}", c)
		}
	})

	t.Run("workos mode with the browser leg dark", func(t *testing.T) {
		h := newWorkOSHarness(t, false)
		var c cfg
		decode(t, mustGet(t, newBrowser(t), h.srv.URL+"/portal/api/auth-config"), &c)
		if c.AuthMode != "workos" || c.WorkOS {
			t.Fatalf("config=%+v, want {workos false} — the SPA must not offer a 501 button", c)
		}
	})

	t.Run("dev-auth mode", func(t *testing.T) {
		h := newHarness(t)
		var c cfg
		decode(t, mustGet(t, newBrowser(t), h.srv.URL+"/portal/api/auth-config"), &c)
		if c.AuthMode != "dev" || c.WorkOS {
			t.Fatalf("config=%+v, want {dev false}", c)
		}
	})
}

// exchangeRaw performs a full, correctly-signed device exchange for brokerToken
// and returns the RAW response, so a refused exchange can be inspected
// (harness.loginBroker fatals on anything but 200).
func (h *workosHarness) exchangeRaw(t *testing.T, brokerToken string) *http.Response {
	t.Helper()
	hc := h.srv.Client()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	resp, err := hc.Get(h.srv.URL + "/v1/auth/nonce")
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	var nb struct{ Nonce string }
	decode(t, resp, &nb)

	sig := ed25519.Sign(priv, exchangeSigningInput(nb.Nonce, pub))
	body, _ := json.Marshal(map[string]string{
		"workos_access_token": brokerToken,
		"device_public_key":   base64.RawURLEncoding.EncodeToString(pub),
		"device_label":        "test",
		"nonce":               nb.Nonce,
		"signature":           base64.RawURLEncoding.EncodeToString(sig),
	})
	resp, err = hc.Post(h.srv.URL+"/v1/auth/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return resp
}
