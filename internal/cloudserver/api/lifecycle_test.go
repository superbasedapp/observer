package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// W1 "lifecycle phase 1" + R5 origin cover (plan §3 W1): device /v1/logout
// (D17), the WorkOS account-lifecycle webhook (D18 phase 1), canonical-host
// enforcement plus the mutual credential-rejection pins, and the E9 SPA wiring
// pin.

// --- harness ---------------------------------------------------------------

// newWebhookHarness builds a WorkOS-mode server (browser leg active, fake
// AuthKit) that ALSO has the lifecycle webhook secret configured. secret == ""
// leaves the webhook unconfigured so the fail-closed 501 can be asserted.
//
// It returns a *workosHarness so the portal helpers in portalauth_test.go
// (signIn / bootstrap / callback) work unchanged.
func newWebhookHarness(t *testing.T, secret string) *workosHarness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
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
		PortalWorkOSEnabled: true,
		WorkOSClientID:      "client_test",
		WorkOSAPIKey:        testWorkOSSecret,
		WorkOSAuthorizeURL:  fake.srv.URL + "/authorize",
		WorkOSTokenURL:      fake.srv.URL + "/token",
		WorkOSWebhookSecret: secret,
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &workosHarness{harness: &harness{srv: srv, store: s}, workos: fake}
}

// loginBroker is harness.login generalized over the raw broker credential, so a
// WorkOS-mode server can be handed "wtok:<subject>" instead of "dev:<subject>".
// It is the device half of an account the portal helpers can also sign into.
func (h *harness) loginBroker(t *testing.T, brokerToken string) *testClient {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := &testClient{t: t, base: h.srv.URL, http: h.srv.Client(), priv: priv, pub: pub}

	resp, err := c.http.Get(c.base + "/v1/auth/nonce")
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
	resp, err = c.http.Post(c.base+"/v1/auth/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var er struct {
		Token      string `json:"api_token"`
		AccountID  string `json:"account_id"`
		Thumbprint string `json:"thumbprint"`
	}
	decode(t, resp, &er)
	c.token, c.accountID, c.thumbprint = er.Token, er.AccountID, er.Thumbprint
	return c
}

// --- device logout (D17) ---------------------------------------------------

// TestDeviceLogoutRevokesPresentedToken is the D17 contract: after logout the
// SAME bearer no longer authenticates, even with a perfectly fresh proof — the
// point being that a copy of the token stolen before logout is now worthless.
func TestDeviceLogoutRevokesPresentedToken(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "logout-alice")

	// It works before.
	if resp := c.do(c.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-logout usage status=%d body=%s", resp.StatusCode, readAll(resp))
	}

	resp := c.do(c.signedReq("POST", "/v1/logout", nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var out struct {
		Status string `json:"status"`
	}
	decode(t, resp, &out)
	if out.Status != "signed_out" {
		t.Fatalf("logout body status=%q, want signed_out", out.Status)
	}

	// A fresh, valid proof on the revoked token is still 401 — the revocation is
	// server-side, not a client-side forget.
	if resp := c.do(c.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-logout usage status=%d, want 401", resp.StatusCode)
	}

	// Idempotency: a repeated logout is not an error path. The middleware now
	// rejects the revoked bearer BEFORE the handler (a stronger outcome than a
	// second 200), so what is asserted here is 401-not-500: the second attempt
	// fails as an authentication failure, never as a server fault. The
	// handler-level "already revoked ⇒ no error" half is pinned at the store seam
	// (TestRevokeAPITokenIdempotent).
	if resp := c.do(c.signedReq("POST", "/v1/logout", nil)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("repeat logout status=%d, want 401 (revoked bearer stops at the middleware)", resp.StatusCode)
	}
}

// TestDeviceLogoutLeavesOtherDevicesAlone pins the blast radius: logging one
// device out must not sign the account out everywhere, and must not revoke the
// device registration (the same device can log in again).
func TestDeviceLogoutLeavesOtherDevicesAlone(t *testing.T) {
	h := newHarness(t)
	first := h.login(t, "logout-bob")
	second := h.login(t, "logout-bob") // same identity, second device
	if first.accountID != second.accountID {
		t.Fatalf("same subject resolved to two accounts: %s vs %s", first.accountID, second.accountID)
	}

	if resp := first.do(first.signedReq("POST", "/v1/logout", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status=%d", resp.StatusCode)
	}
	if resp := second.do(second.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("sibling device status=%d after another device logged out, want 200", resp.StatusCode)
	}

	resp := second.do(second.signedReq("GET", "/v1/devices", nil))
	var list struct {
		Devices []struct {
			Revoked bool `json:"revoked"`
		} `json:"devices"`
	}
	decode(t, resp, &list)
	if len(list.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(list.Devices))
	}
	for i, d := range list.Devices {
		if d.Revoked {
			t.Fatalf("device %d was revoked by a logout; logout revokes the TOKEN only", i)
		}
	}
}

// --- WorkOS lifecycle webhook (D18 phase 1) --------------------------------

// workosSignature builds the `t=<unix-ms>, v1=<hex>` header WorkOS sends, over
// HMAC-SHA256("<t>.<raw body>").
func workosSignature(secret string, body []byte, at time.Time) string {
	ms := at.UnixMilli()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.", ms)))
	mac.Write(body)
	return fmt.Sprintf("t=%d, v1=%s", ms, hex.EncodeToString(mac.Sum(nil)))
}

func webhookEvent(id, eventType, subject string) []byte {
	b, _ := json.Marshal(map[string]any{
		"id":    id,
		"event": eventType,
		"data":  map[string]string{"id": subject},
	})
	return b
}

// webhookEventFields builds a webhook envelope with an explicit `data` object,
// for event shapes webhookEvent's single-id form cannot express: session.*
// and organization_membership.* key the affected user by `user_id`, not `id`
// (their own `id` is the session/membership id instead), and user.updated
// additionally carries email/name (Wave C, gap 2.6).
func webhookEventFields(id, eventType string, data map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"id": id, "event": eventType, "data": data})
	return b
}

// postWebhook delivers body with the given signature header ("" ⇒ unsigned).
func (h *workosHarness) postWebhook(t *testing.T, body []byte, signature string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", h.srv.URL+"/portal/webhooks/workos", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if signature != "" {
		req.Header.Set("WorkOS-Signature", signature)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("webhook POST: %v", err)
	}
	return resp
}

const testWebhookSecret = "whsec_test_secret"

// TestWorkOSWebhookUserDeletedRevokesEverything is the D18 phase-1 headline: a
// verified user.deleted kills BOTH surfaces' credentials for that account — the
// device bearer and the portal cookie — while a bystander account is untouched.
func TestWorkOSWebhookUserDeletedRevokesEverything(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)

	const subject = "wh-victim"
	device := h.loginBroker(t, "wtok:"+subject)
	browser, csrf, account := h.signIn(t, subject)
	if account != device.accountID {
		t.Fatalf("portal and device resolved to different accounts: %s vs %s", account, device.accountID)
	}
	bystander := h.loginBroker(t, "wtok:wh-bystander")

	// Both surfaces work before.
	if resp := device.do(device.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-webhook device usage status=%d", resp.StatusCode)
	}
	resp, err := browser.Get(h.srv.URL + "/portal/api/overview")
	if err != nil {
		t.Fatalf("pre-webhook portal overview: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-webhook portal overview status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	_ = csrf

	body := webhookEvent("event_delete_1", "user.deleted", subject)
	resp = h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var ack struct {
		Status  string `json:"status"`
		EventID string `json:"event_id"`
	}
	decode(t, resp, &ack)
	if ack.Status != "revoked" || ack.EventID != "event_delete_1" {
		t.Fatalf("unexpected ack: %+v", ack)
	}

	// Device bearer + fresh PoP ⇒ 401.
	if resp := device.do(device.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-webhook device usage status=%d, want 401", resp.StatusCode)
	}
	// Portal cookie ⇒ 401.
	resp, err = browser.Get(h.srv.URL + "/portal/api/overview")
	if err != nil {
		t.Fatalf("post-webhook portal overview: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-webhook portal overview status=%d, want 401", resp.StatusCode)
	}
	// Bystander untouched.
	if resp := bystander.do(bystander.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("bystander device usage status=%d after another account's revocation, want 200", resp.StatusCode)
	}
}

// TestWorkOSWebhookUserUpdatedRefreshesProfile is user.updated's headline test
// (Wave C, gap 2.6): a verified delivery refreshes the linked account's
// display profile from the event's email/name fields, through the exact same
// seam a sign-in uses — and touches NOTHING else (no credential is minted or
// revoked).
func TestWorkOSWebhookUserUpdatedRefreshesProfile(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	const subject = "wh-updated"
	device := h.loginBroker(t, "wtok:"+subject)

	body := webhookEventFields("event_updated_1", "user.updated", map[string]any{
		"id":         subject,
		"email":      "updated@example.test",
		"first_name": "Grace",
		"last_name":  "Hopper",
	})
	resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var ack struct {
		Status string `json:"status"`
	}
	decode(t, resp, &ack)
	if ack.Status != "profile_refreshed" {
		t.Fatalf("status=%q, want profile_refreshed", ack.Status)
	}

	prof, err := h.store.AccountProfile(t.Context(), device.accountID)
	if err != nil {
		t.Fatalf("AccountProfile: %v", err)
	}
	if prof.Email != "updated@example.test" {
		t.Fatalf("stored email=%q, want updated@example.test", prof.Email)
	}
	if prof.DisplayName != "Grace Hopper" {
		t.Fatalf("stored display_name=%q, want Grace Hopper", prof.DisplayName)
	}

	// The device credential is untouched — user.updated is a display refresh,
	// never a revocation.
	if resp := device.do(device.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("device usage status=%d after user.updated, want 200 (profile refresh must not revoke anything)", resp.StatusCode)
	}
}

// TestWorkOSWebhookUserUpdatedUnknownSubjectIsNotError mirrors user.deleted's
// unknown-subject shape for user.updated: a user we never linked has nothing
// to refresh, and that is recorded as no_account, not an error.
func TestWorkOSWebhookUserUpdatedUnknownSubjectIsNotError(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	body := webhookEventFields("event_updated_unknown", "user.updated", map[string]any{
		"id": "never-linked-updated-subject", "email": "x@example.test",
	})
	resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200 body=%s", resp.StatusCode, readAll(resp))
	}
	var ack struct {
		Status string `json:"status"`
	}
	decode(t, resp, &ack)
	if ack.Status != "no_account" {
		t.Fatalf("status=%q, want no_account", ack.Status)
	}
}

// TestWorkOSWebhookSessionRevokedRevokesBrowserSessions is session.revoked's
// headline test: a verified delivery carrying the affected user's `user_id`
// revokes every LIVE browser session on the linked account, while the
// account's device credentials (a different surface entirely) keep working —
// this is WorkOS's own session revocation, not D18's account suspension.
func TestWorkOSWebhookSessionRevokedRevokesBrowserSessions(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	const subject = "wh-session-revoked"
	device := h.loginBroker(t, "wtok:"+subject)
	browser, _, account := h.signIn(t, subject)
	if account != device.accountID {
		t.Fatalf("portal and device resolved to different accounts: %s vs %s", account, device.accountID)
	}

	// Works before.
	if resp, err := browser.Get(h.srv.URL + "/portal/api/overview"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-webhook portal overview: err=%v status=%v", err, resp)
	}

	body := webhookEventFields("event_session_revoked_1", "session.revoked", map[string]any{
		"id": "session_01SOMEWORKOSSESSIONID", "user_id": subject,
	})
	resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var ack struct {
		Status string `json:"status"`
	}
	decode(t, resp, &ack)
	if ack.Status != "sessions_revoked" {
		t.Fatalf("status=%q, want sessions_revoked", ack.Status)
	}

	// The portal cookie is dead.
	pr, err := browser.Get(h.srv.URL + "/portal/api/overview")
	if err != nil {
		t.Fatalf("post-webhook portal overview: %v", err)
	}
	if pr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-webhook portal overview status=%d, want 401", pr.StatusCode)
	}
	// The device bearer is UNTOUCHED — session.revoked is the browser leg's own
	// concept; it must never reach the device API's credentials.
	if resp := device.do(device.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("device usage status=%d after session.revoked, want 200 (device tokens are a different surface)", resp.StatusCode)
	}
}

// TestWorkOSWebhookSessionRevokedUnknownSubjectIsNotError mirrors the
// unknown-subject shape for session.revoked.
func TestWorkOSWebhookSessionRevokedUnknownSubjectIsNotError(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	body := webhookEventFields("event_session_revoked_unknown", "session.revoked", map[string]any{
		"id": "session_x", "user_id": "never-linked-session-subject",
	})
	resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200 body=%s", resp.StatusCode, readAll(resp))
	}
	var ack struct {
		Status string `json:"status"`
	}
	decode(t, resp, &ack)
	if ack.Status != "no_account" {
		t.Fatalf("status=%q, want no_account", ack.Status)
	}
}

// TestWorkOSWebhookRejections covers every way a delivery must be refused, and
// pins that a refused delivery leaves NO ledger row (nothing is recorded until
// the signature verifies).
func TestWorkOSWebhookRejections(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	device := h.loginBroker(t, "wtok:wh-reject")

	body := webhookEvent("event_reject_1", "user.deleted", "wh-reject")
	cases := []struct {
		name      string
		signature string
	}{
		{"unsigned", ""},
		{"malformed header", "not-a-signature"},
		{"missing v1", fmt.Sprintf("t=%d", time.Now().UnixMilli())},
		{"wrong secret", workosSignature("whsec_wrong", body, time.Now())},
		{"stale timestamp", workosSignature(testWebhookSecret, body, time.Now().Add(-10*time.Minute))},
		{"future timestamp", workosSignature(testWebhookSecret, body, time.Now().Add(10*time.Minute))},
		{"body tampered after signing", workosSignature(testWebhookSecret, []byte(`{"id":"x","event":"user.deleted"}`), time.Now())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.postWebhook(t, body, tc.signature)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status=%d, want 401 body=%s", resp.StatusCode, readAll(resp))
			}
			resp.Body.Close()
			if _, err := h.store.GetWorkOSEvent(t.Context(), "event_reject_1"); err == nil {
				t.Fatal("a refused delivery must not be recorded in the event ledger")
			}
		})
	}

	// And nothing was revoked by any of it.
	if resp := device.do(device.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("device usage status=%d after refused deliveries, want 200", resp.StatusCode)
	}
}

// TestWorkOSWebhookUnconfiguredFailsClosed pins the posture: with no signing
// secret the route answers 501 and does nothing. It must never accept an
// unverified delivery, because that would make account revocation available to
// anyone who can reach the origin.
func TestWorkOSWebhookUnconfiguredFailsClosed(t *testing.T) {
	h := newWebhookHarness(t, "")
	device := h.loginBroker(t, "wtok:wh-unconfigured")

	body := webhookEvent("event_unconfigured", "user.deleted", "wh-unconfigured")
	// Even a delivery signed with SOME secret is refused — there is nothing to
	// verify against.
	resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status=%d, want 501 body=%s", resp.StatusCode, readAll(resp))
	}
	if resp := h.postWebhook(t, body, ""); resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("unsigned status=%d, want 501", resp.StatusCode)
	}
	if resp := device.do(device.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("device usage status=%d, want 200 (nothing may be revoked by a 501 route)", resp.StatusCode)
	}
}

// TestWorkOSWebhookReplayIsANoOp pins at-least-once handling: a redelivered
// event id is acknowledged 200 as a duplicate WITHOUT re-processing.
func TestWorkOSWebhookReplayIsANoOp(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	const subject = "wh-replay"
	device := h.loginBroker(t, "wtok:"+subject)

	body := webhookEvent("event_replay_1", "user.deleted", subject)
	resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	var first struct {
		Status string `json:"status"`
	}
	decode(t, resp, &first)
	if first.Status != "revoked" {
		t.Fatalf("first delivery status=%q, want revoked", first.Status)
	}
	if resp := device.do(device.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("device still authenticates after revocation: %d", resp.StatusCode)
	}

	// Redelivery: same id, a freshly-signed envelope (WorkOS re-signs on retry).
	resp = h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replay status=%d, want 200 body=%s", resp.StatusCode, readAll(resp))
	}
	var second struct {
		Status string `json:"status"`
	}
	decode(t, resp, &second)
	if second.Status != "duplicate" {
		t.Fatalf("replay status=%q, want duplicate", second.Status)
	}
}

// TestWorkOSWebhookAcknowledgesUnhandled pins phase-1 honesty: an event type we
// do not act on, and a user.deleted for a subject we never linked, are both
// acknowledged + recorded rather than erroring or silently pretending to have
// handled something.
func TestWorkOSWebhookAcknowledgesUnhandled(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	device := h.loginBroker(t, "wtok:wh-ack")

	cases := []struct {
		name, id, eventType, subject, wantStatus string
	}{
		// session.revoked IS a handled type as of Wave C (gap 2.6) — but this
		// fixture's `data` carries only `id` (webhookEvent's shape), never
		// `user_id`, which is what session.* keys the affected user by. So this
		// specific delivery still resolves to "missing subject" ⇒ acknowledged
		// — see TestWorkOSWebhookSessionRevokedRevokesBrowserSessions for the
		// handled shape with a real `user_id`.
		{"session.revoked with no user_id field resolves like a missing subject", "event_ack_1", "session.revoked", "wh-ack", "acknowledged"},
		{"unknown type is recorded only", "event_ack_2", "organization.updated", "wh-ack", "acknowledged"},
		{"organization_membership.created is recorded only", "event_ack_5", "organization_membership.created", "wh-ack", "acknowledged"},
		{"organization_membership.updated is recorded only", "event_ack_6", "organization_membership.updated", "wh-ack", "acknowledged"},
		{"organization_membership.deleted is recorded only", "event_ack_7", "organization_membership.deleted", "wh-ack", "acknowledged"},
		{"unknown subject is not an error", "event_ack_3", "user.deleted", "never-linked-subject", "no_account"},
		{"missing subject is not an error", "event_ack_4", "user.deleted", "", "acknowledged"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := webhookEvent(tc.id, tc.eventType, tc.subject)
			resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d, want 200 body=%s", resp.StatusCode, readAll(resp))
			}
			var ack struct {
				Status string `json:"status"`
			}
			decode(t, resp, &ack)
			if ack.Status != tc.wantStatus {
				t.Fatalf("status=%q, want %q", ack.Status, tc.wantStatus)
			}
			ev, err := h.store.GetWorkOSEvent(t.Context(), tc.id)
			if err != nil {
				t.Fatalf("event not recorded: %v", err)
			}
			if ev.ProcessedAt == nil {
				t.Fatal("an acknowledged event must be stamped processed")
			}
		})
	}

	// None of that revoked anything.
	if resp := device.do(device.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("device usage status=%d after unhandled events, want 200", resp.StatusCode)
	}
}

// TestWorkOSWebhookRejectsMalformedEnvelope pins that a correctly-SIGNED but
// unusable envelope is a 400, not a 500 or a silent 200.
func TestWorkOSWebhookRejectsMalformedEnvelope(t *testing.T) {
	h := newWebhookHarness(t, testWebhookSecret)
	for _, body := range [][]byte{
		[]byte(`{`),
		[]byte(`{"event":"user.deleted"}`),       // no id
		[]byte(`{"id":"event_no_type"}`),         // no event
		[]byte(`{"id":"","event":"","data":{}}`), // empty
	} {
		resp := h.postWebhook(t, body, workosSignature(testWebhookSecret, body, time.Now()))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("body %q: status=%d, want 400", body, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// --- canonical host (R5) ---------------------------------------------------

// newHostHarness builds a dev-auth server with canonical hosts configured.
func newHostHarness(t *testing.T, portalHost, apiHost string) *harness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()
	handler := api.New(api.Options{
		Store:           apiStore,
		Queue:           jobs.NewPGQueue(apiStore),
		Verifier:        identity.NewDevAuth(),
		ExternalBaseURL: base,
		RateLimit:       &api.RateLimitConfig{},
		Attestor:        admAttestor{verified: true},
		Credentials:     jobs.StaticCredentials{Key: "test-key"},
		PortalHost:      portalHost,
		APIHost:         apiHost,
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{srv: srv, store: s}
}

// getWithHost issues a bare GET with an explicit Host header.
func getWithHost(t *testing.T, h *harness, path, host string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", h.srv.URL+path, nil)
	req.Host = host
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s (Host %s): %v", path, host, err)
	}
	return resp
}

// TestCanonicalHostEnforcement is the R5 fence: each surface answers only on its
// own name, the check runs BEFORE authentication (a wrong host is 421, never a
// 401 that leaks whether a credential would have worked), /healthz is
// host-agnostic, and a Host carrying a port still matches.
func TestCanonicalHostEnforcement(t *testing.T) {
	const portalHost, apiHost = "app.example", "cloud.example"
	h := newHostHarness(t, portalHost, apiHost)

	cases := []struct {
		name, path, host string
		want             int
	}{
		{"portal path on the portal host", "/portal/api/session", portalHost, http.StatusUnauthorized},
		{"portal path on the api host", "/portal/api/session", apiHost, http.StatusMisdirectedRequest},
		{"portal path on a stranger host", "/portal/api/session", "evil.example", http.StatusMisdirectedRequest},
		{"api path on the api host", "/v1/usage", apiHost, http.StatusUnauthorized},
		{"api path on the portal host", "/v1/usage", portalHost, http.StatusMisdirectedRequest},
		{"api bootstrap on the wrong host", "/v1/auth/nonce", portalHost, http.StatusMisdirectedRequest},
		{"healthz is host-agnostic", "/healthz", "whatever.example", http.StatusOK},
		{"host with port normalizes", "/v1/usage", apiHost + ":8443", http.StatusUnauthorized},
		{"host case normalizes", "/v1/usage", "CLOUD.Example", http.StatusUnauthorized},
		{"trailing-dot host normalizes", "/portal/api/session", portalHost + ".", http.StatusUnauthorized},
		{"a lookalike prefix is not the portal", "/portalish", portalHost, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := getWithHost(t, h, tc.path, tc.host)
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("GET %s Host=%s: status=%d, want %d", tc.path, tc.host, resp.StatusCode, tc.want)
			}
			if tc.want == http.StatusMisdirectedRequest {
				var body struct {
					Error string `json:"error"`
					Code  string `json:"code"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
					t.Fatalf("421 body is not JSON: %v", err)
				}
				if body.Code != "wrong_host" || body.Error == "" {
					t.Fatalf("421 body = %+v, want a structured wrong_host error", body)
				}
			}
		})
	}
}

// TestCanonicalHostOffByDefault pins that the unconfigured deployment (today's
// single-host staging) accepts any Host, so this landing changed nothing there.
func TestCanonicalHostOffByDefault(t *testing.T) {
	h := newHarness(t) // no PortalHost/APIHost
	for _, path := range []string{"/v1/auth/nonce", "/healthz"} {
		resp := getWithHost(t, h, path, "anything.example")
		resp.Body.Close()
		if resp.StatusCode == http.StatusMisdirectedRequest {
			t.Fatalf("GET %s was host-refused with enforcement unconfigured", path)
		}
	}
}

// TestCanonicalHostOneSurfaceOnly pins the independence of the two halves: with
// only the API host configured, the portal surface stays unenforced.
func TestCanonicalHostOneSurfaceOnly(t *testing.T) {
	h := newHostHarness(t, "", "cloud.example")
	if resp := getWithHost(t, h, "/portal/api/session", "anything.example"); resp.StatusCode == http.StatusMisdirectedRequest {
		t.Fatal("portal was host-refused although PortalHost is unset")
	}
	if resp := getWithHost(t, h, "/v1/usage", "anything.example"); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("api host not enforced: status=%d", resp.StatusCode)
	}
}

// --- mutual credential rejection (R5) --------------------------------------

// TestPortalCookieGrantsNothingOnDeviceAPI pins one half of R5's mutual
// rejection: a perfectly valid portal session cookie carries no authority on
// /v1 — the device API demands a bearer + proof-of-possession, which a browser
// cannot mint.
func TestPortalCookieGrantsNothingOnDeviceAPI(t *testing.T) {
	h := newHarness(t)
	pc := h.portalLogin(t, "cross-alice")

	// The cookie jar attaches the session cookie automatically.
	for _, path := range []string{"/v1/usage", "/v1/devices", "/v1/results"} {
		resp := pc.get(path)
		body := readAll(resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET %s with a portal cookie: status=%d, want 401 body=%s", path, resp.StatusCode, body)
		}
	}
	// Even PAIRED with the CSRF token — which is the browser's only other
	// credential — the device API stays shut.
	req, _ := http.NewRequest("POST", pc.base+"/v1/logout", nil)
	req.Header.Set(csrfHeader, pc.csrf)
	resp, err := pc.http.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /v1/logout with cookie+CSRF: status=%d, want 401", resp.StatusCode)
	}
}

// TestDeviceBearerGrantsNothingOnPortal pins the other half: a valid device
// bearer WITH a valid proof-of-possession is worthless on /portal/api/* — the
// portal demands a session cookie, and a device never holds one.
func TestDeviceBearerGrantsNothingOnPortal(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "cross-bob")

	// Sanity: the same credential works on its own surface.
	if resp := c.do(c.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("device usage status=%d, want 200", resp.StatusCode)
	}

	for _, path := range []string{"/portal/api/session", "/portal/api/overview", "/portal/api/devices"} {
		resp := c.do(c.signedReq("GET", path, nil))
		body := readAll(resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET %s with a device bearer+PoP: status=%d, want 401 body=%s", path, resp.StatusCode, body)
		}
		if strings.Contains(body, "csrf") {
			t.Fatalf("GET %s failed on CSRF rather than on the missing session: %s", path, body)
		}
	}
}

// --- E9: portal SPA wiring pin ---------------------------------------------

// stubSPA stands in for webcloud.Handler(). The pin is about the MOUNT (that
// Handler() still routes UI paths to Options.PortalSPA behind the specific
// /portal/api and /portal/auth patterns), not about the embedded assets, which
// webcloud has its own test for.
func stubSPA() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>portal</title>"))
	})
}

func newSPAHarness(t *testing.T, spa http.Handler) *harness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()
	handler := api.New(api.Options{
		Store:           apiStore,
		Queue:           jobs.NewPGQueue(apiStore),
		Verifier:        identity.NewDevAuth(),
		ExternalBaseURL: base,
		RateLimit:       &api.RateLimitConfig{},
		Attestor:        admAttestor{verified: true},
		Credentials:     jobs.StaticCredentials{Key: "test-key"},
		PortalSPA:       spa,
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{srv: srv, store: s}
}

// TestPortalSPAWiring is the E9 pin: with a PortalSPA the UI routes serve HTML
// (including the client-side-route fallback), with none they 404 — so a future
// refactor cannot silently drop the SPA mount, and the BFF endpoints keep their
// precedence over the catch-all either way.
func TestPortalSPAWiring(t *testing.T) {
	withSPA := newSPAHarness(t, stubSPA())
	for _, path := range []string{"/portal/", "/portal/anything", "/portal/settings/privacy"} {
		resp, err := withSPA.srv.Client().Get(withSPA.srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body := readAll(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status=%d, want 200 (SPA fallback) body=%s", path, resp.StatusCode, body)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("GET %s: Content-Type=%q, want text/html", path, ct)
		}
	}
	// The BFF endpoints keep precedence over the catch-all: an unauthenticated
	// /portal/api/* must still be the API's 401, never the SPA's HTML.
	resp, err := withSPA.srv.Client().Get(withSPA.srv.URL + "/portal/api/session")
	if err != nil {
		t.Fatalf("GET /portal/api/session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/portal/api/session served status=%d, want 401 (the SPA must not shadow the BFF)", resp.StatusCode)
	}

	withoutSPA := newSPAHarness(t, nil)
	for _, path := range []string{"/portal/", "/portal/anything"} {
		resp, err := withoutSPA.srv.Client().Get(withoutSPA.srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s with no SPA: status=%d, want 404", path, resp.StatusCode)
		}
	}
}
