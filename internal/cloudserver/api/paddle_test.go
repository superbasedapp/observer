package api_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// paddle_test.go covers the W9 Paddle webhook: signature verification (valid,
// invalid, stale), fail-closed-when-unconfigured, idempotent intake, and that a
// verified activation actually grants the plan end to end.

const paddleSecret = "pdl_wh_test_secret"

// signedPaddle POSTs a body with a valid Paddle-Signature (ts=<sec>;h1=<hmac>).
func signedPaddle(t *testing.T, base string, body []byte, ts time.Time, secret string) *http.Response {
	t.Helper()
	sec := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sec))
	mac.Write([]byte(":"))
	mac.Write(body)
	sig := fmt.Sprintf("ts=%s;h1=%s", sec, hex.EncodeToString(mac.Sum(nil)))
	req, _ := http.NewRequest("POST", base+"/portal/webhooks/paddle", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Paddle-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post webhook: %v", err)
	}
	return resp
}

// paddleActivationBody builds a subscription.activated delivery. nonce is the
// server-minted checkout nonce (F2): a real, server-initiated checkout carries
// it in custom_data.checkout_nonce, and the webhook requires it to bind.
func paddleActivationBody(accountID, nonce string) []byte {
	return []byte(`{
		"event_id": "evt_activation_1",
		"event_type": "subscription.activated",
		"occurred_at": "2026-06-15T12:00:00Z",
		"data": {
			"id": "sub_1", "customer_id": "ctm_1", "status": "active",
			"custom_data": {"account_id": "` + accountID + `", "checkout_nonce": "` + nonce + `"},
			"current_billing_period": {"ends_at": "2026-07-15T12:00:00Z"},
			"items": [{"price": {"id": "pri_test_plus"}}]
		}
	}`)
}

// mintPaddleNonce creates a server-side checkout intent for accountID and returns
// the raw nonce a server-initiated checkout would present.
func mintPaddleNonce(t *testing.T, h *harness, accountID string) string {
	t.Helper()
	nonce, _, err := h.store.CreateCheckoutIntent(t.Context(), accountID, "pri_test_plus", time.Hour, time.Now())
	if err != nil {
		t.Fatalf("CreateCheckoutIntent: %v", err)
	}
	return nonce
}

func TestPaddleWebhookVerifiedActivationGrantsPlan(t *testing.T) {
	h := newHarnessPaddle(t, paddleSecret)
	c := h.login(t, "frank") // creates a real account we can attribute to
	body := paddleActivationBody(c.accountID, mintPaddleNonce(t, h, c.accountID))

	resp := signedPaddle(t, c.base, body, time.Now(), paddleSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verified webhook status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var out struct {
		Status  string `json:"status"`
		Applied bool   `json:"applied"`
	}
	decode(t, resp, &out)
	if out.Status != "processed" || !out.Applied {
		t.Fatalf("intake=%+v, want processed+applied", out)
	}
	// The account now resolves the paid plan (via the /v1/usage caps).
	uresp := c.do(c.signedReq("GET", "/v1/usage", nil))
	var snap struct {
		DailyCap   int `json:"daily_cap"`
		MonthlyCap int `json:"monthly_cap"`
	}
	decode(t, uresp, &snap)
	if snap.DailyCap != 25 || snap.MonthlyCap != 500 {
		t.Fatalf("caps after activation = %d/%d, want 25/500 (plus_beta)", snap.DailyCap, snap.MonthlyCap)
	}
}

func TestPaddleWebhookRejectsBadSignature(t *testing.T) {
	h := newHarnessPaddle(t, paddleSecret)
	c := h.login(t, "grace")
	body := paddleActivationBody(c.accountID, "") // signature is rejected before the nonce matters

	// Wrong secret ⇒ bad HMAC ⇒ 401, and NOTHING is applied.
	resp := signedPaddle(t, c.base, body, time.Now(), "wrong-secret")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad-signature status=%d, want 401 (body=%s)", resp.StatusCode, readAll(resp))
	}
	// Stale timestamp ⇒ 401 even with a correct HMAC over that timestamp.
	resp = signedPaddle(t, c.base, body, time.Now().Add(-1*time.Hour), paddleSecret)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale-timestamp status=%d, want 401", resp.StatusCode)
	}
	// The account stayed on free (nothing applied).
	uresp := c.do(c.signedReq("GET", "/v1/usage", nil))
	var snap struct {
		DailyCap int `json:"daily_cap"`
	}
	decode(t, uresp, &snap)
	if snap.DailyCap != 20 {
		t.Fatalf("caps after rejected webhooks = %d, want 20 (free — nothing applied)", snap.DailyCap)
	}
}

func TestPaddleWebhookFailsClosedWhenUnconfigured(t *testing.T) {
	h := newHarness(t) // default harness: no Paddle secret
	c := h.login(t, "heidi")
	resp := signedPaddle(t, c.base, paddleActivationBody(c.accountID, ""), time.Now(), paddleSecret)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("unconfigured webhook status=%d, want 501 (fail-closed)", resp.StatusCode)
	}
}

func TestPaddleWebhookIdempotentReplay(t *testing.T) {
	h := newHarnessPaddle(t, paddleSecret)
	c := h.login(t, "ivan")
	body := paddleActivationBody(c.accountID, mintPaddleNonce(t, h, c.accountID))

	if resp := signedPaddle(t, c.base, body, time.Now(), paddleSecret); resp.StatusCode != http.StatusOK {
		t.Fatalf("first delivery status=%d", resp.StatusCode)
	}
	resp := signedPaddle(t, c.base, body, time.Now(), paddleSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replay status=%d", resp.StatusCode)
	}
	var out struct {
		Status string `json:"status"`
	}
	decode(t, resp, &out)
	if out.Status != "duplicate" {
		t.Fatalf("replay status=%q, want duplicate", out.Status)
	}
}

// TestPaddleWebhookBindingRefusedWithoutNonce is the F2 core at the HTTP edge: a
// VERIFIED (correctly signed) delivery whose custom_data names an account but
// carries no server-minted checkout nonce is 200-acknowledged but NOT applied —
// the untrusted account id alone can no longer bind a subscription or grant a
// plan. (A forged self-initiated checkout can set custom_data.account_id but
// cannot produce a valid nonce.)
func TestPaddleWebhookBindingRefusedWithoutNonce(t *testing.T) {
	h := newHarnessPaddle(t, paddleSecret)
	c := h.login(t, "mallory")
	body := paddleActivationBody(c.accountID, "") // valid signature, NO nonce

	resp := signedPaddle(t, c.base, body, time.Now(), paddleSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refused-binding status=%d, want 200 (acknowledged, not 5xx)", resp.StatusCode)
	}
	var out struct {
		Applied bool   `json:"applied"`
		Outcome string `json:"outcome"`
	}
	decode(t, resp, &out)
	if out.Applied || out.Outcome != "binding_refused" {
		t.Fatalf("intake=%+v, want !applied outcome=binding_refused", out)
	}
	// The account stayed on free — nothing was granted.
	uresp := c.do(c.signedReq("GET", "/v1/usage", nil))
	var snap struct {
		DailyCap int `json:"daily_cap"`
	}
	decode(t, uresp, &snap)
	if snap.DailyCap != 20 {
		t.Fatalf("caps after refused binding = %d, want 20 (free — nothing applied)", snap.DailyCap)
	}
}

// TestPaddleCheckoutBindingEndToEnd exercises the full server-initiated checkout
// binding: the portal mints a checkout intent (server-set custom_data + nonce),
// and only a webhook carrying THAT nonce binds the subscription to the account.
func TestPaddleCheckoutBindingEndToEnd(t *testing.T) {
	h := newHarnessPaddle(t, paddleSecret)
	pc := h.portalLogin(t, "checkout-user")

	// Server-initiated checkout: mint the intent.
	resp := pc.mutate("POST", "/portal/api/billing/checkout", []byte(`{"price_id":"pri_test_plus"}`), pc.csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("checkout status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var ck struct {
		PriceID    string `json:"price_id"`
		CustomData struct {
			AccountID     string `json:"account_id"`
			CheckoutNonce string `json:"checkout_nonce"`
		} `json:"custom_data"`
	}
	decode(t, resp, &ck)
	if ck.CustomData.AccountID != pc.accountID || ck.CustomData.CheckoutNonce == "" {
		t.Fatalf("checkout custom_data=%+v, want account=%s + non-empty nonce", ck.CustomData, pc.accountID)
	}

	// The webhook carrying the server-set custom_data binds the subscription.
	body := []byte(`{
		"event_id": "evt_ck_bind",
		"event_type": "subscription.activated",
		"occurred_at": "2026-06-15T12:00:00Z",
		"data": {
			"id": "sub_ck", "customer_id": "ctm_ck", "status": "active",
			"custom_data": {"account_id": "` + ck.CustomData.AccountID + `", "checkout_nonce": "` + ck.CustomData.CheckoutNonce + `"},
			"current_billing_period": {"ends_at": "2026-07-15T12:00:00Z"},
			"items": [{"price": {"id": "pri_test_plus"}}]
		}
	}`)
	wresp := signedPaddle(t, h.srv.URL, body, time.Now(), paddleSecret)
	if wresp.StatusCode != http.StatusOK {
		t.Fatalf("bound-webhook status=%d body=%s", wresp.StatusCode, readAll(wresp))
	}
	var out struct {
		Applied bool   `json:"applied"`
		Outcome string `json:"outcome"`
	}
	decode(t, wresp, &out)
	if !out.Applied || out.Outcome != "applied" {
		t.Fatalf("bound intake=%+v, want applied", out)
	}
	// The portal Billing surface now reflects the active paid subscription.
	bresp := pc.get("/portal/api/billing")
	var bill struct {
		HasSubscription bool `json:"has_subscription"`
		Subscription    struct {
			Status   string `json:"status"`
			PlanName string `json:"plan_name"`
		} `json:"subscription"`
	}
	decode(t, bresp, &bill)
	if !bill.HasSubscription || bill.Subscription.Status != "active" || bill.Subscription.PlanName != "plus_beta" {
		t.Fatalf("billing view=%+v, want active plus_beta subscription", bill)
	}
}

// ---------------------------------------------------------------------------
// 2026-09-11 review remediation (adversarial review of baf3bc4d5). See
// docs/plans/arc2-stream5-paddle-notes-2026-09-02.md's 2026-09-11 delta
// section for the one-line-per-finding summary.
// ---------------------------------------------------------------------------

// TestPortalCheckoutRefusedWhenAlreadySubscribed is P2-3's portal-side half:
// a second checkout must be refused BEFORE a nonce is even minted when the
// account already holds a live subscription — closing the window where a
// customer could be charged twice by Paddle before this system ever sees
// the store-side refusal.
func TestPortalCheckoutRefusedWhenAlreadySubscribed(t *testing.T) {
	h := newHarnessPaddle(t, paddleSecret)
	pc := h.portalLogin(t, "already-subscribed")

	// First checkout binds a live subscription.
	resp := pc.mutate("POST", "/portal/api/billing/checkout", []byte(`{"price_id":"pri_test_plus"}`), pc.csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first checkout status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var ck struct {
		CustomData struct {
			AccountID     string `json:"account_id"`
			CheckoutNonce string `json:"checkout_nonce"`
		} `json:"custom_data"`
	}
	decode(t, resp, &ck)
	body := []byte(`{
		"event_id": "evt_already_sub_bind",
		"event_type": "subscription.activated",
		"occurred_at": "2026-06-15T12:00:00Z",
		"data": {
			"id": "sub_already", "customer_id": "ctm_already", "status": "active",
			"custom_data": {"account_id": "` + ck.CustomData.AccountID + `", "checkout_nonce": "` + ck.CustomData.CheckoutNonce + `"},
			"current_billing_period": {"ends_at": "2026-07-15T12:00:00Z"},
			"items": [{"price": {"id": "pri_test_plus"}}]
		}
	}`)
	wresp := signedPaddle(t, h.srv.URL, body, time.Now(), paddleSecret)
	if wresp.StatusCode != http.StatusOK {
		t.Fatalf("bind webhook status=%d body=%s", wresp.StatusCode, readAll(wresp))
	}

	// A second checkout attempt while that subscription is live must be
	// refused BEFORE a nonce is even minted (409, never reaching Paddle).
	resp2 := pc.mutate("POST", "/portal/api/billing/checkout", []byte(`{"price_id":"pri_test_plus"}`), pc.csrf)
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("second checkout status=%d body=%s, want 409", resp2.StatusCode, readAll(resp2))
	}
}

// TestPaddleSecondLiveSubscriptionRefusedNotError is P2-3's webhook-side
// half: even if a second, DISTINCT subscription id somehow reaches the
// webhook (bypassing the portal's own pre-check above — e.g. an operator-
// initiated checkout, or a race), the delivery must be refused gracefully,
// never a raw 500 from the paddle_subscriptions_one_live constraint.
func TestPaddleSecondLiveSubscriptionRefusedNotError(t *testing.T) {
	h := newHarnessPaddle(t, paddleSecret)
	c := h.login(t, "second-live-webhook")
	body1 := paddleActivationBody(c.accountID, mintPaddleNonce(t, h, c.accountID))
	if resp := signedPaddle(t, c.base, body1, time.Now(), paddleSecret); resp.StatusCode != http.StatusOK {
		t.Fatalf("first activation status=%d body=%s", resp.StatusCode, readAll(resp))
	}

	nonce2, _, err := h.store.CreateCheckoutIntent(t.Context(), c.accountID, "pri_test_plus", time.Hour, time.Now())
	if err != nil {
		t.Fatalf("CreateCheckoutIntent: %v", err)
	}
	body2 := []byte(`{
		"event_id": "evt_second_live_webhook",
		"event_type": "subscription.activated",
		"occurred_at": "2026-06-15T12:00:00Z",
		"data": {
			"id": "sub_second_live", "customer_id": "ctm_second_live", "status": "active",
			"custom_data": {"account_id": "` + c.accountID + `", "checkout_nonce": "` + nonce2 + `"},
			"current_billing_period": {"ends_at": "2026-07-15T12:00:00Z"},
			"items": [{"price": {"id": "pri_test_plus"}}]
		}
	}`)
	resp := signedPaddle(t, c.base, body2, time.Now(), paddleSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second-live webhook status=%d body=%s, want 200 (refused gracefully, never a raw constraint error)", resp.StatusCode, readAll(resp))
	}
	var out struct {
		Applied bool   `json:"applied"`
		Outcome string `json:"outcome"`
	}
	decode(t, resp, &out)
	if out.Applied || out.Outcome != "refused_second_live" {
		t.Fatalf("second-live webhook intake=%+v, want !Applied outcome=refused_second_live", out)
	}
}

// TestPaddleAuditUsesResolvedAccountNotCustomData is P3-d's core: the audit
// trail must record the RESOLVED account intake acted on, never the
// untrusted custom_data.account_id — pinned with a delivery that carries NO
// custom_data at all (the normal shape of a renewal on an already-bound
// subscription, A1) so the only way the audit row can carry an account at
// all is if it resolved one from the existing binding.
func TestPaddleAuditUsesResolvedAccountNotCustomData(t *testing.T) {
	h := newHarnessPaddle(t, paddleSecret)
	c := h.login(t, "audit-resolved")
	bindBody := paddleActivationBody(c.accountID, mintPaddleNonce(t, h, c.accountID))
	if resp := signedPaddle(t, c.base, bindBody, time.Now(), paddleSecret); resp.StatusCode != http.StatusOK {
		t.Fatalf("bind status=%d body=%s", resp.StatusCode, readAll(resp))
	}

	renewBody := []byte(`{
		"event_id": "evt_audit_renew",
		"event_type": "transaction.completed",
		"occurred_at": "2026-07-15T12:00:00Z",
		"data": {
			"id": "txn_audit_renew", "customer_id": "ctm_1", "subscription_id": "sub_1",
			"current_billing_period": {"ends_at": "2026-08-15T12:00:00Z"},
			"items": [{"price": {"id": "pri_test_plus"}}]
		}
	}`)
	resp := signedPaddle(t, c.base, renewBody, time.Now(), paddleSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("renewal status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var out struct {
		Applied bool `json:"applied"`
	}
	decode(t, resp, &out)
	if !out.Applied {
		t.Fatalf("renewal intake=%+v, want applied", out)
	}

	var acctID string
	if err := h.store.Pool().QueryRow(t.Context(),
		`SELECT account_id::text FROM security_audit_events
		  WHERE event_type = 'paddle_transaction.completed_applied'
		  ORDER BY created_at DESC LIMIT 1`).Scan(&acctID); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if acctID != c.accountID {
		t.Fatalf("audit account_id=%q, want the resolved bound account %q (never the empty custom_data)", acctID, c.accountID)
	}
}

// TestPaddleDecodeNonUUIDAccountIDSanitizedToEmpty is P2-1's api-decode half:
// a custom_data.account_id that does not even parse as a UUID must decode to
// an EMPTY store.PaddleEvent.AccountID — never survive verbatim into the
// store's own gates, where it used to hit a `::uuid` cast and error forever.
// A syntactically valid (even if foreign) UUID passes through unchanged —
// the store's own account-existence check is what handles that case.
func TestPaddleDecodeNonUUIDAccountIDSanitizedToEmpty(t *testing.T) {
	body := []byte(`{
		"event_id": "evt_decode_forged", "event_type": "subscription.activated",
		"data": {
			"id": "sub_decode_forged", "customer_id": "ctm_1", "status": "active",
			"custom_data": {"account_id": "not-a-uuid", "checkout_nonce": "n"}
		}
	}`)
	ev, err := api.DecodePaddleWebhookEnvelope(body, time.Now())
	if err != nil {
		t.Fatalf("DecodePaddleWebhookEnvelope: %v", err)
	}
	if ev.AccountID != "" {
		t.Fatalf("AccountID=%q, want empty (non-UUID sanitized at decode)", ev.AccountID)
	}

	body2 := []byte(`{
		"event_id": "evt_decode_valid", "event_type": "subscription.activated",
		"data": {
			"id": "sub_decode_valid", "customer_id": "ctm_1", "status": "active",
			"custom_data": {"account_id": "00000000-0000-4000-8000-0000000000ff", "checkout_nonce": "n"}
		}
	}`)
	ev2, err := api.DecodePaddleWebhookEnvelope(body2, time.Now())
	if err != nil {
		t.Fatalf("DecodePaddleWebhookEnvelope: %v", err)
	}
	if ev2.AccountID != "00000000-0000-4000-8000-0000000000ff" {
		t.Fatalf("AccountID=%q, want the well-formed UUID passed through unchanged", ev2.AccountID)
	}
}

// TestPaddleWebhookExcessH1CandidatesIgnoredBeyondCap is P3-b's core:
// verifyPaddleSignature bounds candidate h1= values to 4 — a correct h1
// beyond the cap is never reached, so an attacker cannot force unbounded
// HMAC computation per delivery by padding the header with many h1= entries.
func TestPaddleWebhookExcessH1CandidatesIgnoredBeyondCap(t *testing.T) {
	h := newHarnessPaddleFull(t, func(o *api.Options) {
		o.PaddleWebhookSecret = "current-secret"
	})
	body := []byte(`{"event_id":"evt_cap_1","event_type":"subscription.activated","data":{"id":"sub_cap_1","status":"active"}}`)
	// 4 bogus + the real secret in 5th position: capped at 4 candidates, so
	// the real one is never checked -> rejected.
	resp := signedPaddleMulti(t, h.srv.URL, body, time.Now(), []string{"bogus-1", "bogus-2", "bogus-3", "bogus-4", "current-secret"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("5th-position real secret status=%d, want 401 (h1 candidates capped at 4)", resp.StatusCode)
	}

	// The same real secret WITHIN the first 4 candidates still verifies.
	body2 := []byte(`{"event_id":"evt_cap_2","event_type":"subscription.activated","data":{"id":"sub_cap_2","status":"active"}}`)
	resp2 := signedPaddleMulti(t, h.srv.URL, body2, time.Now(), []string{"bogus-1", "bogus-2", "current-secret", "bogus-3"})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("4th-position real secret status=%d body=%s, want 200", resp2.StatusCode, readAll(resp2))
	}
}

// newHarnessPaddleFull builds a harness with full control over Paddle wiring
// (webhook secrets incl. rotation, and the checkout catalogue) — a local
// specialization of api_test.go's newHarnessPaddle for A3/A6/A10, which need
// Options fields that helper doesn't expose. opts may be nil (zero-value
// Paddle wiring — the honest dark posture).
func newHarnessPaddleFull(t *testing.T, opts func(*api.Options)) *harness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	s.SetDeletionJournal(mustJournal(t))
	apiStore.SetDeletionJournal(mustJournal(t))
	priceMap := map[string]store.PaddlePlan{"pri_test_plus": {Name: "plus_beta", Version: 1}}
	s.SetPaddlePriceMap(priceMap)
	apiStore.SetPaddlePriceMap(priceMap)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()
	o := api.Options{
		Store:           apiStore,
		Queue:           jobs.NewPGQueue(apiStore),
		Verifier:        identity.NewDevAuth(),
		ExternalBaseURL: base,
		RateLimit:       &api.RateLimitConfig{},
		Attestor:        admAttestor{verified: true},
		Credentials:     jobs.StaticCredentials{Key: "test-key"},
	}
	if opts != nil {
		opts(&o)
	}
	handler := api.New(o).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{srv: srv, store: s}
}

// signedPaddleMulti POSTs a body with a Paddle-Signature header carrying ONE
// h1 per secret in `secrets` (the shape Paddle sends during ITS OWN secret
// rotation — A3 / gap 1.7). An empty `secrets` slice produces a header with
// ts but no h1 at all.
func signedPaddleMulti(t *testing.T, base string, body []byte, ts time.Time, secrets []string) *http.Response {
	t.Helper()
	sec := strconv.FormatInt(ts.Unix(), 10)
	var sb strings.Builder
	sb.WriteString("ts=" + sec)
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(sec))
		mac.Write([]byte(":"))
		mac.Write(body)
		sb.WriteString(";h1=" + hex.EncodeToString(mac.Sum(nil)))
	}
	req, _ := http.NewRequest("POST", base+"/portal/webhooks/paddle", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Paddle-Signature", sb.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post webhook: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// A3 (gap 1.7): webhook-secret rotation — multiple h1 values on the header,
// and multiple configured secrets, must never be an outage.
// ---------------------------------------------------------------------------

func TestPaddleWebhookRotationAcceptsCurrentAndPreviousSecret(t *testing.T) {
	h := newHarnessPaddleFull(t, func(o *api.Options) {
		o.PaddleWebhookSecret = "current-secret"
		o.PaddleWebhookSecrets = []string{"previous-secret"}
	})
	// Signed with the CURRENT secret.
	body1 := []byte(`{"event_id":"evt_rot_1","event_type":"subscription.activated","data":{"id":"sub_rot_1","status":"active"}}`)
	resp := signedPaddleMulti(t, h.srv.URL, body1, time.Now(), []string{"current-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("current-secret status=%d body=%s, want 200", resp.StatusCode, readAll(resp))
	}
	// Signed with the still-accepted PREVIOUS secret.
	body2 := []byte(`{"event_id":"evt_rot_2","event_type":"subscription.activated","data":{"id":"sub_rot_2","status":"active"}}`)
	resp = signedPaddleMulti(t, h.srv.URL, body2, time.Now(), []string{"previous-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("previous-secret status=%d body=%s, want 200", resp.StatusCode, readAll(resp))
	}
}

func TestPaddleWebhookMultipleH1AnyMatchAccepted(t *testing.T) {
	h := newHarnessPaddleFull(t, func(o *api.Options) {
		o.PaddleWebhookSecret = "current-secret"
	})
	body := []byte(`{"event_id":"evt_rot_3","event_type":"subscription.activated","data":{"id":"sub_rot_3","status":"active"}}`)
	// Paddle-shaped multi-h1 header: one bad, one good.
	resp := signedPaddleMulti(t, h.srv.URL, body, time.Now(), []string{"wrong-secret", "current-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("multi-h1 status=%d body=%s, want 200 (any h1 matching any configured secret)", resp.StatusCode, readAll(resp))
	}
}

func TestPaddleWebhookAllSecretsBadRejected(t *testing.T) {
	h := newHarnessPaddleFull(t, func(o *api.Options) {
		o.PaddleWebhookSecret = "current-secret"
		o.PaddleWebhookSecrets = []string{"previous-secret"}
	})
	body := []byte(`{"event_id":"evt_rot_4","event_type":"subscription.activated","data":{"id":"sub_rot_4","status":"active"}}`)
	resp := signedPaddleMulti(t, h.srv.URL, body, time.Now(), []string{"wrong-1", "wrong-2"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("all-bad status=%d, want 401", resp.StatusCode)
	}
}

func TestPaddleWebhookEmptyH1ListRejected(t *testing.T) {
	h := newHarnessPaddleFull(t, func(o *api.Options) {
		o.PaddleWebhookSecret = "current-secret"
	})
	body := []byte(`{"event_id":"evt_rot_5","event_type":"subscription.activated","data":{"id":"sub_rot_5","status":"active"}}`)
	// ts present, but no h1 at all.
	resp := signedPaddleMulti(t, h.srv.URL, body, time.Now(), nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-h1 status=%d, want 401", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// A4 (gap 1.1): the pure environment-switch validator.
// ---------------------------------------------------------------------------

func TestValidatePaddleCheckoutEnv(t *testing.T) {
	livePrices := []api.PaddlePriceEntry{{PriceID: "pri_live_1", PlanName: "plus_beta", PlanVersion: 1, Interval: "month"}}
	cases := []struct {
		name    string
		in      api.PaddleCheckoutEnv
		wantErr bool
	}{
		{"default sandbox, no token, ok (dark)", api.PaddleCheckoutEnv{}, false},
		{"sandbox with valid test_ token ok", api.PaddleCheckoutEnv{Environment: "sandbox", ClientToken: "test_abc"}, false},
		{"sandbox with a live_ token rejected", api.PaddleCheckoutEnv{Environment: "sandbox", ClientToken: "live_abc"}, true},
		{"live with everything configured ok", api.PaddleCheckoutEnv{
			Environment: "live", ClientToken: "live_abc", WebhookConfigured: true, Prices: livePrices,
		}, false},
		{"live with empty token rejected", api.PaddleCheckoutEnv{
			Environment: "live", WebhookConfigured: true, Prices: livePrices,
		}, true},
		{"live with a sandbox token rejected", api.PaddleCheckoutEnv{
			Environment: "live", ClientToken: "test_abc", WebhookConfigured: true, Prices: livePrices,
		}, true},
		{"live with no webhook secret rejected", api.PaddleCheckoutEnv{
			Environment: "live", ClientToken: "live_abc", Prices: livePrices,
		}, true},
		{"live with no prices rejected", api.PaddleCheckoutEnv{
			Environment: "live", ClientToken: "live_abc", WebhookConfigured: true,
		}, true},
		{"unknown environment value rejected", api.PaddleCheckoutEnv{Environment: "staging"}, true},
		{"non-numeric trial days rejected", api.PaddleCheckoutEnv{TrialDaysRaw: "abc"}, true},
		{"trial days out of range rejected", api.PaddleCheckoutEnv{TrialDaysRaw: "91"}, true},
		{"negative trial days rejected", api.PaddleCheckoutEnv{TrialDaysRaw: "-1"}, true},
		{"trial days at the boundary ok", api.PaddleCheckoutEnv{TrialDaysRaw: "90"}, false},
		{"seven-day trial ok", api.PaddleCheckoutEnv{TrialDaysRaw: "7"}, false},
		// P3-f: sandbox-in-prod detector.
		{"sandbox + token on a public origin rejected", api.PaddleCheckoutEnv{
			Environment: "sandbox", ClientToken: "test_abc", OriginIsPublic: true,
		}, true},
		{"sandbox + token on a non-public origin ok", api.PaddleCheckoutEnv{
			Environment: "sandbox", ClientToken: "test_abc", OriginIsPublic: false,
		}, false},
		{"sandbox with NO token on a public origin ok (still the honest dark posture)", api.PaddleCheckoutEnv{
			Environment: "sandbox", OriginIsPublic: true,
		}, false},
		{"live + public origin unaffected by the sandbox gate (still needs its own live_ token)", api.PaddleCheckoutEnv{
			Environment: "live", ClientToken: "live_abc", WebhookConfigured: true, Prices: livePrices, OriginIsPublic: true,
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := api.ValidatePaddleCheckoutEnv(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidatePaddleCheckoutEnv(%+v) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestPaddleCheckoutEnvFromProcess is P3-f's env-reading half: loopback
// hosts are never public, a non-loopback host is public unless the operator
// explicitly flags it via SBCI_PADDLE_ALLOW_SANDBOX_ON_PUBLIC_ORIGIN=1.
func TestPaddleCheckoutEnvFromProcess(t *testing.T) {
	noFlag := func(string) string { return "" }
	allowFlag := func(k string) string {
		if k == "SBCI_PADDLE_ALLOW_SANDBOX_ON_PUBLIC_ORIGIN" {
			return "1"
		}
		return ""
	}
	cases := []struct {
		name   string
		base   string
		getenv func(string) string
		want   bool
	}{
		{"localhost is never public", "http://localhost:8090", noFlag, false},
		{"127.0.0.1 is never public", "http://127.0.0.1:8090", noFlag, false},
		{"IPv6 loopback is never public", "http://[::1]:8090", noFlag, false},
		{"a real host is public by default", "https://cloud.superbased.app", noFlag, true},
		{"a real host is not public when explicitly flagged as staging", "https://staging.example.com", allowFlag, false},
		{"an unparseable base URL fails closed as public", "://not a url", noFlag, true},
		{"an empty base URL fails closed as public", "", noFlag, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := api.PaddleCheckoutEnvFromProcess(tc.base, tc.getenv); got != tc.want {
				t.Fatalf("PaddleCheckoutEnvFromProcess(%q) = %v, want %v", tc.base, got, tc.want)
			}
		})
	}
}

func TestValidatePaddleCheckoutEnvOutputShape(t *testing.T) {
	out, err := api.ValidatePaddleCheckoutEnv(api.PaddleCheckoutEnv{})
	if err != nil {
		t.Fatalf("ValidatePaddleCheckoutEnv: %v", err)
	}
	if out.Environment != "sandbox" {
		t.Errorf("environment=%q, want sandbox default", out.Environment)
	}
	if out.Prices == nil {
		t.Errorf("Prices is nil, want a non-nil empty slice (so JSON encodes [] not null)")
	}
	if out.Available() {
		t.Errorf("Available()=true with no client token and no prices")
	}

	prices := []api.PaddlePriceEntry{
		{PriceID: "pri_z", PlanName: "plus_beta", PlanVersion: 1, Interval: "month"},
		{PriceID: "pri_a", PlanName: "plus_beta", PlanVersion: 1, Interval: "year"},
	}
	out, err = api.ValidatePaddleCheckoutEnv(api.PaddleCheckoutEnv{
		Environment: "sandbox", ClientToken: "test_abc", Prices: prices,
	})
	if err != nil {
		t.Fatalf("ValidatePaddleCheckoutEnv: %v", err)
	}
	if !out.Available() {
		t.Errorf("Available()=false with a token and a price configured")
	}
	if len(out.Prices) != 2 || out.Prices[0].PriceID != "pri_a" || out.Prices[1].PriceID != "pri_z" {
		t.Fatalf("Prices=%+v, want sorted by PriceID [pri_a, pri_z]", out.Prices)
	}
}

// ---------------------------------------------------------------------------
// A6: the portal checkout catalogue on GET /portal/api/billing.
// ---------------------------------------------------------------------------

type portalBillingView struct {
	Checkout struct {
		Available   bool                   `json:"available"`
		Environment string                 `json:"environment"`
		ClientToken string                 `json:"client_token"`
		Prices      []api.PaddlePriceEntry `json:"prices"`
		TrialDays   int                    `json:"trial_days"`
	} `json:"checkout"`
}

func TestPortalBillingCheckoutCatalogueUnavailableWithoutConfig(t *testing.T) {
	h := newHarnessPaddleFull(t, nil) // no PaddleCheckout configured -> zero value
	pc := h.portalLogin(t, "billing-catalogue-none")
	var out portalBillingView
	decode(t, pc.get("/portal/api/billing"), &out)
	if out.Checkout.Available {
		t.Errorf("checkout.available=true with no PaddleCheckout configured")
	}
	if out.Checkout.Prices == nil {
		t.Errorf("checkout.prices is null, want []")
	}
}

func TestPortalBillingCheckoutCatalogueAvailableWithConfig(t *testing.T) {
	checkout, err := api.ValidatePaddleCheckoutEnv(api.PaddleCheckoutEnv{
		Environment: "sandbox", ClientToken: "test_abc",
		Prices: []api.PaddlePriceEntry{
			{PriceID: "pri_test_plus", PlanName: "plus_beta", PlanVersion: 1, Interval: "month", Display: "$15/mo"},
		},
		TrialDaysRaw: "7",
	})
	if err != nil {
		t.Fatalf("ValidatePaddleCheckoutEnv: %v", err)
	}
	h := newHarnessPaddleFull(t, func(o *api.Options) { o.PaddleCheckout = checkout })
	pc := h.portalLogin(t, "billing-catalogue-avail")
	var out portalBillingView
	decode(t, pc.get("/portal/api/billing"), &out)
	if !out.Checkout.Available || out.Checkout.Environment != "sandbox" || out.Checkout.ClientToken != "test_abc" ||
		out.Checkout.TrialDays != 7 || len(out.Checkout.Prices) != 1 || out.Checkout.Prices[0].PriceID != "pri_test_plus" {
		t.Fatalf("checkout=%+v, want available sandbox test_abc [pri_test_plus] trial=7", out.Checkout)
	}
}

func TestPortalCheckoutUnavailableMessageMentionsPrices(t *testing.T) {
	h := newHarnessPaddleFull(t, nil)
	pc := h.portalLogin(t, "checkout-msg")
	resp := pc.mutate("POST", "/portal/api/billing/checkout", []byte(`{"price_id":"pri_unknown"}`), pc.csrf)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status=%d, want 501", resp.StatusCode)
	}
	body := readAll(resp)
	if !strings.Contains(body, "SBCI_PADDLE_PRICES") {
		t.Fatalf("501 body=%q, want it to mention SBCI_PADDLE_PRICES", body)
	}
}

// ---------------------------------------------------------------------------
// A10: golden fixtures decoded through the REAL envelope decoder + classified
// through the REAL (exported) classifier. As of 2026-09-12 most of these are
// REAL Paddle sandbox webhook deliveries (checkout + simulator runs) captured
// against the live staging destination; two remain Paddle's own documented
// example payloads because nothing was ever captured for them (no
// subscription.activated fires on a trial-priced purchase; no chargeback
// occurred). See testdata/paddle/README.md for exact provenance per fixture.
// ---------------------------------------------------------------------------

func TestPaddleGoldenFixturesClassify(t *testing.T) {
	cases := []struct {
		file      string
		wantKind  string
		wantBinds bool
	}{
		{"subscription.created.json", "activate", true},
		{"subscription.activated.json", "activate", true},
		{"subscription.trialing.json", "activate", true},
		// Real subscription.updated delivery carries status=canceled (a
		// same-second cancel-with-updated pair), so it classifies as a
		// cancellation, not a grant.
		{"subscription.updated.json", "cancel", false},
		{"subscription.canceled.json", "cancel", false},
		{"subscription.past_due.json", "status_only", false},
		{"transaction.completed.json", "activate", true},
		{"transaction.payment_failed.json", "status_only", false},
		// The real simulator delivery for adjustment.created is a PARTIAL,
		// pending_approval refund (Paddle's own canned simulator example),
		// not a full/approved one — resolveAdjustmentAction treats that as
		// status_only, not revoke. The filename is kept for continuity with
		// the fixture history; see the README for the full explanation.
		{"adjustment.created.refund_full_approved.json", "status_only", false},
		{"adjustment.created.chargeback.json", "revoke", false},
		// A8's explicit-ignore rows, now pinned against real delivered
		// shapes instead of only store.TestClassifyPaddleEventTable's
		// hand-built values.
		{"transaction.created.json", "ignore", false},
		{"transaction.ready.json", "ignore", false},
		{"transaction.paid.json", "ignore", false},
		{"transaction.updated.json", "ignore", false},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", "paddle", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			ev, err := api.DecodePaddleWebhookEnvelope(body, time.Now())
			if err != nil {
				t.Fatalf("DecodePaddleWebhookEnvelope: %v", err)
			}
			if ev.EventID == "" || ev.EventType == "" {
				t.Fatalf("decoded event missing id/type: %+v", ev)
			}
			kind, binds := store.ClassifyPaddleEvent(ev)
			if kind != tc.wantKind || binds != tc.wantBinds {
				t.Errorf("%s: classify = (%q,%v), want (%q,%v)", tc.file, kind, binds, tc.wantKind, tc.wantBinds)
			}
		})
	}
}

// TestPaddleGoldenFixtureTransactionCompletedCarriesSubscriptionID pins the
// one field transaction.completed's classification depends on: a real Paddle
// transaction-completed payload's data.subscription_id must decode onto
// PaddleEvent.SubscriptionID (not, say, data.id, which is the transaction's
// own id).
func TestPaddleGoldenFixtureTransactionCompletedCarriesSubscriptionID(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "paddle", "transaction.completed.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	ev, err := api.DecodePaddleWebhookEnvelope(body, time.Now())
	if err != nil {
		t.Fatalf("DecodePaddleWebhookEnvelope: %v", err)
	}
	if ev.SubscriptionID == "" {
		t.Fatalf("decoded transaction.completed has empty SubscriptionID")
	}
	if ev.SubscriptionID == ev.EventID {
		t.Fatalf("SubscriptionID incorrectly decoded from the wrong field")
	}
}
