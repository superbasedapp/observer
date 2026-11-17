package api_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// paddle_lifecycle_test.go covers the webhook and checkout halves of the Fable
// review of 2026-11-17 (docs/security.md BILL-FR7, BILL-FR10, BILL-FR22): the
// decoder's new capability facts, and the checkout's one-trial rule.

// TestDecodePaddleWebhookPaidAndQuantity: TransactionPaid is positive
// evidence only (FR-7), and data.items[0].quantity is read (FR-22).
func TestDecodePaddleWebhookPaidAndQuantity(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		paid     bool
		quantity int64
	}{
		{"paid renewal", `{"event_id":"e1","event_type":"transaction.completed","data":{"subscription_id":"sub_1","items":[{"quantity":4,"price":{"id":"pri_x"}}],"details":{"totals":{"total":"1500","grand_total":"1500"}}}}`, true, 4},
		{"grand_total wins over total", `{"event_id":"e2","event_type":"transaction.completed","data":{"subscription_id":"sub_1","details":{"totals":{"total":"1500","grand_total":"0"}}}}`, false, 0},
		{"total when grand_total is absent", `{"event_id":"e3","event_type":"transaction.completed","data":{"subscription_id":"sub_1","details":{"totals":{"total":"900"}}}}`, true, 0},
		{"zero total", `{"event_id":"e4","event_type":"transaction.completed","data":{"subscription_id":"sub_1","details":{"totals":{"grand_total":"0"}}}}`, false, 0},
		{"no totals at all", `{"event_id":"e5","event_type":"transaction.completed","data":{"subscription_id":"sub_1"}}`, false, 0},
		{"malformed total", `{"event_id":"e6","event_type":"transaction.completed","data":{"subscription_id":"sub_1","details":{"totals":{"grand_total":"abc"}}}}`, false, 0},
		{"subscription event quantity", `{"event_id":"e7","event_type":"subscription.created","data":{"id":"sub_2","status":"active","items":[{"quantity":3,"price":{"id":"pri_team"}}]}}`, false, 3},
	}
	for _, c := range cases {
		ev, err := api.DecodePaddleWebhookEnvelope([]byte(c.body), time.Now())
		if err != nil {
			t.Fatalf("%s: decode: %v", c.name, err)
		}
		if ev.TransactionPaid != c.paid || ev.Quantity != c.quantity {
			t.Errorf("%s: TransactionPaid=%v Quantity=%d, want %v %d", c.name, ev.TransactionPaid, ev.Quantity, c.paid, c.quantity)
		}
	}
}

// The real $0 sandbox trial-start transaction is not a payment.
func TestRealZeroTransactionIsNotPaid(t *testing.T) {
	body, err := os.ReadFile("testdata/paddle_trial/transaction.completed.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	ev, err := api.DecodePaddleWebhookEnvelope(body, time.Now())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.TransactionPaid || ev.Quantity != 1 {
		t.Fatalf("TransactionPaid=%v Quantity=%d, want false 1", ev.TransactionPaid, ev.Quantity)
	}
}

// TestPortalCheckoutRefusesSecondTrial: while the deployment advertises a
// trial, an account that has had one gets 409 trial_already_used and no
// intent; with no trial advertised the same account may check out (FR-10).
func TestPortalCheckoutRefusesSecondTrial(t *testing.T) {
	for _, c := range []struct {
		name      string
		trialDays int
		want      int
	}{
		{"trial advertised: refused", 7, http.StatusConflict},
		{"no trial advertised: allowed", 0, http.StatusOK},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarnessPaddleFull(t, func(o *api.Options) {
				o.PaddleWebhookSecret = paddleSecret
				o.PaddleCheckout = api.PaddleCheckout{Environment: "sandbox", TrialDays: c.trialDays}
			})
			pc := h.portalLogin(t, "trial-again")
			ctx := context.Background()
			now := time.Now().UTC()
			nonce, _, err := h.store.CreateCheckoutIntent(ctx, pc.accountID, "pri_test_plus", 0, now)
			if err != nil {
				t.Fatalf("mint: %v", err)
			}
			// The first subscription trialed, then was canceled.
			for i, ev := range []store.PaddleEvent{
				{EventType: "subscription.trialing", AccountID: pc.accountID, CheckoutNonce: nonce, Status: "trialing", CurrentPeriodEnd: now.AddDate(0, 0, 7)},
				{EventType: "subscription.canceled", Status: "canceled"},
			} {
				ev.EventID = "evt_trial_" + string(rune('a'+i))
				ev.SubscriptionID, ev.CustomerID, ev.PriceID = "sub_trial", "ctm_t", "pri_test_plus"
				ev.OccurredAt, ev.Now = now.Add(time.Duration(i)*time.Minute), now.Add(time.Duration(i)*time.Minute)
				if _, err := h.store.ProcessPaddleEvent(ctx, ev); err != nil {
					t.Fatalf("event %d: %v", i, err)
				}
			}
			resp := pc.mutate("POST", "/portal/api/billing/checkout", []byte(`{"price_id":"pri_test_plus"}`), pc.csrf)
			if resp.StatusCode != c.want {
				t.Fatalf("checkout status=%d body=%s, want %d", resp.StatusCode, readAll(resp), c.want)
			}
			if c.want == http.StatusConflict {
				var e struct {
					Code string `json:"code"`
				}
				decode(t, resp, &e)
				if e.Code != "trial_already_used" {
					t.Fatalf("error code = %q, want trial_already_used", e.Code)
				}
			}
		})
	}
}
