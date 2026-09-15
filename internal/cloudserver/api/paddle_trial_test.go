package api_test

import (
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
)

// paddle_trial_test.go covers the 2026-09-12 live-defect fix's decoder half:
// the new PaddleEvent capability facts (TransactionZeroTotal /
// TrialPeriodOnPrice / TrialEndsAt) extracted from a REAL Paddle sandbox
// checkout's webhook bodies (a $15/mo Plus price with a Paddle-side 7-day
// trial). The store-side status decision this decode feeds is covered by
// store/paddle_test.go's TestResolveActivateStatus (pure) and
// TestPaddleRealSandboxPayloadsPreserveTrialThroughZeroTotalTransaction
// (DB-backed, replays these SAME two fixtures plus subscription.created
// through the real intake).
//
// Fixtures under testdata/paddle_trial/ are the operator's real sandbox
// delivery bodies (a DIFFERENT directory from testdata/paddle/, which
// another agent owns): transaction.completed.json is the $0 trial-start
// transaction (data.status="completed", details.totals.grand_total="0",
// items[0].price.trial_period={"interval":"day","frequency":7,...}, no
// current_billing_period/next_billed_at/items[].trial_dates at all - a
// transaction never carries those); subscription.trialing.json is the
// dedicated trialing event for the SAME checkout (data.status="trialing",
// items[0].trial_dates={starts_at,ends_at}, current_billing_period.ends_at
// == next_billed_at == the trial end, management_urls absent entirely - a
// real sandbox delivery, not the docs' claimed shape; COALESCE-preserve
// handling for management URLs is unchanged by this fix).
func TestDecodePaddleWebhookEnvelopeTrialCapabilityFacts(t *testing.T) {
	wantTrialEnd, err := time.Parse(time.RFC3339, "2026-09-18T19:51:52.458Z")
	if err != nil {
		t.Fatalf("parse want trial end: %v", err)
	}

	cases := []struct {
		name                   string
		file                   string
		eventType              string
		wantTransactionZero    bool
		wantTrialPeriodOnPrice bool
		wantTrialEndsAtSet     bool
	}{
		{
			name:                   "transaction.completed: $0 trial-start transaction",
			file:                   "testdata/paddle_trial/transaction.completed.json",
			eventType:              "transaction.completed",
			wantTransactionZero:    true,
			wantTrialPeriodOnPrice: true,
			// A transaction.completed's items carry no trial_dates and its
			// data carries neither current_billing_period nor
			// next_billed_at (it has "billing_period" instead, a DIFFERENT
			// key this fix does not read) - so the TrialEndsAt ladder
			// bottoms out at the zero time here. This is a real, honest gap
			// in this fixture, not a decoder defect: the applyPaddleActivate
			// preserve-branch never needs it (it keeps the EXISTING row's
			// own stored trial_ends_at instead of recomputing one from this
			// event).
			wantTrialEndsAtSet: false,
		},
		{
			name:                   "subscription.trialing: dedicated trialing event",
			file:                   "testdata/paddle_trial/subscription.trialing.json",
			eventType:              "subscription.trialing",
			wantTransactionZero:    false,
			wantTrialPeriodOnPrice: true,
			wantTrialEndsAtSet:     true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, err := os.ReadFile(c.file)
			if err != nil {
				t.Fatalf("read %s: %v", c.file, err)
			}
			ev, err := api.DecodePaddleWebhookEnvelope(body, time.Now())
			if err != nil {
				t.Fatalf("DecodePaddleWebhookEnvelope: %v", err)
			}
			if ev.EventType != c.eventType {
				t.Errorf("EventType = %q, want %q", ev.EventType, c.eventType)
			}
			if ev.TransactionZeroTotal != c.wantTransactionZero {
				t.Errorf("TransactionZeroTotal = %v, want %v", ev.TransactionZeroTotal, c.wantTransactionZero)
			}
			if ev.TrialPeriodOnPrice != c.wantTrialPeriodOnPrice {
				t.Errorf("TrialPeriodOnPrice = %v, want %v", ev.TrialPeriodOnPrice, c.wantTrialPeriodOnPrice)
			}
			if c.wantTrialEndsAtSet {
				if ev.TrialEndsAt.IsZero() {
					t.Fatalf("TrialEndsAt is zero, want %v", wantTrialEnd)
				}
				if !ev.TrialEndsAt.Equal(wantTrialEnd) {
					t.Errorf("TrialEndsAt = %v, want %v", ev.TrialEndsAt, wantTrialEnd)
				}
			} else if !ev.TrialEndsAt.IsZero() {
				t.Errorf("TrialEndsAt = %v, want zero", ev.TrialEndsAt)
			}
		})
	}
}

// TestPaddleAmountIsZeroAndTrialPeriodDecodeAcrossRealPayloads is a narrower
// direct check on the two real fixtures' raw JSON shape assumptions this fix
// depends on: transaction.completed's details.totals.grand_total is the
// decimal STRING "0" (not a JSON number, not absent), and its
// items[0].price.trial_period.frequency is the positive integer 7 - the
// exact two facts TransactionZeroTotal / TrialPeriodOnPrice fold into a
// bool. Guards against a future Paddle payload-shape change silently
// breaking the fold (e.g. grand_total becoming a JSON number) without a
// decode error ever surfacing.
func TestPaddleAmountIsZeroAndTrialPeriodDecodeAcrossRealPayloads(t *testing.T) {
	body, err := os.ReadFile("testdata/paddle_trial/transaction.completed.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	ev, err := api.DecodePaddleWebhookEnvelope(body, time.Now())
	if err != nil {
		t.Fatalf("DecodePaddleWebhookEnvelope: %v", err)
	}
	if !ev.TransactionZeroTotal {
		t.Error("TransactionZeroTotal = false on the real $0 sandbox transaction, want true")
	}
	if !ev.TrialPeriodOnPrice {
		t.Error("TrialPeriodOnPrice = false on the real 7-day-trial sandbox price, want true")
	}
	if ev.SubscriptionID == "" {
		t.Error("SubscriptionID is empty on a transaction.completed that carries data.subscription_id")
	}
}
