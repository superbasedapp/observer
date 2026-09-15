package store_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// paddle_test.go covers W9 Paddle billing + the Stream 5 additions: activation
// binds only with a server-minted checkout nonce (F2), refund/chargeback revoke
// paid access immediately (G2-08), chargeback_reverse restores it, and partial
// refunds keep access. Processing stays idempotent + retry-safe, cancellation
// still defers to the cycle boundary, and unattributed / unknown-price events
// never escalate. Ground-truthed by CALLING the store against live PG.

const testPrice = "pri_test_plus"

func paddleStore(t *testing.T) (*store.Store, string, time.Time) {
	t.Helper()
	s, _ := newStore(t)
	s.SetPaddlePriceMap(map[string]store.PaddlePlan{testPrice: {Name: "plus_beta", Version: 1}})
	acct := makeAccount(t, s)
	return s, acct, time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
}

// mintNonce creates a server-side checkout intent for acct and returns the raw
// nonce a real (server-initiated) checkout would carry in custom_data — the F2
// proof the webhook requires before binding a subscription to the account.
func mintNonce(t *testing.T, s *store.Store, acct string, now time.Time) string {
	t.Helper()
	nonce, _, err := s.CreateCheckoutIntent(context.Background(), acct, testPrice, time.Hour, now)
	if err != nil {
		t.Fatalf("CreateCheckoutIntent: %v", err)
	}
	return nonce
}

func TestPaddleActivationGrantsPaidPlan(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()

	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_a", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	})
	if err != nil || !in.Applied || in.Duplicate {
		t.Fatalf("activation intake=%+v err=%v, want Applied,!Duplicate", in, err)
	}
	// The plan is now plus_beta with its caps (25/500/4) — resolved from plans,
	// not from the billing row (never a competing entitlement source).
	al, err := s.ResolveAllowance(ctx, acct, "session_enrichment", now)
	if err != nil {
		t.Fatalf("ResolveAllowance: %v", err)
	}
	if al.Plan.Name != "plus_beta" || al.DailyCap != 25 || al.MonthlyCap != 500 || al.ConcurrencyCap != 4 {
		t.Fatalf("allowance = %+v, want plus_beta 25/500/4", al)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.Status != "active" || sub.PlanName != "plus_beta" {
		t.Fatalf("subscription = %+v err=%v, want active plus_beta", sub, err)
	}
}

func TestPaddleProcessingIsIdempotent(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	ev := store.PaddleEvent{
		EventID: "evt_dup", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}
	if _, err := s.ProcessPaddleEvent(ctx, ev); err != nil {
		t.Fatalf("first: %v", err)
	}
	in, err := s.ProcessPaddleEvent(ctx, ev)
	if err != nil || !in.Duplicate {
		t.Fatalf("replay intake=%+v err=%v, want Duplicate", in, err)
	}
}

func TestPaddleCancellationDowngradesAtCycleBoundary(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_a", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}); err != nil {
		t.Fatalf("activate: %v", err)
	}
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_c", EventType: "subscription.canceled", AccountID: acct,
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "canceled", PriceID: testPrice,
		OccurredAt: now.Add(time.Minute), CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now.Add(time.Minute),
	})
	if err != nil || !in.Applied {
		t.Fatalf("cancel intake=%+v err=%v, want Applied", in, err)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.Status != "canceled" || sub.CanceledAt == nil {
		t.Fatalf("subscription = %+v err=%v, want canceled with CanceledAt", sub, err)
	}
	// Still on plus_beta NOW (keeps what they paid for); the downgrade to free is
	// scheduled at the cycle boundary (W4 floors it), so a resolve AFTER the
	// boundary yields free.
	alNow, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", now)
	if alNow.Plan.Name != "plus_beta" {
		t.Errorf("immediately after cancel plan = %q, want plus_beta (paid through the period)", alNow.Plan.Name)
	}
	alLater, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", now.AddDate(0, 2, 0))
	if alLater.Plan.Name != "free" {
		t.Errorf("well after the period plan = %q, want free", alLater.Plan.Name)
	}
}

// TestPaddleFullRefundRevokesImmediately is the G2-08 core: a full, approved
// refund revokes paid access at the refund instant — NOT ceiled to the cycle
// boundary the way a graceful cancellation is (money returned ⇒ no F11 floor).
func TestPaddleFullRefundRevokesImmediately(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)

	refundAt := now.Add(2 * time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_refund", EventType: "adjustment.created",
		// No custom_data on adjustments — attributed via the bound subscription.
		SubscriptionID:   "sub_1",
		AdjustmentAction: "refund", AdjustmentType: "full", AdjustmentStatus: "approved",
		OccurredAt: refundAt, Now: refundAt,
	})
	if err != nil || !in.Applied {
		t.Fatalf("refund intake=%+v err=%v, want Applied", in, err)
	}
	// Access is gone AT the refund instant (immediate, not boundary-ceiled).
	alAfter, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", refundAt)
	if alAfter.Plan.Name != "free" {
		t.Fatalf("plan at refund instant = %q, want free (revoked immediately, not at cycle boundary)", alAfter.Plan.Name)
	}
	// Before the refund it was still paid.
	alBefore, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", now.Add(time.Hour))
	if alBefore.Plan.Name != "plus_beta" {
		t.Fatalf("plan before refund = %q, want plus_beta", alBefore.Plan.Name)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.Status != "refunded" {
		t.Fatalf("subscription = %+v err=%v, want status refunded", sub, err)
	}
}

// TestPaddleChargebackRevokesAndReverseRestores: a chargeback revokes immediately
// and records 'charged_back'; a chargeback_reverse restores the paid plan.
func TestPaddleChargebackRevokesAndReverseRestores(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)

	cbAt := now.Add(2 * time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_cb", EventType: "adjustment.created", SubscriptionID: "sub_1",
		AdjustmentAction: "chargeback", AdjustmentType: "full", AdjustmentStatus: "approved",
		OccurredAt: cbAt, Now: cbAt,
	}); err != nil || !in.Applied {
		t.Fatalf("chargeback intake=%+v err=%v, want Applied", in, err)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", cbAt); al.Plan.Name != "free" {
		t.Fatalf("plan after chargeback = %q, want free", al.Plan.Name)
	}
	if sub, _ := s.AccountSubscription(ctx, acct); sub.Status != "charged_back" {
		t.Fatalf("status after chargeback = %q, want charged_back", sub.Status)
	}

	revAt := now.Add(3 * time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_cb_rev", EventType: "adjustment.created", SubscriptionID: "sub_1",
		AdjustmentAction: "chargeback_reverse", AdjustmentType: "full", AdjustmentStatus: "reversed",
		OccurredAt: revAt, Now: revAt,
	}); err != nil || !in.Applied {
		t.Fatalf("reverse intake=%+v err=%v, want Applied", in, err)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", revAt); al.Plan.Name != "plus_beta" {
		t.Fatalf("plan after chargeback_reverse = %q, want plus_beta (restored)", al.Plan.Name)
	}
	if sub, _ := s.AccountSubscription(ctx, acct); sub.Status != "active" {
		t.Fatalf("status after reverse = %q, want active", sub.Status)
	}
}

// TestPaddlePartialRefundKeepsAccess: a partial refund is recorded but the
// account keeps its paid plan (only a full refund revokes).
func TestPaddlePartialRefundKeepsAccess(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)

	prAt := now.Add(2 * time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_partial", EventType: "adjustment.created", SubscriptionID: "sub_1",
		AdjustmentAction: "refund", AdjustmentType: "partial", AdjustmentStatus: "approved",
		OccurredAt: prAt, Now: prAt,
	})
	if err != nil || !in.Applied {
		t.Fatalf("partial refund intake=%+v err=%v, want Applied (recorded)", in, err)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", prAt); al.Plan.Name != "plus_beta" {
		t.Fatalf("plan after partial refund = %q, want plus_beta (access retained)", al.Plan.Name)
	}
	if sub, _ := s.AccountSubscription(ctx, acct); sub.Status != "active" {
		t.Fatalf("status after partial refund = %q, want active", sub.Status)
	}
}

// TestPaddleBindingRefusedWithoutNonce is the F2 core: a subscription with a
// (valid, signed) account id but NO / a WRONG server-minted checkout nonce must
// not bind — the untrusted custom_data.account_id alone can no longer grant.
func TestPaddleBindingRefusedWithoutNonce(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()

	// No nonce at all.
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_nonnonce", EventType: "subscription.activated", AccountID: acct,
		CustomerID: "ctm_1", SubscriptionID: "sub_forge", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	})
	if err != nil || in.Applied || in.Outcome != "binding_refused" {
		t.Fatalf("no-nonce intake=%+v err=%v, want !Applied outcome=binding_refused", in, err)
	}
	// A wrong nonce (never minted) is also refused.
	in, err = s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_badnonce", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: "not-a-real-nonce",
		CustomerID:    "ctm_1", SubscriptionID: "sub_forge", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	})
	if err != nil || in.Applied || in.Outcome != "binding_refused" {
		t.Fatalf("bad-nonce intake=%+v err=%v, want !Applied outcome=binding_refused", in, err)
	}
	// The account never got a subscription or a paid plan.
	if _, err := s.AccountSubscription(ctx, acct); err == nil {
		t.Fatalf("a subscription was bound without a valid nonce")
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", now); al.Plan.Name != "free" {
		t.Fatalf("plan after refused binding = %q, want free", al.Plan.Name)
	}
}

// TestPaddleNonceIsSingleUse: a minted nonce binds exactly one subscription; a
// second distinct subscription presenting the same nonce is refused.
func TestPaddleNonceIsSingleUse(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	nonce := mintNonce(t, s, acct, now)

	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_bind1", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: nonce, CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active",
		PriceID: testPrice, OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}); err != nil || !in.Applied {
		t.Fatalf("first bind intake=%+v err=%v, want Applied", in, err)
	}
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_bind2", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: nonce, CustomerID: "ctm_1", SubscriptionID: "sub_2", Status: "active",
		PriceID: testPrice, OccurredAt: now.Add(time.Minute), CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now.Add(time.Minute),
	})
	if err != nil || in.Applied || in.Outcome != "binding_refused" {
		t.Fatalf("reused-nonce intake=%+v err=%v, want !Applied outcome=binding_refused", in, err)
	}
}

// TestPaddleAdjustmentUnattributedWhenUnbound: a refund for a subscription we
// have no binding for is recorded but never applied (no custom_data to forge).
func TestPaddleAdjustmentUnattributedWhenUnbound(t *testing.T) {
	s, _, now := paddleStore(t)
	ctx := context.Background()
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_adj_orphan", EventType: "adjustment.created", SubscriptionID: "sub_unknown",
		AdjustmentAction: "refund", AdjustmentType: "full", AdjustmentStatus: "approved",
		OccurredAt: now, Now: now,
	})
	if err != nil || in.Applied || in.Outcome != "unattributed" {
		t.Fatalf("orphan adjustment intake=%+v err=%v, want !Applied outcome=unattributed", in, err)
	}
}

func TestPaddleUnattributedEventDoesNotEscalate(t *testing.T) {
	s, _, now := paddleStore(t)
	ctx := context.Background()
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_noacct", EventType: "subscription.activated",
		SubscriptionID: "sub_x", Status: "active", PriceID: testPrice, Now: now,
	})
	if err != nil || in.Applied {
		t.Fatalf("unattributed intake=%+v err=%v, want !Applied", in, err)
	}
}

func TestPaddleUnknownPriceDoesNotEscalate(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_badprice", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: "pri_FOREIGN", Now: now,
	})
	if err != nil || in.Applied || in.Outcome != "unknown_price" {
		t.Fatalf("unknown-price intake=%+v err=%v, want !Applied outcome=unknown_price", in, err)
	}
	// The account stays on free — a foreign price can never grant a plan.
	al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", now)
	if al.Plan.Name != "free" {
		t.Errorf("plan after unknown-price event = %q, want free", al.Plan.Name)
	}
}

// TestPaddleUnderApiRoleAssignsPlan is the F1 regression guard: the PRODUCTION
// front-door role sbci_api must be able to assign a plan on activation. The
// functional tests run as sbci_app, which masked the missing account_plans
// INSERT/UPDATE grant; this binds a store to sbci_api and proves the webhook path
// works under the real role (it 500'd before migration 0025). It also proves
// sbci_api can mint + consume a checkout nonce (0030 grants).
func TestPaddleUnderApiRoleAssignsPlan(t *testing.T) {
	base, pool := newStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	acct := makeAccount(t, base)

	api, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatalf("NewForRole(api): %v", err)
	}
	api.SetPaddlePriceMap(map[string]store.PaddlePlan{testPrice: {Name: "plus_beta", Version: 1}})

	nonce, _, err := api.CreateCheckoutIntent(ctx, acct, testPrice, time.Hour, now)
	if err != nil {
		t.Fatalf("under sbci_api: CreateCheckoutIntent: %v", err)
	}
	in, err := api.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_api", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: nonce, CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	})
	if err != nil || !in.Applied {
		t.Fatalf("under sbci_api: intake=%+v err=%v, want Applied (F1 regression — api lacked account_plans INSERT/UPDATE)", in, err)
	}
	al, err := api.ResolveAllowance(ctx, acct, "session_enrichment", now)
	if err != nil || al.Plan.Name != "plus_beta" {
		t.Fatalf("under sbci_api: plan=%v err=%v, want plus_beta", al.Plan.Name, err)
	}
}

// TestPaddleDeletedAccountNotRevived is the F2/F9 regression guard: a signed
// webhook that arrives AFTER an account is deleted must not revive the
// subscription or grant a plan — even with a valid checkout nonce.
func TestPaddleDeletedAccountNotRevived(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	nonce := mintNonce(t, s, acct, now)
	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("delete: %v", err)
	}
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_late", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: nonce, CustomerID: "ctm_1", SubscriptionID: "sub_late", Status: "active", PriceID: testPrice,
		CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("late event err: %v", err)
	}
	if in.Applied {
		t.Fatalf("a webhook revived a deleted account: %+v", in)
	}
	if _, err := s.AccountSubscription(ctx, acct); err == nil {
		t.Fatalf("subscription created for a deleted account")
	}
}

// TestPaddleStaleEventIgnored is the F3 regression guard: an out-of-order (older
// occurred_at) delivery for a subscription is ignored rather than restoring old
// state — e.g. a late activation cannot revive paid access after a cancellation.
func TestPaddleStaleEventIgnored(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	// Activate at T (occurred later), then cancel at T+1h.
	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_act", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_cancel", EventType: "subscription.canceled", AccountID: acct,
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "canceled", PriceID: testPrice,
		OccurredAt: now.Add(time.Hour), CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	// A STALE distinct activation with an OLDER occurred_at arrives late.
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_stale", EventType: "subscription.activated", AccountID: acct,
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: now.Add(-time.Hour), Now: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("stale event err: %v", err)
	}
	if in.Applied {
		t.Fatalf("stale out-of-order activation was applied, reviving paid access: %+v", in)
	}
	// The subscription is still canceled.
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.Status != "canceled" {
		t.Fatalf("subscription=%+v err=%v, want still canceled after stale event", sub, err)
	}
}

func TestPaddleDeletionPurgesSubscription(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)
	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.AccountSubscription(ctx, acct); err == nil {
		t.Fatalf("subscription survived account deletion")
	}
}

// activatePaid is the common "the account holds a live paid subscription" setup:
// mint a checkout nonce and process an activation that binds sub to acct.
func activatePaid(t *testing.T, s *store.Store, acct, sub string, now time.Time) {
	t.Helper()
	in, err := s.ProcessPaddleEvent(context.Background(), store.PaddleEvent{
		EventID: "evt_act_" + sub, EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: sub, Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	})
	if err != nil || !in.Applied {
		t.Fatalf("activatePaid intake=%+v err=%v, want Applied", in, err)
	}
}

// ---------------------------------------------------------------------------
// A1 (gap 1.5 bug fix): upsertSubscriptionTx must write the RESOLVED account,
// never the untrusted ev.AccountID — the normal shape of a renewal / a bound
// update carries no custom_data at all.
// ---------------------------------------------------------------------------

// TestPaddleRenewalWithEmptyAccountIDApplies is the core A1 regression: a
// transaction.completed renewal on an already-bound subscription, carrying
// NO custom_data.account_id (the normal shape Paddle actually sends), must
// apply cleanly instead of failing the ::uuid cast on "" and 500ing forever.
func TestPaddleRenewalWithEmptyAccountIDApplies(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)

	renewAt := now.AddDate(0, 1, 0)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_renew", EventType: "transaction.completed",
		// AccountID and CheckoutNonce both empty: the normal shape of a
		// renewal on an already-bound subscription.
		CustomerID: "ctm_1", SubscriptionID: "sub_1", PriceID: testPrice,
		OccurredAt: renewAt, CurrentPeriodEnd: renewAt.AddDate(0, 1, 0), Now: renewAt,
	})
	if err != nil || !in.Applied || in.Outcome != "applied" {
		t.Fatalf("renewal intake=%+v err=%v, want Applied outcome=applied", in, err)
	}
	if in.Note == "" {
		t.Errorf("renewal intake has empty Note")
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.Status != "active" {
		t.Fatalf("subscription=%+v err=%v, want active after renewal", sub, err)
	}
	if !renewAt.Equal(*sub.CurrentPeriodEnd) && !sub.CurrentPeriodEnd.Equal(renewAt.AddDate(0, 1, 0)) {
		// CurrentPeriodEnd should have advanced to the renewal's new period end.
		if sub.CurrentPeriodEnd == nil || !sub.CurrentPeriodEnd.Equal(renewAt.AddDate(0, 1, 0)) {
			t.Errorf("current_period_end after renewal = %v, want %v", sub.CurrentPeriodEnd, renewAt.AddDate(0, 1, 0))
		}
	}
}

// TestPaddlePaymentFailedWithEmptyAccountIDRecordsStatus is A1's dunning
// case: transaction.payment_failed on a bound subscription with empty
// AccountID must record status_only with no error and no plan disruption.
func TestPaddlePaymentFailedWithEmptyAccountIDRecordsStatus(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)

	failAt := now.Add(time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_pf", EventType: "transaction.payment_failed",
		CustomerID: "ctm_1", SubscriptionID: "sub_1",
		OccurredAt: failAt, Now: failAt,
	})
	if err != nil || !in.Applied || in.Outcome != "status_only" {
		t.Fatalf("payment_failed intake=%+v err=%v, want Applied outcome=status_only", in, err)
	}
	// Access continues through dunning: still plus_beta, and the row is not
	// broken by the empty AccountID.
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", failAt); al.Plan.Name != "plus_beta" {
		t.Errorf("plan after payment_failed = %q, want plus_beta (dunning, access continues)", al.Plan.Name)
	}
	if sub, err := s.AccountSubscription(ctx, acct); err != nil || sub.Status != "active" {
		t.Fatalf("subscription=%+v err=%v, want still active", sub, err)
	}
}

// TestPaddleBoundUpdateWithEmptyCustomDataApplies is A1's third required
// case: a bound subscription.updated with no custom_data must apply.
func TestPaddleBoundUpdateWithEmptyCustomDataApplies(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)

	updAt := now.Add(2 * time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_upd", EventType: "subscription.updated",
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: updAt, CurrentPeriodEnd: updAt.AddDate(0, 1, 0), Now: updAt,
	})
	if err != nil || !in.Applied || in.Outcome != "applied" {
		t.Fatalf("bound update intake=%+v err=%v, want Applied outcome=applied", in, err)
	}
}

// TestPaddleForeignAccountIDIgnoredOnBoundSubscription is A1's cross-tenant
// guard: a bound subscription's event carrying a FOREIGN account id in
// custom_data must resolve the TRUE (bound) account, never the forged one —
// the foreign account gets no subscription row, and the true account is the
// one that gets updated.
func TestPaddleForeignAccountIDIgnoredOnBoundSubscription(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	foreign := makeAccount(t, s)
	activatePaid(t, s, acct, "sub_1", now)

	evAt := now.Add(3 * time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_forge", EventType: "subscription.updated",
		AccountID:  foreign, // forged — this subscription is bound to `acct`, not `foreign`
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: evAt, CurrentPeriodEnd: evAt.AddDate(0, 1, 0), Now: evAt,
	})
	if err != nil || !in.Applied {
		t.Fatalf("forged-account update intake=%+v err=%v, want Applied (resolved from the binding)", in, err)
	}
	// The foreign account got nothing.
	if _, err := s.AccountSubscription(ctx, foreign); err == nil {
		t.Fatalf("a forged custom_data.account_id created a subscription row for the foreign account")
	}
	if al, _ := s.ResolveAllowance(ctx, foreign, "session_enrichment", evAt); al.Plan.Name != "free" {
		t.Errorf("foreign account plan = %q, want free (never touched)", al.Plan.Name)
	}
	// The true (bound) account is the one that was updated.
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.Status != "active" || sub.SubscriptionID != "sub_1" {
		t.Fatalf("true account subscription=%+v err=%v, want active sub_1", sub, err)
	}
}

// ---------------------------------------------------------------------------
// A7 (gap 1.11 trial handling / gap 1.4 management URLs)
// ---------------------------------------------------------------------------

// TestPaddleTrialActivationPersistsTrialingAndGrants: a trialing activation
// persists status='trialing' + trial_ends_at, and grants the plan — the
// portal can render "trial ends in N days" instead of the pre-fix
// fold-into-'active'.
func TestPaddleTrialActivationPersistsTrialingAndGrants(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	trialEnd := now.AddDate(0, 0, 7)

	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_trial", EventType: "subscription.trialing", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "trialing", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: trialEnd, Now: now,
	})
	if err != nil || !in.Applied {
		t.Fatalf("trial activation intake=%+v err=%v, want Applied", in, err)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.Status != "trialing" {
		t.Fatalf("subscription=%+v err=%v, want status=trialing", sub, err)
	}
	if sub.TrialEndsAt == nil || !sub.TrialEndsAt.Equal(trialEnd) {
		t.Fatalf("trial_ends_at = %v, want %v", sub.TrialEndsAt, trialEnd)
	}
	// The plan is granted during the trial (plus_beta access).
	al, err := s.ResolveAllowance(ctx, acct, "session_enrichment", now)
	if err != nil || al.Plan.Name != "plus_beta" {
		t.Fatalf("plan during trial = %q err=%v, want plus_beta", al.Plan.Name, err)
	}
}

// TestPaddleTrialConvertsToActiveOnTransaction: a transaction.completed after
// a trialing activation converts the row to 'active' and clears trial_ends_at.
func TestPaddleTrialConvertsToActiveOnTransaction(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	trialEnd := now.AddDate(0, 0, 7)
	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_trial", EventType: "subscription.trialing", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "trialing", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: trialEnd, Now: now,
	}); err != nil {
		t.Fatalf("trial activation: %v", err)
	}

	billedAt := trialEnd.Add(time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_first_bill", EventType: "transaction.completed",
		CustomerID: "ctm_1", SubscriptionID: "sub_1", PriceID: testPrice,
		OccurredAt: billedAt, CurrentPeriodEnd: billedAt.AddDate(0, 1, 0), Now: billedAt,
	})
	if err != nil || !in.Applied {
		t.Fatalf("first billing intake=%+v err=%v, want Applied", in, err)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.Status != "active" {
		t.Fatalf("subscription=%+v err=%v, want status=active after conversion", sub, err)
	}
	if sub.TrialEndsAt != nil {
		t.Errorf("trial_ends_at = %v, want nil after converting to active", sub.TrialEndsAt)
	}
}

// TestPaddleCancelDuringTrialEffectiveAtTrialEnd is the A7 core: a
// cancellation that arrives while the subscription is TRIALING downgrades
// effective at the trial's own end — NOT ceiled to the next monthly cycle
// boundary the way a graceful post-trial cancellation is. The trial end is
// chosen deliberately mid-month so a wrongly-applied ceiling would push the
// downgrade to a LATER instant than the assertions below allow for.
func TestPaddleCancelDuringTrialEffectiveAtTrialEnd(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	// now is mid-month (the 15th); trial end lands on the 22nd — nowhere near
	// a calendar-month boundary, so CeilToMonthlyCycleStart would push it to
	// the 1st of the FOLLOWING month if it were (wrongly) applied here.
	trialEnd := now.AddDate(0, 0, 7)
	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_trial", EventType: "subscription.trialing", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "trialing", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: trialEnd, Now: now,
	}); err != nil {
		t.Fatalf("trial activation: %v", err)
	}

	cancelAt := now.Add(time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_trial_cancel", EventType: "subscription.canceled",
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "canceled", PriceID: testPrice,
		OccurredAt: cancelAt, CurrentPeriodEnd: trialEnd, Now: cancelAt,
	})
	if err != nil || !in.Applied {
		t.Fatalf("trial cancel intake=%+v err=%v, want Applied", in, err)
	}
	// Still paid access right up to (and including) the trial end.
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", trialEnd.Add(-time.Minute)); al.Plan.Name != "plus_beta" {
		t.Errorf("plan just before trial end = %q, want plus_beta", al.Plan.Name)
	}
	// Free EXACTLY at the trial end — not ceiled to the next month boundary.
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", trialEnd); al.Plan.Name != "free" {
		t.Errorf("plan at trial end = %q, want free (effective at trial end, not the monthly ceiling)", al.Plan.Name)
	}
	// The monthly ceiling this would have landed on (the 1st of the following
	// UTC month) is confirmed LATER than the trial end, so the two are
	// genuinely distinguishable in this test — not free already for some
	// other reason.
	ceiling := store.CeilToMonthlyCycleStart(trialEnd)
	if !ceiling.After(trialEnd) {
		t.Fatalf("test setup: expected the monthly ceiling %v to be after the trial end %v", ceiling, trialEnd)
	}
}

// TestPaddleManagementURLAcceptReject is a table-driven acceptance test for
// the https+paddle.com validation gate: only a link that parses as https on
// paddle.com/*.paddle.com is ever persisted, everything else silently drops
// (a webhook body is attacker-shaped input until the signature is verified,
// and even verified we never render an arbitrary URL from it).
func TestPaddleManagementURLAcceptReject(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		accepts bool
	}{
		{"valid paddle.com", "https://paddle.com/portal/abc", true},
		{"valid subdomain", "https://customer-portal.paddle.com/subscriptions/abc", true},
		{"http scheme rejected", "http://paddle.com/portal/abc", false},
		{"foreign host rejected", "https://evil.example.com/paddle.com", false},
		{"host-prefix spoof rejected", "https://paddle.com.evil.example.com/x", false},
		{"empty rejected", "", false},
		{"malformed rejected", "not a url", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, acct, now := paddleStore(t)
			ctx := context.Background()
			in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
				EventID: "evt_mgmt", EventType: "subscription.activated", AccountID: acct,
				CheckoutNonce: mintNonce(t, s, acct, now),
				CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
				ManagementUpdateURL: tc.url,
				OccurredAt:          now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
			})
			if err != nil || !in.Applied {
				t.Fatalf("intake=%+v err=%v, want Applied", in, err)
			}
			sub, err := s.AccountSubscription(ctx, acct)
			if err != nil {
				t.Fatalf("AccountSubscription: %v", err)
			}
			got := sub.ManagementURLs != nil && sub.ManagementURLs.UpdatePaymentMethod == tc.url
			if got != tc.accepts {
				t.Fatalf("url=%q management_urls=%+v, want accepted=%v", tc.url, sub.ManagementURLs, tc.accepts)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A8 (gap 1.6 event coverage): one row per resolvePaddleAction table entry,
// exercised through the exported ClassifyPaddleEvent (no DB writes needed).
// ---------------------------------------------------------------------------

func TestClassifyPaddleEventTable(t *testing.T) {
	cases := []struct {
		name      string
		ev        store.PaddleEvent
		wantKind  string
		wantBinds bool
	}{
		{"canceled", store.PaddleEvent{EventType: "subscription.canceled"}, "cancel", false},
		{"past_due own type", store.PaddleEvent{EventType: "subscription.past_due"}, "status_only", false},
		{"paused own type", store.PaddleEvent{EventType: "subscription.paused"}, "status_only", false},
		{"trialing dedicated event", store.PaddleEvent{EventType: "subscription.trialing", Status: "trialing"}, "activate", true},
		{"trialing status on updated", store.PaddleEvent{EventType: "subscription.updated", Status: "trialing"}, "activate", true},
		{"imported", store.PaddleEvent{EventType: "subscription.imported", Status: "active"}, "activate", true},
		{"activated active", store.PaddleEvent{EventType: "subscription.activated", Status: "active"}, "activate", true},
		{"updated canceled status", store.PaddleEvent{EventType: "subscription.updated", Status: "canceled"}, "cancel", false},
		{"updated past_due status", store.PaddleEvent{EventType: "subscription.updated", Status: "past_due"}, "status_only", false},
		{"transaction completed bound", store.PaddleEvent{EventType: "transaction.completed", SubscriptionID: "sub_1"}, "activate", true},
		{"transaction completed no sub", store.PaddleEvent{EventType: "transaction.completed"}, "ignore", false},
		{"transaction payment_failed", store.PaddleEvent{EventType: "transaction.payment_failed"}, "status_only", false},
		{"transaction past_due", store.PaddleEvent{EventType: "transaction.past_due"}, "status_only", false},
		{"transaction billed ignored", store.PaddleEvent{EventType: "transaction.billed"}, "ignore", false},
		{"transaction paid ignored", store.PaddleEvent{EventType: "transaction.paid"}, "ignore", false},
		{"transaction ready ignored", store.PaddleEvent{EventType: "transaction.ready"}, "ignore", false},
		{"transaction updated ignored", store.PaddleEvent{EventType: "transaction.updated"}, "ignore", false},
		{"transaction canceled ignored", store.PaddleEvent{EventType: "transaction.canceled"}, "ignore", false},
		{"adjustment full refund approved", store.PaddleEvent{EventType: "adjustment.created", AdjustmentAction: "refund", AdjustmentType: "full", AdjustmentStatus: "approved"}, "revoke", false},
		{"adjustment chargeback", store.PaddleEvent{EventType: "adjustment.created", AdjustmentAction: "chargeback", AdjustmentType: "full"}, "revoke", false},
		{"adjustment chargeback_reverse", store.PaddleEvent{EventType: "adjustment.created", AdjustmentAction: "chargeback_reverse"}, "restore", false},
		{"unknown event ignored", store.PaddleEvent{EventType: "something.else"}, "ignore", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, binds := store.ClassifyPaddleEvent(tc.ev)
			if kind != tc.wantKind || binds != tc.wantBinds {
				t.Errorf("ClassifyPaddleEvent(%+v) = (%q,%v), want (%q,%v)", tc.ev, kind, binds, tc.wantKind, tc.wantBinds)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A9 (gap 1.9): a Paddle-side plan CHANGE on a bound subscription routes
// through assignPlanTx's F11 rule — a downgrade defers to the cycle
// boundary, an upgrade is immediate.
// ---------------------------------------------------------------------------

const testPriceStarter = "pri_test_starter"

// seedStarterPlan inserts a plan strictly between free and plus_beta (caps
// 10/200/3), mirroring migration 0012's INSERT shape, so a plus_beta→starter
// move is unambiguously a downgrade and a starter→plus_beta move is
// unambiguously an upgrade. Idempotent (ON CONFLICT DO NOTHING).
func seedStarterPlan(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap, budget_pool)
		 VALUES ('starter_test', 1, 'Starter (test)', 10, 200, 3, 'plus_beta')
		 ON CONFLICT (name, version) DO NOTHING`)
	if err != nil {
		t.Fatalf("seedStarterPlan: %v", err)
	}
}

// TestPaddlePlanChangeDowngradeDefersToCycleBoundary: a subscription.updated
// moving a bound subscription from plus_beta to a LOWER plan must defer the
// downgrade to the cycle boundary (F11), exactly like a graceful
// cancellation — never take effect immediately just because it arrived as an
// "activate" action.
func TestPaddlePlanChangeDowngradeDefersToCycleBoundary(t *testing.T) {
	s, pool := newStore(t)
	seedStarterPlan(t, pool)
	acct := makeAccount(t, s)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	s.SetPaddlePriceMap(map[string]store.PaddlePlan{
		testPrice:        {Name: "plus_beta", Version: 1},
		testPriceStarter: {Name: "starter_test", Version: 1},
	})
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)

	changeAt := now.Add(time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_downgrade", EventType: "subscription.updated",
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPriceStarter,
		OccurredAt: changeAt, CurrentPeriodEnd: changeAt.AddDate(0, 1, 0), Now: changeAt,
	})
	if err != nil || !in.Applied {
		t.Fatalf("downgrade intake=%+v err=%v, want Applied", in, err)
	}
	// Immediately after: still plus_beta (F11 keeps what was paid for).
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", changeAt); al.Plan.Name != "plus_beta" {
		t.Errorf("plan right after the downgrade event = %q, want plus_beta (deferred)", al.Plan.Name)
	}
	// Well after the cycle boundary: starter_test.
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", changeAt.AddDate(0, 2, 0)); al.Plan.Name != "starter_test" {
		t.Errorf("plan well after the boundary = %q, want starter_test", al.Plan.Name)
	}
}

// TestPaddlePlanChangeUpgradeIsImmediate: a subscription.updated moving a
// bound subscription to a HIGHER plan takes effect immediately.
func TestPaddlePlanChangeUpgradeIsImmediate(t *testing.T) {
	s, pool := newStore(t)
	seedStarterPlan(t, pool)
	acct := makeAccount(t, s)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	s.SetPaddlePriceMap(map[string]store.PaddlePlan{
		testPrice:        {Name: "plus_beta", Version: 1},
		testPriceStarter: {Name: "starter_test", Version: 1},
	})
	ctx := context.Background()
	// Baseline: activate on the LOWER plan first. mintNonce always mints for
	// testPrice, so a checkout intent for testPriceStarter is minted directly
	// here (P3-c cross-checks the intent's stored price against the event's
	// own price at bind time — a mismatched nonce would now be correctly
	// refused, so the fixture must mint for the SAME price it binds with).
	nonce, _, err := s.CreateCheckoutIntent(ctx, acct, testPriceStarter, time.Hour, now)
	if err != nil {
		t.Fatalf("CreateCheckoutIntent: %v", err)
	}
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_base", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: nonce, CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active",
		PriceID: testPriceStarter, OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}); err != nil || !in.Applied {
		t.Fatalf("baseline activation intake=%+v err=%v, want Applied", in, err)
	}

	changeAt := now.Add(time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_upgrade", EventType: "subscription.updated",
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: changeAt, CurrentPeriodEnd: changeAt.AddDate(0, 1, 0), Now: changeAt,
	})
	if err != nil || !in.Applied {
		t.Fatalf("upgrade intake=%+v err=%v, want Applied", in, err)
	}
	// Immediately after: plus_beta already, no deferral.
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", changeAt); al.Plan.Name != "plus_beta" {
		t.Errorf("plan right after the upgrade event = %q, want plus_beta (immediate)", al.Plan.Name)
	}
}

// ---------------------------------------------------------------------------
// A5 (gap 1.8): ParsePaddlePriceEntries is pure — no DB required.
// ---------------------------------------------------------------------------

func TestParsePaddlePriceEntries(t *testing.T) {
	cases := []struct {
		name    string
		prices  string
		legacy  string
		want    map[string]store.PaddlePlan
		wantErr bool
	}{
		{
			name:   "legacy only",
			legacy: "pri_legacy",
			want:   map[string]store.PaddlePlan{"pri_legacy": {Name: "plus_beta", Version: 1, Interval: "month"}},
		},
		{
			name:   "multi price with display",
			prices: "pri_a=plus_beta:1:month:$15/mo",
			want:   map[string]store.PaddlePlan{"pri_a": {Name: "plus_beta", Version: 1, Interval: "month", Display: "$15/mo"}},
		},
		{
			name:   "multi price without display",
			prices: "pri_a=plus_beta:1:year",
			want:   map[string]store.PaddlePlan{"pri_a": {Name: "plus_beta", Version: 1, Interval: "year"}},
		},
		{
			name:   "legacy plus multi combine",
			prices: "pri_a=plus_beta:2:year:$150/yr",
			legacy: "pri_legacy",
			want: map[string]store.PaddlePlan{
				"pri_legacy": {Name: "plus_beta", Version: 1, Interval: "month"},
				"pri_a":      {Name: "plus_beta", Version: 2, Interval: "year", Display: "$150/yr"},
			},
		},
		{
			name:   "multiple comma-separated entries",
			prices: "pri_a=plus_beta:1:month, pri_b=plus_beta:2:year",
			want: map[string]store.PaddlePlan{
				"pri_a": {Name: "plus_beta", Version: 1, Interval: "month"},
				"pri_b": {Name: "plus_beta", Version: 2, Interval: "year"},
			},
		},
		{name: "empty is empty map", want: map[string]store.PaddlePlan{}},
		{name: "bad interval rejected", prices: "pri_a=plus_beta:1:week", wantErr: true},
		{name: "duplicate id rejected", prices: "pri_a=plus_beta:1:month,pri_a=plus_beta:2:year", wantErr: true},
		{name: "missing plan name rejected", prices: "pri_a==1:month", wantErr: true},
		{name: "non-numeric version rejected", prices: "pri_a=plus_beta:x:month", wantErr: true},
		{name: "zero version rejected", prices: "pri_a=plus_beta:0:month", wantErr: true},
		{name: "malformed entry no equals rejected", prices: "pri_a_plus_beta_1_month", wantErr: true},
		{name: "too few parts rejected", prices: "pri_a=plus_beta:1", wantErr: true},
		{name: "empty entry id rejected", prices: "=plus_beta:1:month", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.ParsePaddlePriceEntries(tc.prices, tc.legacy)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePaddlePriceEntries(%q,%q) = %+v, want error", tc.prices, tc.legacy, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePaddlePriceEntries(%q,%q): %v", tc.prices, tc.legacy, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParsePaddlePriceEntries(%q,%q) = %+v, want %+v", tc.prices, tc.legacy, got, tc.want)
			}
			for id, wantPlan := range tc.want {
				if gotPlan, ok := got[id]; !ok || gotPlan != wantPlan {
					t.Errorf("entry %s = %+v, want %+v", id, gotPlan, wantPlan)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A5: PlanExists — the startup-validation store method.
// ---------------------------------------------------------------------------

func TestPlanExists(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	if ok, err := s.PlanExists(ctx, "plus_beta", 1); err != nil || !ok {
		t.Fatalf("PlanExists(plus_beta,1) = %v err=%v, want true", ok, err)
	}
	if ok, err := s.PlanExists(ctx, "plus_beta", store.LatestPlanVersion); err != nil || !ok {
		t.Fatalf("PlanExists(plus_beta,LatestPlanVersion) = %v err=%v, want true", ok, err)
	}
	if ok, err := s.PlanExists(ctx, "plus_beta", 99); err != nil || ok {
		t.Fatalf("PlanExists(plus_beta,99) = %v err=%v, want false", ok, err)
	}
	if ok, err := s.PlanExists(ctx, "no_such_plan", 1); err != nil || ok {
		t.Fatalf("PlanExists(no_such_plan,1) = %v err=%v, want false", ok, err)
	}
	if ok, err := s.PlanExists(ctx, "", 1); err != nil || ok {
		t.Fatalf("PlanExists(\"\",1) = %v err=%v, want false", ok, err)
	}
}

// ---------------------------------------------------------------------------
// 2026-09-11 review remediation (adversarial review of baf3bc4d5). See
// docs/plans/arc2-stream5-paddle-notes-2026-09-02.md's 2026-09-11 delta
// section for the one-line-per-finding summary.
// ---------------------------------------------------------------------------

// TestPaddleCancelThenResubscribeRestoresPaidAccess is P1-1's core: a
// graceful cancellation schedules a free downgrade at the cycle boundary
// (F11); if the account then activates a NEW subscription (a fresh Paddle
// checkout, distinct subscription id) BEFORE that boundary fires, the new
// activation must actually win — not silently no-op behind assignPlanTx's
// "the open row already starts at/after this" conflict guard, which (pre-fix)
// left the STALE free-downgrade schedule in place to fire regardless.
func TestPaddleCancelThenResubscribeRestoresPaidAccess(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)

	cancelAt := now.Add(time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_cancel", EventType: "subscription.canceled", AccountID: acct,
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "canceled", PriceID: testPrice,
		OccurredAt: cancelAt, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: cancelAt,
	}); err != nil || !in.Applied {
		t.Fatalf("cancel intake=%+v err=%v, want Applied", in, err)
	}
	// The downgrade is scheduled at the cycle boundary, not yet in force.
	ceiling := store.CeilToMonthlyCycleStart(now.AddDate(0, 1, 0))
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", ceiling.Add(-time.Minute)); al.Plan.Name != "plus_beta" {
		t.Fatalf("test setup: plan just before the scheduled downgrade = %q, want plus_beta", al.Plan.Name)
	}

	// Re-subscribe 2 days later — a NEW nonce and a NEW subscription id (a
	// fresh Paddle checkout) — while the stale free downgrade is still
	// scheduled for `ceiling`.
	resubAt := now.AddDate(0, 0, 2)
	nonce2 := mintNonce(t, s, acct, resubAt)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_resub", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: nonce2, CustomerID: "ctm_2", SubscriptionID: "sub_2", Status: "active",
		PriceID: testPrice, OccurredAt: resubAt, CurrentPeriodEnd: resubAt.AddDate(0, 1, 0), Now: resubAt,
	})
	if err != nil || !in.Applied || in.Outcome != "applied" {
		t.Fatalf("re-subscribe intake=%+v err=%v, want Applied outcome=applied (P1-1: must never swallow as a no-op conflict)", in, err)
	}

	// WELL PAST the original stale schedule's boundary, the account is STILL
	// paid — through sub_2, never dropped to free by the superseded schedule.
	checkAt := ceiling.AddDate(0, 0, 5)
	al, err := s.ResolveAllowance(ctx, acct, "session_enrichment", checkAt)
	if err != nil || al.Plan.Name != "plus_beta" {
		t.Fatalf("plan past the stale schedule's boundary = %+v err=%v, want plus_beta (restored via sub_2)", al, err)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.SubscriptionID != "sub_2" || sub.Status != "active" {
		t.Fatalf("subscription=%+v err=%v, want active sub_2", sub, err)
	}
}

// TestPaddleTrialCancelThenResubscribeRestoresPaidAccess is P1-1's trial
// variant: a cancellation during a trial schedules the free downgrade at the
// trial's own end (A7); resubscribing before that instant must still win
// over the stale schedule.
func TestPaddleTrialCancelThenResubscribeRestoresPaidAccess(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	trialEnd := now.AddDate(0, 0, 7)

	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_trial", EventType: "subscription.trialing", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "trialing", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: trialEnd, Now: now,
	}); err != nil || !in.Applied {
		t.Fatalf("trial activation intake=%+v err=%v, want Applied", in, err)
	}

	cancelAt := now.Add(time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_trial_cancel", EventType: "subscription.canceled",
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "canceled", PriceID: testPrice,
		OccurredAt: cancelAt, CurrentPeriodEnd: trialEnd, Now: cancelAt,
	}); err != nil || !in.Applied {
		t.Fatalf("trial cancel intake=%+v err=%v, want Applied", in, err)
	}
	// The downgrade is scheduled for the trial's own end, not yet in force.
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", trialEnd.Add(-time.Minute)); al.Plan.Name != "plus_beta" {
		t.Fatalf("test setup: plan just before the scheduled trial-end downgrade = %q, want plus_beta", al.Plan.Name)
	}

	// Re-subscribe with a NEW checkout WHILE the trial-cancel downgrade is
	// still scheduled for trialEnd.
	resubAt := now.Add(2 * time.Hour)
	nonce2 := mintNonce(t, s, acct, resubAt)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_resub", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: nonce2, CustomerID: "ctm_2", SubscriptionID: "sub_2", Status: "active",
		PriceID: testPrice, OccurredAt: resubAt, CurrentPeriodEnd: resubAt.AddDate(0, 1, 0), Now: resubAt,
	})
	if err != nil || !in.Applied || in.Outcome != "applied" {
		t.Fatalf("re-subscribe intake=%+v err=%v, want Applied outcome=applied (P1-1: must never swallow as a no-op conflict)", in, err)
	}

	// Well past the ORIGINAL trial-cancel's scheduled downgrade instant, the
	// account is STILL paid — through sub_2, not the stale trial schedule.
	checkAt := trialEnd.AddDate(0, 0, 3)
	al, err := s.ResolveAllowance(ctx, acct, "session_enrichment", checkAt)
	if err != nil || al.Plan.Name != "plus_beta" {
		t.Fatalf("plan after the stale trial-end schedule = %+v err=%v, want plus_beta (restored via sub_2)", al, err)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.SubscriptionID != "sub_2" || sub.Status != "active" {
		t.Fatalf("subscription=%+v err=%v, want active sub_2", sub, err)
	}
}

// TestPaddleFirstPurchaseWebhooksRaceBothApply is P1-2's core: a first
// purchase's transaction.completed and subscription.created/trialing
// deliveries typically share the SAME custom_data (account_id + checkout
// nonce) and can race in. Before the fix, whichever acquired the per-account
// advisory lock SECOND still tried (and failed) to consume the already-
// consumed nonce and lost as "binding_refused" forever, even though its own
// subscription WAS by then bound. Both legs must apply.
func TestPaddleFirstPurchaseWebhooksRaceBothApply(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	nonce := mintNonce(t, s, acct, now)
	trialEnd := now.AddDate(0, 0, 7)

	evTxn := store.PaddleEvent{
		EventID: "evt_race_txn", EventType: "transaction.completed",
		AccountID: acct, CheckoutNonce: nonce, CustomerID: "ctm_race",
		SubscriptionID: "sub_race", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}
	evSub := store.PaddleEvent{
		EventID: "evt_race_sub", EventType: "subscription.created", Status: "trialing",
		AccountID: acct, CheckoutNonce: nonce, CustomerID: "ctm_race",
		SubscriptionID: "sub_race", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: trialEnd, Now: now,
	}

	var wg sync.WaitGroup
	var inTxn, inSub store.BillingIntake
	var errTxn, errSub error
	wg.Add(2)
	go func() { defer wg.Done(); inTxn, errTxn = s.ProcessPaddleEvent(ctx, evTxn) }()
	go func() { defer wg.Done(); inSub, errSub = s.ProcessPaddleEvent(ctx, evSub) }()
	wg.Wait()

	if errTxn != nil || errSub != nil {
		t.Fatalf("race errors: txn=%v sub=%v", errTxn, errSub)
	}
	if !inTxn.Applied || inTxn.Outcome == "binding_refused" {
		t.Fatalf("transaction.completed leg lost the race: %+v", inTxn)
	}
	if !inSub.Applied || inSub.Outcome == "binding_refused" {
		t.Fatalf("subscription.created leg lost the race: %+v", inSub)
	}

	al, err := s.ResolveAllowance(ctx, acct, "session_enrichment", now)
	if err != nil || al.Plan.Name != "plus_beta" {
		t.Fatalf("plan after the race = %+v err=%v, want plus_beta (both legs must have bound to the SAME account)", al, err)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil {
		t.Fatalf("AccountSubscription: %v", err)
	}
	if sub.SubscriptionID != "sub_race" {
		t.Fatalf("subscription=%+v, want sub_race bound", sub)
	}
	// Whichever leg wrote last decides the row's final status — both are
	// legitimate outcomes of the race (this test's point is that NEITHER leg
	// is refused, not which one wins the write). trial_ends_at must be
	// consistent with whatever status won.
	if sub.Status == "trialing" {
		if sub.TrialEndsAt == nil || !sub.TrialEndsAt.Equal(trialEnd) {
			t.Fatalf("status=trialing but trial_ends_at=%v, want %v", sub.TrialEndsAt, trialEnd)
		}
	} else if sub.Status != "active" {
		t.Fatalf("status=%q, want active or trialing", sub.Status)
	}
}

// TestPaddleForgedAccountIDNeverErrors is P2-1's core: neither a non-UUID
// custom_data.account_id nor a syntactically valid but entirely foreign UUID
// may ever cause ProcessPaddleEvent to return an error (which would leave
// processed_at NULL and make Paddle redeliver the same failing event
// forever) — both shapes must resolve to a 200-class outcome.
func TestPaddleForgedAccountIDNeverErrors(t *testing.T) {
	s, _, now := paddleStore(t)
	ctx := context.Background()

	// Shape 1: a non-UUID account id. The api decode boundary
	// (paddleEventFromEnvelope) sanitizes this to "" before it ever reaches
	// the store — reproduced directly here to prove the store side alone
	// (the billing_events insert-ordering fix) also never errors on it.
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_forged_nonuuid", EventType: "subscription.activated",
		AccountID: "not-a-uuid-at-all!!", CheckoutNonce: "whatever",
		CustomerID: "ctm_forged_1", SubscriptionID: "sub_forged_1", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	})
	if err != nil {
		t.Fatalf("non-UUID account id: err=%v, want no error", err)
	}
	if in.Applied || (in.Outcome != "binding_refused" && in.Outcome != "unattributed") {
		t.Fatalf("non-UUID account id intake=%+v, want !Applied outcome in {binding_refused, unattributed}", in)
	}

	// Shape 2: a syntactically valid UUID that names no real account. No real
	// checkout intent can exist for it (checkout_intents.account_id itself
	// FK-references accounts — minting one would require the account to
	// exist, defeating the point), so the nonce here is an arbitrary
	// non-empty placeholder: the account-existence check must refuse this
	// BEFORE any nonce is ever consumed.
	foreignUUID := "00000000-0000-4000-8000-0000000000ff"
	in, err = s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_forged_randomuuid", EventType: "subscription.activated",
		AccountID: foreignUUID, CheckoutNonce: "placeholder-nonce",
		CustomerID: "ctm_forged_2", SubscriptionID: "sub_forged_2", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	})
	if err != nil {
		t.Fatalf("foreign valid UUID: err=%v, want no error", err)
	}
	if in.Applied || in.Outcome != "account_not_found" {
		t.Fatalf("foreign valid UUID intake=%+v, want !Applied outcome=account_not_found", in)
	}
}

// TestPaddleTrialPastDueThenCanceledEndsAtTrialEnd is P2-2's core: a
// trialing subscription that goes past_due BEFORE it is canceled must still
// end at the trial's own end, not ride paid access all the way to the next
// monthly cycle boundary (the OLD priorStatus=="trialing" check missed this
// because applyPaddleStatusOnly's past_due transition changes `status` but
// never touches trial_ends_at).
func TestPaddleTrialPastDueThenCanceledEndsAtTrialEnd(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	trialEnd := now.AddDate(0, 0, 7)

	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_trial", EventType: "subscription.trialing", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "trialing", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: trialEnd, Now: now,
	}); err != nil {
		t.Fatalf("trial activation: %v", err)
	}

	pastDueAt := now.Add(2 * time.Hour)
	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_pd", EventType: "subscription.past_due",
		CustomerID: "ctm_1", SubscriptionID: "sub_1",
		OccurredAt: pastDueAt, Now: pastDueAt,
	}); err != nil {
		t.Fatalf("past_due: %v", err)
	}
	// trial_ends_at survives the status_only transition.
	if sub, err := s.AccountSubscription(ctx, acct); err != nil || sub.Status != "past_due" || sub.TrialEndsAt == nil {
		t.Fatalf("subscription after past_due=%+v err=%v, want status=past_due with trial_ends_at intact", sub, err)
	}

	cancelAt := now.Add(3 * time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_cancel", EventType: "subscription.canceled",
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "canceled",
		// Deliberately NO current_billing_period on the cancellation itself —
		// a cancellation delivered after a past_due detour may carry none —
		// proving the downgrade is anchored to the STORED trial end, not
		// whatever (or nothing) the cancel event itself carries.
		OccurredAt: cancelAt, Now: cancelAt,
	})
	if err != nil || !in.Applied {
		t.Fatalf("cancel intake=%+v err=%v, want Applied", in, err)
	}

	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", trialEnd.Add(-time.Minute)); al.Plan.Name != "plus_beta" {
		t.Errorf("plan just before trial end = %q, want plus_beta", al.Plan.Name)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", trialEnd); al.Plan.Name != "free" {
		t.Errorf("plan at trial end = %q, want free (a never-paid trial must not ride the monthly ceiling)", al.Plan.Name)
	}
	ceiling := store.CeilToMonthlyCycleStart(trialEnd)
	if !ceiling.After(trialEnd) {
		t.Fatalf("test setup: expected the monthly ceiling %v to be after the trial end %v", ceiling, trialEnd)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", ceiling.Add(-time.Minute)); al.Plan.Name != "free" {
		t.Errorf("plan just before the monthly ceiling = %q, want free (the OLD bug rode paid access all the way to here)", al.Plan.Name)
	}
}

// TestPaddleSecondLiveSubscriptionRefusedNotError is P2-3's store-level core:
// a second, DISTINCT subscription id activating while another is still live
// for the same account must be refused gracefully — never the raw 23505
// paddle_subscriptions_one_live violation that would abort the whole
// transaction and 500 the delivery forever.
func TestPaddleSecondLiveSubscriptionRefusedNotError(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)

	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_second_live", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_2", SubscriptionID: "sub_2", Status: "active", PriceID: testPrice,
		// A minute later — well inside mintNonce's 1h TTL (the intent must
		// still be LIVE so this test exercises the second-live refusal, not
		// an incidental nonce expiry).
		OccurredAt: now.Add(time.Minute), CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("second-live intake err=%v, want no error (refused gracefully, not a raw constraint violation)", err)
	}
	if in.Applied || in.Outcome != "refused_second_live" {
		t.Fatalf("second-live intake=%+v, want !Applied outcome=refused_second_live", in)
	}
	// sub_1 is still the account's live subscription — untouched.
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.SubscriptionID != "sub_1" || sub.Status != "active" {
		t.Fatalf("subscription=%+v err=%v, want sub_1 still active", sub, err)
	}
	al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", now.Add(time.Hour))
	if al.Plan.Name != "plus_beta" {
		t.Errorf("plan after the refused second-live attempt = %q, want plus_beta (sub_1 untouched)", al.Plan.Name)
	}
}

// TestPaddleBindingRefusedOnPriceMismatch is P3-c's core: a webhook binding
// a DIFFERENT price than the one the checkout intent was actually minted for
// must be refused — the intent's stored price_id (migration 0030) is a real
// cross-check, not merely audit decoration.
func TestPaddleBindingRefusedOnPriceMismatch(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	s.SetPaddlePriceMap(map[string]store.PaddlePlan{
		testPrice:        {Name: "plus_beta", Version: 1},
		testPriceStarter: {Name: "starter_test", Version: 1},
	})
	// The intent is minted for testPrice...
	nonce := mintNonce(t, s, acct, now)

	// ...but the webhook reports a DIFFERENT (also known) price.
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_price_mismatch", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: nonce, CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active",
		PriceID: testPriceStarter, OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	})
	if err != nil || in.Applied || in.Outcome != "binding_refused" {
		t.Fatalf("price-mismatch intake=%+v err=%v, want !Applied outcome=binding_refused", in, err)
	}
	if _, err := s.AccountSubscription(ctx, acct); err == nil {
		t.Fatalf("a price-mismatched binding created a subscription")
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", now); al.Plan.Name != "free" {
		t.Errorf("plan after refused price-mismatch binding = %q, want free", al.Plan.Name)
	}
}

// TestPaddleCancelKeepsStoredPlanOnUnknownPrice is P3-e's core: a
// cancellation arriving with an unknown/unrecognized price must keep the
// row's OWN stored plan (starter_test here, deliberately NOT plus_beta) —
// never silently rewrite it to a fixed plus_beta v1 label.
func TestPaddleCancelKeepsStoredPlanOnUnknownPrice(t *testing.T) {
	s, pool := newStore(t)
	seedStarterPlan(t, pool)
	acct := makeAccount(t, s)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	s.SetPaddlePriceMap(map[string]store.PaddlePlan{
		testPriceStarter: {Name: "starter_test", Version: 1},
	})
	ctx := context.Background()

	nonce, _, err := s.CreateCheckoutIntent(ctx, acct, testPriceStarter, time.Hour, now)
	if err != nil {
		t.Fatalf("CreateCheckoutIntent: %v", err)
	}
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_base", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: nonce, CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active",
		PriceID: testPriceStarter, OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}); err != nil || !in.Applied {
		t.Fatalf("baseline activation intake=%+v err=%v, want Applied", in, err)
	}

	// Cancellation arrives with a price this deployment does NOT recognize
	// (e.g. a Paddle-side price change to something not yet provisioned).
	cancelAt := now.Add(time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_cancel_unknown_price", EventType: "subscription.canceled",
		CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "canceled", PriceID: "pri_UNRECOGNIZED",
		OccurredAt: cancelAt, CurrentPeriodEnd: cancelAt.AddDate(0, 1, 0), Now: cancelAt,
	})
	if err != nil || !in.Applied {
		t.Fatalf("cancel intake=%+v err=%v, want Applied", in, err)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil {
		t.Fatalf("AccountSubscription: %v", err)
	}
	if sub.PlanName != "starter_test" || sub.PlanVersion != 1 {
		t.Fatalf("subscription after unknown-price cancel plan=%s v%d, want starter_test v1 (kept from the existing row, never rewritten to plus_beta)", sub.PlanName, sub.PlanVersion)
	}
	al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", cancelAt)
	if al.Plan.Name != "starter_test" {
		t.Errorf("plan right after cancel = %q, want starter_test (kept through the period, never a wrongly-defaulted plus_beta)", al.Plan.Name)
	}
}

// TestResolveActivateStatus is the pure table-driven test for the 2026-09-12
// live-defect fix's decision function: a real Paddle sandbox checkout
// delivers subscription.created (trialing) -> subscription.trialing
// (trialing) -> transaction.completed (the $0 trial-start transaction, which
// carries NO subscription status at all) - and that last, harmless $0
// transaction must never convert a still-trialing row to 'active' or clear
// its trial_ends_at.
func TestResolveActivateStatus(t *testing.T) {
	trialEnd := time.Date(2026, 9, 18, 19, 51, 52, 0, time.UTC)
	otherTrialEnd := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name             string
		ev               store.PaddleEvent
		existingStatus   string
		existingTrialEnd *time.Time
		wantStatus       string
		wantTrialEnd     *time.Time
	}{
		{
			name: "trialing row + zero-total transaction.completed keeps trialing and its own trial end",
			ev: store.PaddleEvent{
				EventType: "transaction.completed", Status: "completed",
				TransactionZeroTotal: true, TrialPeriodOnPrice: true,
			},
			existingStatus: "trialing", existingTrialEnd: &trialEnd,
			wantStatus: "trialing", wantTrialEnd: &trialEnd,
		},
		{
			name: "trialing row + non-zero transaction.completed converts to active",
			ev: store.PaddleEvent{
				EventType: "transaction.completed", Status: "completed",
				TransactionZeroTotal: false, TrialPeriodOnPrice: true,
			},
			existingStatus: "trialing", existingTrialEnd: &trialEnd,
			wantStatus: "active", wantTrialEnd: nil,
		},
		{
			name: "no row yet + zero-total transaction.completed + trial_period on price binds as trialing",
			ev: store.PaddleEvent{
				EventType: "transaction.completed", Status: "completed",
				TransactionZeroTotal: true, TrialPeriodOnPrice: true,
			},
			existingStatus: "", existingTrialEnd: nil,
			wantStatus: "trialing", wantTrialEnd: nil,
		},
		{
			name: "no row yet + zero-total transaction.completed but NO trial_period on price activates",
			ev: store.PaddleEvent{
				EventType: "transaction.completed", Status: "completed",
				TransactionZeroTotal: true, TrialPeriodOnPrice: false,
			},
			existingStatus: "", existingTrialEnd: nil,
			wantStatus: "active", wantTrialEnd: nil,
		},
		{
			name:           "explicit subscription.trialing event resolves to trialing",
			ev:             store.PaddleEvent{EventType: "subscription.trialing", Status: "trialing"},
			existingStatus: "", existingTrialEnd: nil,
			wantStatus: "trialing", wantTrialEnd: nil,
		},
		{
			name:           "subscription.activated with status active resolves to active",
			ev:             store.PaddleEvent{EventType: "subscription.activated", Status: "active"},
			existingStatus: "", existingTrialEnd: nil,
			wantStatus: "active", wantTrialEnd: nil,
		},
		{
			name: "past_due row + zero-total transaction.completed still resolves to active - ONLY an existing trialing row is preserved",
			ev: store.PaddleEvent{
				EventType: "transaction.completed", Status: "completed",
				TransactionZeroTotal: true, TrialPeriodOnPrice: true,
			},
			existingStatus: "past_due", existingTrialEnd: &otherTrialEnd,
			wantStatus: "active", wantTrialEnd: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotStatus, gotTrialEnd := store.ResolveActivateStatus(c.ev, c.existingStatus, c.existingTrialEnd)
			if gotStatus != c.wantStatus {
				t.Errorf("status = %q, want %q", gotStatus, c.wantStatus)
			}
			switch {
			case c.wantTrialEnd == nil && gotTrialEnd != nil:
				t.Errorf("trialEnd = %v, want nil", gotTrialEnd)
			case c.wantTrialEnd != nil && (gotTrialEnd == nil || !gotTrialEnd.Equal(*c.wantTrialEnd)):
				t.Errorf("trialEnd = %v, want %v", gotTrialEnd, c.wantTrialEnd)
			}
		})
	}
}

// TestPaddleRealSandboxPayloadsPreserveTrialThroughZeroTotalTransaction is the
// end-to-end regression for the 2026-09-12 live defect: it replays the THREE
// real Paddle sandbox delivery bodies, IN THE ORDER Paddle actually sent them
// (subscription.created -> subscription.trialing -> transaction.completed),
// through the REAL decoder (api.DecodePaddleWebhookEnvelope) and the real
// store intake (s.ProcessPaddleEvent) - never a hand-built store.PaddleEvent
// literal - and asserts the row is still 'trialing' with trial_ends_at set
// after all three, rather than the pre-fix 'active' with a nulled
// trial_ends_at.
//
// The fixture bodies carry a REAL sandbox account_id/checkout_nonce/price_id
// foreign to this test's throwaway database; account/nonce/price identity is
// rebound to this test's own account + server-minted nonce + provisioned
// price AFTER decoding, so every OTHER decoded field (status, event type,
// TransactionZeroTotal, TrialPeriodOnPrice, TrialEndsAt, CurrentPeriodEnd,
// OccurredAt...) is exactly what the real decoder produced from the real
// bytes.
func TestPaddleRealSandboxPayloadsPreserveTrialThroughZeroTotalTransaction(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	nonce := mintNonce(t, s, acct, now)

	files := []string{
		"testdata/paddle_trial/subscription.created.json",
		"testdata/paddle_trial/subscription.trialing.json",
		"testdata/paddle_trial/transaction.completed.json",
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		ev, err := api.DecodePaddleWebhookEnvelope(body, now)
		if err != nil {
			t.Fatalf("decode %s: %v", f, err)
		}
		ev.AccountID = acct
		ev.CheckoutNonce = nonce
		ev.PriceID = testPrice
		ev.Now = now
		if in, err := s.ProcessPaddleEvent(ctx, ev); err != nil {
			t.Fatalf("process %s: %v", f, err)
		} else if !in.Applied {
			t.Fatalf("process %s: intake=%+v, want Applied", f, in)
		}
	}

	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil {
		t.Fatalf("AccountSubscription: %v", err)
	}
	if sub.Status != "trialing" {
		t.Fatalf("status after replaying all 3 real deliveries = %q, want trialing (the $0 trial-start transaction must not convert to active)", sub.Status)
	}
	if sub.TrialEndsAt == nil {
		t.Fatalf("trial_ends_at is nil after replay, want set (the real trial end, 2026-09-18)")
	}
}
