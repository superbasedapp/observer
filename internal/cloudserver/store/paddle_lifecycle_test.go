package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// paddle_lifecycle_test.go covers the subscription-lifecycle rules of the
// Fable review of 2026-11-17 (docs/security.md BILL-FR2, BILL-FR7, BILL-FR8,
// BILL-FR9, BILL-FR10, BILL-FR22): pure rule tables one case per row, then
// the DB-backed paths through ProcessPaddleEvent.

// --- pure rules ---------------------------------------------------------

func TestActivateMayReopen(t *testing.T) {
	paid := store.PaddleEvent{EventType: "transaction.completed", TransactionPaid: true}
	unpaid := store.PaddleEvent{EventType: "transaction.completed", TransactionZeroTotal: true}
	noTotals := store.PaddleEvent{EventType: "transaction.completed"}
	update := store.PaddleEvent{EventType: "subscription.updated", Status: "active"}
	resumed := store.PaddleEvent{EventType: "subscription.resumed", Status: "active"}
	cases := []struct {
		name     string
		ev       store.PaddleEvent
		existing string
		want     bool
	}{
		{"no row yet", update, "", true},
		{"live row: update", update, "active", true},
		{"past_due row: update", update, "past_due", true},
		{"paused row: resumed", resumed, "paused", true},
		{"refunded: subscription.updated active stays refunded", update, "refunded", false},
		{"charged_back: subscription.updated active stays", update, "charged_back", false},
		{"canceled: resumed stays canceled", resumed, "canceled", false},
		{"refunded: zero-total transaction stays", unpaid, "refunded", false},
		{"refunded: transaction with no totals stays", noTotals, "refunded", false},
		{"refunded: paid renewal re-opens (rule: paid transaction)", paid, "refunded", true},
		{"canceled: paid transaction re-opens", paid, "canceled", true},
	}
	for _, c := range cases {
		if got := store.ActivateMayReopen(c.ev, c.existing); got != c.want {
			t.Errorf("%s: ActivateMayReopen = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPendingTerminalSuperseded(t *testing.T) {
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		ev   store.PaddleEvent
		want bool
	}{
		{"activation after the cancel", store.PaddleEvent{EventType: "subscription.created", Status: "active", OccurredAt: at.Add(time.Hour)}, false},
		{"paid transaction before the cancel", store.PaddleEvent{EventType: "transaction.completed", TransactionPaid: true, OccurredAt: at.Add(-time.Hour)}, false},
		{"paid transaction at the cancel instant", store.PaddleEvent{EventType: "transaction.completed", TransactionPaid: true, OccurredAt: at}, false},
		{"zero transaction after the cancel", store.PaddleEvent{EventType: "transaction.completed", TransactionZeroTotal: true, OccurredAt: at.Add(time.Hour)}, false},
		{"paid transaction after the cancel", store.PaddleEvent{EventType: "transaction.completed", TransactionPaid: true, OccurredAt: at.Add(time.Hour)}, true},
	}
	for _, c := range cases {
		if got := store.PendingTerminalSuperseded(c.ev, at); got != c.want {
			t.Errorf("%s: PendingTerminalSuperseded = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPaddleDunningDropAt(t *testing.T) {
	occurred := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	since := occurred.Add(-48 * time.Hour)
	grace := 14 * 24 * time.Hour
	cases := []struct {
		name   string
		status string
		since  *time.Time
		want   time.Time
		ok     bool
	}{
		{"paused: drops at the event", "paused", nil, occurred, true},
		{"past_due: grace from the recorded entry", "past_due", &since, since.Add(grace), true},
		{"past_due with no entry: grace from the event", "past_due", nil, occurred.Add(grace), true},
		{"active: no rule", "active", nil, time.Time{}, false},
		{"trialing: no rule", "trialing", nil, time.Time{}, false},
		{"canceled: no rule (cancel has its own path)", "canceled", nil, time.Time{}, false},
	}
	for _, c := range cases {
		got, ok := store.PaddleDunningDropAt(c.status, c.since, occurred, grace)
		if ok != c.ok || !got.Equal(c.want) {
			t.Errorf("%s: PaddleDunningDropAt = %v,%v, want %v,%v", c.name, got, ok, c.want, c.ok)
		}
	}
}

// The account path's default dunning window is the org path's (FR-9: "the
// same grace rule as orgs").
func TestDefaultPaddlePastDueGraceMatchesOrgs(t *testing.T) {
	if store.DefaultPaddlePastDueGrace != entitlementwork.DefaultPastDueGrace {
		t.Fatalf("store.DefaultPaddlePastDueGrace = %v, entitlementwork.DefaultPastDueGrace = %v", store.DefaultPaddlePastDueGrace, entitlementwork.DefaultPastDueGrace)
	}
}

// --- FR-2: the bind window is judged at the event time ------------------

func TestPaddleBindingJudgedAtEventTimeAndRefusalRecorded(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	// Minted with the default window (ttl 0 = CheckoutIntentBindWindow).
	nonce, expires, err := s.CreateCheckoutIntent(ctx, acct, testPrice, 0, now)
	if err != nil {
		t.Fatalf("CreateCheckoutIntent: %v", err)
	}
	if !expires.Equal(now.Add(store.CheckoutIntentBindWindow)) {
		t.Fatalf("expires = %v, want now + %v", expires, store.CheckoutIntentBindWindow)
	}

	// A first event that occurred AFTER the window refuses, is recorded and
	// lists as an open refusal of a paid price.
	late := now.Add(store.CheckoutIntentBindWindow + time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_late", EventType: "subscription.created", AccountID: acct, CheckoutNonce: nonce,
		CustomerID: "ctm_late", SubscriptionID: "sub_late", Status: "active", PriceID: testPrice,
		OccurredAt: late, Now: late,
	})
	if err != nil || in.Applied || in.Outcome != "binding_refused" || in.Reason != "no_live_intent" {
		t.Fatalf("late event intake=%+v err=%v, want binding_refused/no_live_intent", in, err)
	}
	open, err := s.OpenPaddleBindingRefusals(ctx, 10)
	if err != nil || len(open) != 1 || open[0].SubscriptionID != "sub_late" || !open[0].PriceKnown || open[0].Reason != "no_live_intent" {
		t.Fatalf("open refusals = %+v err=%v, want the one sub_late refusal of a known price", open, err)
	}

	// The same nonce, on an event that occurred INSIDE the window but is
	// processed three weeks later (a retry after an outage), still binds:
	// processing time no longer matters, and the sweeper keeps the intent.
	if n, err := s.SweepExpiredCheckoutIntents(ctx, now.Add(store.CheckoutIntentBindWindow+24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("sweep just past the window removed %d (err %v), want 0 (kept for retries)", n, err)
	}
	processed := now.Add(21 * 24 * time.Hour)
	in, err = s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_retry", EventType: "subscription.created", AccountID: acct, CheckoutNonce: nonce,
		CustomerID: "ctm_1", SubscriptionID: "sub_ok", Status: "active", PriceID: testPrice,
		OccurredAt: now.Add(45 * time.Minute), CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: processed,
	})
	if err != nil || !in.Applied || in.Outcome != "applied" {
		t.Fatalf("late-processed in-window event intake=%+v err=%v, want applied", in, err)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", processed); al.Plan.Name != "plus_beta" {
		t.Fatalf("plan after the late bind = %q, want plus_beta", al.Plan.Name)
	}

	// Long after the window plus the retention the sweeper removes it.
	if n, err := s.SweepExpiredCheckoutIntents(ctx, now.Add(store.CheckoutIntentBindWindow+40*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("sweep after retention removed %d (err %v), want 1", n, err)
	}
}

// A later delivery that binds the refused subscription resolves its refusal.
func TestPaddleBindingRefusalResolvedByLaterBind(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_nononce", EventType: "subscription.created", AccountID: acct,
		SubscriptionID: "sub_r", Status: "active", PriceID: testPrice, OccurredAt: now, Now: now,
	}); err != nil || in.Reason != "missing_nonce" {
		t.Fatalf("no-nonce intake=%+v err=%v, want reason missing_nonce", in, err)
	}
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_withnonce", EventType: "transaction.completed", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now), CustomerID: "ctm_1", SubscriptionID: "sub_r", PriceID: testPrice,
		TransactionPaid: true, OccurredAt: now.Add(time.Minute), Now: now.Add(time.Minute),
	}); err != nil || !in.Applied {
		t.Fatalf("binding intake=%+v err=%v, want applied", in, err)
	}
	if open, err := s.OpenPaddleBindingRefusals(ctx, 10); err != nil || len(open) != 0 {
		t.Fatalf("open refusals after the bind = %+v err=%v, want none", open, err)
	}
}

// --- FR-7: a terminal row re-opens only on a paid renewal ---------------

func TestPaddleRefundedSubscriptionReopensOnlyOnPaidRenewal(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)
	refundAt := now.Add(time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_refund", EventType: "adjustment.updated", SubscriptionID: "sub_1",
		AdjustmentAction: "refund", AdjustmentType: "full", AdjustmentStatus: "approved",
		OccurredAt: refundAt, Now: refundAt,
	}); err != nil || !in.Applied {
		t.Fatalf("refund intake=%+v err=%v", in, err)
	}
	steps := []struct {
		name       string
		ev         store.PaddleEvent
		outcome    string
		wantStatus string
		wantPlan   string
	}{
		{
			"subscription.updated active keeps it refunded",
			store.PaddleEvent{EventType: "subscription.updated", Status: "active", PriceID: testPrice},
			"terminal_kept", "refunded", "free",
		},
		{
			"subscription.past_due keeps it refunded",
			store.PaddleEvent{EventType: "subscription.past_due"},
			"terminal_kept", "refunded", "free",
		},
		{
			"a zero-total transaction keeps it refunded",
			store.PaddleEvent{EventType: "transaction.completed", PriceID: testPrice, TransactionZeroTotal: true},
			"terminal_kept", "refunded", "free",
		},
		{
			"a paid renewal re-opens it",
			store.PaddleEvent{EventType: "transaction.completed", PriceID: testPrice, TransactionPaid: true},
			"applied", "active", "plus_beta",
		},
	}
	at := refundAt
	for i, st := range steps {
		at = at.Add(time.Hour)
		ev := st.ev
		ev.EventID = "evt_fr7_" + string(rune('a'+i))
		ev.SubscriptionID, ev.CustomerID = "sub_1", "ctm_1"
		ev.OccurredAt, ev.Now = at, at
		in, err := s.ProcessPaddleEvent(ctx, ev)
		if err != nil || in.Outcome != st.outcome {
			t.Fatalf("%s: intake=%+v err=%v, want outcome %s", st.name, in, err, st.outcome)
		}
		if sub, _ := s.AccountSubscription(ctx, acct); sub.Status != st.wantStatus {
			t.Fatalf("%s: status = %q, want %q", st.name, sub.Status, st.wantStatus)
		}
		if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", at); al.Plan.Name != st.wantPlan {
			t.Fatalf("%s: plan = %q, want %q", st.name, al.Plan.Name, st.wantPlan)
		}
	}
}

// The org path follows the same rule (its plan is the row's status).
func TestOrgRefundedSubscriptionNotReopenedByUpdate(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	f.activateOrg(t, "evt_o0", "sub_o", orgTestPriceTeam, f.now)
	for i, ev := range []store.PaddleEvent{
		{EventType: "adjustment.updated", AdjustmentAction: "refund", AdjustmentType: "full", AdjustmentStatus: "approved"},
		{EventType: "subscription.updated", Status: "active", PriceID: orgTestPriceTeam},
		{EventType: "subscription.past_due"},
	} {
		at := f.now.Add(time.Duration(i+1) * time.Hour)
		ev.EventID, ev.SubscriptionID, ev.CustomerID = "evt_o"+string(rune('a'+i)), "sub_o", "ctm_org"
		ev.OccurredAt, ev.Now = at, at
		if _, err := f.s.ProcessPaddleEvent(ctx, ev); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if sub, _ := f.s.OrgSubscription(ctx, f.org.OrgID); sub.Status != "refunded" {
			t.Fatalf("step %d (%s): org status = %q, want refunded", i, ev.EventType, sub.Status)
		}
	}
}

// --- FR-8: a terminal event before the binding ---------------------------

func TestPaddleCancelBeforeBindIsKeptAndApplied(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_cancel_first", EventType: "subscription.canceled", SubscriptionID: "sub_early",
		Status: "canceled", PriceID: testPrice, OccurredAt: now.Add(2 * time.Hour), Now: now.Add(2 * time.Hour),
	})
	if err != nil || in.Applied || in.Outcome != "terminal_pending" {
		t.Fatalf("early cancel intake=%+v err=%v, want terminal_pending", in, err)
	}
	// The (late) activation binds the subscription as canceled, no plan.
	in, err = s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_created_late", EventType: "subscription.created", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now), CustomerID: "ctm_1", SubscriptionID: "sub_early",
		Status: "active", PriceID: testPrice, OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now.Add(3 * time.Hour),
	})
	if err != nil || in.Outcome != "bound_terminal" {
		t.Fatalf("late bind intake=%+v err=%v, want bound_terminal", in, err)
	}
	if sub, _ := s.AccountSubscription(ctx, acct); sub.Status != "canceled" {
		t.Fatalf("status = %q, want canceled", sub.Status)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", now.Add(3*time.Hour)); al.Plan.Name != "free" {
		t.Fatalf("plan = %q, want free (nothing to revoke later)", al.Plan.Name)
	}
	// A redelivery of the activation is a replay of a bound subscription: it
	// may not re-open the canceled row.
	in, err = s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_updated_after", EventType: "subscription.updated", SubscriptionID: "sub_early",
		Status: "active", PriceID: testPrice, OccurredAt: now.Add(4 * time.Hour), Now: now.Add(4 * time.Hour),
	})
	if err != nil || in.Outcome != "terminal_kept" {
		t.Fatalf("update after the terminal bind intake=%+v err=%v, want terminal_kept", in, err)
	}
}

func TestPaddleRefundBeforeBindSupersededByLaterPayment(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_refund_first", EventType: "adjustment.created", SubscriptionID: "sub_p",
		AdjustmentAction: "refund", AdjustmentType: "full", AdjustmentStatus: "approved",
		OccurredAt: now, Now: now,
	}); err != nil || in.Outcome != "terminal_pending" {
		t.Fatalf("early refund intake=%+v err=%v, want terminal_pending", in, err)
	}
	later := now.Add(24 * time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_paid_after", EventType: "transaction.completed", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, later.Add(-time.Minute)), CustomerID: "ctm_1", SubscriptionID: "sub_p",
		PriceID: testPrice, TransactionPaid: true, OccurredAt: later, Now: later,
	})
	if err != nil || !in.Applied || in.Outcome != "applied" {
		t.Fatalf("paid bind after the refund intake=%+v err=%v, want applied", in, err)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", later); al.Plan.Name != "plus_beta" {
		t.Fatalf("plan = %q, want plus_beta", al.Plan.Name)
	}
}

// A non-terminal status event on an unbound subscription is still only
// unattributed (nothing to keep).
func TestPaddlePartialRefundUnboundStaysUnattributed(t *testing.T) {
	s, _, now := paddleStore(t)
	in, err := s.ProcessPaddleEvent(context.Background(), store.PaddleEvent{
		EventID: "evt_partial_orphan", EventType: "adjustment.created", SubscriptionID: "sub_unknown",
		AdjustmentAction: "refund", AdjustmentType: "partial", AdjustmentStatus: "approved",
		OccurredAt: now, Now: now,
	})
	if err != nil || in.Applied || in.Outcome != "unattributed" {
		t.Fatalf("intake=%+v err=%v, want unattributed", in, err)
	}
}

// --- FR-9: paused and past_due on the account path ----------------------

func TestPaddleAccountPausedDropsPlanAndResumeRestores(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)
	pauseAt := now.Add(24 * time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_pause", EventType: "subscription.paused", SubscriptionID: "sub_1",
		OccurredAt: pauseAt, Now: pauseAt,
	}); err != nil || !in.Applied {
		t.Fatalf("pause intake=%+v err=%v", in, err)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", pauseAt.Add(time.Minute)); al.Plan.Name != "free" {
		t.Fatalf("plan while paused = %q, want free", al.Plan.Name)
	}
	resumeAt := pauseAt.Add(48 * time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_resume", EventType: "subscription.resumed", CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "active",
		PriceID: testPrice, OccurredAt: resumeAt, Now: resumeAt,
	}); err != nil || !in.Applied {
		t.Fatalf("resume intake=%+v err=%v", in, err)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", resumeAt.Add(time.Minute)); al.Plan.Name != "plus_beta" {
		t.Fatalf("plan after resume = %q, want plus_beta", al.Plan.Name)
	}
}

func TestPaddleAccountPastDueKeepsPlanThroughGrace(t *testing.T) {
	s, acct, now := paddleStore(t)
	s.SetPaddlePastDueGrace(3 * 24 * time.Hour)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)
	pdAt := now.Add(24 * time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_pd", EventType: "subscription.past_due", SubscriptionID: "sub_1",
		OccurredAt: pdAt, Now: pdAt,
	}); err != nil || !in.Applied {
		t.Fatalf("past_due intake=%+v err=%v", in, err)
	}
	// A second dunning event does not move the window.
	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_pd_again", EventType: "transaction.payment_failed", SubscriptionID: "sub_1",
		OccurredAt: pdAt.Add(24 * time.Hour), Now: pdAt.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("payment_failed: %v", err)
	}
	for _, c := range []struct {
		at   time.Time
		want string
	}{
		{pdAt.Add(2 * 24 * time.Hour), "plus_beta"},
		{pdAt.Add(3*24*time.Hour + time.Minute), "free"},
	} {
		if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", c.at); al.Plan.Name != c.want {
			t.Fatalf("plan at %v = %q, want %q", c.at, al.Plan.Name, c.want)
		}
	}
	// Recovery inside the window supersedes the scheduled drop.
	recAt := pdAt.Add(48 * time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_recover", EventType: "transaction.completed", CustomerID: "ctm_1", SubscriptionID: "sub_1",
		PriceID: testPrice, TransactionPaid: true, OccurredAt: recAt, Now: recAt,
	}); err != nil || !in.Applied {
		t.Fatalf("recovery intake=%+v err=%v", in, err)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", pdAt.Add(10*24*time.Hour)); al.Plan.Name != "plus_beta" {
		t.Fatalf("plan after recovery, past the old drop = %q, want plus_beta", al.Plan.Name)
	}
}

// --- FR-10: one trial per account scope and per org ---------------------

func TestPaddleTrialUseRecordedPerScope(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	other := makeAccount(t, s)
	if used, err := s.AccountTrialUsed(ctx, acct); err != nil || used {
		t.Fatalf("before any trial: used=%v err=%v", used, err)
	}
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_trial", EventType: "subscription.trialing", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now), CustomerID: "ctm_1", SubscriptionID: "sub_t",
		Status: "trialing", PriceID: testPrice, OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 0, 7), Now: now,
	}); err != nil || !in.Applied {
		t.Fatalf("trial intake=%+v err=%v", in, err)
	}
	for _, c := range []struct {
		name    string
		account string
		want    bool
	}{{"the trialing account", acct, true}, {"another account", other, false}} {
		if used, err := s.AccountTrialUsed(ctx, c.account); err != nil || used != c.want {
			t.Fatalf("%s: AccountTrialUsed = %v err=%v, want %v", c.name, used, err, c.want)
		}
	}
}

func TestOrgTrialUseRecorded(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	if in, err := f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_org_trial", EventType: "subscription.trialing", AccountID: f.owner, OrgID: f.org.OrgID,
		CheckoutNonce: f.orgNonce(t, orgTestPriceTeam), CustomerID: "ctm_org", SubscriptionID: "sub_ot",
		Status: "trialing", PriceID: orgTestPriceTeam, OccurredAt: f.now, CurrentPeriodEnd: f.now.AddDate(0, 0, 7), Now: f.now,
	}); err != nil || !in.Applied {
		t.Fatalf("org trial intake=%+v err=%v", in, err)
	}
	if used, err := f.s.OrgTrialUsed(ctx, f.org.OrgID); err != nil || !used {
		t.Fatalf("OrgTrialUsed = %v err=%v, want true", used, err)
	}
	// The org's trial is the org's, not the paying account's own scope.
	if used, err := f.s.AccountTrialUsed(ctx, f.owner); err != nil || used {
		t.Fatalf("AccountTrialUsed(owner) = %v err=%v, want false", used, err)
	}
	if used, err := f.s.OrgTrialUsed(ctx, "not-a-uuid"); err != nil || used {
		t.Fatalf("OrgTrialUsed(malformed) = %v err=%v, want false", used, err)
	}
}

// --- FR-22: seat quantity, the personal org, operator grants -------------

func TestOrgBindReadsSeatQuantity(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	in, err := f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_seats", EventType: "subscription.activated", AccountID: f.owner, OrgID: f.org.OrgID,
		CheckoutNonce: f.orgNonce(t, orgTestPriceTeam), CustomerID: "ctm_org", SubscriptionID: "sub_seats",
		Status: "active", PriceID: orgTestPriceTeam, Quantity: 1, OccurredAt: f.now, Now: f.now,
	})
	if err != nil || !in.Applied || !strings.Contains(in.Note, "below the plan's minimum 3") {
		t.Fatalf("intake=%+v err=%v, want applied with a below-minimum seat note", in, err)
	}
	var seats int64
	if err := f.pool.QueryRow(ctx, `SELECT seat_quantity FROM paddle_subscriptions WHERE paddle_subscription_id = 'sub_seats'`).Scan(&seats); err != nil || seats != 1 {
		t.Fatalf("seat_quantity = %d err=%v, want 1", seats, err)
	}
}

func TestAccountSubscriptionSeesPersonalOrgSubscription(t *testing.T) {
	s, pool := newStore(t)
	s.SetPaddlePriceMap(map[string]store.PaddlePlan{testPrice: {Name: "plus_beta", Version: 1}})
	acct := makeAccount(t, s)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)
	org, _, err := s.EnsurePersonalOrg(ctx, acct, "")
	if err != nil {
		t.Fatalf("EnsurePersonalOrg: %v", err)
	}
	// What migrate-personal does to the row (store/personalmig.go).
	if _, err := pool.Exec(ctx, `UPDATE paddle_subscriptions SET org_id = $2::uuid WHERE paddle_subscription_id = $1`, "sub_1", org.OrgID); err != nil {
		t.Fatalf("re-key: %v", err)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.SubscriptionID != "sub_1" || sub.OrgID != org.OrgID || !store.SubscriptionIsLive(sub.Status) {
		t.Fatalf("AccountSubscription = %+v err=%v, want the live re-keyed sub_1", sub, err)
	}
	// And the store refuses a second live account subscription beside it.
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_second", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now.Add(time.Hour-time.Minute)), CustomerID: "ctm_2", SubscriptionID: "sub_2",
		Status: "active", PriceID: testPrice, OccurredAt: now.Add(time.Hour), Now: now.Add(time.Hour),
	})
	if err != nil || in.Outcome != "refused_second_live" {
		t.Fatalf("second account subscription intake=%+v err=%v, want refused_second_live", in, err)
	}
}

func TestPaddleCancelFallsBackToOperatorGrant(t *testing.T) {
	s, pool := newStore(t)
	s.SetPaddlePriceMap(map[string]store.PaddlePlan{testPrice: {Name: "plus_beta", Version: 1}})
	seedStarterPlan(t, pool)
	acct := makeAccount(t, s)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	if _, err := s.AssignPlan(ctx, acct, "starter_test", 1, now.Add(-30*24*time.Hour), now.Add(-30*24*time.Hour)); err != nil {
		t.Fatalf("operator grant: %v", err)
	}
	activatePaid(t, s, acct, "sub_1", now)
	cancelAt := now.Add(time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_cancel", EventType: "subscription.canceled", CustomerID: "ctm_1", SubscriptionID: "sub_1", Status: "canceled",
		PriceID: testPrice, OccurredAt: cancelAt, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: cancelAt,
	}); err != nil || !in.Applied {
		t.Fatalf("cancel intake=%+v err=%v", in, err)
	}
	after := store.CeilToMonthlyCycleStart(now.AddDate(0, 1, 0)).Add(24 * time.Hour)
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", after); al.Plan.Name != "starter_test" {
		t.Fatalf("plan after the cancel boundary = %q, want the operator's starter_test", al.Plan.Name)
	}
}

func TestPaddleRefundKeepsLaterOperatorGrant(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	activatePaid(t, s, acct, "sub_1", now)
	grantAt := now.Add(time.Hour)
	if _, err := s.AssignPlan(ctx, acct, "plus_beta", 1, grantAt, grantAt); err != nil {
		t.Fatalf("operator grant: %v", err)
	}
	refundAt := now.Add(2 * time.Hour)
	in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_refund", EventType: "adjustment.updated", SubscriptionID: "sub_1",
		AdjustmentAction: "refund", AdjustmentType: "full", AdjustmentStatus: "approved",
		OccurredAt: refundAt, Now: refundAt,
	})
	if err != nil || !in.Applied || !strings.Contains(in.Note, "operator plan grant") {
		t.Fatalf("refund intake=%+v err=%v, want applied keeping the operator grant", in, err)
	}
	if al, _ := s.ResolveAllowance(ctx, acct, "session_enrichment", refundAt.Add(time.Minute)); al.Plan.Name != "plus_beta" {
		t.Fatalf("plan after the refund = %q, want the operator's plus_beta", al.Plan.Name)
	}
	if sub, _ := s.AccountSubscription(ctx, acct); sub.Status != "refunded" {
		t.Fatalf("status = %q, want refunded", sub.Status)
	}
}
