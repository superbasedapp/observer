package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// paddle_lifecycle.go holds the subscription-lifecycle rules the Fable review
// of 2026-11-17 added to the one Paddle webhook path (docs/security.md
// BILL-FR2, BILL-FR7, BILL-FR8, BILL-FR9, BILL-FR10, BILL-FR22):
//
//   - FR-2: a checkout intent is bindable for CheckoutIntentBindWindow judged
//     at the event's own occurred_at, kept past that for the redelivery
//     horizon, and every refused binding leaves a durable record
//     (paddle_binding_refusals, billing_events.outcome).
//   - FR-7: a terminal row (canceled, refunded, charged_back) is re-opened
//     only by a paid transaction.completed (activateReopenRules).
//   - FR-8: a terminal event for a subscription not bound yet is kept by
//     subscription id and applied at bind (paddle_pending_terminals).
//   - FR-9: on the account path, paused drops the plan at once and past_due
//     after the dunning grace (paddleDunningRules), the org rule.
//   - FR-10: the first trial of an account scope or an org is recorded
//     (paddle_trial_uses) and the checkout refuses a second one.
//   - FR-22: a Paddle drop lands on the plan the account holds without Paddle
//     (an operator grant, else free) and never replaces an operator grant
//     made after the subscription started (paddleDropTargetTx).

// CheckoutIntentBindWindow is how long after it was minted a checkout nonce
// can bind a subscription, judged at the binding event's occurred_at (FR-2).
// A Paddle checkout normally completes in minutes, but 3-D Secure, a held
// overlay or a cloud-api outage during a roll can push the first webhook far
// past that; the old 30-minute window refused such a paid binding for good.
// Seven days covers Paddle's retry schedule. A leaked nonce still binds only
// to the account (and org) it was minted for, at the price it was minted for.
const CheckoutIntentBindWindow = 7 * 24 * time.Hour

// checkoutIntentRetention is how long an intent is kept after its bind window
// ends before SweepExpiredCheckoutIntents deletes it, so a delivery of an
// event that occurred inside the window but is processed late (Paddle retries,
// a replay) still finds it.
const checkoutIntentRetention = 30 * 24 * time.Hour

// DefaultPaddlePastDueGrace is the account path's dunning window when none is
// set (FR-9): the same 14 days entitlementwork.DefaultPastDueGrace gives an org
// (SBCI_PADDLE_PAST_DUE_GRACE_DAYS, operator ruling L-124). The store cannot
// import entitlementwork (it imports the store), so the value is repeated and
// paddle_lifecycle_test.go pins the two equal.
const DefaultPaddlePastDueGrace = 14 * 24 * time.Hour

// paddlePlanSource is the account_plans.source of every Paddle-driven write.
const paddlePlanSource = "paddle"

// The machine reasons of a refused binding (FR-2, BillingIntake.Reason).
const (
	bindRefusalNoAccount          = "no_account"
	bindRefusalAccountNotUUID     = "account_not_uuid"
	bindRefusalMissingNonce       = "missing_nonce"
	bindRefusalUnknownPrice       = "unknown_price"
	bindRefusalNoLiveIntent       = "no_live_intent"
	bindRefusalPriceMismatch      = "intent_price_mismatch"
	bindRefusalScope              = "scope_mismatch"
	bindRefusalAccountNotFound    = "account_not_found"
	bindRefusalAccountNotBillable = "account_not_billable"
	bindRefusalOrgNotBillable     = "org_not_billable"
	bindRefusalSecondLive         = "second_live"
)

// SetPaddlePastDueGrace wires the account path's dunning window (FR-9) at
// bootstrap, the same SBCI_PADDLE_PAST_DUE_GRACE_DAYS value the org plan view
// uses. Zero or negative keeps DefaultPaddlePastDueGrace.
func (s *Store) SetPaddlePastDueGrace(d time.Duration) {
	s.paddlePastDueGrace = d
}

// pastDueGrace is the configured dunning window, or the default.
func (s *Store) pastDueGrace() time.Duration {
	if s.paddlePastDueGrace <= 0 {
		return DefaultPaddlePastDueGrace
	}
	return s.paddlePastDueGrace
}

// --- FR-2: the durable record of a delivery's outcome -------------------

// recordBindingOutcomeTx keeps the refusal record of a refused binding (any
// intake with a Reason) and marks earlier refusals of a subscription resolved
// once a delivery for it applies. Runs in ProcessPaddleEvent's stamp
// transaction (system context).
func (s *Store) recordBindingOutcomeTx(ctx context.Context, tx pgx.Tx, ev PaddleEvent, intake BillingIntake, now time.Time) error {
	if ev.SubscriptionID == "" {
		return nil
	}
	if intake.Reason != "" {
		var occurred *time.Time
		if !ev.OccurredAt.IsZero() {
			t := ev.OccurredAt.UTC()
			occurred = &t
		}
		note := intake.Note
		if len(note) > 500 {
			note = note[:500]
		}
		_, known := s.paddlePlanForPrice(ev.PriceID)
		if _, e := tx.Exec(ctx,
			`INSERT INTO paddle_binding_refusals
			     (event_id, event_type, paddle_subscription_id, paddle_customer_id, price_id,
			      price_known, reason, note, occurred_at, recorded_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			 ON CONFLICT (event_id) DO NOTHING`,
			ev.EventID, ev.EventType, ev.SubscriptionID, nullableText(ev.CustomerID), nullableText(ev.PriceID),
			known, intake.Reason, nullableText(note), occurred, now); e != nil {
			return fmt.Errorf("record binding refusal: %w", e)
		}
	}
	if intake.Applied {
		if _, e := tx.Exec(ctx,
			`UPDATE paddle_binding_refusals SET resolved_at = $2
			  WHERE paddle_subscription_id = $1 AND resolved_at IS NULL`,
			ev.SubscriptionID, now); e != nil {
			return fmt.Errorf("resolve binding refusals: %w", e)
		}
	}
	return nil
}

// PaddleBindingRefusal is one open refused binding (FR-2): what an operator
// needs to find the payment in Paddle and decide (refund, or a manual bind).
type PaddleBindingRefusal struct {
	EventID        string     `json:"event_id"`
	EventType      string     `json:"event_type"`
	SubscriptionID string     `json:"subscription_id"`
	CustomerID     string     `json:"customer_id,omitempty"`
	PriceID        string     `json:"price_id,omitempty"`
	PriceKnown     bool       `json:"price_known"`
	Reason         string     `json:"reason"`
	Note           string     `json:"note,omitempty"`
	OccurredAt     *time.Time `json:"occurred_at,omitempty"`
	RecordedAt     time.Time  `json:"recorded_at"`
}

// OpenPaddleBindingRefusals lists the refused bindings no later delivery has
// resolved, newest first, at most limit (1..500; default 100).
func (s *Store) OpenPaddleBindingRefusals(ctx context.Context, limit int) ([]PaddleBindingRefusal, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []PaddleBindingRefusal
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT event_id, event_type, paddle_subscription_id, coalesce(paddle_customer_id, ''),
			        coalesce(price_id, ''), price_known, reason, coalesce(note, ''), occurred_at, recorded_at
			   FROM paddle_binding_refusals
			  WHERE resolved_at IS NULL
			  ORDER BY recorded_at DESC
			  LIMIT $1`, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r PaddleBindingRefusal
			if e := rows.Scan(&r.EventID, &r.EventType, &r.SubscriptionID, &r.CustomerID, &r.PriceID,
				&r.PriceKnown, &r.Reason, &r.Note, &r.OccurredAt, &r.RecordedAt); e != nil {
				return e
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.OpenPaddleBindingRefusals: %w", err)
	}
	return out, nil
}

// --- FR-7: re-opening a terminal row ------------------------------------

// terminalSubscriptionStatus reports whether a row status is terminal: the
// subscription no longer pays, and its plan was dropped or scheduled to drop.
func terminalSubscriptionStatus(status string) bool {
	switch status {
	case "canceled", "refunded", "charged_back":
		return true
	}
	return false
}

// activateReopenRules are the activations that may re-open a terminal row,
// walked top-down (one test case per row, paddle_lifecycle_test.go). A full
// refund or chargeback revokes the plan but does not cancel the Paddle
// subscription (runbook 5c), so Paddle keeps sending subscription.updated
// with status active; only a renewal that actually charged the customer is
// evidence they pay again. A chargeback_reverse is not here: it is its own
// action (restore).
var activateReopenRules = []struct {
	name   string
	reopen func(ev PaddleEvent) bool
}{
	{"paid transaction", func(ev PaddleEvent) bool {
		return ev.EventType == "transaction.completed" && ev.TransactionPaid
	}},
}

// ActivateMayReopen reports whether an activation may be applied to a row in
// existingStatus: always for a live or new row, and for a terminal row only
// when a row of activateReopenRules matches (FR-7). Pure.
func ActivateMayReopen(ev PaddleEvent, existingStatus string) bool {
	if !terminalSubscriptionStatus(existingStatus) {
		return true
	}
	for _, r := range activateReopenRules {
		if r.reopen(ev) {
			return true
		}
	}
	return false
}

// terminalKeptIntake is the outcome of an activation ActivateMayReopen refused.
func terminalKeptIntake(existingStatus string) BillingIntake {
	return BillingIntake{
		Applied: false, Outcome: "terminal_kept",
		Note: "the subscription is " + existingStatus + "; only a paid renewal re-opens it",
	}
}

// --- FR-8: terminal events before the binding ---------------------------

// pendingTerminalStatus maps a non-binding action on an unbound subscription
// to the terminal status to keep for the bind, or false when the action is not
// terminal (status_only, restore: nothing to keep).
func pendingTerminalStatus(ev PaddleEvent, act paddleAction) (string, bool) {
	switch act.kind {
	case "cancel":
		return "canceled", true
	case "revoke":
		return revokeStatus(ev), true
	}
	return "", false
}

// errPaddleBoundConcurrently asks for a redelivery: the subscription was bound
// while its terminal event was being recorded, so the event belongs on the
// bound path.
var errPaddleBoundConcurrently = errors.New("cloudserver/store: subscription was bound while its terminal event was recorded; redeliver")

// paddleSubscriptionLockTx serializes the binding of one subscription with
// recordPendingTerminal (FR-8). Both take it inside their transaction.
func paddleSubscriptionLockTx(ctx context.Context, tx pgx.Tx, subscriptionID string) error {
	_, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('sbci_paddle_sub:' || $1, 0))`, subscriptionID)
	return err
}

// recordPendingTerminal keeps a terminal state for a subscription that is not
// bound yet (FR-8). Under the subscription lock it re-checks the binding: a
// binding that committed meanwhile turns this into errPaddleBoundConcurrently
// (a 5xx, so Paddle redelivers onto the bound path) rather than a record the
// bind would never read. A later terminal event replaces an earlier one; an
// already-applied record is never moved.
func (s *Store) recordPendingTerminal(ctx context.Context, ev PaddleEvent, status string, now time.Time) (BillingIntake, error) {
	occurred := ev.OccurredAt
	if occurred.IsZero() {
		occurred = now
	}
	var periodEnd *time.Time
	if !ev.CurrentPeriodEnd.IsZero() {
		t := ev.CurrentPeriodEnd.UTC()
		periodEnd = &t
	}
	bound := false
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if e := paddleSubscriptionLockTx(ctx, tx, ev.SubscriptionID); e != nil {
			return fmt.Errorf("subscription lock: %w", e)
		}
		var acct *string
		if e := tx.QueryRow(ctx, `SELECT sbci_paddle_account_for_subscription($1)::text`, ev.SubscriptionID).Scan(&acct); e != nil {
			return fmt.Errorf("re-resolve binding: %w", e)
		}
		if acct != nil && *acct != "" {
			bound = true
			return nil
		}
		_, e := tx.Exec(ctx,
			`INSERT INTO paddle_pending_terminals
			     (paddle_subscription_id, status, event_id, occurred_at, current_period_end, recorded_at)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (paddle_subscription_id) DO UPDATE SET
			     status = EXCLUDED.status, event_id = EXCLUDED.event_id,
			     occurred_at = EXCLUDED.occurred_at, current_period_end = EXCLUDED.current_period_end,
			     recorded_at = EXCLUDED.recorded_at
			   WHERE paddle_pending_terminals.applied_at IS NULL
			     AND paddle_pending_terminals.occurred_at < EXCLUDED.occurred_at`,
			ev.SubscriptionID, status, ev.EventID, occurred.UTC(), periodEnd, now)
		return e
	})
	if err != nil {
		return BillingIntake{}, fmt.Errorf("cloudserver/store.recordPendingTerminal: %w", err)
	}
	if bound {
		return BillingIntake{}, errPaddleBoundConcurrently
	}
	return BillingIntake{
		Applied: false, Outcome: "terminal_pending",
		Note: "subscription not bound yet; " + status + " is kept for the binding",
	}, nil
}

// pendingTerminal is one unapplied paddle_pending_terminals row.
type pendingTerminal struct {
	Status     string
	OccurredAt time.Time
	PeriodEnd  *time.Time
}

// pendingTerminalTx reads the unapplied terminal state of a subscription.
func pendingTerminalTx(ctx context.Context, tx pgx.Tx, subscriptionID string) (pendingTerminal, bool, error) {
	var p pendingTerminal
	err := tx.QueryRow(ctx,
		`SELECT status, occurred_at, current_period_end FROM paddle_pending_terminals
		  WHERE paddle_subscription_id = $1 AND applied_at IS NULL`, subscriptionID).
		Scan(&p.Status, &p.OccurredAt, &p.PeriodEnd)
	if errors.Is(err, pgx.ErrNoRows) {
		return pendingTerminal{}, false, nil
	}
	if err != nil {
		return pendingTerminal{}, false, err
	}
	return p, true, nil
}

// markPendingTerminalAppliedTx stamps the subscription's pending terminal as
// read by its binding.
func markPendingTerminalAppliedTx(ctx context.Context, tx pgx.Tx, subscriptionID string, now time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE paddle_pending_terminals SET applied_at = $2
		  WHERE paddle_subscription_id = $1 AND applied_at IS NULL`, subscriptionID, now)
	return err
}

// PendingTerminalSuperseded reports whether a binding delivery outranks a
// terminal state recorded before it (FR-8): only a paid transaction.completed
// that occurred after the terminal event, the FR-7 re-open rule. Pure.
func PendingTerminalSuperseded(ev PaddleEvent, terminalAt time.Time) bool {
	return ev.OccurredAt.After(terminalAt) && ActivateMayReopen(ev, "canceled")
}

// bindPendingTerminalTx binds a subscription whose terminal state arrived
// first: the row is written in that state, scoped like any binding (orgID ""
// on the account path), and no plan is granted. A trial the subscription
// started is still recorded (FR-10): cancelling it does not give it back.
func (s *Store) bindPendingTerminalTx(ctx context.Context, tx pgx.Tx, ev PaddleEvent, account, orgID string, p pendingTerminal, occurred time.Time) (BillingIntake, error) {
	plan, _ := s.paddlePlanForPrice(ev.PriceID) // the bind gate proved it known
	last := occurred
	if p.OccurredAt.After(last) {
		last = p.OccurredAt
	}
	canceledAt := p.OccurredAt.UTC()
	periodEnd := p.PeriodEnd
	if periodEnd == nil && !ev.CurrentPeriodEnd.IsZero() {
		t := ev.CurrentPeriodEnd.UTC()
		periodEnd = &t
	}
	if e := upsertSubscriptionTx(ctx, tx, account, orgID, ev, plan, p.Status, &canceledAt, periodEnd, last); e != nil {
		return BillingIntake{}, fmt.Errorf("bind terminal subscription: %w", e)
	}
	if st, _ := resolveActivateStatus(ev, "", nil); st == "trialing" {
		if e := recordTrialUseTx(ctx, tx, account, orgID, ev.SubscriptionID, occurred); e != nil {
			return BillingIntake{}, fmt.Errorf("record trial use: %w", e)
		}
	}
	return BillingIntake{
		Applied: true, Outcome: "bound_terminal",
		Note: "bound as " + p.Status + " (its terminal event arrived first); no plan granted",
	}, nil
}

// --- FR-9: dunning on the account path ----------------------------------

// paddleDunningRules say when a subscription in a dunning status stops
// carrying the account's plan, walked top-down, first match wins (one test
// case per row). The org path's rule (entitlementwork liveRules): paused
// carries nothing, past_due carries the plan for the grace window from when
// it entered past_due. A past_due row with no recorded entry (the 0098
// trigger always sets one; defensive) starts the window at the event.
var paddleDunningRules = []struct {
	status string
	dropAt func(since *time.Time, occurred time.Time, grace time.Duration) time.Time
}{
	{"paused", func(_ *time.Time, occurred time.Time, _ time.Duration) time.Time { return occurred }},
	{"past_due", func(since *time.Time, occurred time.Time, grace time.Duration) time.Time {
		start := occurred
		if since != nil {
			start = *since
		}
		return start.Add(grace)
	}},
}

// PaddleDunningDropAt returns when an account subscription in status stops
// carrying its plan, and false for a status no dunning rule covers. Pure.
func PaddleDunningDropAt(status string, since *time.Time, occurred time.Time, grace time.Duration) (time.Time, bool) {
	for _, r := range paddleDunningRules {
		if r.status == status {
			return r.dropAt(since, occurred, grace).UTC(), true
		}
	}
	return time.Time{}, false
}

// applyAccountPaddleStatusOnly is the account path's status_only action:
// record the state (applyPaddleStatusOnly), then, for paused and past_due,
// schedule the plan's drop by paddleDunningRules (FR-9). A recovery
// (subscription.resumed, an active update, a paid renewal) is an activation,
// and assignPlanTx's immediate activation supersedes the scheduled drop.
func applyAccountPaddleStatusOnly(ctx context.Context, tx pgx.Tx, s *Store, ev PaddleEvent, account string, occurred, now time.Time) (BillingIntake, error) {
	in, err := applyPaddleStatusOnly(ctx, tx, ev, account, occurred)
	if err != nil {
		return in, err
	}
	var status string
	var since *time.Time
	e := tx.QueryRow(ctx,
		`SELECT status, past_due_since FROM paddle_subscriptions
		  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
		account, ev.SubscriptionID).Scan(&status, &since)
	if errors.Is(e, pgx.ErrNoRows) {
		return in, nil
	}
	if e != nil {
		return BillingIntake{}, fmt.Errorf("read subscription status: %w", e)
	}
	dropAt, ok := PaddleDunningDropAt(status, since, occurred, s.pastDueGrace())
	if !ok {
		return in, nil
	}
	target, keep, err := paddleDropTargetTx(ctx, tx, account, now)
	if err != nil {
		return BillingIntake{}, err
	}
	if keep {
		in.Note = status + "; the operator plan grant in force is kept"
		return in, nil
	}
	if e := paddleMoveAccountPlanAtTx(ctx, tx, account, target, dropAt, now); e != nil && !errors.Is(e, ErrPlanAssignmentConflict) {
		return BillingIntake{}, fmt.Errorf("schedule %s drop: %w", status, e)
	}
	if dropAt.Before(now) {
		dropAt = now
	}
	in.Note = status + "; plan moves to " + target.Name + " at " + dropAt.Format(time.RFC3339)
	return in, nil
}

// --- FR-22: drops land on the plan the account holds without Paddle ------

// paddleDropTargetTx decides where a Paddle-driven drop (cancel, refund,
// chargeback, pause, an expired dunning window) moves the account. keep is
// true when the plan in force at now was not written by Paddle: an operator
// grant made after the subscription started, which a Paddle event must never
// replace. Otherwise the target is the plan of the account's latest non-Paddle
// assignment (the operator grant Paddle's activation replaced), else free.
func paddleDropTargetTx(ctx context.Context, tx pgx.Tx, account string, now time.Time) (Plan, bool, error) {
	var source string
	e := tx.QueryRow(ctx,
		`SELECT source FROM account_plans
		  WHERE account_id = $1::uuid AND effective_from <= $2
		    AND (effective_until IS NULL OR effective_until > $2)
		  ORDER BY effective_from DESC LIMIT 1`, account, now).Scan(&source)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
	case e != nil:
		return Plan{}, false, fmt.Errorf("read plan in force: %w", e)
	case source != paddlePlanSource:
		return Plan{}, true, nil
	}
	var name string
	var version int
	e = tx.QueryRow(ctx,
		`SELECT p.name, p.version FROM account_plans ap
		   JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND ap.source <> $2
		  ORDER BY ap.effective_from DESC LIMIT 1`, account, paddlePlanSource).Scan(&name, &version)
	if errors.Is(e, pgx.ErrNoRows) {
		name, version = PlanFree, DefaultFreePlanVersion
	} else if e != nil {
		return Plan{}, false, fmt.Errorf("read operator grant: %w", e)
	}
	target, err := loadPlanTx(ctx, tx, name, version)
	if err != nil {
		return Plan{}, false, fmt.Errorf("load drop target: %w", err)
	}
	return target, false, nil
}

// paddleMoveAccountPlanAtTx moves the account onto target from EXACTLY
// effective (raised to now), bypassing assignPlanTx's F11 cycle ceiling: the
// trial-end, pause, dunning and refund drops are not graceful downgrades of
// paid-for allowance. Anything scheduled after effective is superseded; a
// row starting exactly at effective is replaced; the row covering effective
// is closed there. ErrPlanAssignmentConflict means the account already holds
// target at effective (a replay). The same "close, then insert" shape as
// assignPlanTx and revokePlanToFreeTx (CLAUDE.md #4). Caller holds tenant
// context and the account's advisory lock.
func paddleMoveAccountPlanAtTx(ctx context.Context, tx pgx.Tx, account string, target Plan, effective, now time.Time) error {
	effective = effective.UTC()
	if effective.Before(now) {
		effective = now.UTC()
	}
	if _, e := tx.Exec(ctx,
		`DELETE FROM account_plans WHERE account_id = $1::uuid AND effective_from > $2`,
		account, effective); e != nil {
		return fmt.Errorf("clear scheduled assignments: %w", e)
	}
	current, err := resolvePlanTx(ctx, tx, account, effective)
	if err != nil {
		return err
	}
	if current.ID == target.ID {
		return ErrPlanAssignmentConflict
	}
	if _, e := tx.Exec(ctx,
		`DELETE FROM account_plans WHERE account_id = $1::uuid AND effective_from = $2`,
		account, effective); e != nil {
		return fmt.Errorf("replace assignment at the instant: %w", e)
	}
	if _, e := tx.Exec(ctx,
		`UPDATE account_plans SET effective_until = $2
		  WHERE account_id = $1::uuid AND effective_from < $2
		    AND (effective_until IS NULL OR effective_until > $2)`,
		account, effective); e != nil {
		return fmt.Errorf("close covering assignment: %w", e)
	}
	if _, e := tx.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, source)
		 VALUES ($1::uuid, $2::uuid, $3, $4)`,
		account, target.ID, effective, paddlePlanSource); e != nil {
		return fmt.Errorf("insert assignment: %w", e)
	}
	return nil
}

// personalOrgIDTx is the account's personal org id under tenant context, ""
// when it has none (FR-22: a subscription migrate-personal re-keyed onto it
// is still the account's own).
func personalOrgIDTx(ctx context.Context, tx pgx.Tx) (string, error) {
	o, err := personalOrgTx(ctx, tx)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return o.OrgID, nil
}

// --- FR-10: one trial per account scope and per org ---------------------

// recordTrialUseTx records the first trial of a scope: the account's own
// (orgID "") or an org's. A scope that already has one keeps its first row.
func recordTrialUseTx(ctx context.Context, tx pgx.Tx, account, orgID, subscriptionID string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO paddle_trial_uses (account_id, org_id, paddle_subscription_id, first_trial_at)
		 VALUES ($1::uuid, $2::uuid, $3, $4)
		 ON CONFLICT DO NOTHING`,
		account, nullableUUID(orgID), subscriptionID, at.UTC())
	return err
}

// AccountTrialUsed reports whether the account's own scope (not an org it
// pays for) has had a Paddle trial (FR-10).
func (s *Store) AccountTrialUsed(ctx context.Context, accountID string) (bool, error) {
	var used bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM paddle_trial_uses WHERE account_id = $1::uuid AND org_id IS NULL)`,
			accountID).Scan(&used)
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.AccountTrialUsed: %w", err)
	}
	return used, nil
}

// OrgTrialUsed reports whether org orgID has had a Paddle trial (FR-10),
// whoever paid for it. A malformed id names no org: false.
func (s *Store) OrgTrialUsed(ctx context.Context, orgID string) (bool, error) {
	if !validOrgID(orgID) {
		return false, nil
	}
	var used bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM paddle_trial_uses WHERE org_id = $1::uuid)`, orgID).Scan(&used)
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.OrgTrialUsed: %w", err)
	}
	return used, nil
}

// --- small helpers ------------------------------------------------------

// nullableUUID passes "" as SQL NULL for a ::uuid parameter.
func nullableUUID(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}

// nullableText passes "" as SQL NULL.
func nullableText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
