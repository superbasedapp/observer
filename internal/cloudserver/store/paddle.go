package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// paddle.go is the store owner of W9 Paddle billing (divergence remediation plan
// §3 "W9"; ruling R4; closes D6). It turns a verified Paddle webhook event into
// a W4 plan assignment — Paddle is the event source, but entitlement authority
// stays in account_plans/plans (never a competing source). Everything here is
// idempotent on the Paddle event id and retry-safe: a delivery recorded but not
// finished (crash) re-runs on redelivery.

// PaddlePriceToPlan maps a Paddle price id to the W4 plan it grants. It is a
// compiled-in table (the real pri_* ids are provisioned in the operator's Paddle
// account and wired at deploy via SBCI_PADDLE_PRICE_* — until then this holds the
// documented placeholders). A price not in this map is a config error: the event
// is recorded and audited but grants no plan (fail-closed — a random/foreign
// price can never escalate an account).
type PaddlePlan struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	// Interval is the billing interval this price sells on ("month" | "year").
	// A5/gap 1.8: today only "month" is launched (no annual plan), but the
	// shape is billing-interval-aware from the start so an annual price is a
	// config addition, not a schema change.
	Interval string `json:"interval,omitempty"`
	// Display is an optional human-readable label for the portal catalogue
	// (e.g. "$15/mo"). Empty is fine — the portal falls back to computing its
	// own label from the plan.
	Display string `json:"display,omitempty"`
}

// PaddleEvent is the slice of a Paddle Billing (v2) webhook envelope W9 acts on.
// The raw body is verified + decoded at the API boundary; this is the normalized
// shape the store consumes. It carries NO card/payment data — only ids, status,
// the resolved account, the price (→ plan), and the period end.
type PaddleEvent struct {
	EventID          string    // evt_... (idempotency key)
	EventType        string    // subscription.activated | .updated | .canceled | ...
	OccurredAt       time.Time // provider clock (may be zero)
	AccountID        string    // resolved from data.custom_data.account_id (may be "")
	CustomerID       string    // ctm_...
	SubscriptionID   string    // sub_...
	Status           string    // active | canceled | past_due | paused (subscription/transaction status)
	PriceID          string    // pri_... (→ plan via the price map)
	CurrentPeriodEnd time.Time // data.current_billing_period.ends_at (may be zero)
	// NextBilledAt is data.next_billed_at — the fallback trial-end estimate
	// when current_billing_period.ends_at is absent (A7 / gap 1.11).
	NextBilledAt time.Time
	Now          time.Time

	// ManagementUpdateURL / ManagementCancelURL carry Paddle's hosted
	// customer-portal links (data.management_urls.update_payment_method /
	// .cancel — A7 / gap 1.4). Raw and UNTRUSTED until validated (https +
	// paddle.com) at the store boundary; empty when Paddle didn't send them
	// (subscription.updated deliberately omits management_urls per Paddle's
	// own docs).
	ManagementUpdateURL string
	ManagementCancelURL string

	// CheckoutNonce is the server-minted nonce carried in the checkout's
	// custom_data.checkout_nonce (G2-07 / F2). It is REQUIRED to bind a
	// not-yet-linked subscription to an account: the untrusted AccountID alone
	// never binds. Empty for events on an already-bound subscription.
	CheckoutNonce string
	// Adjustment* carry the refund/chargeback slice of an adjustment.* event
	// (G2-08). Adjustments carry no custom_data, so the account is resolved from
	// the bound subscription, never from AccountID.
	AdjustmentAction string // refund | chargeback | chargeback_reverse | credit | ...
	AdjustmentType   string // full | partial (empty ⇒ treated as full)
	AdjustmentStatus string // pending_approval | approved | rejected | reversed

	// TransactionZeroTotal (live-defect fix, 2026-09-12) is true when this
	// event's details.totals amount (grand_total, falling back to total when
	// grand_total is absent) parses as decimal zero - Paddle's own $0
	// trial-start transaction.completed shape. Only meaningful on
	// transaction.* events; empty/absent totals (every non-transaction event)
	// resolve to false.
	TransactionZeroTotal bool
	// TrialPeriodOnPrice (live-defect fix, 2026-09-12) is true when any of
	// this event's items carry a Paddle-side price trial_period (frequency
	// > 0). Consulted ONLY to decide whether a zero-total
	// transaction.completed that binds a not-yet-seen subscription should
	// land as 'trialing' rather than 'active'.
	TrialPeriodOnPrice bool
	// TrialEndsAt (live-defect fix, 2026-09-12) is the best-known trial end
	// for this event: items[0].trial_dates.ends_at when present, else
	// CurrentPeriodEnd, else NextBilledAt. May be zero - a
	// transaction.completed's payload carries none of these three sources on
	// a fresh first-purchase delivery.
	TrialEndsAt time.Time
}

// BillingIntake reports what happened to a delivery.
type BillingIntake struct {
	EventID   string
	Duplicate bool // already fully processed — replay-acked, not re-run
	Applied   bool // a plan assignment / subscription change was made
	// Outcome is a short machine tag for the audit trail: applied | duplicate |
	// ignored | unattributed | binding_refused | unknown_price | account_not_found
	// | not_billable | stale | status_only.
	Outcome string
	Note    string
	// AccountID is the RESOLVED account this event was attributed to — NEVER
	// the untrusted request-supplied custom_data.account_id (P3-d). Empty
	// when the event could not be attributed to any account (ignored,
	// unattributed, binding_refused, unknown_price — every outcome reached
	// before an account row was proven to exist). Populated as soon as the
	// account is proven to exist, even for an outcome that changes nothing
	// (account_not_found is the one exception: the id there names an
	// account that does NOT exist, so it is deliberately left unattributed).
	// This is what the webhook handler audits under, not ev.AccountID.
	AccountID string
}

var (
	// ErrBillingUnattributed means the event carried no resolvable account id.
	ErrBillingUnattributed = errors.New("cloudserver/store: billing event has no account_id")
	// ErrBillingUnknownPrice means the price id is not in the compiled-in map.
	ErrBillingUnknownPrice = errors.New("cloudserver/store: billing event price id is not a known plan price")
)

// ProcessPaddleEvent is the idempotent, retry-safe billing driver. It:
//  1. records the event (billing_events, event_id PK) — a duplicate that already
//     COMPLETED (processed_at set) replay-acks and does nothing else;
//  2. applies the event to the account's subscription + plan, resolving the
//     TRUSTED account (if any) along the way;
//  3. stamps processed_at AND (P2-1) the RESOLVED account_id, never the
//     request-supplied ev.AccountID.
//
// Steps 1 and 3 are WithSystem (billing_events is a system table); step 2 is
// tenant-scoped inside applyPaddleEvent. A crash between 1 and 3 leaves
// processed_at NULL, so Paddle's redelivery re-runs the (idempotent) apply. The
// apply is itself idempotent: subscription upsert is by (account, subscription
// id), and the plan assignment no-ops when the account already holds the target
// plan.
//
// P2-1 (a forged custom_data.account_id must never 500 forever): step 1 used
// to insert ev.AccountID directly, before ANY gate had a chance to run. A
// non-UUID value failed the `::uuid` cast; a syntactically valid but foreign
// UUID (no such account) failed the FK — either way Postgres raised a hard
// error, ProcessPaddleEvent returned it, and Paddle redelivered the SAME
// failing event forever (processed_at never got a chance to be set). The
// insert now always writes account_id=NULL; the RESOLVED account (proven to
// exist by applyPaddleEvent, or "" when never attributed / never confirmed to
// exist) is written only at step 3, once resolution has already happened —
// so the audit column can never itself be the reason a delivery fails.
func (s *Store) ProcessPaddleEvent(ctx context.Context, ev PaddleEvent) (BillingIntake, error) {
	if ev.EventID == "" || ev.EventType == "" {
		return BillingIntake{}, errors.New("cloudserver/store.ProcessPaddleEvent: event_id and event_type required")
	}
	now := ev.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	// 1. Idempotent record. A row that already has processed_at is settled.
	// account_id starts NULL — see the P2-1 note above.
	var alreadyProcessed bool
	var exists bool
	if err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Try to claim the event. ON CONFLICT DO NOTHING means a redelivery does
		// not insert; we then read the existing row's processed_at.
		var occurred *time.Time
		if !ev.OccurredAt.IsZero() {
			t := ev.OccurredAt.UTC()
			occurred = &t
		}
		ct, e := tx.Exec(ctx,
			`INSERT INTO billing_events (event_id, event_type, occurred_at, received_at)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (event_id) DO NOTHING`,
			ev.EventID, ev.EventType, occurred, now)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			// Redelivery: read whether it already completed.
			exists = true
			return tx.QueryRow(ctx,
				`SELECT processed_at IS NOT NULL FROM billing_events WHERE event_id=$1`,
				ev.EventID).Scan(&alreadyProcessed)
		}
		return nil
	}); err != nil {
		return BillingIntake{}, fmt.Errorf("cloudserver/store.ProcessPaddleEvent: record: %w", err)
	}
	if exists && alreadyProcessed {
		return BillingIntake{EventID: ev.EventID, Duplicate: true, Outcome: "duplicate", Note: "already processed"}, nil
	}

	// 2. Apply. Errors here leave processed_at NULL so a redelivery retries.
	intake, resolvedAccount, err := s.applyPaddleEvent(ctx, ev, now)
	if err != nil {
		return BillingIntake{}, err
	}

	// 3. Stamp processed + the RESOLVED account (P2-1 / P3-d).
	if err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var acct *string
		if resolvedAccount != "" {
			acct = &resolvedAccount
		}
		_, e := tx.Exec(ctx,
			`UPDATE billing_events SET processed_at=$2, account_id=$3::uuid WHERE event_id=$1`,
			ev.EventID, now, acct)
		return e
	}); err != nil {
		return BillingIntake{}, fmt.Errorf("cloudserver/store.ProcessPaddleEvent: stamp: %w", err)
	}
	intake.EventID = ev.EventID
	intake.AccountID = resolvedAccount
	return intake, nil
}

// paddleAction is the resolved entitlement effect of one Paddle event.
type paddleAction struct {
	// kind ∈ {activate, cancel, revoke, restore, status_only, ignore}.
	//   activate     — grant/confirm the paid plan (subscription active / renewal).
	//   cancel       — graceful cancellation: deferred cycle-boundary downgrade
	//                  (keeps what they paid for through the period).
	//   revoke       — IMMEDIATE downgrade to free (full refund / chargeback —
	//                  money returned, so no F11 boundary protection).
	//   restore      — re-grant the subscription's plan (chargeback_reverse).
	//   status_only  — record the event / subscription state without changing the
	//                  entitlement (past_due, paused, partial refund, credit, a
	//                  pending/rejected refund) — access is unchanged.
	//   ignore       — event type outside our model; 200-acked, never acted on.
	kind string
	// binds is true when this action may ESTABLISH a subscription→account link
	// (an activation / a first successful transaction). A bind requires a valid
	// server-minted checkout nonce (F2); adjustments never bind.
	binds bool
}

// resolvePaddleAction is the table-driven event→action classifier (CLAUDE.md #5).
// It is STATUS-aware (Sol F3): a subscription.updated carrying a canceled status
// is a cancellation, not a grant; past_due/paused are status-only (access
// continues through dunning). Refunds/chargebacks arrive as adjustment.* events
// and are classified by resolveAdjustmentAction. Unknown event types are ignored.
//
// A8 (2026-09-12 production-live gap 1.6) widened this from the
// subscription.*-only destination the register found: subscription.trialing
// and subscription.imported are their own binding activations (a dedicated
// trialing event — Paddle also reports status="trialing" on the shared
// activated/created/resumed/updated family, both routes land here);
// subscription.past_due / subscription.paused are their OWN event types (not
// only a status on subscription.updated) and stay status_only; the
// transaction.billed/paid/ready/updated/canceled family is explicitly
// ignored — billed/paid/ready all precede the transaction.completed this
// model actually acts on, and a transaction-level cancellation is a one-off
// outside the subscription model.
func resolvePaddleAction(ev PaddleEvent) paddleAction {
	switch ev.EventType {
	case "subscription.canceled":
		return paddleAction{kind: "cancel"}
	case "subscription.past_due", "subscription.paused":
		return paddleAction{kind: "status_only"}
	case "subscription.activated", "subscription.created", "subscription.resumed",
		"subscription.updated", "subscription.trialing", "subscription.imported":
		switch ev.Status {
		case "canceled":
			return paddleAction{kind: "cancel"}
		case "active", "trialing", "":
			return paddleAction{kind: "activate", binds: true}
		default: // past_due, paused, or any other non-active state
			return paddleAction{kind: "status_only"}
		}
	case "transaction.completed":
		// A successful subscription payment (initial or renewal) confirms paid
		// access — it can also be the binding event for a first purchase. A
		// transaction with no subscription is a one-off outside our model.
		if ev.SubscriptionID == "" {
			return paddleAction{kind: "ignore"}
		}
		return paddleAction{kind: "activate", binds: true}
	case "transaction.payment_failed", "transaction.past_due":
		// Dunning: record the state, never downgrade — access continues while
		// Paddle retries (the cancellation/expiry, if any, arrives as its own
		// subscription.* event).
		return paddleAction{kind: "status_only"}
	case "transaction.billed", "transaction.paid", "transaction.ready",
		"transaction.updated", "transaction.canceled":
		// billed/paid/ready all PRECEDE transaction.completed, which is the
		// event this model actually acts on; a transaction-level cancellation
		// is a one-off outside the subscription model. 200-acked, never acted
		// on — explicit rows so this is a documented decision, not a
		// fallthrough to the default.
		return paddleAction{kind: "ignore"}
	case "adjustment.created", "adjustment.updated":
		return resolveAdjustmentAction(ev.AdjustmentAction, ev.AdjustmentType, ev.AdjustmentStatus)
	default:
		return paddleAction{kind: "ignore"}
	}
}

// ClassifyPaddleEvent is a thin, read-only export of resolvePaddleAction (A10):
// it reports the entitlement action kind an event resolves to and whether that
// action may bind a not-yet-linked subscription, WITHOUT touching the
// database. Used by golden-fixture tests to verify the classifier against
// Paddle's documented example payloads. kind ∈ {activate, cancel, revoke,
// restore, status_only, ignore}.
func ClassifyPaddleEvent(ev PaddleEvent) (kind string, binds bool) {
	act := resolvePaddleAction(ev)
	return act.kind, act.binds
}

// ResolveActivateStatus is a thin, read-only export of resolveActivateStatus
// (same precedent as ClassifyPaddleEvent above): the live-defect fix's
// (2026-09-12) status + trial-end decision for an "activate" action, WITHOUT
// touching the database. Used by table-driven tests.
func ResolveActivateStatus(ev PaddleEvent, existingStatus string, existingTrialEnd *time.Time) (status string, trialEnd *time.Time) {
	return resolveActivateStatus(ev, existingStatus, existingTrialEnd)
}

// resolveAdjustmentAction classifies a refund/chargeback (adjustment.*) into an
// entitlement effect. Adjustments never bind (they act on an already-linked
// subscription). Paddle's action/type/status vocabulary is documented at
// https://developer.paddle.com/webhooks/adjustments/adjustment-created
// (action ∈ refund|chargeback|chargeback_reverse|credit|credit_reverse|
// chargeback_warning|chargeback_warning_reverse; type ∈ full|partial; status ∈
// pending_approval|approved|rejected|reversed).
//
//   - A FULL, APPROVED refund revokes paid access (money returned). A refund
//     starts pending_approval and only becomes effective at approved — a
//     pending/rejected refund is recorded but changes nothing.
//   - A chargeback is a bank reversal that is already effective on creation, so
//     a full chargeback revokes without waiting on approval.
//   - A PARTIAL refund/chargeback is recorded but KEEPS access (the customer was
//     only partly refunded).
//   - A chargeback_reverse (Paddle won the dispute back) restores access.
//   - credit / credit_reverse / chargeback_warning* are recorded, no change.
func resolveAdjustmentAction(action, typ, status string) paddleAction {
	switch action {
	case "refund":
		if typ != "partial" && status == "approved" {
			return paddleAction{kind: "revoke"}
		}
		return paddleAction{kind: "status_only"}
	case "chargeback":
		if typ != "partial" {
			return paddleAction{kind: "revoke"}
		}
		return paddleAction{kind: "status_only"}
	case "chargeback_reverse":
		return paddleAction{kind: "restore"}
	default: // credit, credit_reverse, chargeback_warning(_reverse), unknown
		return paddleAction{kind: "status_only"}
	}
}

// applyPaddleEvent applies one billing event to the account's subscription + plan
// inside a SINGLE tenant transaction (Sol F4: subscription upsert and plan
// assignment are atomic, and a per-account advisory lock serializes concurrent
// deliveries). It guards on account eligibility (Sol F2/F9: a deleted/closed
// account can never be revived or targeted), per-subscription event ordering
// (Sol F3: a stale out-of-order delivery is ignored), and — the G2-07/F2 core —
// binds a NOT-yet-linked subscription to an account ONLY when a server-minted
// checkout nonce matches (the untrusted custom_data.account_id alone never binds).
//
// The second return value is the RESOLVED account (P2-1 / P3-d): "" unless an
// `accounts` row was actually proven to exist for the id in play, so a caller
// can safely use it to attribute an audit row or a billing_events.account_id
// write without ever risking an FK failure on a foreign/forged id.
func (s *Store) applyPaddleEvent(ctx context.Context, ev PaddleEvent, now time.Time) (BillingIntake, string, error) {
	act := resolvePaddleAction(ev)
	if act.kind == "ignore" {
		return BillingIntake{Applied: false, Outcome: "ignored", Note: "event type not acted on"}, "", nil
	}

	// Resolve the TRUSTED account for this subscription from the existing binding
	// (the paddle_subscriptions linkage), bypassing RLS via a SECURITY DEFINER
	// resolver — adjustments carry no custom_data, so this is the only honest
	// attribution path for them.
	boundAccount, bound, err := s.paddleAccountForSubscription(ctx, ev.SubscriptionID)
	if err != nil {
		return BillingIntake{}, "", err
	}

	account := boundAccount
	needBind := false
	if !bound {
		if !act.binds {
			// An adjustment / status event on a subscription we have no binding for
			// cannot be attributed — record it, act on nothing.
			return BillingIntake{Applied: false, Outcome: "unattributed", Note: "subscription not bound to an account"}, "", nil
		}
		// F2 binding gate: a fresh subscription binds to an account ONLY with a
		// valid server-minted checkout nonce. The untrusted custom_data.account_id
		// is necessary but not sufficient. P2-1: the api decode boundary
		// (paddleEventFromEnvelope) already sanitizes a non-UUID account id to
		// "" before this is ever reached — this uuid.Parse check is
		// DEFENSE-IN-DEPTH so the store is safe standalone (a direct caller
		// that skips the api decode step, e.g. a test or a future non-HTTP
		// intake path, gets the same fail-closed refusal here rather than a
		// hard `::uuid` cast error deeper in the transaction).
		trimmedAccountID := strings.TrimSpace(ev.AccountID)
		if trimmedAccountID == "" {
			return BillingIntake{Applied: false, Outcome: "binding_refused", Note: "no account in custom_data"}, "", nil
		}
		if _, e := uuid.Parse(trimmedAccountID); e != nil {
			return BillingIntake{Applied: false, Outcome: "binding_refused", Note: "account id in custom_data is not a valid uuid"}, "", nil
		}
		if strings.TrimSpace(ev.CheckoutNonce) == "" {
			return BillingIntake{Applied: false, Outcome: "binding_refused", Note: "missing checkout nonce"}, "", nil
		}
		// A binding must grant a real plan; a foreign/unknown price can never bind.
		if _, known := s.paddlePlanForPrice(ev.PriceID); !known {
			return BillingIntake{Applied: false, Outcome: "unknown_price", Note: "binding refused: unknown price " + ev.PriceID}, "", nil
		}
		account = trimmedAccountID
		needBind = true
	}

	var periodEnd *time.Time
	if !ev.CurrentPeriodEnd.IsZero() {
		t := ev.CurrentPeriodEnd.UTC()
		periodEnd = &t
	}
	occurred := ev.OccurredAt
	if occurred.IsZero() {
		occurred = now
	}

	var intake BillingIntake
	var resolvedAccount string
	err = s.WithAccount(ctx, account, func(ctx context.Context, tx pgx.Tx) error {
		// F4: serialize every billing apply for this account. A concurrent replay
		// of the same (or a racing) event blocks here rather than interleaving.
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, account); e != nil {
			return fmt.Errorf("advisory lock: %w", e)
		}

		// F2/F9: the account must exist and be billable. A deleted/closed account
		// can never be revived or granted a plan by a (late) signed webhook. Checked
		// BEFORE consuming any checkout nonce. P2-1: `account` may be a
		// syntactically valid but entirely foreign UUID (no such account) here —
		// the ::uuid cast still succeeds, so this resolves to the graceful
		// account_not_found outcome below rather than a hard error, PROVIDED the
		// billing_events insert earlier never attempted to write this same
		// unverified id (see ProcessPaddleEvent's P2-1 note).
		var status string
		if e := tx.QueryRow(ctx, `SELECT status FROM accounts WHERE account_id=$1::uuid`, account).Scan(&status); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				intake = BillingIntake{Applied: false, Outcome: "account_not_found", Note: "account not found"}
				return nil
			}
			return fmt.Errorf("read account: %w", e)
		}
		// The account row is PROVEN to exist from here on — safe to attribute.
		resolvedAccount = account
		if status == "deleted" || status == "closed" {
			intake = BillingIntake{Applied: false, Outcome: "not_billable", Note: "account not billable (" + status + ")"}
			return nil
		}

		if needBind {
			// P1-2: RE-RESOLVE the binding now that the advisory lock is held.
			// transaction.completed and subscription.created/trialing for the
			// SAME first-purchase checkout typically carry the SAME
			// custom_data (account_id + checkout_nonce) and race in — both
			// read `bound=false` from the pre-lock check above before either
			// has committed. Without this re-check, whichever of the two
			// acquires the lock SECOND still tries to consume the (by then
			// already-consumed) nonce and loses as "binding_refused" even
			// though its own subscription IS now bound — and is stamped
			// processed forever (billing_events is keyed by event_id, so a
			// redelivery of the LOSING event replays the same refusal). A
			// plain RLS-scoped SELECT under `account` (the tx is already
			// scoped to it) is sufficient: both racing events resolve the
			// SAME account_id from custom_data, so re-checking under that
			// account is exactly the right re-resolution.
			var alreadyBound bool
			if e := tx.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM paddle_subscriptions WHERE account_id=$1::uuid AND paddle_subscription_id=$2)`,
				account, ev.SubscriptionID).Scan(&alreadyBound); e != nil {
				return fmt.Errorf("re-resolve binding: %w", e)
			}
			needBind = !alreadyBound
		}
		if needBind {
			// Consume the single-use checkout intent for this account. No live
			// matching intent ⇒ the binding is refused (the custom_data.account_id
			// was not proven by the server-initiated checkout).
			ok, intentPrice, e := consumeCheckoutIntentTx(ctx, tx, account, ev.CheckoutNonce, ev.SubscriptionID, now)
			if e != nil {
				return fmt.Errorf("consume checkout intent: %w", e)
			}
			if !ok {
				intake = BillingIntake{Applied: false, Outcome: "binding_refused", Note: "no matching live checkout nonce for account"}
				return nil
			}
			// P3-c: the checkout intent records the price the portal minted
			// the nonce for (audit / cross-check, migration 0030). A webhook
			// binding a DIFFERENT price than what was actually checked out
			// for is refused — an empty stored price (a legacy/unset intent)
			// carries no assertion either way, so it is never a mismatch.
			if intentPrice != "" && intentPrice != ev.PriceID {
				intake = BillingIntake{
					Applied: false, Outcome: "binding_refused",
					Note: "checkout intent price does not match the event's price",
				}
				return nil
			}
		}

		// F3: per-subscription ordering. If we have already applied an event at or
		// after this one's occurred_at, this delivery is stale — ignore it.
		var lastEventAt *time.Time
		e := tx.QueryRow(ctx,
			`SELECT last_event_at FROM paddle_subscriptions
			  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
			account, ev.SubscriptionID).Scan(&lastEventAt)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return fmt.Errorf("read subscription: %w", e)
		}
		if lastEventAt != nil && occurred.Before(*lastEventAt) {
			intake = BillingIntake{Applied: false, Outcome: "stale", Note: "stale event (out of order)"}
			return nil
		}

		intake, e = applyResolvedAction(ctx, tx, s, ev, act, account, periodEnd, occurred, now)
		return e
	})
	if err != nil {
		return BillingIntake{}, "", err
	}
	return intake, resolvedAccount, nil
}

// applyResolvedAction performs the per-kind entitlement mutation. It runs inside
// applyPaddleEvent's tenant transaction, after the advisory lock, billability,
// binding, and ordering guards have passed.
func applyResolvedAction(ctx context.Context, tx pgx.Tx, s *Store, ev PaddleEvent, act paddleAction, account string, periodEnd *time.Time, occurred, now time.Time) (BillingIntake, error) {
	switch act.kind {
	case "activate":
		return applyPaddleActivate(ctx, tx, s, ev, account, periodEnd, occurred, now)
	case "cancel":
		return applyPaddleCancel(ctx, tx, s, ev, account, periodEnd, occurred, now)
	case "revoke":
		return applyPaddleRevoke(ctx, tx, ev, account, occurred, now)
	case "restore":
		return applyPaddleRestore(ctx, tx, ev, account, occurred, now)
	case "status_only":
		return applyPaddleStatusOnly(ctx, tx, ev, account, occurred)
	default:
		return BillingIntake{Applied: false, Outcome: "ignored", Note: "no action"}, nil
	}
}

// resolveActivateStatus decides the row status (and, when preserving an
// existing trial, the trial end to keep) for an "activate" action - the pure
// decision the 2026-09-12 live-defect fix pulled out of applyPaddleActivate
// so it is directly table-tested (CLAUDE.md #5).
//
// A REAL Paddle sandbox checkout delivers, in order: subscription.created
// (status "trialing"), subscription.trialing (status "trialing"), then
// transaction.completed for the $0 trial-start transaction (no subscription
// status at all - transactions never carry one). The pre-fix code resolved
// EVERY transaction.completed to 'active', which converted a still-trialing
// row to active and (via upsertSubscriptionTx's CASE) nulled its
// trial_ends_at the instant that harmless $0 transaction landed - even
// though no money moved and the trial had not ended.
//
// Rules, in order:
//  1. An explicit trialing signal (ev.Status=="trialing" or
//     ev.EventType=="subscription.trialing") always resolves to trialing.
//     trialEnd is left nil here - the caller already has its own
//     periodEnd/TrialEndsAt ladder for this branch, unchanged from before
//     this fix.
//  2. A transaction.completed that moved NO money
//     (ev.TransactionZeroTotal) is status-PRESERVING:
//     - an existing 'trialing' row stays 'trialing', keeping ITS OWN
//     existingTrialEnd (never recomputed from the transaction, which
//     carries no current_billing_period to recompute from);
//     - no existing row yet (this zero-total transaction is itself the
//     first delivery to bind the subscription) and the price carries a
//     Paddle-side trial (ev.TrialPeriodOnPrice) also resolves to
//     'trialing', trialEnd nil (the caller's ladder fills it from
//     ev.TrialEndsAt if available).
//  3. Anything else - a genuine non-zero transaction.completed, or any
//     other status the shared activated/created/resumed/updated family
//     reports - resolves to 'active'. Deliberately simple: ONLY an
//     existing 'trialing' row is preserved; a past_due or paused row that
//     happens to receive a zero-total transaction still resolves to
//     'active' (a zero-total transaction is never itself evidence of an
//     ongoing trial for a row that has already left the trialing state).
func resolveActivateStatus(ev PaddleEvent, existingStatus string, existingTrialEnd *time.Time) (status string, trialEnd *time.Time) {
	if ev.Status == "trialing" || ev.EventType == "subscription.trialing" {
		return "trialing", nil
	}
	if ev.EventType == "transaction.completed" && ev.TransactionZeroTotal {
		switch {
		case existingStatus == "trialing":
			return "trialing", existingTrialEnd
		case existingStatus == "" && ev.TrialPeriodOnPrice:
			return "trialing", nil
		}
	}
	return "active", nil
}

// applyPaddleActivate handles the "activate" action: an activation / successful
// payment / trialing subscription resolves to a row and the plan grant. A7
// (gap 1.11): the row status honestly persists 'trialing' - rather than the
// prior fold-into-'active' - when the event reports it (either a dedicated
// subscription.trialing event or status="trialing" on the shared
// activated/created/resumed/updated family), so the portal can render "trial
// ends in N days". A genuine, non-zero-total transaction.completed (money
// actually moved - the trial ended and billing began) resolves to 'active'
// and, via upsertSubscriptionTx's CASE, clears a previously-recorded
// trial_ends_at. A ZERO-total transaction.completed (live-defect fix,
// 2026-09-12 - Paddle's own $0 trial-start transaction, delivered AFTER the
// subscription.trialing event for the same checkout) is status-preserving
// instead: see resolveActivateStatus for the full decision table.
func applyPaddleActivate(ctx context.Context, tx pgx.Tx, s *Store, ev PaddleEvent, account string, periodEnd *time.Time, occurred, now time.Time) (BillingIntake, error) {
	// P2-3: refuse a SECOND distinct live subscription for this account BEFORE
	// attempting the write, rather than letting Postgres refuse it via the
	// paddle_subscriptions_one_live partial unique index. A mid-transaction
	// 23505 would abort this entire transaction (Postgres refuses every later
	// statement, including COMMIT, once one statement inside a transaction
	// errors) — there is no way to catch that error and still commit the
	// graceful outcome below, so this must be a pre-check, not a post-hoc
	// error mapping. Excludes ev.SubscriptionID itself so a renewal/update on
	// the SAME subscription is never refused.
	var conflictingSub string
	checkErr := tx.QueryRow(ctx,
		`SELECT paddle_subscription_id FROM paddle_subscriptions
		  WHERE account_id=$1::uuid AND paddle_subscription_id<>$2
		    AND status NOT IN ('canceled','refunded','charged_back')
		  LIMIT 1`,
		account, ev.SubscriptionID).Scan(&conflictingSub)
	switch {
	case errors.Is(checkErr, pgx.ErrNoRows):
		// no competing live subscription — proceed
	case checkErr != nil:
		return BillingIntake{}, fmt.Errorf("check live subscription: %w", checkErr)
	default:
		return BillingIntake{
			Applied: false, Outcome: "refused_second_live",
			Note: "account already holds a live subscription (" + conflictingSub + "); this distinct subscription id was refused",
		}, nil
	}

	plan, known := s.paddlePlanForPrice(ev.PriceID)
	if !known {
		// A bound renewal whose price we don't recognize must not disrupt the
		// existing grant — keep the subscription's current plan.
		var pName string
		var pVer int
		if e := tx.QueryRow(ctx,
			`SELECT plan_name, plan_version FROM paddle_subscriptions
			  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
			account, ev.SubscriptionID).Scan(&pName, &pVer); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return BillingIntake{Applied: false, Outcome: "unknown_price", Note: "unknown price " + ev.PriceID}, nil
			}
			return BillingIntake{}, fmt.Errorf("read subscription plan: %w", e)
		}
		plan = PaddlePlan{Name: pName, Version: pVer}
	}
	// Read the row's EXISTING status/trial_ends_at BEFORE the upsert -
	// resolveActivateStatus needs to know whether this subscription is
	// already trialing (to preserve it) or has no row yet (to decide whether
	// a zero-total transaction.completed may itself bind as trialing). No
	// row yet ⇒ existingStatus stays "" (ErrNoRows is not an error here).
	var existingStatus string
	var existingTrialEnd *time.Time
	if e := tx.QueryRow(ctx,
		`SELECT status, trial_ends_at FROM paddle_subscriptions
		  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
		account, ev.SubscriptionID).Scan(&existingStatus, &existingTrialEnd); e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return BillingIntake{}, fmt.Errorf("read existing subscription for activate: %w", e)
	}
	rowStatus, preservedTrialEnd := resolveActivateStatus(ev, existingStatus, existingTrialEnd)
	// activatePeriodEnd feeds BOTH current_period_end and (while trialing)
	// trial_ends_at in upsertSubscriptionTx. A preserved trial keeps its OWN
	// stored end (the zero-total transaction carries no billing period to
	// recompute one from); otherwise fall back to ev.TrialEndsAt when the
	// event itself carried no current_billing_period (a fresh
	// transaction.completed binding as trialing with no prior row).
	activatePeriodEnd := periodEnd
	if rowStatus == "trialing" {
		switch {
		case preservedTrialEnd != nil:
			activatePeriodEnd = preservedTrialEnd
		case activatePeriodEnd == nil && !ev.TrialEndsAt.IsZero():
			t := ev.TrialEndsAt.UTC()
			activatePeriodEnd = &t
		}
	}
	if e := upsertSubscriptionTx(ctx, tx, account, ev, plan, rowStatus, nil, activatePeriodEnd, occurred); e != nil {
		return BillingIntake{}, fmt.Errorf("upsert subscription: %w", e)
	}
	if _, e := assignPlanTx(ctx, tx, account, plan.Name, plan.Version, now, now, "paddle"); e != nil {
		if errors.Is(e, ErrPlanAssignmentConflict) {
			return BillingIntake{Applied: true, Outcome: "applied", Note: "subscription " + rowStatus + "; plan unchanged"}, nil
		}
		return BillingIntake{}, fmt.Errorf("assign plan: %w", e)
	}
	return BillingIntake{Applied: true, Outcome: "applied", Note: "subscription " + rowStatus + "; plan " + plan.Name}, nil
}

// applyPaddleCancel handles the "cancel" action: the subscription row is marked
// canceled and the downgrade to free is scheduled.
//
// A7 (gap 1.11) operator ruling: a cancellation that arrives while the
// subscription was TRIALING downgrades effective at the trial's own end (the
// period end) — NOT ceiled to the next monthly cycle boundary the way a
// graceful post-trial cancellation is. F11's "keep what you paid for" floor
// protects allowance a developer is part-way through spending BECAUSE they
// paid for it; nothing was paid for during a trial, so there is no cycle to
// protect, and the trial's own end is the honest boundary.
func applyPaddleCancel(ctx context.Context, tx pgx.Tx, s *Store, ev PaddleEvent, account string, periodEnd *time.Time, occurred, now time.Time) (BillingIntake, error) {
	var priorPlanName string
	var priorPlanVersion int
	var priorTrialEndsAt *time.Time
	if e := tx.QueryRow(ctx,
		`SELECT plan_name, plan_version, trial_ends_at FROM paddle_subscriptions
		  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
		account, ev.SubscriptionID).Scan(&priorPlanName, &priorPlanVersion, &priorTrialEndsAt); e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return BillingIntake{}, fmt.Errorf("read prior subscription: %w", e)
	}
	// P2-2: derive "was trialing" from trial_ends_at, not the row's CURRENT
	// status. applyPaddleStatusOnly (past_due/paused) never touches
	// trial_ends_at, so a subscription that went trialing -> past_due ->
	// canceled still carries a non-nil trial_ends_at at cancel time even
	// though `status` itself has moved past "trialing" — a priorStatus==
	// "trialing" check alone missed exactly that sequence and let a
	// never-actually-paid trial ride paid access all the way to the next
	// monthly cycle boundary (F11) instead of ending at the trial's own end.
	wasTrialing := priorTrialEndsAt != nil

	plan, known := s.paddlePlanForPrice(ev.PriceID)
	if !known {
		if priorPlanName != "" {
			// P3-e: an unknown/missing cancellation price must keep the
			// row's OWN stored plan — F2 guarantees a paddle_subscriptions
			// row already exists by the time a cancel reaches here (cancel
			// never binds; the account here was resolved from the existing
			// binding), so defaulting to a fixed plus_beta v1 label would
			// silently corrupt the row for an account actually on a
			// different plan (e.g. a Paddle-side price change to something
			// this deploy has not provisioned).
			plan = PaddlePlan{Name: priorPlanName, Version: priorPlanVersion}
		} else {
			// No prior row to read from — defensive only; not reachable
			// through the normal F2-gated flow (see above).
			plan = PaddlePlan{Name: PlanPlusBeta, Version: 1}
		}
	}
	if e := upsertSubscriptionTx(ctx, tx, account, ev, plan, "canceled", &now, periodEnd, occurred); e != nil {
		return BillingIntake{}, fmt.Errorf("upsert subscription: %w", e)
	}
	effective := ev.CurrentPeriodEnd
	if wasTrialing && priorTrialEndsAt != nil {
		// P2-2: anchor to the STORED trial end, not whatever (or nothing)
		// the cancellation event's own current_billing_period happens to
		// carry — which may already have moved on (e.g. after a past_due
		// detour) or be entirely absent on a cancellation delivered after
		// dunning.
		effective = *priorTrialEndsAt
	}
	if effective.IsZero() {
		effective = now
	}
	if wasTrialing {
		if e := scheduleTrialCancelDowngradeTx(ctx, tx, account, effective, now, "paddle"); e != nil {
			if errors.Is(e, ErrPlanAssignmentConflict) {
				return BillingIntake{Applied: true, Outcome: "applied", Note: "canceled during trial; already scheduled"}, nil
			}
			return BillingIntake{}, fmt.Errorf("schedule trial-cancel downgrade: %w", e)
		}
		return BillingIntake{Applied: true, Outcome: "applied", Note: "canceled during trial; downgrade at trial end"}, nil
	}
	// DefaultFreePlanVersion, not a hardcoded 1: a cancellation must land the
	// account on the SAME free plan an account with no assignment resolves,
	// otherwise a canceled subscriber silently keeps the superseded free
	// allowance (v1's 5/day) forever. The downgrade still defers to the cycle
	// boundary because moving back TO the free pool is not an activation.
	if _, e := assignPlanTx(ctx, tx, account, PlanFree, DefaultFreePlanVersion, effective, now, "paddle"); e != nil {
		if errors.Is(e, ErrPlanAssignmentConflict) {
			return BillingIntake{Applied: true, Outcome: "applied", Note: "canceled; already on free"}, nil
		}
		return BillingIntake{}, fmt.Errorf("downgrade: %w", e)
	}
	return BillingIntake{Applied: true, Outcome: "applied", Note: "canceled; downgrade scheduled at cycle boundary"}, nil
}

// scheduleTrialCancelDowngradeTx schedules the free downgrade to start EXACTLY
// at `effective` (the trial's own end), bypassing assignPlanTx's F11 monthly-
// cycle ceiling — see applyPaddleCancel's doc comment for why that ceiling
// does not apply while trialing. It mirrors assignPlanTx / revokePlanToFreeTx's
// "close the open row, insert the new one" shape (CLAUDE.md #4: same
// invariants, no second entitlement-write path) rather than introducing a
// third. Caller already holds the account's advisory lock
// (applyPaddleEvent) and tenant context.
func scheduleTrialCancelDowngradeTx(ctx context.Context, tx pgx.Tx, accountID string, effective, now time.Time, source string) error {
	effective = effective.UTC()
	if effective.Before(now) {
		effective = now
	}
	free, err := loadPlanTx(ctx, tx, PlanFree, DefaultFreePlanVersion)
	if err != nil {
		return err
	}
	// Supersede anything scheduled after the new effective instant — the
	// trial cancellation is itself the authoritative downgrade schedule now
	// (mirrors revokePlanToFreeTx's "clear scheduled assignments" step).
	if _, e := tx.Exec(ctx,
		`DELETE FROM account_plans WHERE account_id = $1::uuid AND effective_from > $2`,
		accountID, effective); e != nil {
		return fmt.Errorf("clear scheduled assignments: %w", e)
	}
	var openID string
	var openFrom time.Time
	e := tx.QueryRow(ctx,
		`SELECT id::text, effective_from FROM account_plans
		  WHERE account_id = $1::uuid AND effective_until IS NULL FOR UPDATE`,
		accountID).Scan(&openID, &openFrom)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
		// No open assignment — the account is already on the implicit default
		// free plan with nothing scheduled; a trial cancellation confirms
		// that, nothing to write.
		return nil
	case e != nil:
		return fmt.Errorf("lock open assignment: %w", e)
	default:
		if !openFrom.Before(effective) {
			return ErrPlanAssignmentConflict
		}
		if _, e := tx.Exec(ctx,
			`UPDATE account_plans SET effective_until = $3
			  WHERE account_id = $1::uuid AND id = $2::uuid`,
			accountID, openID, effective); e != nil {
			return fmt.Errorf("close open assignment: %w", e)
		}
	}
	if _, e := tx.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, source)
		 VALUES ($1::uuid, $2::uuid, $3, $4)`,
		accountID, free.ID, effective, source); e != nil {
		return fmt.Errorf("insert free assignment: %w", e)
	}
	return nil
}

// applyPaddleRevoke handles the "revoke" action (full refund / chargeback):
// paid access is revoked NOW (no cycle-boundary floor — money returned) and the
// subscription row records the honest terminal state.
func applyPaddleRevoke(ctx context.Context, tx pgx.Tx, ev PaddleEvent, account string, occurred, now time.Time) (BillingIntake, error) {
	rowStatus := "refunded"
	if ev.AdjustmentAction == "chargeback" {
		rowStatus = "charged_back"
	}
	if _, e := tx.Exec(ctx,
		`UPDATE paddle_subscriptions
		    SET status=$3, canceled_at=$4, last_event_at=$5, updated_at=now()
		  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
		account, ev.SubscriptionID, rowStatus, now, occurred); e != nil {
		return BillingIntake{}, fmt.Errorf("mark subscription %s: %w", rowStatus, e)
	}
	if e := revokePlanToFreeTx(ctx, tx, account, now, "paddle"); e != nil {
		return BillingIntake{}, fmt.Errorf("revoke to free: %w", e)
	}
	return BillingIntake{Applied: true, Outcome: "applied", Note: rowStatus + "; paid access revoked"}, nil
}

// applyPaddleRestore handles the "restore" action (chargeback_reverse): the
// subscription's plan is restored immediately.
func applyPaddleRestore(ctx context.Context, tx pgx.Tx, ev PaddleEvent, account string, occurred, now time.Time) (BillingIntake, error) {
	var pName string
	var pVer int
	if e := tx.QueryRow(ctx,
		`SELECT plan_name, plan_version FROM paddle_subscriptions
		  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
		account, ev.SubscriptionID).Scan(&pName, &pVer); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return BillingIntake{Applied: false, Outcome: "unattributed", Note: "no subscription to restore"}, nil
		}
		return BillingIntake{}, fmt.Errorf("read subscription plan: %w", e)
	}
	if _, e := tx.Exec(ctx,
		`UPDATE paddle_subscriptions
		    SET status='active', canceled_at=NULL, last_event_at=$3, updated_at=now()
		  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
		account, ev.SubscriptionID, occurred); e != nil {
		return BillingIntake{}, fmt.Errorf("restore subscription: %w", e)
	}
	if _, e := assignPlanTx(ctx, tx, account, pName, pVer, now, now, "paddle"); e != nil {
		if errors.Is(e, ErrPlanAssignmentConflict) {
			return BillingIntake{Applied: true, Outcome: "applied", Note: "chargeback reversed; plan unchanged"}, nil
		}
		return BillingIntake{}, fmt.Errorf("restore plan: %w", e)
	}
	return BillingIntake{Applied: true, Outcome: "applied", Note: "chargeback reversed; plan " + pName + " restored"}, nil
}

// applyPaddleStatusOnly handles the "status_only" action: record the state
// (past_due, paused, partial refund, credit) without touching the plan — access
// is unchanged. Only last_event_at is stamped so the F3 ordering guard
// advances; plan_name/version are never overwritten (an adjustment carries no
// price). A8: subscription.past_due / subscription.paused are now their OWN
// event types (gap 1.6), not only a status on subscription.updated — both
// routes resolve the same row status.
func applyPaddleStatusOnly(ctx context.Context, tx pgx.Tx, ev PaddleEvent, account string, occurred time.Time) (BillingIntake, error) {
	newStatus := ""
	switch ev.EventType {
	case "subscription.activated", "subscription.created", "subscription.resumed", "subscription.updated":
		if ev.Status == "past_due" || ev.Status == "paused" {
			newStatus = ev.Status
		}
	case "subscription.past_due":
		newStatus = "past_due"
	case "subscription.paused":
		newStatus = "paused"
	}
	if newStatus != "" {
		if _, e := tx.Exec(ctx,
			`UPDATE paddle_subscriptions SET status=$3, last_event_at=$4, updated_at=now()
			  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
			account, ev.SubscriptionID, newStatus, occurred); e != nil {
			return BillingIntake{}, fmt.Errorf("update subscription status: %w", e)
		}
	} else {
		if _, e := tx.Exec(ctx,
			`UPDATE paddle_subscriptions SET last_event_at=$3, updated_at=now()
			  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
			account, ev.SubscriptionID, occurred); e != nil {
			return BillingIntake{}, fmt.Errorf("stamp subscription event: %w", e)
		}
	}
	return BillingIntake{Applied: true, Outcome: "status_only", Note: "recorded; access unchanged"}, nil
}

// upsertSubscriptionTx writes the account's subscription linkage inside the
// caller's tenant transaction, stamping last_event_at for the F3 ordering
// guard.
//
// BUG FIX (A1 / gap 1.5, 2026-09-12): this used to write the UNTRUSTED
// ev.AccountID as the row's account_id, while every caller runs inside a tx
// already scoped to the RESOLVED `account` (applyPaddleEvent's binding +
// ordering guards). For any activate/cancel on an ALREADY-BOUND subscription
// whose delivery carries no custom_data.account_id — the normal shape of a
// transaction.completed renewal or a bound subscription.updated — ev.AccountID
// was "", the ::uuid cast failed, and the store returned an error that made
// Paddle redeliver forever. `account` is now the single source of truth for
// this column, exactly as every other write in this file already uses it.
//
// A7 (gap 1.11 trial handling, gap 1.4 management URLs): trial_ends_at is set
// only when status='trialing' (periodEnd, falling back to ev.NextBilledAt) and
// CLEARED the moment a later event resolves the row to any other status — a
// transaction.completed or an explicit active status converts trialing to
// paid, honestly. management_update_url / management_cancel_url are stored
// ONLY when validatePaddleManagementURL accepts them (https + paddle.com — a
// webhook body is attacker-shaped input until the signature is verified, and
// even verified we never persist an arbitrary URL from it); COALESCE keeps a
// previously-stored URL when this particular event didn't carry one (Paddle's
// own docs: subscription.updated omits management_urls entirely).
func upsertSubscriptionTx(ctx context.Context, tx pgx.Tx, account string, ev PaddleEvent, plan PaddlePlan, status string, canceledAt, periodEnd *time.Time, occurred time.Time) error {
	var trialEndsAt *time.Time
	if status == "trialing" {
		switch {
		case periodEnd != nil:
			trialEndsAt = periodEnd
		case !ev.NextBilledAt.IsZero():
			t := ev.NextBilledAt.UTC()
			trialEndsAt = &t
		}
	}
	updateURL := validatePaddleManagementURL(ev.ManagementUpdateURL)
	cancelURL := validatePaddleManagementURL(ev.ManagementCancelURL)
	_, e := tx.Exec(ctx,
		`INSERT INTO paddle_subscriptions
		     (account_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version,
		      status, current_period_end, canceled_at, last_event_at, trial_ends_at,
		      management_update_url, management_cancel_url, created_at, updated_at)
		 VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now(), now())
		 ON CONFLICT (account_id, paddle_subscription_id) DO UPDATE SET
		     paddle_customer_id    = EXCLUDED.paddle_customer_id,
		     plan_name             = EXCLUDED.plan_name,
		     plan_version          = EXCLUDED.plan_version,
		     status                = EXCLUDED.status,
		     current_period_end    = EXCLUDED.current_period_end,
		     canceled_at           = COALESCE(EXCLUDED.canceled_at, paddle_subscriptions.canceled_at),
		     last_event_at         = EXCLUDED.last_event_at,
		     trial_ends_at         = CASE WHEN EXCLUDED.status = 'trialing' THEN EXCLUDED.trial_ends_at ELSE NULL END,
		     management_update_url = COALESCE(EXCLUDED.management_update_url, paddle_subscriptions.management_update_url),
		     management_cancel_url = COALESCE(EXCLUDED.management_cancel_url, paddle_subscriptions.management_cancel_url),
		     updated_at            = now()`,
		account, ev.CustomerID, ev.SubscriptionID, plan.Name, plan.Version,
		status, periodEnd, canceledAt, occurred, trialEndsAt, updateURL, cancelURL)
	return e
}

// validatePaddleManagementURL accepts a Paddle-hosted management URL (gap 1.4)
// ONLY when it parses as an https URL whose host is paddle.com or a
// *.paddle.com subdomain. A webhook body is attacker-shaped input until the
// signature is verified, and even verified we never persist — let alone later
// render — an arbitrary URL taken from it. Returns nil (not stored) for
// anything else, including an empty string.
func validatePaddleManagementURL(raw string) *string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if host != "paddle.com" && !strings.HasSuffix(host, ".paddle.com") {
		return nil
	}
	return &raw
}

// PaddleManagementURLs is Paddle's hosted customer-portal link pair (gap 1.4).
// Only URLs that pass validatePaddleManagementURL are ever stored, so a
// non-empty field here is always an https paddle.com / *.paddle.com link.
type PaddleManagementURLs struct {
	UpdatePaymentMethod string `json:"update_payment_method"`
	Cancel              string `json:"cancel"`
}

// PaddleSubscription is the account's current subscription linkage for the portal
// Billing page.
type PaddleSubscription struct {
	SubscriptionID   string     `json:"subscription_id"`
	CustomerID       string     `json:"customer_id"`
	PlanName         string     `json:"plan_name"`
	PlanVersion      int        `json:"plan_version"`
	Status           string     `json:"status"`
	CurrentPeriodEnd *time.Time `json:"current_period_end,omitempty"`
	CanceledAt       *time.Time `json:"canceled_at,omitempty"`
	// TrialEndsAt is set only while Status == "trialing" (A7 / gap 1.11).
	TrialEndsAt *time.Time `json:"trial_ends_at,omitempty"`
	// ManagementURLs is nil when Paddle sent neither link (or when a link
	// failed validatePaddleManagementURL) — the portal falls back to "use the
	// receipt email Paddle sent you" in that case (gap 1.4).
	ManagementURLs *PaddleManagementURLs `json:"management_urls,omitempty"`
}

// AccountSubscription returns the account's most relevant subscription — the
// live one (active/trialing/past_due/paused) when present, else the most
// recently updated terminal one (canceled/refunded/charged_back), so the
// portal Billing surface shows the honest current state including a revoked
// (refunded/charged_back) subscription. Returns ErrNotFound when the account
// has no subscription at all.
func (s *Store) AccountSubscription(ctx context.Context, accountID string) (PaddleSubscription, error) {
	var out PaddleSubscription
	var trialEndsAt *time.Time
	var updateURL, cancelURL *string
	found := false
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT paddle_subscription_id, paddle_customer_id, plan_name, plan_version,
			        status, current_period_end, canceled_at, trial_ends_at,
			        management_update_url, management_cancel_url
			   FROM paddle_subscriptions
			  WHERE account_id=$1::uuid
			  ORDER BY (status IN ('active','trialing','past_due','paused')) DESC, updated_at DESC
			  LIMIT 1`, accountID).
			Scan(&out.SubscriptionID, &out.CustomerID, &out.PlanName, &out.PlanVersion,
				&out.Status, &out.CurrentPeriodEnd, &out.CanceledAt, &trialEndsAt,
				&updateURL, &cancelURL)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		found = true
		return nil
	})
	if err != nil {
		return PaddleSubscription{}, fmt.Errorf("cloudserver/store.AccountSubscription: %w", err)
	}
	if !found {
		return PaddleSubscription{}, ErrNotFound
	}
	out.TrialEndsAt = trialEndsAt
	if updateURL != nil || cancelURL != nil {
		m := &PaddleManagementURLs{}
		if updateURL != nil {
			m.UpdatePaymentMethod = *updateURL
		}
		if cancelURL != nil {
			m.Cancel = *cancelURL
		}
		out.ManagementURLs = m
	}
	return out, nil
}

// priceMap is the compiled-in Paddle price → plan mapping, overridable at
// construction (SetPaddlePriceMap) from deploy config. Nil/empty means no price
// is known (every activation fails closed as unknown-price), which is the
// correct dark posture until the operator wires real pri_* ids.
func (s *Store) paddlePlanForPrice(priceID string) (PaddlePlan, bool) {
	if priceID == "" {
		return PaddlePlan{}, false
	}
	if p, ok := s.paddlePrices[priceID]; ok {
		return p, true
	}
	return PaddlePlan{}, false
}

// SetPaddlePriceMap wires the price→plan map at service bootstrap (from
// SBCI_PADDLE_PRICE_PLUS etc.). Call before serving webhooks.
func (s *Store) SetPaddlePriceMap(m map[string]PaddlePlan) {
	s.paddlePrices = m
}

// PaddlePriceKnown reports whether priceID maps to a plan — the portal checkout
// endpoint uses it to refuse minting an intent for a price that could never grant
// a plan (the dark posture when no prices are provisioned: every price unknown).
func (s *Store) PaddlePriceKnown(priceID string) bool {
	_, ok := s.paddlePlanForPrice(priceID)
	return ok
}

// paddleAccountForSubscription resolves the account a subscription is bound to,
// via the SECURITY DEFINER resolver (owner sbci_defs, BYPASSRLS) so it works
// without tenant context — the attribution path for adjustment.* events, which
// carry only a subscription id and no custom_data. Returns ("", false, nil) when
// the subscription is not (yet) bound.
func (s *Store) paddleAccountForSubscription(ctx context.Context, subscriptionID string) (string, bool, error) {
	if strings.TrimSpace(subscriptionID) == "" {
		return "", false, nil
	}
	var acct *string
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT sbci_paddle_account_for_subscription($1)::text`, subscriptionID).Scan(&acct)
	})
	if err != nil {
		return "", false, fmt.Errorf("cloudserver/store.paddleAccountForSubscription: %w", err)
	}
	if acct == nil || *acct == "" {
		return "", false, nil
	}
	return *acct, true, nil
}

// hashCheckoutNonce is the storage form of a checkout nonce — sha256(raw). The
// raw nonce is never persisted (exchange_nonces discipline).
func hashCheckoutNonce(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// CreateCheckoutIntent mints a single-use, TTL'd checkout nonce for an
// authenticated account (G2-07 / F2). It stores sha256(nonce) and returns the raw
// nonce to the caller ONCE — the portal puts it in the checkout's
// custom_data.checkout_nonce so the webhook can later prove the subscription was
// created by a SERVER-initiated checkout for this exact account.
func (s *Store) CreateCheckoutIntent(ctx context.Context, accountID, priceID string, ttl time.Duration, now time.Time) (string, time.Time, error) {
	if strings.TrimSpace(accountID) == "" {
		return "", time.Time{}, errors.New("cloudserver/store.CreateCheckoutIntent: account id required")
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	now = now.UTC()
	expiresAt := now.Add(ttl)
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, fmt.Errorf("cloudserver/store.CreateCheckoutIntent: entropy: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	var priceArg *string
	if p := strings.TrimSpace(priceID); p != "" {
		priceArg = &p
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO checkout_intents (account_id, nonce_hash, price_id, created_at, expires_at)
			 VALUES ($1::uuid, $2, $3, $4, $5)`,
			accountID, hashCheckoutNonce(raw), priceArg, now, expiresAt)
		return e
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("cloudserver/store.CreateCheckoutIntent: %w", err)
	}
	return raw, expiresAt, nil
}

// consumeCheckoutIntentTx atomically claims the single live checkout intent for
// (account, nonce), returning (matched, price_id). It returns matched=false
// when there is no unconsumed-and-unexpired intent for that account whose
// hash matches AND no already-consumed intent for the SAME subscription id —
// the binding is refused. Runs inside the caller's tenant transaction
// (checkout_intents is a SYSTEM table, so the account_id filter is explicit,
// not RLS).
//
// P1-2: the WHERE clause additionally matches an intent already consumed by
// THIS SAME subscription id — idempotent for a re-resolved race (the P1-2
// re-check above should already route a genuinely racing second delivery
// onto the already-bound path before this is even called, but a delivery
// that reaches here with the SAME subscription id it already bound — e.g. a
// crash between this consume and the caller's later commit, forcing a
// redelivery that arrives needing a fresh resolve — must not be refused just
// because its own earlier attempt already burned the nonce). A DIFFERENT
// subscription id presenting an already-consumed intent is still refused
// (`consumed_subscription_id` must equal `subscriptionID`, never merely
// non-null). The already-expired branch is admitted only on that same exact
// match — expiry no longer matters once the nonce has already been proven
// used for this exact subscription.
func consumeCheckoutIntentTx(ctx context.Context, tx pgx.Tx, accountID, rawNonce, subscriptionID string, now time.Time) (bool, string, error) {
	var intentID string
	var priceID *string
	e := tx.QueryRow(ctx,
		`UPDATE checkout_intents
		    SET consumed_at = COALESCE(consumed_at, $4),
		        consumed_subscription_id = COALESCE(consumed_subscription_id, $3)
		  WHERE account_id = $1::uuid
		    AND nonce_hash = $2
		    AND (
		          (consumed_at IS NULL AND expires_at > $4)
		       OR (consumed_at IS NOT NULL AND consumed_subscription_id = $3)
		        )
		  RETURNING intent_id::text, price_id`,
		accountID, hashCheckoutNonce(rawNonce), subscriptionID, now.UTC()).Scan(&intentID, &priceID)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, "", nil
	}
	if e != nil {
		return false, "", e
	}
	price := ""
	if priceID != nil {
		price = *priceID
	}
	return true, price, nil
}

// SweepExpiredCheckoutIntents deletes checkout intents past their TTL (consumed
// or not). Content-free housekeeping; safe to call from a periodic sweep.
func (s *Store) SweepExpiredCheckoutIntents(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM checkout_intents WHERE expires_at <= $1`, now.UTC())
		if e != nil {
			return e
		}
		n = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.SweepExpiredCheckoutIntents: %w", err)
	}
	return n, nil
}

// PlanExists reports whether a (name, version) row exists in the immutable
// plans catalogue (migration 0012). A5 (gap 1.8) uses this at startup: every
// price in a configured Paddle price map must resolve to a REAL plan, so a
// typo in SBCI_PADDLE_PRICES fails the deploy loudly instead of quietly
// fail-closing every live activation as "unknown price" months later. Pass
// LatestPlanVersion (0) to accept any published version of that name.
func (s *Store) PlanExists(ctx context.Context, name string, version int) (bool, error) {
	if strings.TrimSpace(name) == "" {
		return false, nil
	}
	var ok bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM plans WHERE name=$1 AND ($2 = 0 OR version = $2))`,
			name, version).Scan(&ok)
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.PlanExists: %w", err)
	}
	return ok, nil
}

// ParsePaddlePriceEntries parses the A5 (gap 1.8) multi-price catalogue:
// SBCI_PADDLE_PRICES, a comma-separated list of
// "pri_x=plan:version:interval[:display]" entries, PLUS the backward-compatible
// single legacy SBCI_PADDLE_PRICE_PLUS id (mapped to plus_beta v1 month, the
// original single-price shape). Table-driven and pure (CLAUDE.md #5) — no
// os.Getenv here, so it is directly testable. A malformed entry, an unknown
// interval, or a duplicate price id is a startup error, never a silently
// dropped row: a price that fails to parse must not quietly leave a plan
// unpurchasable.
func ParsePaddlePriceEntries(pricesEnv, legacyPriceID string) (map[string]PaddlePlan, error) {
	m := map[string]PaddlePlan{}
	if id := strings.TrimSpace(legacyPriceID); id != "" {
		m[id] = PaddlePlan{Name: PlanPlusBeta, Version: 1, Interval: "month"}
	}
	pricesEnv = strings.TrimSpace(pricesEnv)
	if pricesEnv == "" {
		return m, nil
	}
	for _, entry := range strings.Split(pricesEnv, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, spec, ok := strings.Cut(entry, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" || strings.TrimSpace(spec) == "" {
			return nil, fmt.Errorf("cloudserver/store.ParsePaddlePriceEntries: malformed entry %q (want pri_x=plan:version:interval[:display])", entry)
		}
		parts := strings.SplitN(spec, ":", 4)
		if len(parts) < 3 {
			return nil, fmt.Errorf("cloudserver/store.ParsePaddlePriceEntries: %s: want plan:version:interval[:display], got %q", id, spec)
		}
		planName := strings.TrimSpace(parts[0])
		if planName == "" {
			return nil, fmt.Errorf("cloudserver/store.ParsePaddlePriceEntries: %s: empty plan name", id)
		}
		version, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || version < 1 {
			return nil, fmt.Errorf("cloudserver/store.ParsePaddlePriceEntries: %s: version must be a positive integer, got %q", id, parts[1])
		}
		interval := strings.ToLower(strings.TrimSpace(parts[2]))
		if interval != "month" && interval != "year" {
			return nil, fmt.Errorf("cloudserver/store.ParsePaddlePriceEntries: %s: interval must be month or year, got %q", id, parts[2])
		}
		display := ""
		if len(parts) == 4 {
			display = strings.TrimSpace(parts[3])
		}
		if _, dup := m[id]; dup {
			return nil, fmt.Errorf("cloudserver/store.ParsePaddlePriceEntries: duplicate price id %s", id)
		}
		m[id] = PaddlePlan{Name: planName, Version: version, Interval: interval, Display: display}
	}
	return m, nil
}
