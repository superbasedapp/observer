package store

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/orgdeletion"
)

// deletion.go brings account deletion to substantive COMPLETION (divergence
// remediation plan §3 W6d; closes E6). The prior skeleton fenced the account,
// tombstoned result text, revoked credentials and deleted a few tables but left
// the request 'processing' forever with most tenant tables still populated.
//
// W6d makes deletion a complete, FK-safe purge-or-pseudonymize in ONE
// transaction, flips the request to 'done', and — via an append-only journal
// OUTSIDE the Postgres restore domain (see SuppressFromJournal) — makes the
// deletion survivable across a point-in-time restore.
//
// DESIGN NOTE — FK-forced matrix refinement (surfaced by ground-truthing the FK
// graph, 2026-09-02; flagged for the grouped Sol review):
// the plan's W6d matrix classified analysis_results/result_revisions as
// "tombstone at deletion, PURGE 30 days later". But the enrichment cluster is
// FK-connected: result_revisions -> analysis_results -> analysis_jobs ->
// {evidence_objects, usage_reservations}; evidence_objects -> cloud_sessions ->
// cloud_projects. Tombstone-keeping analysis_results therefore PINS the whole
// cluster (analysis_jobs, evidence_objects, usage_reservations, cloud_sessions,
// cloud_projects) — none of them can be purged while a retained result row
// references them — so a partial "purge some, keep some" at deletion is not
// FK-implementable. The chosen resolution PURGES the entire enrichment cluster
// immediately at deletion, children-before-parents, in one transaction. This is
// strictly MORE privacy-protective than the tombstone-then-30d design (it
// removes the data sooner), it needs no fragile time-coupled sweep, and it loses
// no audit basis: the retained tables that carry a real legal/billing/consent
// basis (consent_receipts, consent_events, portal_consent_events,
// analysis_usage_ledger, security_audit_events, structural_grants,
// deletion_requests) are untouched by the purge. The 30d tombstone was "built
// reality + a hygiene TTL" (rev-4.1 F7), not a retention requirement, so
// subsuming it into an immediate purge is a faithful refinement. The plan matrix
// is updated to record this; the grouped Sol review ratifies it before deploy.

// DeletionRequest is the recorded request plus a summary of the actions taken.
type DeletionRequest struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// Legacy summary counts kept on the API response shape.
	JobsCanceled   int `json:"jobs_canceled"`
	DevicesRevoked int `json:"devices_revoked"`
	TokensRevoked  int `json:"tokens_revoked"`
	// PurgedRows is the total tenant rows purged across the enrichment cluster +
	// credential + lifecycle tables (content-free; a count, never any text).
	PurgedRows int `json:"purged_rows"`
	// SubscriptionsCanceled is how many subscriptions Paddle could still bill
	// the deletion confirmed canceled before it purged them (ORGDEL-7).
	SubscriptionsCanceled int `json:"subscriptions_canceled"`
}

// deletionAccountTombstoneTTL is how long the pseudonymized account ROW is kept
// after 'done' before a later retention pass purges it outright (abuse/forensics
// basis, same clock as security_audit_events). The enrichment data is already
// gone at 'done'; this governs only the opaque tombstone row + retained audit.
const deletionAccountTombstoneTTL = 24 * 30 * 24 * time.Hour // ~24 months

// ErrDeletionPaysForLiveOrg is the sentinel a refused account deletion wraps
// when the account pays for an org that is still live (C2.front-door-5 A,
// wave 15; docs/security.md PORTALORG-9). The error is a
// *PaysForLiveOrgError naming the orgs.
var ErrDeletionPaysForLiveOrg = errors.New("cloudserver/store: the account pays for a live org")

// PaidLiveOrg is one org whose subscription a deleting account pays for.
// Slug and DisplayName are empty when the org is not visible to the account
// any more (it still counts: orgdeletion.DecideBilling refuses it).
type PaidLiveOrg struct {
	OrgID       string
	Slug        string
	DisplayName string
}

// PaysForLiveOrgError is a refused account deletion: the account pays for
// these live orgs.
type PaysForLiveOrgError struct {
	Orgs []PaidLiveOrg
}

func (e *PaysForLiveOrgError) Error() string {
	return fmt.Sprintf("cloudserver/store: the account pays for %d live org(s); end or move that billing before deleting the account", len(e.Orgs))
}

// Unwrap makes errors.Is(err, ErrDeletionPaysForLiveOrg) true.
func (e *PaysForLiveOrgError) Unwrap() error { return ErrDeletionPaysForLiveOrg }

// accountSubscriptionsSQL reads every subscription row the account pays for
// (the rows the deletion's purge deletes), with what the billing rule
// (orgdeletion.DecideBilling) reads about each one's org. An org the account
// can no longer see (no membership, so RLS hides the row) reads as not seen:
// billing that cannot be shown is still billing (PORTALORG-9). The personal
// org is the one the account created (personalOrgTx's rule).
const accountSubscriptionsSQL = `SELECT ps.paddle_subscription_id, ps.status, coalesce(ps.org_id::text, ''),
	        o.org_id IS NOT NULL, coalesce(o.kind = 'personal' AND o.created_by = $1::uuid, false),
	        coalesce(o.status, ''), coalesce(o.slug, ''), coalesce(o.display_name, '')
	   FROM paddle_subscriptions ps
	   LEFT JOIN orgs o ON o.org_id = ps.org_id
	  WHERE ps.account_id = $1::uuid
	  ORDER BY ps.paddle_subscription_id`

// accountBillingTx reads the account's subscriptions and sorts them by the
// account deletion's billing rule (ORGDEL-7; orgdeletion.PlanAccountBilling),
// inside the caller's account transaction. Every billing decision of an
// account deletion (the console's precheck, the cancellation pass and the
// deletion transaction's re-check) goes through it.
func accountBillingTx(ctx context.Context, tx pgx.Tx, accountID string) (orgdeletion.AccountBilling, error) {
	rows, err := tx.Query(ctx, accountSubscriptionsSQL, accountID)
	if err != nil {
		return orgdeletion.AccountBilling{}, fmt.Errorf("account subscriptions: %w", err)
	}
	defer rows.Close()
	var subs []orgdeletion.AccountSubscription
	for rows.Next() {
		var a orgdeletion.AccountSubscription
		if err := rows.Scan(&a.ID, &a.Status, &a.OrgID, &a.OrgSeen, &a.PersonalOrg, &a.OrgStatus, &a.Slug, &a.DisplayName); err != nil {
			return orgdeletion.AccountBilling{}, fmt.Errorf("account subscriptions: %w", err)
		}
		subs = append(subs, a)
	}
	if err := rows.Err(); err != nil {
		return orgdeletion.AccountBilling{}, fmt.Errorf("account subscriptions: %w", err)
	}
	return orgdeletion.PlanAccountBilling(subs), nil
}

// paidLiveOrgs names the orgs of the subscriptions that refuse the deletion,
// one per org, in org id order.
func paidLiveOrgs(refuse []orgdeletion.AccountSubscription) []PaidLiveOrg {
	var out []PaidLiveOrg
	for _, a := range refuse {
		if !slices.ContainsFunc(out, func(o PaidLiveOrg) bool { return o.OrgID == a.OrgID }) {
			out = append(out, PaidLiveOrg{OrgID: a.OrgID, Slug: a.Slug, DisplayName: a.DisplayName})
		}
	}
	slices.SortFunc(out, func(a, b PaidLiveOrg) int { return cmp.Compare(a.OrgID, b.OrgID) })
	return out
}

// paidLiveOrgsTx returns the live orgs the account pays for (the refuse fate)
// inside the caller's account transaction.
func paidLiveOrgsTx(ctx context.Context, tx pgx.Tx, accountID string) ([]PaidLiveOrg, error) {
	b, err := accountBillingTx(ctx, tx, accountID)
	if err != nil {
		return nil, err
	}
	return paidLiveOrgs(b.Refuse), nil
}

// refuseIfPaysForLiveOrg returns a *PaysForLiveOrgError when b refuses the
// deletion.
func refuseIfPaysForLiveOrg(b orgdeletion.AccountBilling) error {
	if len(b.Refuse) > 0 {
		return &PaysForLiveOrgError{Orgs: paidLiveOrgs(b.Refuse)}
	}
	return nil
}

// lockAccountBillingTx takes the Paddle webhook's per-account advisory lock
// (paddle.go, F4: every billing apply for the account holds it), taken first
// as the webhook takes it first, so the two never wait on each other in a
// cycle.
func lockAccountBillingTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, accountID); err != nil {
		return fmt.Errorf("account billing lock: %w", err)
	}
	return nil
}

// PaidLiveOrgs returns the live orgs accountID pays for (empty: the account
// may be deleted as far as org billing goes). The console asks before it
// sends the user through a step-up re-authentication that the deletion
// would then refuse; the deletion itself re-checks inside its transaction.
func (s *Store) PaidLiveOrgs(ctx context.Context, accountID string) ([]PaidLiveOrg, error) {
	b, err := s.AccountDeletionBilling(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.PaidLiveOrgs: %w", err)
	}
	return b.PaysFor, nil
}

// DeletionBilling is what deleting an account does with its billing now
// (ORGDEL-7), for the console's precheck.
type DeletionBilling struct {
	// Cancel is how many subscriptions Paddle may still bill the deletion
	// cancels at Paddle before it deletes anything (the account's own plans,
	// its personal org's, those of orgs already on their way out, and
	// refunded or charged-back ones, which Paddle still renews).
	Cancel int
	// CancelAvailable reports that this deployment can cancel them (a
	// Paddle client is wired, SetDeletionBilling). With Cancel > 0 and no
	// client the deletion is refused (BillingCancelUnavailable).
	CancelAvailable bool
	// PaysFor are the live orgs that refuse the deletion (PORTALORG-9).
	PaysFor []PaidLiveOrg
}

// AccountDeletionBilling reads what deleting accountID would do with its
// billing now. The deletion decides again when it runs.
func (s *Store) AccountDeletionBilling(ctx context.Context, accountID string) (DeletionBilling, error) {
	var b orgdeletion.AccountBilling
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		b, e = accountBillingTx(ctx, tx, accountID)
		return e
	})
	if err != nil {
		return DeletionBilling{}, fmt.Errorf("cloudserver/store.AccountDeletionBilling: %w", err)
	}
	return DeletionBilling{Cancel: len(b.Cancel), CancelAvailable: s.deletionBilling != nil, PaysFor: paidLiveOrgs(b.Refuse)}, nil
}

// SetDeletionBilling wires the billing seam an account deletion cancels the
// account's live Paddle subscriptions through (ORGDEL-7): the same
// orgdeletion.Billing the worker's org deletion uses (cmd/observer-cloud's
// deletionBilling over the Paddle API client). nil leaves it unwired: a
// deletion that must cancel a live subscription is then refused with
// BillingCancelUnavailable, never run without the cancellation.
func (s *Store) SetDeletionBilling(b orgdeletion.Billing) {
	s.deletionBilling = b
}

// ErrDeletionBillingCancel is wrapped by an account deletion refused because
// a live subscription it would purge was not confirmed canceled at Paddle
// (ORGDEL-7). The error is a *BillingCancelError; nothing was deleted.
var ErrDeletionBillingCancel = errors.New("cloudserver/store: a live subscription could not be canceled at Paddle")

// BillingCancelReason says why an account deletion's cancellation failed.
type BillingCancelReason string

// The reasons.
const (
	// BillingCancelUnavailable: this deployment has no Paddle client to
	// cancel with. The customer cancels from the billing page, then retries.
	BillingCancelUnavailable BillingCancelReason = "unavailable"
	// BillingCancelRefused: Paddle refused the cancellation for a reason a
	// retry cannot fix (orgdeletion.ErrBillingRefused).
	BillingCancelRefused BillingCancelReason = "refused"
	// BillingCancelFailed: Paddle could not be reached, rate limited or
	// failed; a retry may succeed.
	BillingCancelFailed BillingCancelReason = "failed"
	// BillingCancelChanged: a live subscription appeared after the
	// cancellations ran (a checkout finished meanwhile); a retry cancels it.
	BillingCancelChanged BillingCancelReason = "changed"
)

// BillingCancelError is a refused account deletion: the live subscription
// SubscriptionID was not confirmed canceled at Paddle, so nothing was
// deleted, no journal record was written and a step-up was not consumed.
type BillingCancelError struct {
	Reason         BillingCancelReason
	SubscriptionID string
	// Class is the failure's error class (orgdeletion.ClassOf), "" when the
	// seam was never called.
	Class string
	Err   error
}

func (e *BillingCancelError) Error() string {
	msg := fmt.Sprintf("cloudserver/store: account deletion refused: subscription %s not canceled at Paddle (%s", e.SubscriptionID, e.Reason)
	if e.Class != "" {
		msg += ", " + e.Class
	}
	msg += ")"
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap makes errors.Is(err, ErrDeletionBillingCancel) true and keeps the
// seam's error reachable.
func (e *BillingCancelError) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrDeletionBillingCancel}
	}
	return []error{ErrDeletionBillingCancel, e.Err}
}

// billingCancelReasons maps the billing seam's errors to a reason, top-down;
// anything else is a failure a retry may fix.
var billingCancelReasons = []struct {
	is     error
	reason BillingCancelReason
}{
	{orgdeletion.ErrSeamUnwired, BillingCancelUnavailable},
	{orgdeletion.ErrBillingRefused, BillingCancelRefused},
}

// newBillingCancelError classes the billing seam's error for subscription id.
func newBillingCancelError(id string, err error) *BillingCancelError {
	out := &BillingCancelError{Reason: BillingCancelFailed, SubscriptionID: id, Class: orgdeletion.ClassOf(err), Err: err}
	for _, r := range billingCancelReasons {
		if errors.Is(err, r.is) {
			out.Reason = r.reason
			break
		}
	}
	return out
}

// The security audit events of an account deletion's cancellations (system
// table security_audit_events, retained with the deletion's other audit; a
// subscription id, a scope and an error class, never content).
const (
	auditDeletionBillingCanceled     = "deletion_billing_canceled"
	auditDeletionBillingCancelFailed = "deletion_billing_cancel_failed"
)

// billingScope names what a canceled subscription paid for, for the audit.
func billingScope(a orgdeletion.AccountSubscription) string {
	switch {
	case a.OrgID == "":
		return "account"
	case a.PersonalOrg:
		return "personal_org"
	}
	return "org"
}

// auditDeletionBilling records one cancellation outcome in its own
// transaction, so the record of a Paddle action outlives a deletion
// transaction that later rolls back.
func (s *Store) auditDeletionBilling(ctx context.Context, accountID, event string, a orgdeletion.AccountSubscription, class string) error {
	detail := map[string]string{"subscription_id": a.ID, "scope": billingScope(a)}
	if a.OrgID != "" {
		detail["org_id"] = a.OrgID
	}
	if class != "" {
		detail["class"] = class
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("audit detail: %w", err)
	}
	return s.RecordAudit(ctx, accountID, event, string(b))
}

// cancelDeletionBilling is the account deletion's first half (ORGDEL-7): it
// decides, in a short account transaction, what the deletion would refuse
// for (a live org the account pays for, the account's orgs, an unusable
// step-up) and which subscriptions Paddle may still bill it must cancel
// first (orgdeletion.Subscription.MayBill), then cancels each through the
// billing seam OUTSIDE any transaction (no lock is held
// across a Paddle call) and audits each outcome. It returns the
// subscriptions confirmed canceled; the deletion transaction re-reads the
// billing and refuses when a subscription it must cancel is not among them.
//
// The seam is idempotent (cmd/observer-cloud's deletionBilling reads the
// subscription first: already canceled is success), so a retried deletion
// repeats the same cancellations harmlessly. The step-up is only checked
// here, not consumed: the deletion transaction consumes it, so a refused
// deletion leaves it usable for the retry.
func (s *Store) cancelDeletionBilling(ctx context.Context, accountID string, su *stepUp, now time.Time) (map[string]bool, error) {
	var b orgdeletion.AccountBilling
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if e := lockAccountBillingTx(ctx, tx, accountID); e != nil {
			return e
		}
		var e error
		if b, e = accountBillingTx(ctx, tx, accountID); e != nil {
			return e
		}
		if e := refuseIfPaysForLiveOrg(b); e != nil {
			return e
		}
		if e := refuseIfOrgsBlockTx(ctx, tx, accountID); e != nil {
			return e
		}
		if su != nil && len(b.Cancel) > 0 {
			// No billing is canceled on a request whose re-authentication
			// would be refused.
			return checkStepUpTx(ctx, tx, accountID, su.sessionID, StepUpActionDeletion, su.authzID, now)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	confirmed := map[string]bool{}
	if len(b.Cancel) == 0 {
		return confirmed, nil
	}
	if s.deletionBilling == nil {
		return nil, &BillingCancelError{Reason: BillingCancelUnavailable, SubscriptionID: b.Cancel[0].ID}
	}
	for _, a := range b.Cancel {
		err := s.deletionBilling.CancelOrgSubscription(ctx, orgdeletion.CancelRequest{
			OrgID: a.OrgID, SubscriptionID: a.ID, IdempotencyKey: orgdeletion.AccountCancelKey(accountID, a.ID),
		})
		if err != nil {
			ce := newBillingCancelError(a.ID, err)
			if aerr := s.auditDeletionBilling(ctx, accountID, auditDeletionBillingCancelFailed, a, ce.Class); aerr != nil {
				ce.Err = errors.Join(ce.Err, aerr)
			}
			return nil, ce
		}
		// Fail closed on the audit like on the journal: a cancellation
		// that cannot be recorded does not let the deletion proceed (the
		// retry finds the subscription canceled and records it then).
		if err := s.auditDeletionBilling(ctx, accountID, auditDeletionBillingCanceled, a, ""); err != nil {
			return nil, fmt.Errorf("audit cancellation: %w", err)
		}
		confirmed[a.ID] = true
	}
	return confirmed, nil
}

// refuseUnconfirmedCancels returns a *BillingCancelError when b has a live
// subscription to cancel that the cancellation pass did not confirm.
func refuseUnconfirmedCancels(b orgdeletion.AccountBilling, confirmed map[string]bool) error {
	for _, a := range b.Cancel {
		if !confirmed[a.ID] {
			return &BillingCancelError{Reason: BillingCancelChanged, SubscriptionID: a.ID}
		}
	}
	return nil
}

// CreateDeletionRequest records and executes an account deletion (dev-auth
// body-reauth path). It fails closed if no deletion journal is configured — a
// deletion must never run without a durable, restore-surviving record.
func (s *Store) CreateDeletionRequest(ctx context.Context, accountID string, now time.Time) (DeletionRequest, error) {
	return s.runDeletion(ctx, accountID, now, nil)
}

// CreateDeletionRequestWithStepUp is the WorkOS-mode entry point: it consumes a
// one-use step-up authorization and runs the SAME deletion in the SAME
// transaction (atomic — a failed deletion rolls the authorization back
// unconsumed, and a consumed authorization can never drive a second deletion).
func (s *Store) CreateDeletionRequestWithStepUp(ctx context.Context, accountID, sessionID, authzID string, now time.Time) (DeletionRequest, error) {
	return s.runDeletion(ctx, accountID, now, &stepUp{sessionID: sessionID, authzID: authzID})
}

type stepUp struct {
	sessionID string
	authzID   string
}

// runDeletion is the shared driver. It writes the durable "accepted" journal
// record INSIDE the transaction, AFTER authorization is established (a step-up is
// consumed) but BEFORE the destructive purge — so:
//   - a REFUSED step-up (invalid binding) never reaches the journal write, so a
//     later restore can never re-delete an account whose deletion was refused;
//   - a persisted "accepted" record only ever corresponds to an AUTHORIZED
//     deletion, so re-applying it on restore is always correct, even if this
//     transaction later rolled back (the user authorized the deletion and would
//     have retried);
//   - if the journal write itself fails, the transaction rolls back — no
//     deletion commits without a durable, restore-surviving record (fail-closed).
//
// The informational "done" record is written after commit (best-effort;
// suppression rests on "accepted").
//
// ORGDEL-7: before that transaction, cancelDeletionBilling cancels at Paddle
// every subscription Paddle may still bill that the purge would delete (a
// refunded or charged-back one too: Paddle still renews it), and the
// transaction re-reads the billing under the webhook's lock and refuses when
// one of them was not confirmed canceled. So a committed deletion never
// purged a subscription Paddle still bills, and a failed cancellation deletes nothing
// (*BillingCancelError; the customer retries). The only state a failure can
// leave is "subscription canceled, account not deleted", which bills nothing
// and the retry completes.
func (s *Store) runDeletion(ctx context.Context, accountID string, now time.Time, su *stepUp) (DeletionRequest, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if s.deletionJournal == nil {
		return DeletionRequest{}, errors.New("cloudserver/store: deletion journal not configured (fail-closed)")
	}

	confirmed, err := s.cancelDeletionBilling(ctx, accountID, su, now)
	if err != nil {
		return DeletionRequest{}, deletionRefusal(err)
	}

	var req DeletionRequest
	err = s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		// C2.front-door-5 A: an account that pays for a live org is not
		// deleted (its purge would delete the subscription row the org's
		// billing runs on, PORTALORG-9). Checked before the step-up is
		// consumed and before the journal's "accepted" record, so a refused
		// deletion is never re-applied by a restore and the step-up stays
		// usable. The Paddle webhook's per-account lock serialises this with
		// a concurrent binding of a new subscription: whichever commits
		// second sees the other (the webhook refuses a closed account).
		if e := lockAccountBillingTx(ctx, tx, accountID); e != nil {
			return e
		}
		b, e := accountBillingTx(ctx, tx, accountID)
		if e != nil {
			return e
		}
		if e := refuseIfPaysForLiveOrg(b); e != nil {
			return e
		}
		// ORGDEL-7: every subscription Paddle may still bill that the purge
		// below deletes was confirmed canceled at Paddle by
		// cancelDeletionBilling; one that appeared since (a checkout that
		// finished meanwhile) refuses.
		if e := refuseUnconfirmedCancels(b, confirmed); e != nil {
			return e
		}
		// M6.9: the account's orgs. A team org it is the billing owner or the
		// only owner of blocks the deletion until ownership or billing moves
		// or the team is deleted (orgdeletion.Precheck); checked with the
		// billing rule, before the step-up is consumed and before the journal.
		if e := refuseIfOrgsBlockTx(ctx, tx, accountID); e != nil {
			return e
		}
		if su != nil {
			if e := consumeStepUpTx(ctx, tx, accountID, su.sessionID, StepUpActionDeletion, su.authzID, now); e != nil {
				return e // refused step-up: rolls back, no journal write
			}
		}
		// Authorized. Durable "accepted" record before the destructive work.
		if e := s.deletionJournal.Append(ctx, deletionjournal.Record{
			Event:     deletionjournal.EventAccepted,
			AccountID: accountID,
			At:        now,
		}); e != nil {
			return fmt.Errorf("journal accepted: %w", e)
		}
		req, e = deletionCompleteTx(ctx, tx, accountID, now, len(confirmed))
		return e
	})
	if err != nil {
		return DeletionRequest{}, deletionRefusal(err)
	}

	// Informational done record; suppression already rests on the accepted one.
	if e := s.deletionJournal.Append(ctx, deletionjournal.Record{
		Event:     deletionjournal.EventDone,
		AccountID: accountID,
		RequestID: req.ID,
		At:        now,
	}); e != nil {
		return req, fmt.Errorf("cloudserver/store: deletion done but journal done-record failed: %w", e)
	}
	return req, nil
}

// deletionRefusal returns a refused deletion's typed error as is (the api
// answers each), and wraps anything else.
func deletionRefusal(err error) error {
	if errors.Is(err, ErrStepUpInvalid) {
		return ErrStepUpInvalid
	}
	var paid *PaysForLiveOrgError
	if errors.As(err, &paid) {
		return paid
	}
	var blocked *AccountDeletionBlockedError
	if errors.As(err, &blocked) {
		return blocked
	}
	var cancel *BillingCancelError
	if errors.As(err, &cancel) {
		return cancel
	}
	return fmt.Errorf("cloudserver/store.CreateDeletionRequest: %w", err)
}

// deletionCompleteTx is the complete, FK-safe deletion inside the caller's tenant
// transaction. Every DELETE is account-scoped and RLS-bounded (SET LOCAL ROLE +
// tenant GUC), so it can only ever remove THIS account's rows. Order is
// children-before-parents so every NO-ACTION foreign key holds (see the design
// note above for the FK graph).
func deletionCompleteTx(ctx context.Context, tx pgx.Tx, accountID string, now time.Time, subscriptionsCanceled int) (DeletionRequest, error) {
	req := DeletionRequest{SubscriptionsCanceled: subscriptionsCanceled}

	// Fence + record (state starts 'processing'; flipped to 'done' at the end).
	if _, e := tx.Exec(ctx,
		`UPDATE accounts SET status = 'closed', updated_at = now()
		  WHERE account_id = $1::uuid AND status NOT IN ('closed','deleted')`,
		accountID); e != nil {
		return DeletionRequest{}, fmt.Errorf("fence account: %w", e)
	}
	if e := tx.QueryRow(ctx,
		`INSERT INTO deletion_requests (account_id, scope, state)
		 VALUES ($1::uuid, 'account', 'processing') RETURNING id::text, state`,
		accountID).Scan(&req.ID, &req.State); e != nil {
		return DeletionRequest{}, fmt.Errorf("record request: %w", e)
	}

	// M6.9: the org-side half (personal org, memberships, subject
	// deactivation, the WorkOS user) is a follow-up the worker drives; it is
	// written here, before identity_links is purged below, so it holds the
	// subjects, and so a journal replay after a restore writes it again.
	if e := recordAccountFollowupTx(ctx, tx, accountID, req.ID, now); e != nil {
		return DeletionRequest{}, e
	}

	// Cancel non-terminal jobs first: releases reservations and deletes their
	// in-flight evidence. Must precede the analysis_jobs purge below.
	canceled, e := cancelNonTerminalJobsTx(ctx, tx, accountID, now)
	if e != nil {
		return DeletionRequest{}, fmt.Errorf("cancel jobs: %w", e)
	}
	req.JobsCanceled = canceled

	// Count devices + tokens before purging them (the summary counts).
	if e := tx.QueryRow(ctx,
		`SELECT count(*) FROM device_registrations WHERE account_id = $1::uuid`,
		accountID).Scan(&req.DevicesRevoked); e != nil {
		return DeletionRequest{}, fmt.Errorf("count devices: %w", e)
	}
	if e := tx.QueryRow(ctx,
		`SELECT count(*) FROM api_tokens WHERE account_id = $1::uuid`,
		accountID).Scan(&req.TokensRevoked); e != nil {
		return DeletionRequest{}, fmt.Errorf("count tokens: %w", e)
	}

	// PURGE order (children before parents). Each entry returns its row count so
	// the total is honest and the FK order is explicit and testable.
	purges := []struct {
		what string
		sql  string
	}{
		// Export artifacts (an assembled export is itself account data — plan §3
		// W6d "Export/deletion ordering": the deletion pass deletes any export
		// already assembled before the request). Independent of the FK cluster
		// (references only accounts), so order-free.
		{"export_artifacts", `DELETE FROM export_artifacts WHERE account_id = $1::uuid`},
		// Community contributions (W5). Tenant-owned; references only accounts +
		// the community_metrics registry (both NO ACTION), so it is independent of
		// the FK cluster and order-free. Deletion removes every contribution the
		// account made — the plan's opt-out/deletion linkage (§3 W5, R3 24h
		// removal); the published band snapshots recompute without them.
		{"leaderboard_contributions", `DELETE FROM leaderboard_contributions WHERE account_id = $1::uuid`},
		// Enrichment cluster, children first.
		{"result_revisions", `DELETE FROM result_revisions WHERE account_id = $1::uuid`},
		{"analysis_results", `DELETE FROM analysis_results WHERE account_id = $1::uuid`},
		{"analysis_jobs", `DELETE FROM analysis_jobs WHERE account_id = $1::uuid`},
		{"evidence_objects", `DELETE FROM evidence_objects WHERE account_id = $1::uuid`},
		{"evidence_blobs", `DELETE FROM evidence_blobs WHERE account_id = $1::uuid`},
		{"usage_reservations", `DELETE FROM usage_reservations WHERE account_id = $1::uuid`},
		{"usage_cycles", `DELETE FROM usage_cycles WHERE account_id = $1::uuid`},
		// R-AI1 (0078): the per-account token windows. The per-session token
		// ledger is a column of cloud_sessions and goes with it.
		{"usage_token_windows", `DELETE FROM usage_token_windows WHERE account_id = $1::uuid`},
		{"cloud_sessions", `DELETE FROM cloud_sessions WHERE account_id = $1::uuid`},
		{"cloud_projects", `DELETE FROM cloud_projects WHERE account_id = $1::uuid`},
		// Structural rail (structural_snapshots references device_registrations,
		// so it must precede the device purge below).
		{"structural_account_days", `DELETE FROM structural_account_days WHERE account_id = $1::uuid`},
		{"structural_snapshots", `DELETE FROM structural_snapshots WHERE account_id = $1::uuid`},
		// Credentials (api_tokens references device_registrations).
		{"api_tokens", `DELETE FROM api_tokens WHERE account_id = $1::uuid`},
		{"device_registrations", `DELETE FROM device_registrations WHERE account_id = $1::uuid`},
		{"browser_sessions", `DELETE FROM browser_sessions WHERE account_id = $1::uuid`},
		{"pop_replay", `DELETE FROM pop_replay WHERE account_id = $1::uuid`},
		{"step_up_authorizations", `DELETE FROM step_up_authorizations WHERE account_id = $1::uuid`},
		// C2 (0131): the portal passkeys, their ceremonies and the recovery
		// code hashes. Account-keyed, order-free.
		{"portal_passkey_ceremonies", `DELETE FROM portal_passkey_ceremonies WHERE account_id = $1::uuid`},
		{"portal_recovery_codes", `DELETE FROM portal_recovery_codes WHERE account_id = $1::uuid`},
		{"portal_passkeys", `DELETE FROM portal_passkeys WHERE account_id = $1::uuid`},
		// FR-6 / FR-24 (0145): the single-use new-device approvals and the
		// recovery-code failure counter. Account-keyed, order-free; purged now
		// rather than at the 24-month sweep's ON DELETE CASCADE.
		{"device_approvals", `DELETE FROM device_approvals WHERE account_id = $1::uuid`},
		{"portal_recovery_failures", `DELETE FROM portal_recovery_failures WHERE account_id = $1::uuid`},
		// Getting started v2 (0150, CONNECT-1): the account's resolved connect
		// requests (machine names, masked networks). The request is a system
		// table keyed by account once resolved; its poll proofs cascade.
		{"connect_requests", `DELETE FROM connect_requests WHERE account_id = $1::uuid`},
		// Plans / entitlements / portal preferences / billing linkage.
		// paddle_subscriptions references only accounts (NO ACTION), independent of
		// the FK cluster. ORGDEL-7: every live row purged here was confirmed
		// canceled at Paddle before this transaction (cancelDeletionBilling) and
		// re-checked under the billing lock (refuseUnconfirmedCancels).
		{"paddle_subscriptions", `DELETE FROM paddle_subscriptions WHERE account_id = $1::uuid`},
		// checkout_intents (migration 0030) is the account's ephemeral pre-checkout
		// state: a server-minted, single-use, TTL'd nonce hash bound to THIS
		// account. Account-scoped tenant data, so it is purged here explicitly —
		// its ON DELETE CASCADE only fires when the 24-month sweep finally drops
		// the pseudonymized account row, which is far too late for a deletion.
		// References only accounts (SYSTEM table, no RLS), so it is order-free.
		{"checkout_intents", `DELETE FROM checkout_intents WHERE account_id = $1::uuid`},
		{"entitlements", `DELETE FROM entitlements WHERE account_id = $1::uuid`},
		{"account_plans", `DELETE FROM account_plans WHERE account_id = $1::uuid`},
		{"portal_consent_choices", `DELETE FROM portal_consent_choices WHERE account_id = $1::uuid`},
		// The display-only profile row (migration 0033: the email + name the
		// portal top bar renders). Purged explicitly here rather than left to its
		// ON DELETE CASCADE, which would only fire when the 24-month sweep drops
		// the pseudonymized account row — 24 months too late for the one row that
		// holds a plain-text email address.
		{"account_profiles", `DELETE FROM account_profiles WHERE account_id = $1::uuid`},
		// The provider-asserted address the OIDC issuer signs (0074, A4): the
		// same reasoning as account_profiles, a plain-text address purged now
		// rather than at the 24-month sweep.
		{"account_verified_emails", `DELETE FROM account_verified_emails WHERE account_id = $1::uuid`},
		// Identity last of the purges — the subject store, gone with the profile
		// row above, leaves nothing that names the human behind the account.
		{"identity_links", `DELETE FROM identity_links WHERE account_id = $1::uuid`},
	}
	for _, p := range purges {
		ct, e := tx.Exec(ctx, p.sql, accountID)
		if e != nil {
			return DeletionRequest{}, fmt.Errorf("purge %s: %w", p.what, e)
		}
		req.PurgedRows += int(ct.RowsAffected())
	}

	// RETAIN (audit / legal / billing basis) — untouched except structural_grants,
	// which is REVOKED (the registration row survives as the consent-registration
	// fact, like consent_receipts, but authorizes no further upload):
	//   consent_receipts, consent_events, portal_consent_events,
	//   analysis_usage_ledger, security_audit_events, deletion_requests.
	// org_usage_days is org-scoped, not the account's, so an account deletion
	// never reaches it: it is kept 10 years from its day, after the org is
	// deleted too, with its member ids minimised at 13 months (W16-D9,
	// orgusage.go; the deletion matrix in docs/cloud-intelligence.md).
	if _, e := tx.Exec(ctx,
		`UPDATE structural_grants SET revoked_at = $2, updated_at = $2
		  WHERE account_id = $1::uuid AND revoked_at IS NULL`,
		accountID, now); e != nil {
		return DeletionRequest{}, fmt.Errorf("revoke structural grants: %w", e)
	}
	// community_grants is RETAINED-then-revoked on the same basis (the consent-
	// registration fact survives, authorizes no further contribution); the
	// 24-month retention sweep ages the revoked row out (migration 0026).
	if _, e := tx.Exec(ctx,
		`UPDATE community_grants SET revoked_at = $2, updated_at = $2
		  WHERE account_id = $1::uuid AND revoked_at IS NULL`,
		accountID, now); e != nil {
		return DeletionRequest{}, fmt.Errorf("revoke community grants: %w", e)
	}

	// Pseudonymize the account: keep the opaque UUID row as an irreversible
	// tombstone. status='deleted', deletion clock recorded, consent_generation
	// nulled to the reserved non-authorizing state (belt-and-suspenders behind
	// the status gate that already refuses non-'active' auth).
	if _, e := tx.Exec(ctx,
		`UPDATE accounts
		    SET status = 'deleted', consent_generation = NULL,
		        deleted_at = $2, purge_after = $3, updated_at = $2
		  WHERE account_id = $1::uuid`,
		accountID, now, now.Add(deletionAccountTombstoneTTL)); e != nil {
		return DeletionRequest{}, fmt.Errorf("pseudonymize account: %w", e)
	}

	// Flip the request to 'done' — reached only after every purge above committed
	// in this same transaction (all-or-nothing).
	if _, e := tx.Exec(ctx,
		`UPDATE deletion_requests SET state = 'done', completed_at = $2, detail = $3::jsonb
		  WHERE id = $1::uuid`,
		req.ID, now, fmt.Sprintf(`{"purged_rows":%d,"jobs_canceled":%d,"subscriptions_canceled":%d}`,
			req.PurgedRows, req.JobsCanceled, req.SubscriptionsCanceled)); e != nil {
		return DeletionRequest{}, fmt.Errorf("finalize request: %w", e)
	}
	req.State = "done"
	return req, nil
}

// SuppressFromJournal re-applies deletion to every account named in the
// deletion journal that is NOT currently tombstoned — the restore-runbook step
// that suppresses accounts a point-in-time restore resurrected. It is idempotent
// (an already-'deleted' account is skipped) and must run BEFORE the restored
// service reopens. Returns the number of accounts re-suppressed.
func (s *Store) SuppressFromJournal(ctx context.Context, now time.Time) (int, error) {
	if s.deletionJournal == nil {
		return 0, errors.New("cloudserver/store.SuppressFromJournal: no journal configured")
	}
	records, err := s.deletionJournal.Records(ctx)
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.SuppressFromJournal: %w", err)
	}
	suppressed := 0
	for _, accountID := range deletionjournal.AcceptedAccounts(records) {
		// Read current status under the tenant context.
		var status string
		var exists bool
		err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
			e := tx.QueryRow(ctx,
				`SELECT status FROM accounts WHERE account_id = $1::uuid`, accountID).Scan(&status)
			if errors.Is(e, pgx.ErrNoRows) {
				return nil // account row gone entirely — nothing to suppress
			}
			if e != nil {
				return e
			}
			exists = true
			return nil
		})
		if err != nil {
			return suppressed, fmt.Errorf("cloudserver/store.SuppressFromJournal: read %s: %w", accountID, err)
		}
		if !exists || status == "deleted" {
			continue // already gone or already tombstoned — idempotent skip
		}
		// Resurrected by the restore: re-run the complete deletion.
		// No Paddle call here: an "accepted" record is written only after
		// every subscription Paddle may still bill that the deletion purged
		// was confirmed canceled (runDeletion, ORGDEL-7), so a row the
		// restore brought back is one Paddle no longer bills.
		if err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := deletionCompleteTx(ctx, tx, accountID, now, 0)
			return e
		}); err != nil {
			return suppressed, fmt.Errorf("cloudserver/store.SuppressFromJournal: re-delete %s: %w", accountID, err)
		}
		suppressed++
	}
	return suppressed, nil
}
