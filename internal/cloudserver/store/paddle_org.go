package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marmutapp/superbased-observer/internal/entitlements"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// paddle_org.go is the ORG branch of the one Paddle subscription store (lead
// decision W14-D3; plan 07 M6.5; docs/security.md PORTALORG-3..6). There is
// no second subscription table: an org's paid plan is a paddle_subscriptions
// row whose org_id is set (cloud 0050), written by the same webhook handler
// (ProcessPaddleEvent) through the branch below, beside the unchanged account
// path.
//
//   - The row's account_id is the account that paid (the billing owner who
//     ran the checkout). It stays the RLS key of 0024, so every write runs
//     under WithAccount exactly as the account path does.
//   - The org a subscription pays for is decided ONCE, at binding, from the
//     server-minted checkout intent (checkout_intents.org_id, minted by
//     CreateOrgCheckoutIntent for the org's billing owner). Afterwards the
//     row's own org_id decides; Paddle's custom_data.org_id is only
//     cross-checked, never trusted.
//   - The org branch changes NO account plan (account_plans): an org's
//     entitlement is the signed document the worker issues from the row
//     (entitlementwork.SubscriptionPlans reads OrgSubscription). So cancel,
//     refund, chargeback and restore move only the row's status.
//   - One live subscription per org is the 0090 trigger's rule; the branch
//     takes the trigger's advisory key first and writes inside a savepoint,
//     so a second live subscription for one org (paid by ANOTHER account,
//     whose row RLS hides here) is refused as refused_second_live instead of
//     aborting the delivery into an endless Paddle redelivery.

// Org billing errors.
var (
	// ErrOrgBillingForbidden: the caller is not the org's billing owner.
	ErrOrgBillingForbidden = errors.New("cloudserver/store: only the org's billing owner may start a checkout")
	// ErrOrgNotBillable: the org cannot take a new subscription (wrong kind,
	// or on its way out).
	ErrOrgNotBillable = errors.New("cloudserver/store: org cannot take a subscription")
)

// orgKindEntitlements maps an org registry kind to the entitlements kind its
// plans carry. The worker keeps its own copy (entitlementwork.KindFor); the
// store cannot import that package (it imports this one).
var orgKindEntitlements = map[OrgKind]entitlements.Kind{
	OrgPersonal: entitlements.KindPersonal,
	OrgTeam:     entitlements.KindTeam,
}

// OrgEntitlementsKind returns the entitlements kind of an org registry kind.
func OrgEntitlementsKind(k OrgKind) (entitlements.Kind, bool) {
	v, ok := orgKindEntitlements[k]
	return v, ok
}

// catalogPlanKind returns the entitlements catalog kind of a mapped Paddle
// plan, and false when the catalog has no such (name, version): a legacy
// account plan version (plus_beta v1-v4) is migration history, not a catalog
// template, and is always an account plan.
func catalogPlanKind(p PaddlePlan) (entitlements.Kind, bool) {
	b, ok := entitlements.Plan(p.Name, p.Version)
	if !ok {
		return "", false
	}
	return b.Kind, true
}

// catalogOrgPlan reports whether p is an org plan: a catalog template of an
// org kind (personal, team, dedicated, self-hosted), never an account plan.
func catalogOrgPlan(p PaddlePlan) bool {
	k, ok := catalogPlanKind(p)
	return ok && k != entitlements.KindAccount
}

// PaddlePriceKind returns the entitlements kind of the plan a price maps to:
// entitlements.KindAccount for an account (personal-plane) plan, an org kind
// for an org plan, and false for an unknown price. The portal uses it to
// offer each checkout only the prices of its own scope.
func (s *Store) PaddlePriceKind(priceID string) (entitlements.Kind, bool) {
	p, ok := s.paddlePlanForPrice(priceID)
	if !ok {
		return "", false
	}
	if k, ok := catalogPlanKind(p); ok {
		return k, true
	}
	return entitlements.KindAccount, true
}

// orgBindingRefusal is the scope check of a NEW binding: the scope comes from
// the consumed checkout intent (intentOrg, "" for an account checkout), the
// price must be a plan of that scope, and an untrusted custom_data.org_id may
// only repeat the intent's. It returns the refusal note, or "" to bind.
func (s *Store) orgBindingRefusal(ev PaddleEvent, intentOrg string) string {
	plan, _ := s.paddlePlanForPrice(ev.PriceID)
	claimed := strings.TrimSpace(ev.OrgID)
	switch {
	case intentOrg == "" && claimed != "":
		return "custom_data names an org but the checkout was an account checkout"
	case intentOrg == "" && catalogOrgPlan(plan):
		return "an org plan price cannot bind to an account checkout"
	case intentOrg != "" && claimed != "" && !strings.EqualFold(claimed, intentOrg):
		return "custom_data org does not match the checkout's org"
	case intentOrg != "" && !catalogOrgPlan(plan):
		return "an account plan price cannot bind to an org checkout"
	}
	return ""
}

// boundSubscriptionOrgTx returns the org scope of an already-bound
// subscription ("" for an account subscription or when the row is not
// visible).
func boundSubscriptionOrgTx(ctx context.Context, tx pgx.Tx, account, subscriptionID string) (string, error) {
	var org *string
	err := tx.QueryRow(ctx,
		`SELECT org_id::text FROM paddle_subscriptions
		  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
		account, subscriptionID).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if org == nil {
		return "", nil
	}
	return *org, nil
}

// orgLiveLockTx takes the 0090 trigger's advisory key for an org, so the
// trigger's own lock on the write is a re-entry.
func orgLiveLockTx(ctx context.Context, tx pgx.Tx, orgID string) error {
	_, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('sbci_paddle_live:org:' || $1::uuid::text, 0))`, orgID)
	return err
}

// isOneLiveViolation reports whether err is the 0090 trigger's refusal.
func isOneLiveViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "paddle_subscriptions_one_live"
}

// inSavepointTx runs fn in a savepoint of tx. A one-live refusal rolls the
// savepoint back and reports refused=true, leaving tx usable; any other error
// is returned as is.
func inSavepointTx(ctx context.Context, tx pgx.Tx, fn func(pgx.Tx) error) (refused bool, err error) {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("savepoint: %w", err)
	}
	if err := fn(sp); err != nil {
		if rbErr := sp.Rollback(ctx); rbErr != nil {
			return false, fmt.Errorf("rollback to savepoint: %w (after %w)", rbErr, err)
		}
		if isOneLiveViolation(err) {
			return true, nil
		}
		return false, err
	}
	if err := sp.Commit(ctx); err != nil {
		return false, fmt.Errorf("release savepoint: %w", err)
	}
	return false, nil
}

// orgRefusedSecondLive is the intake for a second live subscription of an org.
func orgRefusedSecondLive() BillingIntake {
	return BillingIntake{
		Applied: false, Outcome: "refused_second_live",
		Note: "the org already holds a live subscription; this distinct subscription id was refused",
	}
}

// applyOrgResolvedAction is the org twin of applyResolvedAction: the same
// action kinds, applied to the row only.
func applyOrgResolvedAction(ctx context.Context, tx pgx.Tx, s *Store, ev PaddleEvent, act paddleAction, account, orgID string, periodEnd *time.Time, occurred, now time.Time) (BillingIntake, error) {
	switch act.kind {
	case "activate":
		return applyOrgPaddleActivate(ctx, tx, s, ev, account, orgID, periodEnd, occurred)
	case "cancel":
		return applyOrgPaddleCancel(ctx, tx, s, ev, account, orgID, periodEnd, occurred, now)
	case "revoke":
		return applyOrgPaddleSetStatus(ctx, tx, ev, account, orgID, revokeStatus(ev), &now, occurred)
	case "restore":
		return applyOrgPaddleSetStatus(ctx, tx, ev, account, orgID, "active", nil, occurred)
	case "status_only":
		return applyPaddleStatusOnly(ctx, tx, ev, account, occurred)
	default:
		return BillingIntake{Applied: false, Outcome: "ignored", Note: "no action"}, nil
	}
}

// revokeStatus is the terminal status of a revoke (full refund or
// chargeback), the account path's applyPaddleRevoke rule.
func revokeStatus(ev PaddleEvent) string {
	if ev.AdjustmentAction == "chargeback" {
		return "charged_back"
	}
	return "refunded"
}

// readOrgSubscriptionRowTx reads this account's row for the subscription.
func readOrgSubscriptionRowTx(ctx context.Context, tx pgx.Tx, account, subscriptionID string) (found bool, plan PaddlePlan, status string, trialEnd *time.Time, err error) {
	e := tx.QueryRow(ctx,
		`SELECT plan_name, plan_version, status, trial_ends_at FROM paddle_subscriptions
		  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
		account, subscriptionID).Scan(&plan.Name, &plan.Version, &status, &trialEnd)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, PaddlePlan{}, "", nil, nil
	}
	if e != nil {
		return false, PaddlePlan{}, "", nil, e
	}
	return true, plan, status, trialEnd, nil
}

// orgBillableForBindingTx checks, for a FIRST write of an org subscription,
// that the paying account still sees the org (membership RLS), that the org
// is not on its way out, and that the plan is of the org's kind. It returns
// the refusal note, or "".
func orgBillableForBindingTx(ctx context.Context, tx pgx.Tx, orgID string, plan PaddlePlan) (string, error) {
	var kind, status string
	err := tx.QueryRow(ctx, `SELECT kind, status FROM orgs WHERE org_id=$1::uuid`, orgID).Scan(&kind, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "the paying account is not a member of the org", nil
	}
	if err != nil {
		return "", err
	}
	if !orgStatusBillable(platformcontract.TenantState(status)) {
		return "the org is " + status + " and takes no new subscription", nil
	}
	want, ok := OrgEntitlementsKind(OrgKind(kind))
	got, known := catalogPlanKind(plan)
	if !ok || !known || want != got {
		return "the plan is not a plan of the org's kind", nil
	}
	return "", nil
}

// orgBillableStatuses are the lifecycle states an org may start a
// subscription in: being created, in service, or suspended (a suspended org
// paying is how it comes back).
var orgBillableStatuses = map[platformcontract.TenantState]bool{
	platformcontract.StateProvisioning: true,
	platformcontract.StateActive:       true,
	platformcontract.StateSuspended:    true,
}

func orgStatusBillable(st platformcontract.TenantState) bool { return orgBillableStatuses[st] }

// applyOrgPaddleActivate: an activation, renewal or trial on an org
// subscription. The status rules are the account path's
// (resolveActivateStatus); there is no plan assignment.
func applyOrgPaddleActivate(ctx context.Context, tx pgx.Tx, s *Store, ev PaddleEvent, account, orgID string, periodEnd *time.Time, occurred time.Time) (BillingIntake, error) {
	if err := orgLiveLockTx(ctx, tx, orgID); err != nil {
		return BillingIntake{}, fmt.Errorf("org live lock: %w", err)
	}
	found, rowPlan, existingStatus, existingTrialEnd, err := readOrgSubscriptionRowTx(ctx, tx, account, ev.SubscriptionID)
	if err != nil {
		return BillingIntake{}, fmt.Errorf("read org subscription: %w", err)
	}
	plan, known := s.paddlePlanForPrice(ev.PriceID)
	switch {
	case known && !catalogOrgPlan(plan):
		// An account price on an org subscription: never a grant of the
		// wrong scope. A bound row keeps its own plan.
		if !found {
			return BillingIntake{Applied: false, Outcome: "unknown_price", Note: "not an org plan price " + ev.PriceID}, nil
		}
		plan = rowPlan
	case !known && !found:
		return BillingIntake{Applied: false, Outcome: "unknown_price", Note: "unknown price " + ev.PriceID}, nil
	case !known:
		plan = rowPlan
	}
	if !found {
		note, err := orgBillableForBindingTx(ctx, tx, orgID, plan)
		if err != nil {
			return BillingIntake{}, fmt.Errorf("check org: %w", err)
		}
		if note != "" {
			return BillingIntake{Applied: false, Outcome: "not_billable", Reason: bindRefusalOrgNotBillable, Note: note}, nil
		}
	}
	// FR-7: the account path's re-open rule.
	if !ActivateMayReopen(ev, existingStatus) {
		return terminalKeptIntake(existingStatus), nil
	}
	rowStatus, preservedTrialEnd := resolveActivateStatus(ev, existingStatus, existingTrialEnd)
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
	refused, err := inSavepointTx(ctx, tx, func(sp pgx.Tx) error {
		return upsertSubscriptionTx(ctx, sp, account, orgID, ev, plan, rowStatus, nil, activatePeriodEnd, occurred)
	})
	if err != nil {
		return BillingIntake{}, fmt.Errorf("upsert org subscription: %w", err)
	}
	if refused {
		in := orgRefusedSecondLive()
		if !found {
			in.Reason = bindRefusalSecondLive
		}
		return in, nil
	}
	if rowStatus == "trialing" {
		if e := recordTrialUseTx(ctx, tx, account, orgID, ev.SubscriptionID, occurred); e != nil {
			return BillingIntake{}, fmt.Errorf("record org trial use: %w", e)
		}
	}
	note := "org subscription " + rowStatus + "; plan " + plan.Name
	if !found {
		note += seatQuantityNote(plan, ev.Quantity)
	}
	return BillingIntake{Applied: true, Outcome: "applied", Note: note}, nil
}

// seatQuantityNote reads the seat quantity Paddle bills a new org
// subscription for against its plan's seat minimum (FR-22): a quantity below
// the minimum still binds (the customer has paid; refusing would charge them
// for nothing) but says so in the intake note, which the webhook audits and
// the row keeps as seat_quantity. "" when the quantity is unknown or enough.
func seatQuantityNote(plan PaddlePlan, quantity int64) string {
	if quantity <= 0 {
		return ""
	}
	b, ok := entitlements.Plan(plan.Name, plan.Version)
	if !ok {
		return ""
	}
	if minSeats := b.Caps[entitlements.CapSeatsMin]; minSeats > 0 && quantity < minSeats {
		return fmt.Sprintf("; seat quantity %d is below the plan's minimum %d", quantity, minSeats)
	}
	return ""
}

// applyOrgPaddleCancel marks an org subscription canceled. The org falls back
// to its launch plan or floor on the worker's next pass: Paddle sends
// subscription.canceled when the cancellation takes effect (the end of the
// paid period), so there is no boundary to keep here.
func applyOrgPaddleCancel(ctx context.Context, tx pgx.Tx, s *Store, ev PaddleEvent, account, orgID string, periodEnd *time.Time, occurred, now time.Time) (BillingIntake, error) {
	found, rowPlan, _, _, err := readOrgSubscriptionRowTx(ctx, tx, account, ev.SubscriptionID)
	if err != nil {
		return BillingIntake{}, fmt.Errorf("read org subscription: %w", err)
	}
	plan, known := s.paddlePlanForPrice(ev.PriceID)
	if !known || !catalogOrgPlan(plan) {
		if !found {
			return BillingIntake{Applied: false, Outcome: "unattributed", Note: "no org subscription to cancel"}, nil
		}
		plan = rowPlan
	}
	if err := upsertSubscriptionTx(ctx, tx, account, orgID, ev, plan, "canceled", &now, periodEnd, occurred); err != nil {
		return BillingIntake{}, fmt.Errorf("upsert org subscription: %w", err)
	}
	return BillingIntake{Applied: true, Outcome: "applied", Note: "org subscription canceled"}, nil
}

// applyOrgPaddleSetStatus moves an org subscription to status (a revoke's
// terminal state, or a restore's active), inside a savepoint because a
// restore can collide with a newer live subscription of the same org.
func applyOrgPaddleSetStatus(ctx context.Context, tx pgx.Tx, ev PaddleEvent, account, orgID, status string, canceledAt *time.Time, occurred time.Time) (BillingIntake, error) {
	if err := orgLiveLockTx(ctx, tx, orgID); err != nil {
		return BillingIntake{}, fmt.Errorf("org live lock: %w", err)
	}
	var rows int64
	refused, err := inSavepointTx(ctx, tx, func(sp pgx.Tx) error {
		tag, e := sp.Exec(ctx,
			`UPDATE paddle_subscriptions
			    SET status=$3, canceled_at=$4, last_event_at=$5, updated_at=now()
			  WHERE account_id=$1::uuid AND paddle_subscription_id=$2`,
			account, ev.SubscriptionID, status, canceledAt, occurred)
		rows = tag.RowsAffected()
		return e
	})
	if err != nil {
		return BillingIntake{}, fmt.Errorf("set org subscription %s: %w", status, err)
	}
	if refused {
		return orgRefusedSecondLive(), nil
	}
	if rows == 0 {
		return BillingIntake{Applied: false, Outcome: "unattributed", Note: "no org subscription to update"}, nil
	}
	return BillingIntake{Applied: true, Outcome: "applied", Note: "org subscription " + status}, nil
}

// --- reads -------------------------------------------------------------

// validOrgID reports whether id is a UUID. A malformed id names no org, and
// checking it before the query keeps a cast error from ending the
// transaction (the reads below map it to ErrNotFound).
func validOrgID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

// OrgSubscription returns org orgID's most relevant subscription (the live
// one, else the latest), or ErrNotFound when the org has none. It is the
// worker's read (W14-D3, the entitlements PlanSource: entitlementwork
// OrgPlanReader), through the 0098 definer sbci_org_subscription_v2 (0091's
// sbci_org_subscription plus past_due_since, W16-D5), so it
// needs no grant on paddle_subscriptions and no account context. The
// customer id and the management links are not read.
func (s *Store) OrgSubscription(ctx context.Context, orgID string) (PaddleSubscription, error) {
	if !validOrgID(orgID) {
		return PaddleSubscription{}, ErrNotFound
	}
	var out PaddleSubscription
	found := false
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT paddle_subscription_id, plan_name, plan_version, status,
			        current_period_end, canceled_at, trial_ends_at, past_due_since
			   FROM sbci_org_subscription_v2($1::uuid)`, orgID).
			Scan(&out.SubscriptionID, &out.PlanName, &out.PlanVersion, &out.Status,
				&out.CurrentPeriodEnd, &out.CanceledAt, &out.TrialEndsAt, &out.PastDueSince)
		switch {
		case errors.Is(e, pgx.ErrNoRows):
			return nil
		case e != nil:
			return e
		}
		found = true
		return nil
	})
	if err != nil {
		return PaddleSubscription{}, fmt.Errorf("cloudserver/store.OrgSubscription: %w", err)
	}
	if !found {
		return PaddleSubscription{}, ErrNotFound
	}
	return out, nil
}

// PortalOrgSubscription is the console's read of org orgID's most relevant
// subscription, for a caller who is an org admin or owner, or its billing
// owner (the 0098 definer sbci_portal_org_subscription_v2, 0091's rule plus
// past_due_since, checks; anyone else reads ErrNotFound, the same as
// an org with no subscription).
func (s *Store) PortalOrgSubscription(ctx context.Context, accountID, orgID string) (PaddleSubscription, error) {
	if !validOrgID(orgID) {
		return PaddleSubscription{}, ErrNotFound
	}
	var out PaddleSubscription
	var updateURL, cancelURL *string
	found := false
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT paddle_subscription_id, paddle_customer_id, plan_name, plan_version, status,
			        current_period_end, canceled_at, trial_ends_at,
			        management_update_url, management_cancel_url, past_due_since
			   FROM sbci_portal_org_subscription_v2($1::uuid)`, orgID).
			Scan(&out.SubscriptionID, &out.CustomerID, &out.PlanName, &out.PlanVersion, &out.Status,
				&out.CurrentPeriodEnd, &out.CanceledAt, &out.TrialEndsAt, &updateURL, &cancelURL, &out.PastDueSince)
		switch {
		case errors.Is(e, pgx.ErrNoRows):
			return nil
		case e != nil:
			return e
		}
		found = true
		return nil
	})
	if err != nil {
		return PaddleSubscription{}, fmt.Errorf("cloudserver/store.PortalOrgSubscription: %w", err)
	}
	if !found {
		return PaddleSubscription{}, ErrNotFound
	}
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

// CreateOrgCheckoutIntent mints the single-use checkout nonce of an ORG
// checkout (the org twin of CreateCheckoutIntent): only the org's billing
// owner may start one, only for an org that can take a subscription, and
// only for a price of the org's kind. The intent records org_id (0050), and
// the webhook binds the resulting subscription to that org and nothing else.
// It returns ErrNotFound when accountID is not a member,
// ErrOrgBillingForbidden when it is not the billing owner,
// ErrOrgNotBillable for an org that cannot pay, and ErrBillingUnknownPrice
// for a price that is not a plan of the org's kind.
func (s *Store) CreateOrgCheckoutIntent(ctx context.Context, accountID, orgID, priceID string, ttl time.Duration, now time.Time) (string, time.Time, error) {
	priceID = strings.TrimSpace(priceID)
	if strings.TrimSpace(accountID) == "" {
		return "", time.Time{}, errors.New("cloudserver/store.CreateOrgCheckoutIntent: account id required")
	}
	if ttl <= 0 {
		ttl = CheckoutIntentBindWindow
	}
	now = now.UTC()
	expiresAt := now.Add(ttl)
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, fmt.Errorf("cloudserver/store.CreateOrgCheckoutIntent: entropy: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		org, err := getMyOrgTx(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if !org.IsBillingOwner {
			return ErrOrgBillingForbidden
		}
		if !orgStatusBillable(org.Status) {
			return ErrOrgNotBillable
		}
		want, ok := OrgEntitlementsKind(org.Kind)
		if !ok {
			return ErrOrgNotBillable
		}
		plan, known := s.paddlePlanForPrice(priceID)
		got, inCatalog := catalogPlanKind(plan)
		if !known || !inCatalog || got != want {
			return ErrBillingUnknownPrice
		}
		_, e := tx.Exec(ctx,
			`INSERT INTO checkout_intents (account_id, org_id, nonce_hash, price_id, created_at, expires_at)
			 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)`,
			accountID, org.OrgID, hashCheckoutNonce(raw), priceID, now, expiresAt)
		return e
	})
	if err != nil {
		for _, sentinel := range []error{ErrNotFound, ErrOrgBillingForbidden, ErrOrgNotBillable, ErrBillingUnknownPrice} {
			if errors.Is(err, sentinel) {
				return "", time.Time{}, sentinel
			}
		}
		return "", time.Time{}, fmt.Errorf("cloudserver/store.CreateOrgCheckoutIntent: %w", err)
	}
	return raw, expiresAt, nil
}

// liveSubscriptionStatus mirrors the 0090 trigger's (and the old index's)
// "live" predicate: every status but canceled, refunded and charged_back.
func liveSubscriptionStatus(status string) bool {
	switch status {
	case "", "canceled", "refunded", "charged_back":
		return false
	}
	return true
}

// SubscriptionIsLive reports whether a subscription status occupies its
// scope's one live slot (the 0090 rule).
func SubscriptionIsLive(status string) bool { return liveSubscriptionStatus(status) }
