package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Plan names seeded by migration 0012. Both are versioned; the version pinned
// here is the one an unassigned account resolves to.
const (
	// PlanFree is the Signed-in Free plan (v2: 20/day, 100/month, concurrency 2,
	// budget pool 'free', no pinned route - it resolves the feature default).
	PlanFree = "free"
	// PlanPlusBeta is the paid Plus plan (v2: 25/day, 60/month, concurrency 4,
	// its OWN budget pool 'plus_beta' - never the free pool - and its own
	// pinned route). The monthly cap is a COST cap: Plus buys a more capable
	// model with fewer runs, free buys more runs on the cheaper default route.
	PlanPlusBeta = "plus_beta"
	// DefaultFreePlanVersion is the free-plan version an account with NO
	// account_plans row resolves to. Absence-means-free is what lets every
	// pre-existing account keep working with no backfill. Bump this
	// deliberately, in the same change that seeds a new free version — a silent
	// "latest free version wins" would re-tier every unassigned account the
	// moment a new version landed. v2 is migration 0039's row (daily 5 -> 20).
	DefaultFreePlanVersion = 2
	// FreeBudgetPool is the budget_pools key the free plan draws from. Moving
	// OFF it is what makes an assignment an ACTIVATION rather than a downgrade
	// (see assignPlanTx).
	FreeBudgetPool = "free"
)

// LatestPlanVersion asks for the highest published version of a plan by name.
const LatestPlanVersion = 0

// Plan-resolution sentinels.
var (
	// ErrPlanNotFound means no plans row matches the requested (name, version).
	ErrPlanNotFound = errors.New("cloudserver/store: no such plan")
	// ErrPlanAssignmentConflict means the account already has an assignment
	// starting at or after the requested effective_from, so writing this one
	// would create an overlap.
	ErrPlanAssignmentConflict = errors.New("cloudserver/store: conflicting plan assignment")
	// ErrBudgetPoolMissing means the resolved plan names a pool that does not
	// exist. It is a fail-closed configuration error, never a user condition.
	ErrBudgetPoolMissing = errors.New("cloudserver/store: budget pool missing")
)

// Plan is one immutable, versioned entitlement plan definition.
type Plan struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Version        int    `json:"version"`
	Label          string `json:"label"`
	DailyCap       int    `json:"daily_cap"`
	MonthlyCap     int    `json:"monthly_cap"`
	ConcurrencyCap int    `json:"concurrency_cap"`
	BudgetPool     string `json:"budget_pool"`
	// DigestWeekly reports whether this plan includes the weekly project
	// digest job kind (migration 0037, W5). false for every plan predating
	// the column's default.
	DigestWeekly bool `json:"digest_weekly"`
	// ResultsRetentionDays is how many days a result of this plan stays in
	// hosted history before the retention sweep ages it out (migration 0037,
	// default 30).
	ResultsRetentionDays int `json:"results_retention_days"`
	// RouteID pins this plan's jobs to ONE route_registry row (migration 0039,
	// nullable column read through coalesce). Empty means "use the feature's
	// default route" - what every plan predating the column means, and what
	// free v2 keeps meaning. ResolveRouteForPlan is the one reader.
	RouteID string `json:"route_id"`
}

// Allowance is the composed answer to "what may this account spend on this
// feature right now" — the ONE place plan defaults and the per-account
// entitlements override meet (CLAUDE.md #4: one owner for the composed state).
//
// The plan supplies the caps and, always, the budget pool: a per-account cap
// override says how much, never which pool funds it.
type Allowance struct {
	Plan           Plan
	DailyCap       int
	MonthlyCap     int
	ConcurrencyCap int
	BudgetPool     string
	// Source is the entitlements row's source when the override is active,
	// else "plan".
	Source string
	// Overridden reports whether an explicit per-account entitlement override
	// supplied the caps instead of the plan.
	Overridden bool
}

// PlanAssignment is the outcome of AssignPlan.
type PlanAssignment struct {
	AssignmentID  string
	Plan          Plan
	PreviousPlan  Plan
	EffectiveFrom time.Time
	// Deferred reports that the assignment lowers at least one cap and was
	// therefore pushed to the next cycle boundary (R4: downgrades take effect
	// at cycle end, upgrades mid-cycle).
	Deferred bool
}

// NextMonthlyCycleStart returns the first instant of the next UTC calendar
// month — the cycle boundary a deferred downgrade starts at. It is anchored to
// exactly the window MonthlyWindowKey names, so an assignment that begins here
// begins with a fresh monthly counter.
func NextMonthlyCycleStart(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
}

// CeilToMonthlyCycleStart returns the first monthly cycle boundary AT OR AFTER
// t: t itself when t is exactly the first instant of a UTC calendar month,
// otherwise the start of the following month.
//
// This is what a downgrade's effective time is floored to (F11).
// NextMonthlyCycleStart answers "the next boundary after NOW", which is the
// right floor only for a downgrade taking effect immediately. A downgrade
// SCHEDULED for a future mid-cycle instant — say, requested on Oct 20 to take
// effect Nov 15 — is already past that boundary, so the old rule left it exactly
// where it was asked for: mid-cycle, half-way through a monthly counter the
// developer is part-way through spending. Ceiling to the boundary at or after
// the REQUESTED time is the rule that actually holds for every request, and it
// leaves a boundary-exact request untouched (a cycle that has just started has no
// part-spent allowance to protect).
func CeilToMonthlyCycleStart(t time.Time) time.Time {
	u := t.UTC()
	start := time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
	if u.Equal(start) {
		return start
	}
	return start.AddDate(0, 1, 0)
}

// loadPlanTx reads one plan by (name, version). Pass LatestPlanVersion for the
// highest published version of that name.
func loadPlanTx(ctx context.Context, tx pgx.Tx, name string, version int) (Plan, error) {
	var p Plan
	q := `SELECT plan_id::text, name, version, label, daily_cap, monthly_cap, concurrency_cap, budget_pool,
	             digest_weekly, results_retention_days, coalesce(route_id, '')
	        FROM plans WHERE name = $1 AND ($2 = 0 OR version = $2)
	       ORDER BY version DESC LIMIT 1`
	e := tx.QueryRow(ctx, q, name, version).
		Scan(&p.ID, &p.Name, &p.Version, &p.Label, &p.DailyCap, &p.MonthlyCap, &p.ConcurrencyCap, &p.BudgetPool,
			&p.DigestWeekly, &p.ResultsRetentionDays, &p.RouteID)
	if errors.Is(e, pgx.ErrNoRows) {
		return Plan{}, ErrPlanNotFound
	}
	if e != nil {
		return Plan{}, fmt.Errorf("load plan %s v%d: %w", name, version, e)
	}
	return p, nil
}

// resolvePlanTx returns the plan in force for an account at now: the
// account_plans row whose effective window contains now, or — when the account
// has no assignment at all — the default free plan. Absence-means-free is the
// reason no backfill is needed for accounts that predate 0012.
//
// A deferred downgrade shows up here naturally: the running assignment carries
// effective_until = the boundary, and the pending one carries effective_from =
// the boundary, so the switch happens by the clock with no scheduled job.
//
// The caller must already hold tenant context (account_plans is RLS'd).
func resolvePlanTx(ctx context.Context, tx pgx.Tx, accountID string, now time.Time) (Plan, error) {
	var p Plan
	e := tx.QueryRow(ctx,
		`SELECT p.plan_id::text, p.name, p.version, p.label,
		        p.daily_cap, p.monthly_cap, p.concurrency_cap, p.budget_pool,
		        p.digest_weekly, p.results_retention_days, coalesce(p.route_id, '')
		   FROM account_plans ap
		   JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid
		    AND ap.effective_from <= $2
		    AND (ap.effective_until IS NULL OR ap.effective_until > $2)
		  ORDER BY ap.effective_from DESC
		  LIMIT 1`,
		accountID, now).
		Scan(&p.ID, &p.Name, &p.Version, &p.Label, &p.DailyCap, &p.MonthlyCap, &p.ConcurrencyCap, &p.BudgetPool,
			&p.DigestWeekly, &p.ResultsRetentionDays, &p.RouteID)
	if errors.Is(e, pgx.ErrNoRows) {
		return loadPlanTx(ctx, tx, PlanFree, DefaultFreePlanVersion)
	}
	if e != nil {
		return Plan{}, fmt.Errorf("resolve account plan: %w", e)
	}
	return p, nil
}

// resolveAllowanceTx composes the account's effective allowance for a feature:
// the resolved plan's caps and pool, with the entitlements row's caps layered
// on top when that row is an explicit operator override.
//
// The entitlements row must exist — its absence still means "this feature is
// not enabled for this account" (ErrNoEntitlement), exactly as before 0012.
//
// FeatureProjectDigest (W5) is the one exception: a project digest's
// entitlement is granted PURELY by the resolved plan's digest_weekly flag,
// never by a per-account entitlements override, so it is resolved straight
// from the plan and never consults (or requires) an entitlements row — that
// would force a backfill for every existing account before a single digest
// job could be reserved or its usage read back for them. Both the reservation
// path (reserveDigestAllowanceTx) and the read path (Usage/ResolveAllowance)
// go through this ONE branch, so they can never drift.
func resolveAllowanceTx(ctx context.Context, tx pgx.Tx, accountID, feature string, now time.Time) (Allowance, error) {
	plan, err := resolvePlanTx(ctx, tx, accountID, now)
	if err != nil {
		return Allowance{}, err
	}
	if feature == FeatureProjectDigest {
		return Allowance{
			Plan: plan, DailyCap: plan.DailyCap, MonthlyCap: plan.MonthlyCap,
			ConcurrencyCap: plan.ConcurrencyCap, BudgetPool: plan.BudgetPool, Source: "plan",
		}, nil
	}
	var (
		source                              string
		entDaily, entMonthly, entConcurrent int
		overrides                           bool
	)
	e := tx.QueryRow(ctx,
		`SELECT source, daily_cap, monthly_cap, concurrency_cap, overrides_plan
		   FROM entitlements WHERE account_id = $1::uuid AND feature = $2`,
		accountID, feature).Scan(&source, &entDaily, &entMonthly, &entConcurrent, &overrides)
	if errors.Is(e, pgx.ErrNoRows) {
		return Allowance{}, ErrNoEntitlement
	}
	if e != nil {
		return Allowance{}, fmt.Errorf("load entitlement: %w", e)
	}

	a := Allowance{
		Plan:           plan,
		DailyCap:       plan.DailyCap,
		MonthlyCap:     plan.MonthlyCap,
		ConcurrencyCap: plan.ConcurrencyCap,
		BudgetPool:     plan.BudgetPool,
		Source:         "plan",
	}
	if overrides {
		a.DailyCap, a.MonthlyCap, a.ConcurrencyCap = entDaily, entMonthly, entConcurrent
		a.Source, a.Overridden = source, true
	}
	return a, nil
}

// ResolvePlanForAccount is the read-only view of resolvePlanTx: the plan in
// force for an account at now, with NO entitlements row required.
//
// It is deliberately separate from ResolveAllowance, which additionally demands
// an entitlements row (its absence is ErrNoEntitlement, the feature-enablement
// answer). A caller that only needs the plan's DEFINITION — the route it pins,
// say — must not be able to turn a missing entitlement into a routing error, or
// to reorder the submission path's existing refusal codes.
func (s *Store) ResolvePlanForAccount(ctx context.Context, accountID string, now time.Time) (Plan, error) {
	var p Plan
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		p, e = resolvePlanTx(ctx, tx, accountID, now)
		return e
	})
	if err != nil {
		return Plan{}, err
	}
	return p, nil
}

// ResolveAllowance is the read-only view of resolveAllowanceTx, for callers
// that want the effective plan + caps without reserving anything.
func (s *Store) ResolveAllowance(ctx context.Context, accountID, feature string, now time.Time) (Allowance, error) {
	var a Allowance
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		a, e = resolveAllowanceTx(ctx, tx, accountID, feature, now)
		return e
	})
	if err != nil {
		return Allowance{}, err
	}
	return a, nil
}

// AssignPlan is the operator-only plan-assignment path (W4 deliverable 4).
// There is deliberately NO HTTP route: no payment rail exists yet, so a beta
// grant is an operator act through `observer-cloud grant-plan`, not something a
// signed-in user can trigger.
//
// R4 timing is enforced HERE, on the write, not on every read:
//
//   - an UPGRADE (no cap lower than the current plan's) takes effect
//     immediately, so the raised ceiling is visible mid-cycle. The reservation
//     path re-resolves caps per reservation, so the headroom is live the moment
//     this commits.
//   - a DOWNGRADE (any cap lower) is floored at the next monthly cycle
//     boundary, so nobody loses allowance they are part-way through using.
//
// effectiveFrom may be zero (choose the earliest legal instant), or a future
// instant to schedule an assignment; a past instant is raised to now — an
// assignment is never backdated over usage that already happened. version may
// be LatestPlanVersion.
func (s *Store) AssignPlan(ctx context.Context, accountID, planName string, version int, effectiveFrom, now time.Time) (PlanAssignment, error) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	return s.assignPlanSource(ctx, accountID, planName, version, effectiveFrom, now, "beta_manual")
}

// assignPlanSource is AssignPlan with an explicit account_plans.source tag. W9's
// Paddle path uses source='paddle' so a billing-driven assignment is
// distinguishable from an operator beta grant in the assignment history, while
// still flowing through the ONE W4 assignment mechanism (never a competing
// entitlement source).
func (s *Store) assignPlanSource(ctx context.Context, accountID, planName string, version int, effectiveFrom, now time.Time, source string) (PlanAssignment, error) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	var out PlanAssignment
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		out, e = assignPlanTx(ctx, tx, accountID, planName, version, effectiveFrom, now, source)
		return e
	})
	if err != nil {
		return PlanAssignment{}, err
	}
	return out, nil
}

// revokePlanToFreeTx pulls an account back to the free plan IMMEDIATELY (at now),
// superseding any future scheduled assignment. It is the revocation path a
// refund or chargeback takes — deliberately NOT the deferred cycle-boundary
// downgrade assignPlanTx applies to a graceful cancellation.
//
// DECISION (documented, Stream 5): a full refund or chargeback revokes paid
// access at the effective instant, NOT ceiled to the next cycle boundary. The
// F11 "keep what you paid for" floor exists to protect allowance a developer is
// part-way through spending BECAUSE they paid for it; a refund returns their
// money and a chargeback is an adversarial bank reversal, so that protection no
// longer applies. A graceful `subscription.canceled` still defers to the boundary
// (assignPlanTx / the "cancel" action) — only refund/chargeback revoke now.
//
// It respects the account_plans_no_overlap exclusion constraint the same way
// assignPlanTx does: it clears future rows, then closes the in-force row at now,
// then inserts the open free row starting exactly at now (half-open ranges, one
// statement each, so the pair is disjoint and never self-conflicts). Caller must
// already hold tenant context AND the per-account advisory lock.
func revokePlanToFreeTx(ctx context.Context, tx pgx.Tx, accountID string, now time.Time, source string) error {
	now = now.UTC()
	// A refund/chargeback supersedes anything scheduled after now (e.g. a pending
	// cycle-boundary downgrade from an earlier cancellation): paid access is being
	// pulled now, so no later scheduled assignment survives.
	if _, e := tx.Exec(ctx,
		`DELETE FROM account_plans WHERE account_id = $1::uuid AND effective_from > $2`,
		accountID, now); e != nil {
		return fmt.Errorf("clear scheduled assignments: %w", e)
	}
	current, err := resolvePlanTx(ctx, tx, accountID, now)
	if err != nil {
		return err
	}
	if current.Name == PlanFree {
		// Already resolves to free — paid access is already gone; closing and
		// re-opening a free row would only churn history. The future-clear above is
		// the only effect a revocation-while-free can have.
		return nil
	}
	free, err := loadPlanTx(ctx, tx, PlanFree, DefaultFreePlanVersion)
	if err != nil {
		return err
	}
	// Close the in-force paid assignment at now.
	if _, e := tx.Exec(ctx,
		`UPDATE account_plans SET effective_until = $2
		  WHERE account_id = $1::uuid AND effective_from <= $2
		    AND (effective_until IS NULL OR effective_until > $2)`,
		accountID, now); e != nil {
		return fmt.Errorf("close in-force assignment: %w", e)
	}
	if _, e := tx.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, source)
		 VALUES ($1::uuid, $2::uuid, $3, $4)`,
		accountID, free.ID, now, source); e != nil {
		return fmt.Errorf("insert free assignment: %w", e)
	}
	return nil
}

func assignPlanTx(ctx context.Context, tx pgx.Tx, accountID, planName string, version int, effectiveFrom, now time.Time, source string) (PlanAssignment, error) {
	target, err := loadPlanTx(ctx, tx, planName, version)
	if err != nil {
		return PlanAssignment{}, err
	}
	current, err := resolvePlanTx(ctx, tx, accountID, now)
	if err != nil {
		return PlanAssignment{}, err
	}

	lowers := target.DailyCap < current.DailyCap ||
		target.MonthlyCap < current.MonthlyCap ||
		target.ConcurrencyCap < current.ConcurrencyCap

	// ACTIVATION beats the cap comparison. Free's daily cap rose to 20 in plans
	// v2 (migration 0039), so a paid plan whose daily cap is lower than 20 now
	// reads as a DOWNGRADE under a pure cap comparison and its activation would be
	// deferred to the next cycle boundary - a customer who pays on the 3rd would
	// get nothing until the 1st. The direction that actually distinguishes the two
	// is the budget POOL: moving OFF the free pool onto a plan's own pool is an
	// activation and takes effect immediately. F11's "keep what you paid for"
	// floor still governs every move BACK to free and every change within one pool,
	// so a cancellation still lands on a cycle boundary.
	activation := current.BudgetPool == FreeBudgetPool && target.BudgetPool != FreeBudgetPool

	start := effectiveFrom.UTC()
	if effectiveFrom.IsZero() || start.Before(now) {
		start = now
	}
	if lowers && !activation {
		// EVERY downgrade lands on a cycle boundary, whether it was requested for
		// now or scheduled for a future date (F11). Ceiling the requested instant
		// — not just `now` — is what makes a mid-cycle future date behave the same
		// as a mid-cycle immediate one.
		start = CeilToMonthlyCycleStart(start)
	}
	// Deferred means exactly "this does not take effect yet", so it is derived
	// from the resulting instant rather than from the branch that produced it: a
	// scheduled future UPGRADE is deferred too, and previously reported itself as
	// immediate.
	deferred := start.After(now)

	// Close the running open assignment at the new start. The row is locked
	// first so two concurrent grants serialize here rather than racing the
	// account_plans_one_open index.
	var openID, openPlanID string
	var openFrom time.Time
	e := tx.QueryRow(ctx,
		`SELECT id::text, plan_id::text, effective_from FROM account_plans
		  WHERE account_id = $1::uuid AND effective_until IS NULL FOR UPDATE`,
		accountID).Scan(&openID, &openPlanID, &openFrom)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
		// No assignment yet — the account has been running on the implicit
		// default free plan. Nothing to close.
	case e != nil:
		return PlanAssignment{}, fmt.Errorf("lock open assignment: %w", e)
	default:
		if !openFrom.Before(start) {
			// The open assignment has not started yet — it is SCHEDULED for a
			// future instant (a pending cycle-boundary or trial-end downgrade,
			// F11 / scheduleTrialCancelDowngradeTx). Two cases:
			//
			//   - it already names the SAME plan being assigned: a genuine
			//     no-op (e.g. a redelivered event re-asserting an
			//     already-scheduled grant) — refuse rather than duplicate it,
			//     exactly as before.
			//   - it names a DIFFERENT plan (P1-1: cancel-then-resubscribe —
			//     a graceful-cancel free downgrade, or a trial-cancel
			//     downgrade, is still pending when the account activates a
			//     NEW paid subscription). An immediate activation (start ==
			//     now, never itself a lowering change) must WIN over a stale
			//     schedule, not silently no-op behind a false "unchanged"
			//     conflict that would leave the account riding the stale
			//     schedule down to free. Supersede it exactly the way a
			//     refund/chargeback does (revokePlanToFreeTx's shape,
			//     generalized to any target plan): clear every row scheduled
			//     after now and close whatever is genuinely in force AT now,
			//     then fall through to the INSERT below for the new open row.
			//
			// A genuinely scheduled (deferred, i.e. NOT starting now — a
			// downgrade or an explicit future grant) collision is left as a
			// conflict: only an immediate activation is entitled to override
			// a stale schedule.
			if openPlanID == target.ID || deferred {
				return PlanAssignment{}, ErrPlanAssignmentConflict
			}
			if e := supersedeScheduleForImmediateActivationTx(ctx, tx, accountID, now); e != nil {
				return PlanAssignment{}, e
			}
		} else if _, e := tx.Exec(ctx,
			`UPDATE account_plans SET effective_until = $3
			  WHERE account_id = $1::uuid AND id = $2::uuid`,
			accountID, openID, start); e != nil {
			return PlanAssignment{}, fmt.Errorf("close open assignment: %w", e)
		}
	}

	var assignmentID string
	if source == "" {
		source = "beta_manual"
	}
	if e := tx.QueryRow(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, source)
		 VALUES ($1::uuid, $2::uuid, $3, $4) RETURNING id::text`,
		accountID, target.ID, start, source).Scan(&assignmentID); e != nil {
		return PlanAssignment{}, fmt.Errorf("insert assignment: %w", e)
	}
	return PlanAssignment{
		AssignmentID:  assignmentID,
		Plan:          target,
		PreviousPlan:  current,
		EffectiveFrom: start,
		Deferred:      deferred,
	}, nil
}

// supersedeScheduleForImmediateActivationTx clears a pending future schedule
// (a scheduled cycle-boundary or trial-end downgrade whose plan differs from
// what is about to be assigned) and closes whatever is genuinely in force AT
// now, in preparation for assignPlanTx's own INSERT immediately below (P1-1).
// It is revokePlanToFreeTx's "clear scheduled, close in-force" half verbatim
// — CLAUDE.md #4, no second entitlement-write path — generalized to any
// target plan: revokePlanToFreeTx always inserts free itself, but here the
// caller's own subsequent INSERT (common to every assignPlanTx caller)
// supplies whatever plan is actually being assigned, so this stops short of
// inserting.
//
// Caller must already hold tenant context AND the per-account advisory lock
// (assignPlanTx runs inside applyPaddleEvent's WithAccount, after the lock).
func supersedeScheduleForImmediateActivationTx(ctx context.Context, tx pgx.Tx, accountID string, now time.Time) error {
	if _, e := tx.Exec(ctx,
		`DELETE FROM account_plans WHERE account_id = $1::uuid AND effective_from > $2`,
		accountID, now); e != nil {
		return fmt.Errorf("clear scheduled assignments: %w", e)
	}
	if _, e := tx.Exec(ctx,
		`UPDATE account_plans SET effective_until = $2
		  WHERE account_id = $1::uuid AND effective_from <= $2
		    AND (effective_until IS NULL OR effective_until > $2)`,
		accountID, now); e != nil {
		return fmt.Errorf("close in-force assignment: %w", e)
	}
	return nil
}
