package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/enrichbudget"
	"github.com/marmutapp/superbased-observer/internal/reserve"
)

// Feature identifiers. Only session_enrichment ships this arc.
const FeatureSessionEnrichment = "session_enrichment"

// Default Signed-in Free entitlement: 3000 enrichment bundles/month, ≤100/day
// (migration 0041, operator ruling D-299: 0039's 20/day and 100/month rose to
// 100/day and 3000/month). Concurrency is an operational bound.
//
// Since W4 these values live in the seeded `free` row of the `plans` table —
// v3 as of 0041, which is the authority the reservation path consults. They
// are kept here only as the seed written into a new account's entitlements row,
// so that row still reads honestly when nothing overrides it. Keep them equal
// to the plan row's caps: a drift here is invisible (the row is written with
// overrides_plan = false) until an operator flips that flag.
const (
	defaultDailyCap       = 100
	defaultMonthlyCap     = 3000
	defaultConcurrencyCap = 2
)

// concurrencyWindowKey is the fixed window key for the live-in-flight counter
// row (a counter that goes up on reserve and down on settle/release): the
// reserve core's one WindowLive bucket.
const concurrencyWindowKey = reserve.LiveKey

// Reservation-cap sentinels — the API maps these to 429.
var (
	ErrDailyLimit   = errors.New("cloudserver/store: daily allowance exhausted")
	ErrMonthlyLimit = errors.New("cloudserver/store: monthly allowance exhausted")
	ErrConcurrency  = errors.New("cloudserver/store: concurrency limit reached")
	// ErrGlobalBudget means the budget POOL the account's plan draws from is
	// exhausted (W4: one pool per plan, so a Plus account can never drain the
	// free tier's ceiling). The name is unchanged for wire/API compatibility —
	// api/jobs.go maps it to 503 budget_exhausted.
	ErrGlobalBudget  = errors.New("cloudserver/store: plan budget pool exhausted")
	ErrNoEntitlement = errors.New("cloudserver/store: no entitlement for feature")

	// Token-budget refusals (ruling R-AI1). The daily and monthly ones wrap
	// the count sentinels, so a caller that only knows "the daily allowance
	// is exhausted" still reads them that way; the API names them apart.
	ErrDailyTokenBudget   = fmt.Errorf("%w: daily token budget", ErrDailyLimit)
	ErrMonthlyTokenBudget = fmt.Errorf("%w: monthly token budget", ErrMonthlyLimit)
	// ErrSessionTokenBudget means THIS session has used its cumulative
	// enrichment budget; other sessions of the account are unaffected.
	ErrSessionTokenBudget = errors.New("cloudserver/store: session token budget spent")
	// ErrTokenHoldMissing means a submission on a token-budgeted plan came
	// without a worst-case hold, or without the session it charges. It is a
	// caller fault and fails closed.
	ErrTokenHoldMissing = errors.New("cloudserver/store: token hold missing for a token-budgeted plan")
)

// Budget units a reservation records (usage_reservations.budget_unit,
// migration 0078). Closed vocabulary; finalize refuses anything else.
const (
	budgetUnitCount  = "count"
	budgetUnitTokens = "tokens"
)

// seedEntitlementsTx enables the feature for a new account. The row records
// feature ENABLEMENT (its absence is ErrNoEntitlement) and carries the free
// plan's caps as a non-overriding snapshot: overrides_plan is written false, so
// the account's caps resolve from its plan and a later upgrade actually raises
// headroom without any backfill here. An operator who INSERTs an entitlements
// row by hand gets the column's `true` default — an explicit per-account
// override — which is the escape hatch's whole purpose.
//
// Called inside Exchange's transaction (account already scoped).
func seedEntitlementsTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO entitlements (account_id, feature, source, daily_cap, monthly_cap, concurrency_cap, overrides_plan)
		 VALUES ($1::uuid, $2, 'beta_manual', $3, $4, $5, false)
		 ON CONFLICT (account_id, feature) DO NOTHING`,
		accountID, FeatureSessionEnrichment, defaultDailyCap, defaultMonthlyCap, defaultConcurrencyCap)
	if err != nil {
		return fmt.Errorf("cloudserver/store.seedEntitlements: %w", err)
	}
	return nil
}

// DailyWindowKey / MonthlyWindowKey define the UTC-anchored windows (Sol SD6:
// daily is UTC-defined; monthly cycle rollover is by calendar month). The
// bucketing is the reserve core's (reserve.WindowKey on the UTC calendar);
// both windows are in its vocabulary, so its second return is always true.
func DailyWindowKey(now time.Time) string {
	k, _ := reserve.WindowKey(now, reserve.WindowDaily, time.UTC)
	return k
}

// MonthlyWindowKey is DailyWindowKey's calendar-month window.
func MonthlyWindowKey(now time.Time) string {
	k, _ := reserve.WindowKey(now, reserve.WindowMonthly, time.UTC)
	return k
}

// capRefusals maps a refused cap (the reserve core's Breach.Name, which this
// ledger sets to the cycle kind or "pool") to the sentinel the API maps to
// its status. A name not in the table is a concurrency refusal, the old
// default.
func capRefusals() map[string]error {
	return map[string]error{
		"daily":       ErrDailyLimit,
		"monthly":     ErrMonthlyLimit,
		"concurrency": ErrConcurrency, // also enrichbudget.LimitConcurrency
		"pool":        ErrGlobalBudget,
		// The token path (reserve_tokens.go).
		enrichbudget.LimitDaily:   ErrDailyTokenBudget,
		enrichbudget.LimitMonthly: ErrMonthlyTokenBudget,
		enrichbudget.LimitSession: ErrSessionTokenBudget,
	}
}

// unitHold is one reservation's hold against one count cap: the reserve
// core's OverCap boundary with an estimate of one unit, so `used` reaching
// the cap refuses and the hold that lands exactly on the cap is admitted.
func unitHold(name string, capUnits, used int64) reserve.Limit {
	return reserve.Limit{
		Name:      name,
		Unit:      reserve.UnitCount,
		Cap:       float64(capUnits),
		Committed: float64(used),
		Estimate:  1,
	}
}

// refusal asks the reserve core whether one hold fits and returns the
// ledger's sentinel when it does not.
func refusal(l reserve.Limit) error {
	b, breached := reserve.Check(l)
	if !breached {
		return nil
	}
	if err, ok := capRefusals()[b.Name]; ok {
		return err
	}
	return ErrConcurrency
}

// ReserveAllowance atomically enforces daily (≤cap, UTC day) + monthly (≤cap,
// calendar month) + per-account concurrency + the account's plan budget pool in
// ONE transaction with row locks (Sol SD6). Racing devices serialize on the
// cycle rows and cannot exceed any window. It returns the reservation id, to be
// carried on the job and later settled or released.
//
// Every cap and the pool are resolved from the account's LIVE plan on each call
// (W4 / review finding 12), so a mid-cycle upgrade raises the ceiling
// immediately while the counters keep counting, and a Plus reservation draws
// from the plus_beta pool and never from the free tier's.
func (s *Store) ReserveAllowance(ctx context.Context, accountID, feature string, now time.Time) (string, error) {
	var reservationID string
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		reservationID, e = reserveAllowanceTx(ctx, tx, accountID, feature, now, s.spendCeilings)
		return e
	})
	if err != nil {
		return "", err
	}
	return reservationID, nil
}

// reserveAllowanceTx is the reservation logic operating on an existing tenant
// transaction, so a caller (SubmitJob) can make the reservation atomic with the
// evidence + job insert. Its contract is identical to ReserveAllowance.
func reserveAllowanceTx(ctx context.Context, tx pgx.Tx, accountID, feature string, now time.Time, ceilings map[string]SpendCeiling) (string, error) {
	allow, err := resolveAllowanceTx(ctx, tx, accountID, feature, now)
	if err != nil {
		return "", err
	}
	if feature == FeatureProjectDigest && !allow.Plan.DigestWeekly {
		return "", ErrNoEntitlement
	}
	if allow.Tier != nil {
		// A token-budgeted plan reserves through SubmitJob (reserveSubmitTx),
		// which knows the session and the worst-case hold; a bare unit
		// reservation has neither and must not slip past the token budgets.
		return "", ErrTokenHoldMissing
	}
	return reserveForAllowanceTx(ctx, tx, accountID, feature, allow, now, ceilings)
}

// reserveDigestAllowanceTx reserves one FeatureProjectDigest allowance unit for
// accountID's CURRENT plan (W5). It is a thin, named alias of reserveAllowanceTx
// for FeatureProjectDigest — resolveAllowanceTx already branches on that
// feature to resolve straight from the plan, never consulting (or requiring)
// an entitlements row (see its doc comment), so the reservation and the
// read-back usage snapshot can never drift. The caller (SubmitDigestJob,
// reached from the digest scheduler) may have scanned candidates before a
// refund or downgrade. The reservation therefore rechecks digest_weekly inside
// this transaction, then draws against the SAME cycle/pool
// machinery as every other feature, so a runaway digest volume is still
// capped by the plan's caps and pool.
func reserveDigestAllowanceTx(ctx context.Context, tx pgx.Tx, accountID string, now time.Time, ceilings map[string]SpendCeiling) (string, error) {
	return reserveAllowanceTx(ctx, tx, accountID, FeatureProjectDigest, now, ceilings)
}

// reserveForAllowanceTx is the reservation logic shared by
// reserveAllowanceTx and reserveDigestAllowanceTx: given an already-resolved
// Allowance, it enforces daily/monthly/concurrency + the plan's budget pool
// and inserts the reservation row (Sol SD6). It also refuses the reservation
// with ErrSpendCeiling when the pool has a USD spend ceiling (ceilings, see
// spend.go) that its current day or month has reached.
func reserveForAllowanceTx(ctx context.Context, tx pgx.Tx, accountID, feature string, allow Allowance, now time.Time, ceilings map[string]SpendCeiling) (string, error) {
	daily := DailyWindowKey(now)
	monthly := MonthlyWindowKey(now)

	if err := reserveCycle(ctx, tx, accountID, feature, "daily", daily, allow.DailyCap); err != nil {
		return "", err
	}
	if err := reserveCycle(ctx, tx, accountID, feature, "monthly", monthly, allow.MonthlyCap); err != nil {
		return "", err
	}
	if err := reserveCycle(ctx, tx, accountID, feature, "concurrency", concurrencyWindowKey, allow.ConcurrencyCap); err != nil {
		return "", err
	}

	// The plan's budget pool (system table, locked FOR UPDATE). A missing pool
	// is a configuration fault, not a user condition, so it fails closed with
	// its own sentinel rather than reading as "exhausted".
	var gCap, gUsed int64
	e := tx.QueryRow(ctx,
		`SELECT cap, used FROM budget_pools WHERE pool = $1 FOR UPDATE`, allow.BudgetPool).Scan(&gCap, &gUsed)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", ErrBudgetPoolMissing, allow.BudgetPool)
	}
	if e != nil {
		return "", fmt.Errorf("lock budget pool %s: %w", allow.BudgetPool, e)
	}
	if err := refusal(unitHold("pool", gCap, gUsed)); err != nil {
		return "", err
	}
	if err := checkSpendCeilingTx(ctx, tx, ceilings, allow.BudgetPool, now); err != nil {
		return "", err
	}
	if _, e := tx.Exec(ctx,
		`UPDATE budget_pools SET used = used + 1, updated_at = now() WHERE pool = $1`,
		allow.BudgetPool); e != nil {
		return "", fmt.Errorf("bump budget pool %s: %w", allow.BudgetPool, e)
	}

	// The pool is recorded ON the reservation so a later refund returns the unit
	// to the pool it was actually drawn from, even if the account's plan changed
	// in between.
	var reservationID string
	if e := tx.QueryRow(ctx,
		`INSERT INTO usage_reservations (account_id, feature, state, user_units, daily_window, monthly_window, budget_pool)
		 VALUES ($1::uuid, $2, 'reserved', 1, $3, $4, $5) RETURNING id::text`,
		accountID, feature, daily, monthly, allow.BudgetPool).Scan(&reservationID); e != nil {
		return "", fmt.Errorf("insert reservation: %w", e)
	}
	if err := appendLedgerTx(ctx, tx, accountID, ledgerEntry{
		Event: "reserve", UserUnits: 1, Detail: `{"scope":"reserve"}`,
	}); err != nil {
		return "", err
	}
	return reservationID, nil
}

// reserveCycle ensures the counter row exists, locks it, asks the reserve core
// whether one more unit fits under the LIVE cap, and increments. The per-cycle sentinel is chosen by kind so the API can
// tell the user which window blocked them.
//
// W4 / review finding 12: `cap` is the caller's freshly-resolved plan cap, and
// it is authoritative. The stored usage_cycles.cap is a SNAPSHOT taken when the
// window's counter row was created; the previous code took min(snapshot, live),
// which silently pinned a running window to whatever the cap was on its first
// reservation — so a mid-cycle upgrade could not raise headroom until the
// window rolled over. The snapshot is now refreshed to the live value instead
// of constraining it, which is what makes an upgrade take effect immediately
// and a (cycle-end) downgrade take effect the moment its window starts.
func reserveCycle(ctx context.Context, tx pgx.Tx, accountID, feature, kind, windowKey string, cap int) error {
	if _, e := tx.Exec(ctx,
		`INSERT INTO usage_cycles (account_id, feature, cycle_kind, window_key, cap, used)
		 VALUES ($1::uuid, $2, $3, $4, $5, 0)
		 ON CONFLICT (account_id, feature, cycle_kind, window_key) DO NOTHING`,
		accountID, feature, kind, windowKey, cap); e != nil {
		return fmt.Errorf("ensure %s cycle: %w", kind, e)
	}
	var used int
	if e := tx.QueryRow(ctx,
		`SELECT used FROM usage_cycles
		  WHERE account_id = $1::uuid AND feature = $2 AND cycle_kind = $3 AND window_key = $4
		  FOR UPDATE`,
		accountID, feature, kind, windowKey).Scan(&used); e != nil {
		return fmt.Errorf("lock %s cycle: %w", kind, e)
	}
	if err := refusal(unitHold(kind, int64(cap), int64(used))); err != nil {
		return err
	}
	if _, e := tx.Exec(ctx,
		`UPDATE usage_cycles SET used = used + 1, cap = $5, updated_at = now()
		  WHERE account_id = $1::uuid AND feature = $2 AND cycle_kind = $3 AND window_key = $4`,
		accountID, feature, kind, windowKey, cap); e != nil {
		return fmt.Errorf("bump %s cycle: %w", kind, e)
	}
	return nil
}

// SettleReservation marks a reservation settled: the user unit is CONSUMED
// (daily/monthly/global stay), only the concurrency slot is released. Idempotent.
func (s *Store) SettleReservation(ctx context.Context, accountID, reservationID string) error {
	return s.finalizeReservation(ctx, accountID, reservationID, "settled", false)
}

// ReleaseReservation marks a reservation released (or expired) and REFUNDS the
// user unit (daily/monthly/global decremented) plus the concurrency slot — for
// jobs that never produced a result (parked, evidence_expired, canceled).
// Idempotent.
func (s *Store) ReleaseReservation(ctx context.Context, accountID, reservationID string, expired bool) error {
	state := "released"
	if expired {
		state = "expired"
	}
	return s.finalizeReservation(ctx, accountID, reservationID, state, true)
}

// closeOutcome is one row of closeOutcomes.
type closeOutcome struct {
	state   string
	refund  bool
	outcome reserve.Outcome
}

// closeOutcomes maps a terminal reservation state and its refund flag to the
// reserve core's outcome. Every pair the callers pass is a row; anything else
// is refused rather than guessed.
func closeOutcomes() []closeOutcome {
	return []closeOutcome{
		{state: "settled", refund: false, outcome: reserve.OutcomeSettle},
		{state: "released", refund: true, outcome: reserve.OutcomeRelease},
		{state: "expired", refund: true, outcome: reserve.OutcomeExpire},
	}
}

func closeOutcomeFor(newState string, refundUnit bool) (reserve.Outcome, error) {
	for _, r := range closeOutcomes() {
		if r.state == newState && r.refund == refundUnit {
			return r.outcome, nil
		}
	}
	return "", fmt.Errorf("cloudserver/store.finalizeReservation: no close for state %q with refund=%t", newState, refundUnit)
}

func (s *Store) finalizeReservation(ctx context.Context, accountID, reservationID, newState string, refundUnit bool) error {
	return s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return finalizeReservationTx(ctx, tx, accountID, reservationID, newState, refundUnit)
	})
}

// finalizeReservationTx is the reservation-finalize logic on an existing tenant
// transaction (so a terminal job transition can settle/release atomically).
// A token reservation settled through it books its whole hold (the actual is
// unknown here); completeJobWithResultTx passes the provider's actual through
// finalizeReservationActualTx instead.
func finalizeReservationTx(ctx context.Context, tx pgx.Tx, accountID, reservationID, newState string, refundUnit bool) error {
	return finalizeReservationActualTx(ctx, tx, accountID, reservationID, newState, refundUnit, -1)
}

// lockAccountForCloseTx takes the accounts row FOR KEY SHARE at the START of
// a close, the first step of the canonical lock order (reserve_tokens.go).
// Every close ends by inserting a ledger row whose foreign key takes this
// same lock; taken there, after the session and window rows, it waits behind
// a submission that holds the account FOR UPDATE (the FE4 fence) and waits on
// a row the close holds. Taken first, the close simply queues behind the
// submission. KEY SHARE never blocks another close or the deletion fence's
// status UPDATE. A missing row (the account was purged) is not an error here:
// the reservation read that follows reports it.
func lockAccountForCloseTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	var one int
	e := tx.QueryRow(ctx,
		`SELECT 1 FROM accounts WHERE account_id = $1::uuid FOR KEY SHARE`, accountID).Scan(&one)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return fmt.Errorf("lock account for close: %w", e)
	}
	return nil
}

// heldReservation is one usage_reservations row as finalize reads it.
type heldReservation struct {
	id, state, feature, daily, monthly, pool, unit string
	units                                          int
	tokenHold                                      int64
	sessionPK                                      *string
}

// finalizeReservationActualTx closes a reservation. actualTokens is what a
// token reservation's work cost (enrichbudget.ActualTokens; negative =
// unknown, which books the hold); a count reservation ignores it. The close
// is dispatched on the reservation's own recorded unit, never on the plan the
// account holds now.
func finalizeReservationActualTx(ctx context.Context, tx pgx.Tx, accountID, reservationID, newState string, refundUnit bool, actualTokens float64) error {
	if err := lockAccountForCloseTx(ctx, tx, accountID); err != nil {
		return err
	}
	r := heldReservation{id: reservationID}
	e := tx.QueryRow(ctx,
		`SELECT state, feature, user_units, daily_window, monthly_window, budget_pool,
		        budget_unit, token_hold, session_pk::text
			   FROM usage_reservations WHERE account_id = $1::uuid AND id = $2::uuid FOR UPDATE`,
		accountID, reservationID).Scan(&r.state, &r.feature, &r.units, &r.daily, &r.monthly, &r.pool,
		&r.unit, &r.tokenHold, &r.sessionPK)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if e != nil {
		return fmt.Errorf("lock reservation: %w", e)
	}
	outcome, err := closeOutcomeFor(newState, refundUnit)
	if err != nil {
		return err
	}
	if r.unit == budgetUnitTokens {
		return finalizeTokenReservationTx(ctx, tx, accountID, r, newState, outcome, refundUnit, actualTokens)
	}
	if r.unit != budgetUnitCount {
		return fmt.Errorf("cloudserver/store.finalizeReservation: reservation %s has unknown budget unit %q", reservationID, r.unit)
	}
	state, feature, daily, monthly, pool, units := r.state, r.feature, r.daily, r.monthly, r.pool, r.units
	hold := reserve.Hold{State: reserve.HoldFinal, Estimate: float64(units)}
	if state == "reserved" {
		hold.State = reserve.HoldOpen
	}
	// A settle consumes the held units (actual == the hold); a release or
	// expiry refunds them. The core decides; this ledger writes it back.
	settlement, err := reserve.Settle(hold, reserve.Close{Outcome: outcome, Actual: float64(units)})
	if err != nil {
		return fmt.Errorf("cloudserver/store.finalizeReservation: %w", err)
	}
	if settlement.Noop {
		return nil // already finalized — idempotent no-op
	}
	refund := int(settlement.Refund)
	if _, e := tx.Exec(ctx,
		`UPDATE usage_reservations SET state = $3, updated_at = now()
			  WHERE account_id = $1::uuid AND id = $2::uuid`,
		accountID, reservationID, newState); e != nil {
		return fmt.Errorf("update reservation: %w", e)
	}
	// Acquire the counter-row locks in the SAME canonical order as
	// reserveAllowanceTx — daily → monthly → concurrency → global (FB4), the
	// tail of the one order every submit and close shares (accounts row first,
	// taken above by lockAccountForCloseTx; see reserve_tokens.go). A
	// settle (no refund) touches only concurrency; a release/expire (a refund)
	// touches daily/monthly first, then concurrency, then the budget pool,
	// matching the reserve path exactly so a concurrent reserve-vs-release
	// pair can never deadlock on an inverted lock order.
	if refund > 0 {
		if e := decrementCycle(ctx, tx, accountID, feature, "daily", daily, refund); e != nil {
			return e
		}
		if e := decrementCycle(ctx, tx, accountID, feature, "monthly", monthly, refund); e != nil {
			return e
		}
	}
	if settlement.FreesSlot {
		if e := decrementCycle(ctx, tx, accountID, feature, "concurrency", concurrencyWindowKey, units); e != nil {
			return e
		}
	}
	if refund > 0 {
		// Refund the pool the reservation actually drew from (recorded on the
		// row), never the account's CURRENT plan pool — a plan change between
		// reserve and release must not move spend between pools.
		if _, e := tx.Exec(ctx,
			`UPDATE budget_pools SET used = greatest(used - $2, 0), updated_at = now() WHERE pool = $1`,
			pool, refund); e != nil {
			return fmt.Errorf("refund budget pool %s: %w", pool, e)
		}
	}
	return appendLedgerTx(ctx, tx, accountID, ledgerEntry{
		Event: newState, UserUnits: 0, Detail: fmt.Sprintf(`{"refund":%t}`, refundUnit),
	})
}

func decrementCycle(ctx context.Context, tx pgx.Tx, accountID, feature, kind, windowKey string, by int) error {
	if _, e := tx.Exec(ctx,
		`UPDATE usage_cycles SET used = greatest(used - $5, 0), updated_at = now()
		  WHERE account_id = $1::uuid AND feature = $2 AND cycle_kind = $3 AND window_key = $4`,
		accountID, feature, kind, windowKey, by); e != nil {
		return fmt.Errorf("decrement %s cycle: %w", kind, e)
	}
	return nil
}
