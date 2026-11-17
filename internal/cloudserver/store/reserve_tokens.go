package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/enrichbudget"
	"github.com/marmutapp/superbased-observer/internal/reserve"
)

// Token-budgeted reservations (ruling R-AI1, migration 0078). A plan that
// names an enrichment tier enforces, for session enrichment, the tier's daily
// and monthly per-account token budgets and its per-session cumulative
// budget, plus the plan's concurrency cap; the budget pool's unit count and
// USD spend ceiling are checked exactly as on the count path. There is no cap
// on the NUMBER of enrichments.
//
// Every hold is the worst case (enrichbudget.WorstCaseTokens over the
// uploaded envelope and the route's output cap, sized here in the store from
// the submission's own byte count and the route row); settlement books what the
// provider reported (an overrun is recorded, never clamped) and a release or
// expiry refunds the whole hold.
//
// Canonical lock order, shared by every submission and every close (settle,
// release, expiry; count and token paths alike) so a concurrent submit/close
// pair cannot deadlock on an inverted order:
//
//	accounts row -> reservation row -> session ledger -> daily -> monthly -> concurrency -> budget pool
//
//   - accounts row: a submission takes it FOR UPDATE (the FE4 deletion fence)
//     before anything else; a close takes it FOR KEY SHARE first
//     (lockAccountForCloseTx), because every close inserts a ledger row whose
//     foreign key would otherwise take that same KEY SHARE at its END, after
//     the windows, behind a submission that holds the account and waits on a
//     window the close holds.
//   - reservation row: only a close locks an existing reservation (a
//     submission inserts a new one), so it sits between the two.
//   - session ledger: a submission locks the cloud_sessions row as soon as it
//     resolves the session (ensureSessionTx's upsert), before it can know
//     whether the plan is token-budgeted, so the session comes before every
//     window; a close adjusts the session ledger before the windows for the
//     same reason. Before this order a re-enrichment submitted while the
//     worker released or settled the previous job of the same session
//     deadlocked (40P01; tokenlockorder_test.go).
//   - daily -> monthly -> concurrency -> budget pool: the counter rows, in the
//     order the count path (reserve.go) has always used.

// reserveSubmitTx is the reservation a session-enrichment submission takes:
// a token reservation on a token-budgeted plan, the unit reservation
// (reserveForAllowanceTx) otherwise. sessionPK, routeID and evidenceBytes are
// only read on the token path, where the store sizes the worst-case hold
// itself (holdForRouteTx), so no caller can under-size it.
func reserveSubmitTx(ctx context.Context, tx pgx.Tx, accountID, feature, sessionPK, routeID string, evidenceBytes int64, now time.Time, ceilings map[string]SpendCeiling) (string, error) {
	allow, err := resolveAllowanceTx(ctx, tx, accountID, feature, now)
	if err != nil {
		return "", err
	}
	if feature == FeatureProjectDigest && !allow.Plan.DigestWeekly {
		return "", ErrNoEntitlement
	}
	if allow.Tier == nil {
		return reserveForAllowanceTx(ctx, tx, accountID, feature, allow, now, ceilings)
	}
	hold, err := holdForRouteTx(ctx, tx, routeID, evidenceBytes)
	if err != nil {
		return "", err
	}
	return reserveTokensTx(ctx, tx, accountID, feature, sessionPK, hold, allow, now, ceilings)
}

// holdForRouteTx is the worst-case hold of one call on routeID with an
// envelope of evidenceBytes (enrichbudget.WorstCaseTokens over the route's
// own output cap). A route the registry does not hold refuses (fail closed).
func holdForRouteTx(ctx context.Context, tx pgx.Tx, routeID string, evidenceBytes int64) (int64, error) {
	var maxOut int
	e := tx.QueryRow(ctx, `SELECT max_output_tokens FROM route_registry WHERE route_id = $1`, routeID).Scan(&maxOut)
	if errors.Is(e, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: route %q not found", ErrTokenHoldMissing, routeID)
	}
	if e != nil {
		return 0, fmt.Errorf("read route output cap: %w", e)
	}
	return enrichbudget.WorstCaseTokens(evidenceBytes, maxOut), nil
}

// lockTokenWindowTx ensures one token-window row exists, locks it and returns
// its committed tokens.
func lockTokenWindowTx(ctx context.Context, tx pgx.Tx, accountID, feature, kind, key string) (int64, error) {
	if _, e := tx.Exec(ctx,
		`INSERT INTO usage_token_windows (account_id, feature, window_kind, window_key)
		 VALUES ($1::uuid, $2, $3, $4)
		 ON CONFLICT (account_id, feature, window_kind, window_key) DO NOTHING`,
		accountID, feature, kind, key); e != nil {
		return 0, fmt.Errorf("ensure %s token window: %w", kind, e)
	}
	var committed int64
	if e := tx.QueryRow(ctx,
		`SELECT committed_tokens FROM usage_token_windows
		  WHERE account_id = $1::uuid AND feature = $2 AND window_kind = $3 AND window_key = $4
		  FOR UPDATE`,
		accountID, feature, kind, key).Scan(&committed); e != nil {
		return 0, fmt.Errorf("lock %s token window: %w", kind, e)
	}
	return committed, nil
}

// adjustTokenWindowTx adds delta (negative refunds) to one token window,
// never below zero.
func adjustTokenWindowTx(ctx context.Context, tx pgx.Tx, accountID, feature, kind, key string, delta int64) error {
	if delta == 0 {
		return nil
	}
	if _, e := tx.Exec(ctx,
		`UPDATE usage_token_windows SET committed_tokens = greatest(committed_tokens + $5, 0), updated_at = now()
		  WHERE account_id = $1::uuid AND feature = $2 AND window_kind = $3 AND window_key = $4`,
		accountID, feature, kind, key, delta); e != nil {
		return fmt.Errorf("adjust %s token window: %w", kind, e)
	}
	return nil
}

// lockConcurrencyTx ensures the account's live in-flight counter exists,
// locks it and returns how many jobs are in flight.
func lockConcurrencyTx(ctx context.Context, tx pgx.Tx, accountID, feature string, capNow int) (int64, error) {
	if _, e := tx.Exec(ctx,
		`INSERT INTO usage_cycles (account_id, feature, cycle_kind, window_key, cap, used)
		 VALUES ($1::uuid, $2, 'concurrency', $3, $4, 0)
		 ON CONFLICT (account_id, feature, cycle_kind, window_key) DO NOTHING`,
		accountID, feature, concurrencyWindowKey, capNow); e != nil {
		return 0, fmt.Errorf("ensure concurrency cycle: %w", e)
	}
	var used int64
	if e := tx.QueryRow(ctx,
		`SELECT used FROM usage_cycles
		  WHERE account_id = $1::uuid AND feature = $2 AND cycle_kind = 'concurrency' AND window_key = $3
		  FOR UPDATE`,
		accountID, feature, concurrencyWindowKey).Scan(&used); e != nil {
		return 0, fmt.Errorf("lock concurrency cycle: %w", e)
	}
	return used, nil
}

// lockSessionLedgerTx locks a session's row and returns the tokens its
// enrichments have committed so far (the per-session ledger).
func lockSessionLedgerTx(ctx context.Context, tx pgx.Tx, accountID, sessionPK string) (int64, error) {
	var committed int64
	e := tx.QueryRow(ctx,
		`SELECT enrichment_tokens_committed FROM cloud_sessions
		  WHERE account_id = $1::uuid AND id = $2::uuid FOR UPDATE`,
		accountID, sessionPK).Scan(&committed)
	if errors.Is(e, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: session %s not found", ErrTokenHoldMissing, sessionPK)
	}
	if e != nil {
		return 0, fmt.Errorf("lock session ledger: %w", e)
	}
	return committed, nil
}

// adjustSessionLedgerTx adds delta (negative refunds) to a session's ledger,
// never below zero. A session the account deleted meanwhile adjusts nothing.
func adjustSessionLedgerTx(ctx context.Context, tx pgx.Tx, accountID, sessionPK string, delta int64) error {
	if delta == 0 || sessionPK == "" {
		return nil
	}
	if _, e := tx.Exec(ctx,
		`UPDATE cloud_sessions SET enrichment_tokens_committed = greatest(enrichment_tokens_committed + $3, 0)
		  WHERE account_id = $1::uuid AND id = $2::uuid`,
		accountID, sessionPK, delta); e != nil {
		return fmt.Errorf("adjust session ledger: %w", e)
	}
	return nil
}

// lockPoolTx locks the budget pool and refuses when its unit count or its USD
// spend ceiling is reached (the count path's exact checks).
func lockPoolTx(ctx context.Context, tx pgx.Tx, pool string, now time.Time, ceilings map[string]SpendCeiling) error {
	var gCap, gUsed int64
	e := tx.QueryRow(ctx, `SELECT cap, used FROM budget_pools WHERE pool = $1 FOR UPDATE`, pool).Scan(&gCap, &gUsed)
	if errors.Is(e, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %s", ErrBudgetPoolMissing, pool)
	}
	if e != nil {
		return fmt.Errorf("lock budget pool %s: %w", pool, e)
	}
	if err := refusal(unitHold("pool", gCap, gUsed)); err != nil {
		return err
	}
	return checkSpendCeilingTx(ctx, tx, ceilings, pool, now)
}

// reserveTokensTx takes one token reservation: every cap is read under its
// lock first, the reserve core decides over all of them at once, and only an
// admitted hold is written.
func reserveTokensTx(ctx context.Context, tx pgx.Tx, accountID, feature, sessionPK string, hold int64, allow Allowance, now time.Time, ceilings map[string]SpendCeiling) (string, error) {
	if hold <= 0 || sessionPK == "" {
		return "", ErrTokenHoldMissing
	}
	tier := *allow.Tier
	daily, monthly := DailyWindowKey(now), MonthlyWindowKey(now)

	// Canonical order (see the file comment): session ledger, then the
	// windows, then concurrency; the pool after admission.
	var used enrichbudget.Committed
	var err error
	if used.Session, err = lockSessionLedgerTx(ctx, tx, accountID, sessionPK); err != nil {
		return "", err
	}
	if used.Daily, err = lockTokenWindowTx(ctx, tx, accountID, feature, "daily", daily); err != nil {
		return "", err
	}
	if used.Monthly, err = lockTokenWindowTx(ctx, tx, accountID, feature, "monthly", monthly); err != nil {
		return "", err
	}
	if used.InFlight, err = lockConcurrencyTx(ctx, tx, accountID, feature, allow.ConcurrencyCap); err != nil {
		return "", err
	}
	caps := enrichbudget.Caps{
		Daily: tier.DailyTokens, Monthly: tier.MonthlyTokens, Session: tier.SessionTokens,
		Concurrency: int64(allow.ConcurrencyCap),
	}
	if d := enrichbudget.Admit(caps, used, hold); !d.Admitted {
		if d.Refused != nil {
			if e, ok := capRefusals()[d.Refused.Name]; ok {
				return "", e
			}
		}
		return "", ErrTokenHoldMissing
	}
	if err := lockPoolTx(ctx, tx, allow.BudgetPool, now, ceilings); err != nil {
		return "", err
	}

	// Admitted: write the hold in the same order the locks were taken.
	if err := adjustSessionLedgerTx(ctx, tx, accountID, sessionPK, hold); err != nil {
		return "", err
	}
	if err := adjustTokenWindowTx(ctx, tx, accountID, feature, "daily", daily, hold); err != nil {
		return "", err
	}
	if err := adjustTokenWindowTx(ctx, tx, accountID, feature, "monthly", monthly, hold); err != nil {
		return "", err
	}
	if _, e := tx.Exec(ctx,
		`UPDATE usage_cycles SET used = used + 1, cap = $4, updated_at = now()
		  WHERE account_id = $1::uuid AND feature = $2 AND cycle_kind = 'concurrency' AND window_key = $3`,
		accountID, feature, concurrencyWindowKey, allow.ConcurrencyCap); e != nil {
		return "", fmt.Errorf("bump concurrency cycle: %w", e)
	}
	if _, e := tx.Exec(ctx,
		`UPDATE budget_pools SET used = used + 1, updated_at = now() WHERE pool = $1`, allow.BudgetPool); e != nil {
		return "", fmt.Errorf("bump budget pool %s: %w", allow.BudgetPool, e)
	}

	var reservationID string
	if e := tx.QueryRow(ctx,
		`INSERT INTO usage_reservations (account_id, feature, state, user_units, daily_window, monthly_window,
		                                 budget_pool, budget_unit, token_hold, session_pk)
		 VALUES ($1::uuid, $2, 'reserved', 1, $3, $4, $5, $6, $7, $8::uuid) RETURNING id::text`,
		accountID, feature, daily, monthly, allow.BudgetPool, budgetUnitTokens, hold, sessionPK).Scan(&reservationID); e != nil {
		return "", fmt.Errorf("insert reservation: %w", e)
	}
	if err := appendLedgerTx(ctx, tx, accountID, ledgerEntry{
		Event: "reserve", UserUnits: 1,
		Detail: fmt.Sprintf(`{"scope":"reserve","unit":"tokens","hold":%d,"tier":%q,"tier_version":%d}`, hold, tier.Name, tier.Version),
	}); err != nil {
		return "", err
	}
	return reservationID, nil
}

// finalizeTokenReservationTx closes a token reservation: the reserve core
// decides what the hold books (settle: the actual, or the hold when the meter
// is missing; release/expiry: nothing), and the difference from the hold is
// written back to every window the hold was counted in.
func finalizeTokenReservationTx(ctx context.Context, tx pgx.Tx, accountID string, r heldReservation, newState string, outcome reserve.Outcome, refundUnit bool, actualTokens float64) error {
	hold := reserve.Hold{State: reserve.HoldFinal, Estimate: float64(r.tokenHold)}
	if r.state == "reserved" {
		hold.State = reserve.HoldOpen
	}
	settlement, err := reserve.Settle(hold, reserve.Close{Outcome: outcome, Actual: actualTokens})
	if err != nil {
		return fmt.Errorf("cloudserver/store.finalizeReservation: %w", err)
	}
	if settlement.Noop {
		return nil
	}
	booked := int64(math.Ceil(settlement.Booked))
	delta := booked - r.tokenHold
	if _, e := tx.Exec(ctx,
		`UPDATE usage_reservations SET state = $3, updated_at = now() WHERE account_id = $1::uuid AND id = $2::uuid`,
		accountID, r.id, newState); e != nil {
		return fmt.Errorf("update reservation: %w", e)
	}
	// Canonical order (see the file comment): the session ledger before the
	// windows, exactly as a submission takes them.
	if r.sessionPK != nil {
		if err := adjustSessionLedgerTx(ctx, tx, accountID, *r.sessionPK, delta); err != nil {
			return err
		}
	}
	if err := adjustTokenWindowTx(ctx, tx, accountID, r.feature, "daily", r.daily, delta); err != nil {
		return err
	}
	if err := adjustTokenWindowTx(ctx, tx, accountID, r.feature, "monthly", r.monthly, delta); err != nil {
		return err
	}
	if settlement.FreesSlot {
		if err := decrementCycle(ctx, tx, accountID, r.feature, "concurrency", concurrencyWindowKey, r.units); err != nil {
			return err
		}
	}
	if refundUnit {
		// The pool's unit goes back exactly as on the count path, to the pool
		// the reservation drew from.
		if _, e := tx.Exec(ctx,
			`UPDATE budget_pools SET used = greatest(used - $2, 0), updated_at = now() WHERE pool = $1`,
			r.pool, r.units); e != nil {
			return fmt.Errorf("refund budget pool %s: %w", r.pool, e)
		}
	}
	return appendLedgerTx(ctx, tx, accountID, ledgerEntry{
		Event: newState, UserUnits: 0,
		Detail: fmt.Sprintf(`{"refund":%t,"unit":"tokens","hold":%d,"booked":%d,"rule":%q}`, refundUnit, r.tokenHold, booked, settlement.Rule),
	})
}
