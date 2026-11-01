package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Pool spend ceilings (T-946, open sign-up). A budget pool's `cap` (migration
// 0012) counts reservations over the pool's whole life and never resets, so
// with sign-up open to anyone it is no bound on what the provider bill can
// reach in a day. A spend ceiling is that bound: a USD ceiling per UTC day and
// per UTC calendar month on what the jobs of ONE pool cost, summed across
// every account that draws from it. The provider cost each job reports is
// added to the pool's two windows in budget_pool_spend (migration 0044); a
// new reservation is refused, and a queued job is parked before its provider
// call, once either window has reached its ceiling.
//
// The ceiling is checked BEFORE a call and the cost is only known AFTER it, so
// spend can pass a ceiling by what the jobs already in flight cost (at most
// the plan's concurrency per account, a fraction of a cent each on the Haiku
// route). It is a ceiling on the provider bill, not an exact meter.

// ErrSpendCeiling means the account's budget pool reached its daily or monthly
// USD ceiling. It wraps ErrGlobalBudget, so every caller that already treats
// an exhausted pool as "budget exhausted" (the API's 503, the digest
// scheduler's skip) treats a reached ceiling the same way without a change.
var ErrSpendCeiling = fmt.Errorf("%w: spend ceiling reached", ErrGlobalBudget)

// ReasonBudgetExhausted parks a queued job whose budget pool reached its spend
// ceiling after the job was admitted. The job's unit is refunded and nothing
// is sent to the provider.
const ReasonBudgetExhausted = "budget_exhausted"

// SpendCeiling is one pool's USD ceilings. Zero on a window means that window
// has no ceiling.
type SpendCeiling struct {
	DailyUSD   float64
	MonthlyUSD float64
}

// Default Free-pool ceilings: USD 5 per UTC day and USD 50 per UTC month
// across every Signed-in Free account. At the measured cost of one Haiku
// enrichment (about USD 0.001, D-776) that is several thousand jobs a day,
// well above the demo's real load, and a hard stop on a sign-up flood.
const (
	DefaultFreeDailyUSD   = 5.0
	DefaultFreeMonthlyUSD = 50.0
)

// Environment variables that override the Free pool's ceilings. Each is a
// positive decimal number of US dollars.
const (
	EnvFreePoolDailyUSD   = "SBCI_FREE_POOL_DAILY_USD"
	EnvFreePoolMonthlyUSD = "SBCI_FREE_POOL_MONTHLY_USD"
)

// maxCeilingUSD bounds a configured ceiling so a typo (an extra few zeros)
// is refused at startup rather than quietly removing the bound.
const maxCeilingUSD = 100000.0

// DefaultSpendCeilings is the ceiling table a Store enforces unless
// SetSpendCeilings replaces it. Only the Free pool has a ceiling: a paid pool
// is bounded by what its subscribers pay for.
func DefaultSpendCeilings() map[string]SpendCeiling {
	return map[string]SpendCeiling{
		FreeBudgetPool: {DailyUSD: DefaultFreeDailyUSD, MonthlyUSD: DefaultFreeMonthlyUSD},
	}
}

// SpendCeilingsFromEnv builds the ceiling table from the defaults and the two
// Free-pool overrides. An unset variable keeps the default; a set value that
// is not a positive, finite number at most maxCeilingUSD is an error (there
// is deliberately no way to switch the Free ceiling off by configuration).
func SpendCeilingsFromEnv(getenv func(string) string) (map[string]SpendCeiling, error) {
	out := DefaultSpendCeilings()
	free := out[FreeBudgetPool]
	for _, f := range []struct {
		name string
		dst  *float64
	}{
		{EnvFreePoolDailyUSD, &free.DailyUSD},
		{EnvFreePoolMonthlyUSD, &free.MonthlyUSD},
	} {
		raw := strings.TrimSpace(getenv(f.name))
		if raw == "" {
			continue
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || v > maxCeilingUSD {
			return nil, fmt.Errorf("%s=%q must be a positive number of US dollars, at most %.0f", f.name, raw, maxCeilingUSD)
		}
		*f.dst = v
	}
	out[FreeBudgetPool] = free
	return out, nil
}

// SetSpendCeilings replaces the ceiling table (at service bootstrap, from
// SpendCeilingsFromEnv). A nil table keeps the current one.
func (s *Store) SetSpendCeilings(c map[string]SpendCeiling) {
	if c != nil {
		s.spendCeilings = c
	}
}

// spendWindow is one row of the window table every spend read and write walks:
// the window kind stored in budget_pool_spend, its key for an instant, and the
// pool ceiling field it is measured against.
type spendWindow struct {
	kind    string
	key     func(time.Time) string
	ceiling func(SpendCeiling) float64
}

var spendWindows = []spendWindow{
	{kind: "daily", key: DailyWindowKey, ceiling: func(c SpendCeiling) float64 { return c.DailyUSD }},
	{kind: "monthly", key: MonthlyWindowKey, ceiling: func(c SpendCeiling) float64 { return c.MonthlyUSD }},
}

// ceilingReached is the pure decision: true when any window with a ceiling
// has spent at least that ceiling. spent maps a window kind to its spend.
func ceilingReached(c SpendCeiling, spent map[string]float64) bool {
	for _, w := range spendWindows {
		if lim := w.ceiling(c); lim > 0 && spent[w.kind] >= lim {
			return true
		}
	}
	return false
}

// checkSpendCeilingTx returns ErrSpendCeiling when pool has a ceiling and one
// of its current windows has reached it. A pool without a ceiling is never
// read.
func checkSpendCeilingTx(ctx context.Context, tx pgx.Tx, ceilings map[string]SpendCeiling, pool string, now time.Time) error {
	c, ok := ceilings[pool]
	if !ok {
		return nil
	}
	spent := map[string]float64{}
	for _, w := range spendWindows {
		var v float64
		e := tx.QueryRow(ctx,
			`SELECT spent_usd::float8 FROM budget_pool_spend WHERE pool = $1 AND window_kind = $2 AND window_key = $3`,
			pool, w.kind, w.key(now)).Scan(&v)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			return fmt.Errorf("read %s spend for pool %s: %w", w.kind, pool, e)
		}
		spent[w.kind] = v
	}
	if ceilingReached(c, spent) {
		return ErrSpendCeiling
	}
	return nil
}

// reservationPoolTx reads the budget pool a reservation drew from.
func reservationPoolTx(ctx context.Context, tx pgx.Tx, accountID, reservationID string) (string, error) {
	var pool string
	e := tx.QueryRow(ctx,
		`SELECT budget_pool FROM usage_reservations WHERE account_id = $1::uuid AND id = $2::uuid`,
		accountID, reservationID).Scan(&pool)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if e != nil {
		return "", fmt.Errorf("read reservation pool: %w", e)
	}
	return pool, nil
}

// addPoolSpendTx adds usd to every window of pool at now. A non-positive or
// non-finite amount adds nothing.
func addPoolSpendTx(ctx context.Context, tx pgx.Tx, pool string, usd float64, now time.Time) error {
	if !(usd > 0) || math.IsInf(usd, 0) {
		return nil
	}
	for _, w := range spendWindows {
		if _, e := tx.Exec(ctx,
			`INSERT INTO budget_pool_spend (pool, window_kind, window_key, spent_usd)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (pool, window_kind, window_key)
			 DO UPDATE SET spent_usd = budget_pool_spend.spent_usd + EXCLUDED.spent_usd, updated_at = now()`,
			pool, w.kind, w.key(now), usd); e != nil {
			return fmt.Errorf("add %s spend for pool %s: %w", w.kind, pool, e)
		}
	}
	return nil
}

// addReservationSpendTx adds usd to the windows of the pool reservationID drew
// from. An empty reservation id (a job admitted without one) adds nothing.
func addReservationSpendTx(ctx context.Context, tx pgx.Tx, accountID, reservationID string, usd float64, now time.Time) error {
	if reservationID == "" || !(usd > 0) {
		return nil
	}
	pool, err := reservationPoolTx(ctx, tx, accountID, reservationID)
	if err != nil {
		return err
	}
	return addPoolSpendTx(ctx, tx, pool, usd, now)
}

// AddReservationSpend records the provider cost of an attempt that produced no
// accepted result (an invalid output that is retried or failed), so a
// misbehaving route still counts against its pool's ceiling. An accepted
// result's cost is recorded inside CompleteJobWithResult's transaction.
func (s *Store) AddReservationSpend(ctx context.Context, accountID, reservationID string, usd float64, now time.Time) error {
	return s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return addReservationSpendTx(ctx, tx, accountID, reservationID, usd, now)
	})
}

// SpendCeilingReachedForReservation reports whether the pool reservationID
// drew from has reached its spend ceiling at now. The worker asks this before
// every provider attempt, so jobs queued before the ceiling was reached are
// parked instead of being sent. An empty reservation id is never blocked.
func (s *Store) SpendCeilingReachedForReservation(ctx context.Context, accountID, reservationID string, now time.Time) (bool, error) {
	if reservationID == "" {
		return false, nil
	}
	reached := false
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		pool, e := reservationPoolTx(ctx, tx, accountID, reservationID)
		if e != nil {
			return e
		}
		e = checkSpendCeilingTx(ctx, tx, s.spendCeilings, pool, now)
		if errors.Is(e, ErrSpendCeiling) {
			reached = true
			return nil
		}
		return e
	})
	return reached, err
}
