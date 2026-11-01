package store_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The T-946 spend-ceiling suite: a budget pool's USD ceiling per UTC day and
// per UTC month bounds what open sign-up can cost.

func TestSpendCeilingsFromEnv(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		wantDay   float64
		wantMonth float64
		wantErr   string
	}{
		{name: "defaults", env: map[string]string{}, wantDay: 5, wantMonth: 50},
		{name: "both overridden", env: map[string]string{store.EnvFreePoolDailyUSD: "2.5", store.EnvFreePoolMonthlyUSD: " 20 "}, wantDay: 2.5, wantMonth: 20},
		{name: "daily only", env: map[string]string{store.EnvFreePoolDailyUSD: "1"}, wantDay: 1, wantMonth: 50},
		{name: "zero refused (no off switch)", env: map[string]string{store.EnvFreePoolDailyUSD: "0"}, wantErr: store.EnvFreePoolDailyUSD},
		{name: "negative refused", env: map[string]string{store.EnvFreePoolMonthlyUSD: "-1"}, wantErr: store.EnvFreePoolMonthlyUSD},
		{name: "garbage refused", env: map[string]string{store.EnvFreePoolDailyUSD: "five"}, wantErr: store.EnvFreePoolDailyUSD},
		{name: "NaN refused", env: map[string]string{store.EnvFreePoolDailyUSD: "NaN"}, wantErr: store.EnvFreePoolDailyUSD},
		{name: "Inf refused", env: map[string]string{store.EnvFreePoolDailyUSD: "Inf"}, wantErr: store.EnvFreePoolDailyUSD},
		{name: "typo-sized refused", env: map[string]string{store.EnvFreePoolMonthlyUSD: "5000000"}, wantErr: store.EnvFreePoolMonthlyUSD},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.SpendCeilingsFromEnv(func(k string) string { return tc.env[k] })
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v, want one naming %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			c := got[store.FreeBudgetPool]
			if math.Abs(c.DailyUSD-tc.wantDay) > 1e-9 || math.Abs(c.MonthlyUSD-tc.wantMonth) > 1e-9 {
				t.Fatalf("free ceilings = %+v, want %v/%v", c, tc.wantDay, tc.wantMonth)
			}
			if _, ok := got["plus_beta"]; ok {
				t.Fatal("a paid pool must have no ceiling by default")
			}
		})
	}
}

// setSpend writes a pool window's spend directly (admin connection).
func setSpend(t *testing.T, pool *pgxpool.Pool, name, kind, key string, usd float64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO budget_pool_spend (pool, window_kind, window_key, spent_usd) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (pool, window_kind, window_key) DO UPDATE SET spent_usd = EXCLUDED.spent_usd`,
		name, kind, key, usd); err != nil {
		t.Fatalf("set spend: %v", err)
	}
}

func readSpend(t *testing.T, pool *pgxpool.Pool, name, kind, key string) float64 {
	t.Helper()
	var v float64
	if err := pool.QueryRow(context.Background(),
		`SELECT coalesce((SELECT spent_usd::float8 FROM budget_pool_spend WHERE pool=$1 AND window_kind=$2 AND window_key=$3), 0)`,
		name, kind, key).Scan(&v); err != nil {
		t.Fatalf("read spend: %v", err)
	}
	return v
}

// TestSpendCeilingRefusesReservation is the reservation half, table-driven over
// the window state: a reached daily or monthly ceiling refuses with
// ErrSpendCeiling (which is also ErrGlobalBudget, so the API answers 503
// budget_exhausted), and yesterday's spend does not count today.
func TestSpendCeilingRefusesReservation(t *testing.T) {
	now := midMonth()
	day, month := store.DailyWindowKey(now), store.MonthlyWindowKey(now)
	yesterday := store.DailyWindowKey(now.AddDate(0, 0, -1))
	cases := []struct {
		name    string
		daily   map[string]float64 // window_key -> spend
		monthly float64
		blocked bool
	}{
		{name: "nothing spent", blocked: false},
		{name: "under both", daily: map[string]float64{day: 4.99}, monthly: 30, blocked: false},
		{name: "daily reached", daily: map[string]float64{day: 5}, monthly: 5, blocked: true},
		{name: "monthly reached", daily: map[string]float64{day: 0.5}, monthly: 50, blocked: true},
		{name: "yesterday does not count", daily: map[string]float64{yesterday: 9}, monthly: 9, blocked: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, pool := newStore(t)
			acct := makeAccount(t, s)
			for k, v := range tc.daily {
				setSpend(t, pool, store.FreeBudgetPool, "daily", k, v)
			}
			if tc.monthly > 0 {
				setSpend(t, pool, store.FreeBudgetPool, "monthly", month, tc.monthly)
			}
			before := poolBalance(t, pool, store.FreeBudgetPool)
			_, err := s.ReserveAllowance(context.Background(), acct, store.FeatureSessionEnrichment, now)
			if tc.blocked {
				if !errors.Is(err, store.ErrSpendCeiling) || !errors.Is(err, store.ErrGlobalBudget) {
					t.Fatalf("err=%v, want ErrSpendCeiling (and ErrGlobalBudget)", err)
				}
				if got := poolBalance(t, pool, store.FreeBudgetPool); got != before {
					t.Fatalf("a refused reservation moved the pool: %d -> %d", before, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("reservation refused: %v", err)
			}
		})
	}
}

// TestSpendCeilingConfigurable proves SetSpendCeilings is what the store
// enforces, and that a pool with no ceiling (plus_beta) is never blocked.
func TestSpendCeilingConfigurable(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := midMonth()
	setSpend(t, pool, store.FreeBudgetPool, "daily", store.DailyWindowKey(now), 1.0)
	setSpend(t, pool, "plus_beta", "daily", store.DailyWindowKey(now), 1000)

	s.SetSpendCeilings(map[string]store.SpendCeiling{store.FreeBudgetPool: {DailyUSD: 0.5, MonthlyUSD: 10}})
	free := makeAccount(t, s)
	if _, err := s.ReserveAllowance(ctx, free, store.FeatureSessionEnrichment, now); !errors.Is(err, store.ErrSpendCeiling) {
		t.Fatalf("free with a 0.5 ceiling and 1.0 spent: err=%v, want ErrSpendCeiling", err)
	}
	plus := makeAccount(t, s)
	if _, err := s.AssignPlan(ctx, plus, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	if _, err := s.ReserveAllowance(ctx, plus, store.FeatureSessionEnrichment, now); err != nil {
		t.Fatalf("plus_beta has no ceiling, reservation refused: %v", err)
	}
}

// TestReservationSpendAccumulates is the accounting half: spend recorded
// against a reservation lands in its pool's daily and monthly windows, the
// worker's pre-call check flips once the ceiling is reached, and an unknown
// or empty reservation is handled without guessing.
func TestReservationSpendAccumulates(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := midMonth()
	s.SetSpendCeilings(map[string]store.SpendCeiling{store.FreeBudgetPool: {DailyUSD: 0.01, MonthlyUSD: 1}})
	acct := makeAccount(t, s)
	rid, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	reached, err := s.SpendCeilingReachedForReservation(ctx, acct, rid, now)
	if err != nil || reached {
		t.Fatalf("fresh pool: reached=%v err=%v, want false", reached, err)
	}
	for _, usd := range []float64{0.004, 0.004, 0, -1, math.Inf(1)} {
		if err := s.AddReservationSpend(ctx, acct, rid, usd, now); err != nil {
			t.Fatalf("AddReservationSpend(%v): %v", usd, err)
		}
	}
	if got := readSpend(t, pool, store.FreeBudgetPool, "daily", store.DailyWindowKey(now)); math.Abs(got-0.008) > 1e-9 {
		t.Fatalf("daily spend = %v, want 0.008 (non-positive and infinite amounts add nothing)", got)
	}
	if got := readSpend(t, pool, store.FreeBudgetPool, "monthly", store.MonthlyWindowKey(now)); math.Abs(got-0.008) > 1e-9 {
		t.Fatalf("monthly spend = %v, want 0.008", got)
	}
	if reached, _ := s.SpendCeilingReachedForReservation(ctx, acct, rid, now); reached {
		t.Fatal("0.008 of a 0.01 ceiling must not block")
	}
	if err := s.AddReservationSpend(ctx, acct, rid, 0.002, now); err != nil {
		t.Fatalf("AddReservationSpend: %v", err)
	}
	if reached, err := s.SpendCeilingReachedForReservation(ctx, acct, rid, now); err != nil || !reached {
		t.Fatalf("at the ceiling: reached=%v err=%v, want true", reached, err)
	}
	// The next UTC day starts a new daily window; the month still has room.
	if reached, _ := s.SpendCeilingReachedForReservation(ctx, acct, rid, now.AddDate(0, 0, 1)); reached {
		t.Fatal("a new UTC day must start a fresh daily window")
	}
	if reached, err := s.SpendCeilingReachedForReservation(ctx, acct, "", now); err != nil || reached {
		t.Fatalf("empty reservation id: reached=%v err=%v, want false, nil", reached, err)
	}
	if err := s.AddReservationSpend(ctx, acct, "", 1, now); err != nil {
		t.Fatalf("empty reservation id must add nothing, got %v", err)
	}
	if _, err := s.SpendCeilingReachedForReservation(ctx, acct, "00000000-0000-0000-0000-000000000000", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown reservation: err=%v, want ErrNotFound", err)
	}
}
