package jobs_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// costlyInvalidExecutor is billed for every attempt but never produces an
// accepted result, like a route whose output always fails validation.
type costlyInvalidExecutor struct{ usd float64 }

func (e costlyInvalidExecutor) Execute(context.Context, *store.LeasedJob, store.RouteInfo, string, int, func() time.Time, jobs.FinalGate) (jobs.ExecResult, error) {
	return jobs.ExecResult{Outcome: jobs.ExecInvalidOutput, TokensIn: 10, TokensOut: 10, CostUSD: e.usd, Detail: "test"}, nil
}

// TestProcessOnceSpendCeilingParks: a job admitted before its pool reached the
// day's ceiling is parked budget_exhausted before any provider call, and its
// unit is refunded (T-946).
func TestProcessOnceSpendCeilingParks(t *testing.T) {
	s, pool, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	sub := submit(t, s, acct, "canon-spend", now)
	if _, err := pool.Exec(ctx,
		`INSERT INTO budget_pool_spend (pool, window_kind, window_key, spent_usd) VALUES ($1, 'daily', $2, 999)`,
		store.FreeBudgetPool, store.DailyWindowKey(now)); err != nil {
		t.Fatalf("seed spend: %v", err)
	}
	// Every other gate passes, and the executor would bill: the ceiling must
	// stop the job before the executor is entered.
	w := jobs.NewWorker(jobs.Config{WorkerID: "w1", LeaseFor: time.Hour},
		jobs.NewPGQueue(s), s, verifiedAttestor{}, jobs.StaticCredentials{Key: "k"},
		map[string]jobs.Executor{store.FeatureSessionEnrichment: costlyInvalidExecutor{usd: 1}})
	out, err := w.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "parked" || out.Reason != store.ReasonBudgetExhausted {
		t.Fatalf("want parked/budget_exhausted, got %+v", out)
	}
	snap, _ := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 0 {
		t.Fatalf("unit not refunded on park: daily=%d", snap.DailyUsed)
	}
	j, _ := s.GetJob(ctx, acct, sub.JobID)
	if j.State != "parked" {
		t.Fatalf("job state=%s, want parked", j.State)
	}
	var spent float64
	if err := pool.QueryRow(ctx, `SELECT spent_usd::float8 FROM budget_pool_spend WHERE pool=$1 AND window_kind='daily' AND window_key=$2`,
		store.FreeBudgetPool, store.DailyWindowKey(now)).Scan(&spent); err != nil {
		t.Fatalf("read spend: %v", err)
	}
	if spent != 999 {
		t.Fatalf("a parked job added spend: %v", spent)
	}
}

// TestRejectedAttemptsCountAgainstTheCeiling: a provider call whose output is
// rejected was still billed, so each attempt's cost lands in the pool's
// windows even though the job ends without a result.
func TestRejectedAttemptsCountAgainstTheCeiling(t *testing.T) {
	s, pool, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	submit(t, s, acct, "canon-attempts", now)
	w := jobs.NewWorker(jobs.Config{WorkerID: "w1", LeaseFor: time.Hour},
		jobs.NewPGQueue(s), s, verifiedAttestor{}, jobs.StaticCredentials{Key: "k"},
		map[string]jobs.Executor{store.FeatureSessionEnrichment: costlyInvalidExecutor{usd: 0.003}})
	out, err := w.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "failed" || out.Reason != store.ReasonProviderInvalidOutput {
		t.Fatalf("want failed/provider_invalid_output, got %+v", out)
	}
	for _, kind := range []struct{ kind, key string }{
		{"daily", store.DailyWindowKey(now)},
		{"monthly", store.MonthlyWindowKey(now)},
	} {
		var spent float64
		if err := pool.QueryRow(ctx, `SELECT spent_usd::float8 FROM budget_pool_spend WHERE pool=$1 AND window_kind=$2 AND window_key=$3`,
			store.FreeBudgetPool, kind.kind, kind.key).Scan(&spent); err != nil {
			t.Fatalf("read %s spend: %v", kind.kind, err)
		}
		// Two attempts (the default retry budget) at USD 0.003 each.
		if math.Abs(spent-0.006) > 1e-9 {
			t.Fatalf("%s spend = %v, want 0.006", kind.kind, spent)
		}
	}
}
