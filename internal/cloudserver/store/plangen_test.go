package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// generatorExec runs one statement in a transaction marked as the plans
// generator (what 0084's trigger lets through), for drift fixtures.
func generatorExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('sbci.plan_writer', 'generator', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestGeneratePlansOnAMigratedDatabaseIsANoOp: the migrations already hold
// the catalog's rows, so the generator inserts nothing and finds no drift.
func TestGeneratePlansOnAMigratedDatabaseIsANoOp(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	rep, err := store.GeneratePlans(ctx, pool)
	if err != nil {
		t.Fatalf("GeneratePlans: %v", err)
	}
	if len(rep.Inserted) != 0 || strings.Join(rep.Unchanged, ",") != "free v5,plus_beta v5" {
		t.Fatalf("report = %+v", rep)
	}
	drift, err := store.CheckPlans(ctx, pool)
	if err != nil || len(drift) != 0 {
		t.Fatalf("CheckPlans = %v, %v", drift, err)
	}
	// Idempotent.
	if _, err := store.GeneratePlans(ctx, pool); err != nil {
		t.Fatalf("second GeneratePlans: %v", err)
	}
}

// TestPlansRefuseAnInsertOutsideTheGenerator: 0084's trigger refuses an
// insert by the table's owner whose transaction is not the generator's.
func TestPlansRefuseAnInsertOutsideTheGenerator(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	_, err := pool.Exec(context.Background(),
		`INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap, budget_pool)
		 VALUES ('hand_written', 1, 'Hand', 1, 1, 1, 'free')`)
	if err == nil || !strings.Contains(err.Error(), "generated from the entitlements plan catalog") {
		t.Fatalf("a hand insert = %v, want the trigger's refusal", err)
	}
}

// TestGeneratePlansInsertsAMissingRow: a catalog row missing from the table
// is inserted with exactly its projected values.
func TestGeneratePlansInsertsAMissingRow(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DELETE FROM plans WHERE name = 'plus_beta' AND version = 5`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	drift, err := store.CheckPlans(ctx, pool)
	if err != nil || len(drift) != 1 || !drift[0].Missing || drift[0].Name != "plus_beta" {
		t.Fatalf("CheckPlans before = %+v, %v", drift, err)
	}
	rep, err := store.GeneratePlans(ctx, pool)
	if err != nil {
		t.Fatalf("GeneratePlans: %v", err)
	}
	if strings.Join(rep.Inserted, ",") != "plus_beta v5" || strings.Join(rep.Unchanged, ",") != "free v5" {
		t.Fatalf("report = %+v", rep)
	}
	if drift, err := store.CheckPlans(ctx, pool); err != nil || len(drift) != 0 {
		t.Fatalf("CheckPlans after = %+v, %v", drift, err)
	}
}

// TestGeneratePlansRefusesDrift: a row that differs from its template is
// refused (rows are immutable, so it is never rewritten) and the run writes
// nothing, including a missing row it would otherwise have inserted.
func TestGeneratePlansRefusesDrift(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DELETE FROM plans WHERE version = 5`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	generatorExec(t, pool,
		`INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap, budget_pool,
		                    results_retention_days, route_id, enrichment_tier)
		 VALUES ('free', 5, 'Signed-in Free', 99, 3000, 2, 'free', 30, 'session_enrichment.claude-haiku-5-5.v1', 'free')`)
	drift, err := store.CheckPlans(ctx, pool)
	if err != nil || len(drift) != 2 {
		t.Fatalf("CheckPlans = %+v, %v", drift, err)
	}
	if drift[0].Missing || !strings.Contains(strings.Join(drift[0].Diff, ","), "daily_cap 99 != catalog 100") {
		t.Fatalf("free drift = %+v", drift[0])
	}
	if _, err := store.GeneratePlans(ctx, pool); !errors.Is(err, store.ErrPlanDrift) {
		t.Fatalf("GeneratePlans over drift = %v, want ErrPlanDrift", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM plans WHERE name = 'plus_beta' AND version = 5`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused run wrote plus_beta v5 (count %d, %v)", n, err)
	}
}
