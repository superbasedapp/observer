package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
)

const cloudSyncLastTokenBudgetFile = "254_cloud_sync_last_token_budget.sql"

// TestMigration254CloudSyncLastTokenBudget grades the R-AI1 node step: on a
// database whose cloud_sync_last row already holds a sync outcome and plan,
// 254 adds the token-budget columns, keeps every existing value, and reads the
// new columns as empty / NULL (NULL evidence budget = never read, so the node
// fits to its default until the next sync).
func TestMigration254CloudSyncLastTokenBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observer.db")
	database, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer database.Close()
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, lineageWithout(t, cloudSyncLastTokenBudgetFile), lateSteps); err != nil {
		t.Fatalf("migrate to the step before 254: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO cloud_sync_last
		(id, started_at, finished_at, ok, sent, waiting_provider, reconfirm, failed, results,
		 sign_in_expired, error_class, plan_name, plan_label, daily_cap, monthly_cap)
		VALUES (1, '2026-11-13T00:00:00Z', '2026-11-13T00:00:01Z', 1, 2, 0, 0, 0, 3, 0, '', 'free', 'Free', 100, 3000)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, migrations.Files, lateSteps); err != nil {
		t.Fatalf("migrate through 254: %v", err)
	}
	var (
		plan, unit, tier string
		sent, dailyCap   int
		evidence, daily  sql.NullInt64
	)
	if err := database.QueryRowContext(ctx,
		`SELECT plan_name, sent, daily_cap, budget_unit, enrichment_tier, evidence_token_budget, daily_token_budget
		   FROM cloud_sync_last WHERE id = 1`).
		Scan(&plan, &sent, &dailyCap, &unit, &tier, &evidence, &daily); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if plan != "free" || sent != 2 || dailyCap != 100 {
		t.Errorf("existing values changed: plan %q sent %d daily_cap %d", plan, sent, dailyCap)
	}
	if unit != "" || tier != "" || evidence.Valid || daily.Valid {
		t.Errorf("new columns on an existing row = (%q, %q, %v, %v), want '' / NULL", unit, tier, evidence, daily)
	}
}
