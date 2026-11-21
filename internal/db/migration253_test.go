package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
)

const guardEventProjectFile = "253_guard_event_project.sql"

// TestMigration253GuardEventProject grades the GRANT-20 step: on a database
// that already holds guard events, 253 adds the two nullable project columns,
// leaves every existing row NULL (the request draft then falls back to the
// session's project) and touches no chain column, so stored chains verify
// unchanged.
func TestMigration253GuardEventProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observer.db")
	database, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer database.Close()
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, lineageWithout(t, guardEventProjectFile), lateSteps); err != nil {
		t.Fatalf("migrate to the step before 253: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO guard_events (ts, rule_id, chain_prev, chain_hash)
		VALUES ('2026-11-13T00:00:00Z', 'S-793', '', 'h1')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, migrations.Files, lateSteps); err != nil {
		t.Fatalf("migrate through 253: %v", err)
	}
	var hash, root sql.NullString
	var prev, chain string
	if err := database.QueryRowContext(ctx,
		`SELECT project_root_hash, project_root, chain_prev, chain_hash FROM guard_events WHERE rule_id = 'S-793'`).
		Scan(&hash, &root, &prev, &chain); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if hash.Valid || root.Valid {
		t.Errorf("existing row project = (%v, %v), want both NULL", hash, root)
	}
	if prev != "" || chain != "h1" {
		t.Errorf("chain columns changed: prev %q hash %q", prev, chain)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO guard_events (ts, rule_id, chain_prev, chain_hash, project_root_hash, project_root)
		VALUES ('2026-11-13T00:00:01Z', 'S-793', 'h1', 'h2', 'abc', '/r/repo')`); err != nil {
		t.Errorf("write the new columns: %v", err)
	}
}
