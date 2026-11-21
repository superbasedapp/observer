package db

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/migplan"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger/ledgertest"
)

// assertLateStepRow grades one node lateSteps row of the main merge (P-247)
// on the two shapes its probe tells apart:
//
//   - column present: a database migrated through the whole lineage loses the
//     step's per-step record (a database that ran the same ALTER under the
//     step's old number has no record of the new one). The probe adopts the
//     step, so the runner records it adopted and never re-runs the ALTER,
//     which would fail with a duplicate column.
//   - column missing: a database migrated through every other step of the
//     lineage (version at the head, no record and no column for the step).
//     The probe runs the step, which adds the column and records it applied.
func assertLateStepRow(t *testing.T, version int, file, table, column string) {
	t.Helper()
	ctx := context.Background()
	var row *migplan.LateStep
	for i := range lateSteps {
		if lateSteps[i].Version == version {
			row = &lateSteps[i]
		}
	}
	if row == nil || row.Table != table || row.Column != column {
		t.Fatalf("lateSteps has no row %d on %s.%s (got %+v)", version, table, column, row)
	}
	key := migplan.StepKey(version)

	t.Run("column present: adopted, not run", func(t *testing.T) {
		d := ledgertest.OpenRaw(t)
		if err := nodeRunner(ctx, d, migrations.Files, lateSteps); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		if _, err := d.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, key); err != nil {
			t.Fatal(err)
		}
		plan := planFrom(ctx, t, d, migrations.Files, lateSteps)
		if len(plan.Steps) != 1 || plan.Steps[0].Version != version || plan.Steps[0].Action != migplan.ActionAdopt {
			t.Fatalf("plan = %+v, want only step %d adopted", plan.Steps, version)
		}
		if err := nodeRunner(ctx, d, migrations.Files, lateSteps); err != nil {
			t.Fatalf("merged run on a database that already ran the ALTER: %v", err)
		}
		if got := ledgertest.Meta(t, d)[key]; got != migplan.RecordAdopted {
			t.Fatalf("%s = %q, want adopted", key, got)
		}
	})

	t.Run("column missing: run", func(t *testing.T) {
		d := ledgertest.OpenRaw(t)
		if err := nodeRunner(ctx, d, lineageWithout(t, file), lateSteps); err != nil {
			t.Fatalf("migrate without %s: %v", file, err)
		}
		if hasColumn(ctx, t, d, table, column) {
			t.Fatalf("staged database already has %s.%s", table, column)
		}
		if v, _ := Version(ctx, d); v != LatestSchemaVersion() {
			t.Fatalf("staged version = %d, want the head %d", v, LatestSchemaVersion())
		}
		plan := planFrom(ctx, t, d, migrations.Files, lateSteps)
		if got := plan.RunVersions(); len(got) != 1 || got[0] != version {
			t.Fatalf("plan runs %v, want [%d]", got, version)
		}
		if err := nodeRunner(ctx, d, migrations.Files, lateSteps); err != nil {
			t.Fatalf("merged run: %v", err)
		}
		if got := ledgertest.Meta(t, d)[key]; got != migplan.RecordApplied {
			t.Fatalf("%s = %q, want applied", key, got)
		}
		if !hasColumn(ctx, t, d, table, column) {
			t.Fatalf("%s.%s missing after the run", table, column)
		}
	})
}

// TestLateStep220TerminalRunInitiator grades lateSteps row 220 (the release
// line's 214_terminal_run_initiator, renumbered at the main merge, P-247).
func TestLateStep220TerminalRunInitiator(t *testing.T) {
	t.Parallel()
	assertLateStepRow(t, 220, "220_terminal_run_initiator.sql", "terminal_run", "initiator")
}

// TestLateStep221ProjectQualityComplexity grades lateSteps row 221 (main's
// 216_project_quality_complexity, renumbered at the main merge, P-247).
func TestLateStep221ProjectQualityComplexity(t *testing.T) {
	t.Parallel()
	assertLateStepRow(t, 221, "221_project_quality_complexity.sql", "project_quality_daily", "complexity_state")
}
