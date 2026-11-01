package db

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/migplan"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger/ledgertest"
)

// nodeRunner drives the node runner over an explicit lineage (T-979).
func nodeRunner(ctx context.Context, d *sql.DB, source fs.FS, late []migplan.LateStep) error {
	return runMigrationsFrom(ctx, d, defaultMigrationLockWait, source, late)
}

// TestNodeLedgerScenarios holds the node runner to the shared per-step ledger
// contract: fresh, contiguous, a missing lower step, a step that did run, the
// pre-ledger late-step probe, and a failing late step rolling back.
func TestNodeLedgerScenarios(t *testing.T) {
	ledgertest.Scenarios(t, "db.runMigrations", nodeRunner)
}

// TestNodePreLedgerReopenAdoptsRealLineage pins that every existing node
// database (written by a runner older than T-979) keeps its schema: the real
// lineage is adopted step by step and nothing executes.
func TestNodePreLedgerReopenAdoptsRealLineage(t *testing.T) {
	ledgertest.PreLedgerReopen(t, nodeRunner, migrations.Files, lateSteps)
}

// The node late-step table holds exactly the wave lineage fork's two rows;
// TestNodeLateStepsAreTheWaveFork (migration_wavefork_test.go) pins it.

// openLedgerDB opens a fresh, fully migrated node database and returns it
// with the version of the highest step below the head that is not a late
// step: a late step's probe adopts it when its column exists, so deleting its
// record plans nothing (lateSteps).
func openLedgerDB(t *testing.T) (*sql.DB, int) {
	t.Helper()
	d, err := Open(context.Background(), Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	entries, err := readMigrationEntries()
	if err != nil || len(entries) < 2 {
		t.Fatalf("lineage: %v (%d entries)", err, len(entries))
	}
	late := map[int]bool{}
	for _, s := range lateSteps {
		late[s.Version] = true
	}
	for i := len(entries) - 2; i >= 0; i-- {
		if !late[entries[i].version] {
			return d, entries[i].version
		}
	}
	t.Fatal("lineage: no ordinary step below the head")
	return nil, 0
}

// TestPlanMigrationsReportsAPendingLowerStep pins the read-only plan seam
// doctor uses: a current database plans nothing, and one missing the record
// of a step below its version plans exactly that step, without writing.
func TestPlanMigrationsReportsAPendingLowerStep(t *testing.T) {
	ctx := context.Background()
	d, k := openLedgerDB(t)
	plan, err := PlanMigrations(ctx, d)
	if err != nil {
		t.Fatalf("PlanMigrations: %v", err)
	}
	if !plan.Noop() {
		t.Fatalf("current database plans work: %+v", plan)
	}
	if _, err := d.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, migplan.StepKey(k)); err != nil {
		t.Fatal(err)
	}
	plan, err = PlanMigrations(ctx, d)
	if err != nil {
		t.Fatalf("PlanMigrations: %v", err)
	}
	if got := plan.RunVersions(); !reflect.DeepEqual(got, []int{k}) {
		t.Fatalf("pending = %v, want [%d]", got, k)
	}
	if v, _ := Version(ctx, d); v != LatestSchemaVersion() {
		t.Fatalf("Version = %d, want the head %d (a lower pending step does not lower it)", v, LatestSchemaVersion())
	}
	var n int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_meta WHERE key = ?`, migplan.StepKey(k)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("PlanMigrations wrote a record (n=%d, err=%v)", n, err)
	}
}

// TestDeferralCoversALateStep pins that a CLI under a running daemon defers a
// step pending BELOW the recorded version exactly like one above it, so only
// the daemon that owns the database runs it.
func TestDeferralCoversALateStep(t *testing.T) {
	ctx := context.Background()
	d, k := openLedgerDB(t)
	path := filepath.Join(t.TempDir(), "late.db")
	if _, err := d.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		t.Fatalf("copy: %v", err)
	}
	cp, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, migplan.StepKey(k)); err != nil {
		t.Fatal(err)
	}
	_ = cp.Close()

	var calls, gotApplied, gotLatest int
	var gotPending []int
	SetMigrationDeferral(func(_ string, applied, latest int, pending []int) bool {
		calls++
		gotApplied, gotLatest, gotPending = applied, latest, pending
		return true
	})
	t.Cleanup(func() { SetMigrationDeferral(nil) })
	d2, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d2.Close()
	head := LatestSchemaVersion()
	if calls != 1 || gotApplied != head || gotLatest != head || !reflect.DeepEqual(gotPending, []int{k}) {
		t.Fatalf("deferral saw (%d, %d, %v) in %d calls, want (%d, %d, [%d]) once", gotApplied, gotLatest, gotPending, calls, head, head, k)
	}
	var n int
	if err := d2.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_meta WHERE key = ?`, migplan.StepKey(k)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a deferred Open recorded step %d (n=%d, err=%v)", k, n, err)
	}
}

// BenchmarkMigrationFastPath measures what every `observer` start and every
// hook process pays to confirm a current schema: the ledger plan (T-979)
// against the single point read it replaced.
func BenchmarkMigrationFastPath(b *testing.B) {
	ctx := context.Background()
	d, err := Open(ctx, Options{Path: filepath.Join(b.TempDir(), "observer.db")})
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer d.Close()
	b.Run("ledger plan (runMigrations on a current db)", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := runMigrations(ctx, d); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("lineage listing plus version point read (the old fast path)", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := readMigrationEntries(); err != nil {
				b.Fatal(err)
			}
			if _, err := currentVersion(ctx, d); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestAppliedStepsCountsRunsNotAdoptions pins the update rollback's seam
// (T-979): recording the ledger of a pre-ledger database adopts and leaves
// the count alone, and running a late step below the version raises it
// although the version does not move.
func TestAppliedStepsCountsRunsNotAdoptions(t *testing.T) {
	ctx := context.Background()
	late := []migplan.LateStep{{Version: 3, Table: "a", Column: "late_col"}}
	for _, tc := range []struct {
		name      string
		setup     []int
		wantDelta int
	}{
		{name: "adopt only (pre-ledger database that did run step 3)", setup: []int{1, 2, 3, 4}, wantDelta: 0},
		{name: "a late step runs (pre-ledger database without step 3)", setup: []int{1, 2, 4}, wantDelta: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ledgertest.OpenRaw(t)
			if err := nodeRunner(ctx, d, ledgertest.Lineage(tc.setup...), nil); err != nil {
				t.Fatalf("setup: %v", err)
			}
			ledgertest.StripLedger(t, d)
			before, err := AppliedSteps(ctx, d)
			if err != nil || before != 0 {
				t.Fatalf("pre-ledger AppliedSteps = %d, %v; want 0", before, err)
			}
			vBefore, _ := Version(ctx, d)
			if err := nodeRunner(ctx, d, ledgertest.Lineage(1, 2, 3, 4), late); err != nil {
				t.Fatalf("run: %v", err)
			}
			after, err := AppliedSteps(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			if after-before != tc.wantDelta {
				t.Fatalf("applied steps %d -> %d, want a delta of %d", before, after, tc.wantDelta)
			}
			if vAfter, _ := Version(ctx, d); vAfter != vBefore {
				t.Fatalf("version %d -> %d; the case needs an unchanged version", vBefore, vAfter)
			}
		})
	}
}
