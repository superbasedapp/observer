package db

// db_resume_test.go covers plan 07 row E1.2: the runner commits each step in
// its own transaction, so a failure at step N leaves steps below N applied
// and recorded, a rerun resumes at N, and each step's migcheck label is
// recorded next to its version. The tests stage a small lineage in a MapFS
// and drive migrateEntries directly.

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg/pgthrow"
)

// stagedLineage is a three-step lineage; broken3 is step 3's failing body.
func stagedLineage(step3 string) fstest.MapFS {
	return fstest.MapFS{
		"0001_a.sql": {Data: []byte("-- step: expand\nCREATE TABLE e12_a (id int);\n")},
		"0002_b.sql": {Data: []byte("-- step: data\nINSERT INTO e12_a VALUES (1);\n")},
		"0003_c.sql": {Data: []byte(step3)},
		"0004_d.sql": {Data: []byte("-- step: expand\nCREATE TABLE e12_d (id int);\n")},
	}
}

func TestMigrateResumesAtFailedStepAndRecordsLabels(t *testing.T) {
	t.Parallel()
	pool := pgthrow.NewEmptyDB(t, "sbci_e12_resume_")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	broken := stagedLineage("-- step: contract\nCREATE TABLE e12_c (id int);\nSELECT * FROM e12_missing;\n")
	entries, err := readEntriesFrom(broken)
	if err != nil {
		t.Fatalf("readEntriesFrom: %v", err)
	}
	if err := migrateEntries(ctx, pool, MigrateOptions{}, broken, entries); err == nil {
		t.Fatal("migrate of a lineage with a failing step 3 succeeded")
	} else if !strings.Contains(err.Error(), "migration 3") {
		t.Fatalf("error does not name step 3: %v", err)
	}

	// Steps 1-2 are committed and recorded; step 3 left nothing behind.
	if v, err := Version(ctx, pool); err != nil || v != 2 {
		t.Fatalf("Version after failure = %d err=%v, want 2", v, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM e12_a`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("e12_a rows = %d err=%v, want 1 (steps 1-2 stay committed)", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE tablename IN ('e12_c','e12_d')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("e12_c/e12_d tables = %d err=%v, want 0 (failed step rolled back, later step not reached)", n, err)
	}

	// Fix step 3 and rerun: it resumes at 3 and applies 3 onward.
	fixed := stagedLineage("-- step: contract\nCREATE TABLE e12_c (id int);\n")
	entries, err = readEntriesFrom(fixed)
	if err != nil {
		t.Fatalf("readEntriesFrom fixed: %v", err)
	}
	if err := migrateEntries(ctx, pool, MigrateOptions{}, fixed, entries); err != nil {
		t.Fatalf("rerun with step 3 fixed: %v", err)
	}
	if v, err := Version(ctx, pool); err != nil || v != 4 {
		t.Fatalf("Version after rerun = %d err=%v, want 4", v, err)
	}
	// A second rerun is a no-op.
	if err := migrateEntries(ctx, pool, MigrateOptions{}, fixed, entries); err != nil {
		t.Fatalf("idempotent rerun: %v", err)
	}

	// Labels round-trip, one case per step.
	for _, tc := range []struct {
		version int
		want    string
	}{{1, "expand"}, {2, "data"}, {3, "contract"}, {4, "expand"}} {
		got, applied, err := StepLabel(ctx, pool, tc.version)
		if err != nil || !applied || got != tc.want {
			t.Errorf("StepLabel(%d) = %q applied=%v err=%v, want %q", tc.version, got, applied, err, tc.want)
		}
	}
	if _, applied, err := StepLabel(ctx, pool, 99); err != nil || applied {
		t.Errorf("StepLabel(99) applied=%v err=%v, want not applied", applied, err)
	}
}

func TestMigrateRefusesNonTransactionalStep(t *testing.T) {
	t.Parallel()
	pool := pgthrow.NewEmptyDB(t, "sbci_e12_nontx_")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	src := fstest.MapFS{
		"0001_a.sql": {Data: []byte("-- step: expand\nCREATE TABLE e12_nt_a (id int);\n")},
		"0002_b.sql": {Data: []byte("-- step: contract non-transactional\nCREATE TABLE e12_nt_b (id int);\n")},
	}
	entries, err := readEntriesFrom(src)
	if err != nil {
		t.Fatalf("readEntriesFrom: %v", err)
	}
	err = migrateEntries(ctx, pool, MigrateOptions{}, src, entries)
	if err == nil || !strings.Contains(err.Error(), "non-transactional") {
		t.Fatalf("migrate error = %v, want a non-transactional refusal", err)
	}
	if v, verr := Version(ctx, pool); verr != nil || v != 1 {
		t.Fatalf("Version = %d err=%v, want 1 (step 1 applied, step 2 refused)", v, verr)
	}
}

func TestMigrateAddsLabelColumnToExistingLedger(t *testing.T) {
	t.Parallel()
	pool := pgthrow.NewEmptyDB(t, "sbci_e12_upgrade_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// migratePrefix writes the OLD ledger shape (no label column), standing
	// in for a production database at schema 44.
	if err := migratePrefix(ctx, pool, 44); err != nil {
		t.Fatalf("migratePrefix 44: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate over an old-shape ledger: %v", err)
	}
	head, err := MaxEmbeddedVersion()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := Version(ctx, pool); err != nil || v != head {
		t.Fatalf("Version = %d err=%v, want %d", v, err, head)
	}
	if got, applied, err := StepLabel(ctx, pool, 44); err != nil || !applied || got != "" {
		t.Errorf("StepLabel(44) = %q applied=%v err=%v, want empty label (pre-migcheck)", got, applied, err)
	}
	if got, applied, err := StepLabel(ctx, pool, 45); err != nil || !applied || got != "expand" {
		t.Errorf("StepLabel(45) = %q applied=%v err=%v, want expand", got, applied, err)
	}
	if got, applied, err := StepLabel(ctx, pool, 46); err != nil || !applied || got != "contract" {
		t.Errorf("StepLabel(46) = %q applied=%v err=%v, want contract", got, applied, err)
	}
}
