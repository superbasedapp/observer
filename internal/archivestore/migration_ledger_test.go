package archivestore

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/archivestore/migrations"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger/ledgertest"
)

// TestArchiveLedgerScenarios holds this runner to the shared per-step ledger
// contract (T-979): fresh, contiguous, a missing lower step, a step that did
// run, the pre-ledger late-step probe, and a failing late step rolling back.
func TestArchiveLedgerScenarios(t *testing.T) {
	ledgertest.Scenarios(t, "archivestore.runMigrations", runMigrationsFrom)
}

// TestArchivePreLedgerReopenAdoptsRealLineage pins that a database written by
// a runner older than T-979 keeps its schema: the real lineage is adopted step
// by step and nothing executes.
func TestArchivePreLedgerReopenAdoptsRealLineage(t *testing.T) {
	ledgertest.PreLedgerReopen(t, runMigrationsFrom, migrations.Files, lateSteps)
}

// TestArchiveLateStepsStartEmpty pins that no step of this lineage is listed as
// late: a row belongs there only for a real pre-ledger interleaving.
func TestArchiveLateStepsStartEmpty(t *testing.T) {
	if len(lateSteps) != 0 {
		t.Fatalf("lateSteps = %+v; add a row only for a real pre-ledger interleaving, with a staged test", lateSteps)
	}
}
