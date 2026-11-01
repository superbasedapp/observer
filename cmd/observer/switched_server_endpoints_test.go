package main

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSwitchedNodeIsManagedForOrgIntelAndTerminals (operator ruling P-205):
// the org server now admits a switched member's org intel as managed, so the
// node's org intel status treats it as managed (no developer consent asked,
// accept and withdraw refused as on a managed enrolment), and the standalone
// launcher's terminal gate fails closed on an unreadable policy as on any
// managed node. Not switched, and switched back, keep the individual answer.
func TestSwitchedNodeIsManagedForOrgIntelAndTerminals(t *testing.T) {
	budget := []string{govern.AuthorityEnforceBudget}
	for _, c := range []struct {
		name    string
		gen     int64
		auth    []string
		managed bool
	}{
		{"switched", 1, budget, true},
		{"individual, not switched", 0, budget, false},
		{"switched back (narrowing grant)", 2, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
			switchNode(t, dbPath, c.gen, c.auth)
			database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close() })
			st := store.New(database)

			snap, err := loadOrgIntelSnapshot(ctx, st, false, time.Now().UTC())
			if err != nil || snap.Inputs.Managed != c.managed {
				t.Fatalf("org intel managed = %v, %v; want %v", snap.Inputs.Managed, err, c.managed)
			}
			enr, _ := st.LoadEnrolment(ctx)
			if got := orgIntelNodeManaged(ctx, st, enr); got != c.managed {
				t.Fatalf("org intel consent actions see managed = %v, want %v", got, c.managed)
			}
			if got, err := launchNodeManaged(ctx, database); err != nil || got != c.managed {
				t.Fatalf("launcher terminal gate managed = %v, %v; want %v", got, err, c.managed)
			}
		})
	}
}
