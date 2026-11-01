//go:build !sbo_omit_security

package main

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/machineid"
)

// TestSwitchedNodeProvenanceNamesItsMachine (operator ruling P-205): the
// org server certifies a switched member's change key as managed, so the
// key's provenance names this machine on a switched node as on a managed
// enrolment; not switched, and switched back, it names none.
func TestSwitchedNodeProvenanceNamesItsMachine(t *testing.T) {
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
			st := openFixture(t, dbPath)
			enr, _ := st.LoadEnrolment(ctx)
			want := ""
			if c.managed {
				want, _ = machineid.ForOrg(enr.OrgID)
			}
			_, orgID, machine, err := (&provenanceSvc{st: st}).provenanceEnrolment(ctx)
			if err != nil || orgID != enr.OrgID || machine != want {
				t.Fatalf("provenance = org %q machine %q err %v; want org %q machine %q", orgID, machine, err, enr.OrgID, want)
			}
		})
	}
}
