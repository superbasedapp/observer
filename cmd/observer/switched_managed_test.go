package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// switchNode turns a fixture's managed enrolment into the shape a teams to
// enterprise switch leaves: an INDIVIDUAL enrolment holding the org's
// managed-consent fleet replacement (generation gen, the given authority;
// gen 0 is the enrolment-time grant, i.e. not switched).
func switchNode(t *testing.T, dbPath string, gen int64, authority []string) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		t.Fatalf("enrolment: %v", err)
	}
	enr.Tenancy = orgcontract.TenancyIndividual
	if err := st.WriteEnrolment(ctx, *enr); err != nil {
		t.Fatal(err)
	}
	key := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	row, ok, err := st.LoadEnrolmentGrant(ctx, key)
	if err != nil || !ok {
		t.Fatalf("grant: ok=%v err=%v", ok, err)
	}
	row.ReplacementGeneration, row.Authority, row.ConsentMode = gen, authority, govern.ConsentManaged
	if err := st.WriteEnrolmentGrant(ctx, row); err != nil {
		t.Fatal(err)
	}
}

func openFixture(t *testing.T, dbPath string) *store.Store {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database)
}

// TestSwitchedNodeGetsManagedBehaviour (audit R1, operator ruling P-204): a
// node whose org switched it to enterprise holds an individual enrolment
// and the org's managed-consent replacement grant. It gets the managed
// behaviour at the budget launch gate, node intervention and the managed
// policy families, through the one node-side predicate; the same individual
// enrolment holding only its own enrolment-time grant (not switched), or the
// switch-back's narrowing grant, does not.
func TestSwitchedNodeGetsManagedBehaviour(t *testing.T) {
	budget := []string{govern.AuthorityEnforceBudget}
	cases := []struct {
		name    string
		gen     int64
		auth    []string
		managed bool
	}{
		{"switched", 1, budget, true},
		{"individual, not switched", 0, budget, false},
		{"switched back (narrowing grant)", 2, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
			switchNode(t, dbPath, c.gen, c.auth)
			st := openFixture(t, dbPath)

			if managed, err := orgclient.NodeManaged(ctx, st); err != nil || managed != c.managed {
				t.Fatalf("NodeManaged = %v, %v; want %v", managed, err, c.managed)
			}
			granted, _, err := resolveBudgetLaunchAuthority(ctx, st, false)
			if err != nil || granted != c.managed {
				t.Fatalf("budget launch authority = %v, %v; want %v", granted, err, c.managed)
			}
			decision, err := nodeInterventionAuthority(ctx, st, 1000, time.Now().UTC())
			if err != nil || decision.Authorized != c.managed {
				t.Fatalf("node intervention authorized = %v, %v; want %v", decision.Authorized, err, c.managed)
			}
		})
	}
}

// TestSwitchedNodeGetsManagedPolicyFamilies: the managed policy families
// backfill treats a switched node as managed (audit R1).
func TestSwitchedNodeGetsManagedPolicyFamilies(t *testing.T) {
	for _, c := range []struct {
		name string
		gen  int64
		want bool
	}{{"switched", 1, true}, {"individual, not switched", 0, false}} {
		t.Run(c.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "observer.db")
			st := writeManagedFamiliesFixture(t, dbPath, orgcontract.TenancyIndividual, govern.ConsentManaged, time.Now().Add(time.Hour))
			ctx := context.Background()
			enr, _ := st.LoadEnrolment(ctx)
			row, _, _ := st.LoadEnrolmentGrant(ctx, orgclient.OrgKey(enr.OrgServerURL, enr.OrgID))
			row.ReplacementGeneration = c.gen
			if err := st.WriteEnrolmentGrant(ctx, row); err != nil {
				t.Fatal(err)
			}
			facts, ok, err := loadManagedPolicyFacts(ctx, st, time.Now().UTC())
			if err != nil || ok != c.want {
				t.Fatalf("loadManagedPolicyFacts = %+v, %v, %v; want ok=%v", facts, ok, err, c.want)
			}
		})
	}
}
