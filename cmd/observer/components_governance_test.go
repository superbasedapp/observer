package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodecomponents"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func managedGovernanceInputs(authority ...string) componentGovernanceInputs {
	now := time.Now()
	return componentGovernanceInputs{
		Enrolment: &store.Enrolment{OrgID: "o1", OrgName: "Acme", Tenancy: orgcontract.TenancyManaged},
		Grant: &govern.Grant{
			OrgKey: "k", Generation: 3, OrgName: "Acme", ConsentMode: govern.ConsentManaged,
			Authority: authority, ExpiresAt: now.Add(time.Hour),
		},
		Live:    govern.LiveIdentity{Enrolled: true, OrgKey: "k", Generation: 3},
		Now:     now,
		Ceiling: managedconfig.Result{Status: managedconfig.StatusNone, UpdatesAllowed: true},
	}
}

// TestResolveComponentGovernanceSources walks the cmd boundary's mapping of
// the enrolment and grant onto the nodecomponents sources (lane MP-GOV,
// T-677): individual and dormant nodes are not org-managed; a live managed
// grant is, with or without components.govern.
func TestResolveComponentGovernanceSources(t *testing.T) {
	expired := managedGovernanceInputs()
	expired.Grant.ExpiresAt = expired.Now.Add(-time.Minute)
	individual := managedGovernanceInputs()
	individual.Enrolment.Tenancy = orgcontract.TenancyIndividual
	// The boundary (grantFromStore) fills the grant's tenancy facts from
	// the enrolment; the enrolment-time grant is not a switch.
	individual.Grant.Tenancy, individual.Grant.EnrolmentOrgID = orgcontract.TenancyIndividual, "o1"
	// P-204: the same individual enrolment after its org switched it to
	// enterprise (the org's signed replacement, carrying authority).
	switched := managedGovernanceInputs(nodecomponents.Authority)
	switched.Enrolment.Tenancy = orgcontract.TenancyIndividual
	switched.Grant.Tenancy, switched.Grant.EnrolmentOrgID, switched.Grant.ReplacementGeneration = orgcontract.TenancyIndividual, "o1", 1
	withPolicy := managedGovernanceInputs(nodecomponents.Authority)
	spec, err := nodecomponents.Compile(nodecomponents.BodyV1{Allow: []string{"codeintel"}})
	if err != nil {
		t.Fatal(err)
	}
	withPolicy.Policy = &spec

	cases := []struct {
		name    string
		in      componentGovernanceInputs
		managed bool
		source  nodecomponents.Source
	}{
		{"not enrolled", componentGovernanceInputs{Now: time.Now()}, false, nodecomponents.SourceLocal},
		{"individual enrolment", individual, false, nodecomponents.SourceLocal},
		{"individual enrolment of a switched org: managed", switched, true, nodecomponents.SourceLegacyPinned},
		{"managed, grant expired: dormant", expired, false, nodecomponents.SourceDormant},
		{"managed, grant without components.govern: pinned", managedGovernanceInputs(), true, nodecomponents.SourceUnauthorized},
		{"managed, authorized, no policy yet: legacy pinned", managedGovernanceInputs(nodecomponents.Authority), true, nodecomponents.SourceLegacyPinned},
		{"managed, authorized, verified policy", withPolicy, true, nodecomponents.SourcePolicy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := resolveComponentGovernance(tc.in)
			if g.OrgManaged != tc.managed || g.Source != string(tc.source) {
				t.Fatalf("managed %v source %s, want %v %s", g.OrgManaged, g.Source, tc.managed, tc.source)
			}
			if tc.managed && g.OrgName != "Acme" {
				t.Errorf("org name %q", g.OrgName)
			}
		})
	}
}

// TestInitialGrantSetGovernsAManagedNode (lane MP-GOV, plan 6.2 row 9): a
// managed grant carrying components.govern and a signed initial set, with no
// policy delivered yet, runs exactly the set: a component in it stays active
// whatever the local block says, one outside it is inert even when the local
// block adds it.
func TestInitialGrantSetGovernsAManagedNode(t *testing.T) {
	requireCompiled(t, "codeintel", "org.client")
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "o1", OrgName: "Acme", OrgServerURL: "https://org.example", UserID: "u1", Tenancy: orgcontract.TenancyManaged}); err != nil {
		t.Fatal(err)
	}
	if err := st.WriteEnrolmentGrant(ctx, store.EnrolmentGrant{
		OrgKey: orgclient.OrgKey("https://org.example", "o1"), OrgID: "o1", OrgServerURL: "https://org.example",
		Authority: []string{nodecomponents.Authority}, ConsentMode: govern.ConsentManaged,
		GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		InitialComponents: &orgcontract.InitialComponentSet{CatalogVersion: 1, IDs: []string{"codeintel", "org.client"}},
	}); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n\n[components]\nremove = [\"codeintel\"]\nadd = [\"remote\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := componentSnapshotFor(cfgPath)
	if v := snap.View(); v.GovernanceSource != string(nodecomponents.SourceInitialGrant) {
		t.Fatalf("source = %q, want initial_grant", v.GovernanceSource)
	}
	if !snap.Active("codeintel") || !snap.Active("org.client") {
		t.Errorf("initial set narrowed: codeintel %v org.client %v", snap.Active("codeintel"), snap.Active("org.client"))
	}
	if snap.Active("remote") || snap.Active("terminals") {
		t.Errorf("outside the initial set active: remote %v terminals %v", snap.Active("remote"), snap.Active("terminals"))
	}
	if !snap.Active("core") {
		t.Error("core inactive")
	}
}

// TestManagedNodeIgnoresHandWrittenNarrowingAtStart is ledger MODPKG-7 end
// to end through a real node DB (T-677): a managed enrolment with a live
// grant, and a hand-written [components] block removing org.client, guard
// and integration.hooks. The snapshot every process resolves keeps them
// active, the start report warns naming the organization, doctor warns, and
// `observer components remove` refuses. The same block on an individual
// node still narrows it.
func TestManagedNodeIgnoresHandWrittenNarrowingAtStart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	writeEnrolment := func(tenancy string) {
		t.Helper()
		if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "o1", OrgName: "Acme", OrgServerURL: "https://org.example", UserID: "u1", Tenancy: tenancy}); err != nil {
			t.Fatal(err)
		}
	}
	writeEnrolment(orgcontract.TenancyManaged)
	if err := st.WriteEnrolmentGrant(ctx, store.EnrolmentGrant{
		OrgKey: orgclient.OrgKey("https://org.example", "o1"), OrgID: "o1", OrgName: "o1", OrgServerURL: "https://org.example",
		ConsentMode: govern.ConsentManaged, GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n\n[components]\nremove = [\"org.client\", \"guard\", \"integration.hooks\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	snap := componentSnapshotFor(cfgPath)
	for _, id := range []string{"org.client", "guard", "integration.hooks"} {
		if !snap.Active(id) {
			d, _ := snap.Decision(id)
			t.Errorf("%s narrowed on a managed node: %+v", id, d)
		}
	}
	var buf bytes.Buffer
	reportComponentIssues(&buf, snap)
	if !strings.Contains(buf.String(), "WARN components:") || !strings.Contains(buf.String(), "managed by Acme") {
		t.Errorf("start report does not warn naming the org:\n%s", buf.String())
	}
	pc := componentsPolicyCheck(snap.View())
	if pc.Status != diag.StatusWarn || !strings.Contains(pc.Message, "Acme") {
		t.Errorf("doctor components.policy = %+v", pc)
	}
	svc, err := newComponentsService(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Apply(ctx, componentsvc.Change{Remove: []string{"remote"}}, componentsvc.ApplyOptions{Principal: "cli"}); err == nil || !strings.Contains(err.Error(), "Acme") {
		t.Errorf("remove on a managed node = %v, want a refusal naming Acme", err)
	}

	// Individual enrolment: the block narrows, as before.
	database, err = dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	st = store.New(database)
	writeEnrolment(orgcontract.TenancyIndividual)
	_ = database.Close()
	snap = componentSnapshotFor(cfgPath)
	if snap.Active("integration.hooks") || snap.View().OrgManaged {
		t.Errorf("individual node: integration.hooks active %v managed %v", snap.Active("integration.hooks"), snap.View().OrgManaged)
	}
}
