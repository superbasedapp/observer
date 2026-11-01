package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// preFixManagedPolicy is the [org_client.policy] block a managed enrolment
// wrote before review C156-04: node.governance only, never node.features.
const preFixManagedPolicy = "\n[org_client.policy]\n" +
	"# Written automatically by `observer enroll`\n" +
	"accept_families = [\"node.governance\"]\n" +
	"preauthorize_enforce = [\"node.governance\"]\n"

func loadPolicyLists(t *testing.T, cfgPath string) ([]string, []string) {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		body, _ := os.ReadFile(cfgPath)
		t.Fatalf("config.Load: %v\n%s", err, body)
	}
	// The union with the module twins, as every product reader reads it
	// (config.OrgClientPolicyConfig.AcceptedFamilies): a family a released
	// binary does not know is written to accept_module_families.
	return cfg.OrgClient.Policy.AcceptedFamilies(), cfg.OrgClient.Policy.PreauthorizedFamilies()
}

func hasFamily(list []string, f string) bool {
	for _, s := range list {
		if s == f {
			return true
		}
	}
	return false
}

// TestBackfillManagedPolicyFamilies_PreFixNode is the release-blocking pin
// for C156-04: a managed node that enrolled before node.features was mapped
// gets it added (both keys), once, and a later developer removal is kept.
func TestBackfillManagedPolicyFamilies_PreFixNode(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	recPath := filepath.Join(dir, managedFamiliesRecordName)
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"info\"\n"+preFixManagedPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	facts := managedPolicyFacts{OrgKey: "k1", Generation: 3, Governed: govern.ManagedGovernedFamilies(govern.EnterpriseAuthoritySet())}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	acc, pre := loadPolicyLists(t, cfgPath)
	res, err := backfillManagedPolicyFamilies(cfgPath, recPath, facts, config.OrgClientPolicyConfig{AcceptFamilies: acc, PreauthorizeEnforce: pre}, now)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if !hasFamily(res.Added, "node.features") {
		t.Fatalf("Added = %v, want node.features", res.Added)
	}
	acc, pre = loadPolicyLists(t, cfgPath)
	for _, f := range []string{"node.governance", "node.features", "tools.mcp_access"} {
		if !hasFamily(acc, f) || !hasFamily(pre, f) {
			t.Fatalf("after backfill accept=%v preauth=%v, want both to carry %s", acc, pre, f)
		}
	}
	if acc[0] != "node.governance" {
		t.Fatalf("existing entries must keep their order, got %v", acc)
	}

	// Idempotent: the second start writes nothing.
	before, _ := os.ReadFile(cfgPath)
	res, err = backfillManagedPolicyFamilies(cfgPath, recPath, facts, config.OrgClientPolicyConfig{AcceptFamilies: acc, PreauthorizeEnforce: pre}, now)
	if err != nil || len(res.Added) != 0 || res.RecordWritten {
		t.Fatalf("second run = %+v, %v; want a no-op", res, err)
	}
	after, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(before, after) {
		t.Fatalf("second run rewrote the config")
	}

	// A developer who removes node.features after it was offered keeps it
	// removed: it was offered to this enrolment once.
	trimmed := strings.ReplaceAll(string(after), `, "node.features"`, "")
	if err := os.WriteFile(cfgPath, []byte(trimmed), 0o600); err != nil {
		t.Fatal(err)
	}
	acc, pre = loadPolicyLists(t, cfgPath)
	if hasFamily(acc, "node.features") {
		t.Fatalf("test setup: removal did not take, %v", acc)
	}
	res, err = backfillManagedPolicyFamilies(cfgPath, recPath, facts, config.OrgClientPolicyConfig{AcceptFamilies: acc, PreauthorizeEnforce: pre}, now)
	if err != nil || len(res.Added) != 0 {
		t.Fatalf("after a developer removal = %+v, %v; want nothing re-added", res, err)
	}

	// A re-enrolment (new generation) is a fresh offer.
	facts.Generation = 4
	res, err = backfillManagedPolicyFamilies(cfgPath, recPath, facts, config.OrgClientPolicyConfig{AcceptFamilies: acc, PreauthorizeEnforce: pre}, now)
	if err != nil || !hasFamily(res.Added, "node.features") {
		t.Fatalf("new generation = %+v, %v; want node.features offered again", res, err)
	}
}

func TestAddManagedPolicyFamilies_Shapes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "no table at all", body: "[observer]\nlog_level = \"info\"\n"},
		{name: "table without the keys", body: "[org_client.policy]\nnode_workspace = \"ws\"\n"},
		{name: "multi-line arrays", body: "[org_client.policy]\naccept_families = [\n  \"node.governance\", # gov\n  \"admission.input\",\n]\npreauthorize_enforce = [\n  \"node.governance\",\n]\nnode_service = \"svc\"\n\n[proxy]\nport = 8820\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(cfgPath, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			acc, pre := loadPolicyLists(t, cfgPath)
			if err := addManagedPolicyFamilies(cfgPath, config.OrgClientPolicyConfig{AcceptFamilies: acc, PreauthorizeEnforce: pre}, []string{"node.features"}); err != nil {
				t.Fatalf("add: %v", err)
			}
			acc2, pre2 := loadPolicyLists(t, cfgPath)
			if !hasFamily(acc2, "node.features") || !hasFamily(pre2, "node.features") {
				t.Fatalf("accept=%v preauth=%v, want node.features in both", acc2, pre2)
			}
			for _, f := range acc {
				if !hasFamily(acc2, f) {
					t.Fatalf("lost existing accept entry %s: %v", f, acc2)
				}
			}
			body, _ := os.ReadFile(cfgPath)
			for _, keep := range []string{"node_workspace = \"ws\"", "node_service = \"svc\"", "port = 8820"} {
				if strings.Contains(tc.body, keep) && !strings.Contains(string(body), keep) {
					t.Fatalf("lost unrelated line %q:\n%s", keep, body)
				}
			}
		})
	}
}

// TestLoadManagedPolicyFacts gates the backfill to managed enrolments with a
// live managed-consent grant, never an individual node.
func TestLoadManagedPolicyFacts(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name    string
		tenancy string
		consent string
		expires time.Time
		wantOK  bool
	}{
		{name: "managed, managed consent, live", tenancy: orgcontract.TenancyManaged, consent: govern.ConsentManaged, expires: now.Add(time.Hour), wantOK: true},
		{name: "individual enrolment is never touched", tenancy: orgcontract.TenancyIndividual, consent: govern.ConsentInteractive, expires: now.Add(time.Hour)},
		{name: "managed tenancy but interactive consent", tenancy: orgcontract.TenancyManaged, consent: govern.ConsentInteractive, expires: now.Add(time.Hour)},
		{name: "lapsed grant", tenancy: orgcontract.TenancyManaged, consent: govern.ConsentManaged, expires: now.Add(-time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := writeManagedFamiliesFixture(t, filepath.Join(t.TempDir(), "observer.db"), tc.tenancy, tc.consent, tc.expires)
			facts, ok, err := loadManagedPolicyFacts(context.Background(), st, now)
			if err != nil || ok != tc.wantOK {
				t.Fatalf("loadManagedPolicyFacts = %+v, %v, %v; want ok=%v", facts, ok, err, tc.wantOK)
			}
			if ok && !hasFamily(facts.Governed, "node.features") {
				t.Fatalf("governed = %v, want node.features", facts.Governed)
			}
		})
	}
}

// TestReconcileManagedPolicyAtStart_EndToEnd drives the daemon-start seam on
// a pre-fix managed node: a config and DB as an older build left them.
func TestReconcileManagedPolicyAtStart_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	st := writeManagedFamiliesFixture(t, dbPath, orgcontract.TenancyManaged, govern.ConsentManaged, time.Now().Add(time.Hour))
	_ = st
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n" + preFixManagedPolicy
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reconcileManagedPolicyAtStart(context.Background(), cfgPath, &out)
	acc, pre := loadPolicyLists(t, cfgPath)
	if !hasFamily(acc, "node.features") || !hasFamily(pre, "node.features") {
		t.Fatalf("accept=%v preauth=%v after start; want node.features (output %q)", acc, pre, out.String())
	}
	if !strings.Contains(out.String(), "node.features") {
		t.Fatalf("start must say what it added, got %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, managedFamiliesRecordName)); err != nil {
		t.Fatalf("record not written: %v", err)
	}
}

// TestReconcileManagedPolicyAtStart_IndividualUntouched: the same pre-fix
// lists on an individual enrolment are the operator's own opt-in.
func TestReconcileManagedPolicyAtStart_IndividualUntouched(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	writeManagedFamiliesFixture(t, dbPath, orgcontract.TenancyIndividual, govern.ConsentInteractive, time.Now().Add(time.Hour))
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n" + preFixManagedPolicy
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reconcileManagedPolicyAtStart(context.Background(), cfgPath, &bytes.Buffer{})
	after, _ := os.ReadFile(cfgPath)
	if string(after) != body {
		t.Fatalf("an individual node's config was rewritten:\n%s", after)
	}
}

func writeManagedFamiliesFixture(t *testing.T, dbPath, tenancy, consent string, expires time.Time) *store.Store {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	const orgID = "org-families-test"
	const orgURL = "https://org.example.test"
	orgKey := orgclient.OrgKey(orgURL, orgID)
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: orgID, OrgName: "Families Test", OrgServerURL: orgURL,
		UserID: "families-member", Tenancy: tenancy,
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	generation, err := st.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatalf("BumpEnrolmentGeneration: %v", err)
	}
	// The pre-T-311 enterprise-posture grant: no feature.lock.
	if err := st.WriteEnrolmentGrant(ctx, store.EnrolmentGrant{
		OrgKey: orgKey, Generation: generation, OrgID: orgID, OrgName: "Families Test",
		OrgServerURL: orgURL, Authority: govern.EnterpriseAuthoritySet(),
		ConsentMode: consent, GrantedAt: expires.Add(-2 * time.Hour), ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("WriteEnrolmentGrant: %v", err)
	}
	return st
}
