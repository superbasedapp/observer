package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// documents_test.go proves the signed-document tables and store seam (cloud
// migrations 0055-0056, managed-SaaS M6.3) against Postgres: the class and
// grants of both tables, the monotonic version rule for an org's
// entitlements and for the availability stream (equal and older refused,
// nothing written), the per-org independence of versions, concurrent writers,
// and that what is stored verifies. Every test needs Postgres (cloudtestpg;
// SKIPPED loudly without SBCI_TEST_PG_DSN).

var documentTableClasses = []orgTableClass{
	{"org_entitlement_docs", "S", map[string][]string{
		"sbci_worker": {"SELECT", "INSERT"},
		"sbci_app":    {"SELECT", "INSERT"},
	}},
	{"availability_docs", "S", map[string][]string{
		"sbci_worker": {"SELECT", "INSERT"},
		"sbci_app":    {"SELECT", "INSERT"},
	}},
}

func TestSignedDocumentTableClassesAndGrants(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	ctx := context.Background()
	roles := []string{"sbci_api", "sbci_worker", "sbci_aggregator", "sbci_app"}
	privs := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	for _, c := range documentTableClasses {
		var rls, force bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, c.table).Scan(&rls, &force); err != nil {
			t.Fatalf("read RLS state of %s: %v", c.table, err)
		}
		if rls || force {
			t.Errorf("%s (class S) has row-level security enabled", c.table)
		}
		for _, role := range roles {
			for _, p := range privs {
				want := false
				for _, g := range c.grants[role] {
					want = want || g == p
				}
				if got := tablePriv(t, pool, role, c.table, p); got != want {
					t.Errorf("%s %s on %s = %v, want %v", role, p, c.table, got, want)
				}
			}
		}
	}
}

func docKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

// entBody is a composed, issuable entitlements body for org (the team
// floor, the catalog's generator).
func entBody(t *testing.T, org string) []byte {
	t.Helper()
	b, err := entitlements.Compose("team_lapsed", 1, org, time.Now().Unix(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signEnt(t *testing.T, org string, v int64) platformcontract.EntitlementDocument {
	t.Helper()
	return signEntBody(t, org, v, entBody(t, org))
}

func signEntBody(t *testing.T, org string, v int64, body []byte) platformcontract.EntitlementDocument {
	t.Helper()
	d, err := platformcontract.SignEntitlements(docKey(1), org, v, body)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestEntitlementDocumentBodyIsCheckedBeforeStoring (ENTLWORK-1): the store
// refuses a body a host would not accept for the org, before any SQL.
func TestEntitlementDocumentBodyIsCheckedBeforeStoring(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	orgA := provisionTeam(t, api, makeAccount(t, app)).OrgID
	orgB := provisionTeam(t, api, makeAccount(t, app)).OrgID
	unknownCap := strings.Replace(string(entBody(t, orgA)), `"caps":{`, `"caps":{"made_up_cap":1,`, 1)
	for name, body := range map[string][]byte{
		"not an entitlements body":       []byte(`{"plan":"team"}`),
		"names another org":              entBody(t, orgB),
		"a cap this binary cannot issue": []byte(unknownCap),
	} {
		err := app.InsertEntitlementDocument(ctx, orgA, signEntBody(t, orgA, 1, body), store.IssuedBySystem, time.Now())
		if !errors.Is(err, store.ErrEntitlementBody) {
			t.Errorf("%s: err = %v, want ErrEntitlementBody", name, err)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM org_entitlement_docs`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows = %d (%v), want 0", n, err)
	}
}

// TestIssueEntitlementDocumentStoresAndEnqueuesTogether: the worker's seam
// writes the document and its set_entitlements intent in one transaction,
// refuses an intent for another org or verb, and a refused version writes
// neither.
func TestIssueEntitlementDocumentStoresAndEnqueuesTogether(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()
	doc := signEnt(t, f.org.OrgID, 7)
	in := store.OrgIntent{
		OrgID: f.org.OrgID, Verb: store.OutboxSetEntitlements, IdempotencyKey: "entitlements:" + f.org.OrgID + ":7",
		Payload: []byte(`{"tenant_id":"` + f.org.OrgID + `"}`),
	}
	bad := in
	bad.Verb = store.OutboxEvict
	if _, err := f.worker.IssueEntitlementDocument(ctx, f.org.OrgID, doc, store.IssuedBySystem, time.Now(), bad); !errors.Is(err, store.ErrOrgIntentInvalid) {
		t.Fatalf("evict intent = %v, want ErrOrgIntentInvalid", err)
	}
	if ok, err := f.worker.IssueEntitlementDocument(ctx, f.org.OrgID, doc, store.IssuedBySystem, time.Now(), in); err != nil || !ok {
		t.Fatalf("issue as the worker = %v, %v", ok, err)
	}
	// The same version again: refused, and the intent row is not written
	// twice either (it is the same key, but the transaction never gets there).
	again := in
	again.IdempotencyKey += "-again"
	if _, err := f.worker.IssueEntitlementDocument(ctx, f.org.OrgID, doc, store.IssuedBySystem, time.Now(), again); !errors.Is(err, platformcontract.ErrVersionNotNewer) {
		t.Fatalf("repeat = %v, want ErrVersionNotNewer", err)
	}
	var docs, intents int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM org_entitlement_docs WHERE org_id = $1`, f.org.OrgID).Scan(&docs); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM org_outbox WHERE org_id = $1 AND verb = 'set_entitlements'`, f.org.OrgID).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if docs != 1 || intents != 1 {
		t.Fatalf("documents %d, intents %d; want 1 and 1", docs, intents)
	}
}

// TestListOrgsForEntitlementsAsTheWorker: the worker reads each org's id,
// kind and status (0089 adds kind), in pages, purged orgs left out.
func TestListOrgsForEntitlementsAsTheWorker(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()
	second := provisionTeam(t, f.api, makeAccount(t, f.app))
	if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status = 'purged' WHERE org_id = $1`, second.OrgID); err != nil {
		t.Fatal(err)
	}
	third := provisionTeam(t, f.api, makeAccount(t, f.app))
	var all []store.OrgEntitlementView
	after := ""
	for {
		page, err := f.worker.ListOrgsForEntitlements(ctx, after, 1)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(page) == 0 {
			break
		}
		all = append(all, page...)
		after = page[len(page)-1].OrgID
	}
	got := map[string]store.OrgEntitlementView{}
	for _, v := range all {
		got[v.OrgID] = v
	}
	if len(got) != 2 || got[second.OrgID].OrgID != "" {
		t.Fatalf("listed %+v, want the two live orgs only", all)
	}
	for _, id := range []string{f.org.OrgID, third.OrgID} {
		if v := got[id]; v.Kind != store.OrgTeam || v.Status != "provisioning" {
			t.Fatalf("org %s = %+v", id, v)
		}
	}
}

func TestEntitlementDocumentsAreMonotonicPerOrg(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	orgA := provisionTeam(t, api, makeAccount(t, app)).OrgID
	orgB := provisionTeam(t, api, makeAccount(t, app)).OrgID
	now := time.Now()

	if _, err := app.LatestEntitlementDocument(ctx, orgA); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("latest before any issue = %v, want ErrNotFound", err)
	}
	if err := app.InsertEntitlementDocument(ctx, orgA, signEnt(t, orgA, 2), store.IssuedBySystem, now); err != nil {
		t.Fatalf("v2: %v", err)
	}
	for _, v := range []int64{2, 1} {
		if err := app.InsertEntitlementDocument(ctx, orgA, signEnt(t, orgA, v), store.IssuedByStaff("ops-1"), now); !errors.Is(err, platformcontract.ErrVersionNotNewer) {
			t.Errorf("v%d after v2 = %v, want ErrVersionNotNewer", v, err)
		}
	}
	// Another org's stream is independent.
	if err := app.InsertEntitlementDocument(ctx, orgB, signEnt(t, orgB, 1), store.IssuedBySystem, now); err != nil {
		t.Fatalf("org B v1: %v", err)
	}
	if err := app.InsertEntitlementDocument(ctx, orgA, signEnt(t, orgA, 3), store.IssuedByStaff("ops-1"), now); err != nil {
		t.Fatalf("v3: %v", err)
	}
	got, err := app.LatestEntitlementDocument(ctx, orgA)
	if err != nil || got.Version != 3 {
		t.Fatalf("latest = v%d (%v), want v3", got.Version, err)
	}
	keys := platformcontract.KeySet{platformcontract.NewDocumentKey(docKey(1).Public().(ed25519.PublicKey))}
	if err := platformcontract.VerifyEntitlements(got, orgA, keys, 2); err != nil {
		t.Fatalf("stored document does not verify: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM org_entitlement_docs WHERE org_id = $1`, orgA).Scan(&n); err != nil || n != 2 {
		t.Fatalf("org A rows = %d (%v), want 2 (refusals write nothing)", n, err)
	}
	// Shape refusals happen before any SQL.
	if err := app.InsertEntitlementDocument(ctx, orgA, signEnt(t, orgA, 4), "root", now); err == nil {
		t.Error("issued_by outside system|staff:<id> was accepted")
	}
}

func TestEntitlementDocumentsConcurrentWritersStayMonotonic(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	org := provisionTeam(t, api, makeAccount(t, app)).OrgID
	doc := signEnt(t, org, 5)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = app.InsertEntitlementDocument(ctx, org, doc, store.IssuedBySystem, time.Now())
		}(i)
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("two writers of v5: %v / %v, want exactly one success", errs[0], errs[1])
	}
	for _, err := range errs {
		if err != nil && !errors.Is(err, platformcontract.ErrVersionNotNewer) {
			t.Fatalf("the losing writer got %v, want ErrVersionNotNewer", err)
		}
	}
}

func TestAvailabilityDocumentsAreMonotonic(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	ctx := context.Background()
	sign := func(v int64) platformcontract.AvailabilityDocument {
		d, err := platformcontract.SignAvailability(docKey(2), v, []byte(`{"issued_at":"2026-11-13T12:00:00Z"}`))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if _, err := app.LatestAvailabilityDocument(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("latest before any issue = %v, want ErrNotFound", err)
	}
	if err := app.InsertAvailabilityDocument(ctx, sign(1), store.IssuedBySystem, time.Now()); err != nil {
		t.Fatalf("v1: %v", err)
	}
	if err := app.InsertAvailabilityDocument(ctx, sign(1), store.IssuedBySystem, time.Now()); !errors.Is(err, platformcontract.ErrVersionNotNewer) {
		t.Fatalf("v1 again = %v, want ErrVersionNotNewer", err)
	}
	if err := app.InsertAvailabilityDocument(ctx, sign(2), store.IssuedByStaff("ops-2"), time.Now()); err != nil {
		t.Fatalf("v2: %v", err)
	}
	got, err := app.LatestAvailabilityDocument(ctx)
	if err != nil || got.Version != 2 {
		t.Fatalf("latest = v%d (%v), want v2", got.Version, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM availability_docs`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows = %d (%v), want 2", n, err)
	}
}
