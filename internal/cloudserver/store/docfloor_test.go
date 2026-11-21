package store_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// docfloor_test.go proves the version-floor table and its store seam (cloud
// 0097, W16-D6) against Postgres: its class and grants (append-only; the
// operator role writes, the worker reads), the worker role's read, and that
// a floor raise and a concurrent document insert of the same stream
// serialise on the stream lock. The verb's own walk (dry run, apply,
// refusals, idempotence) is cmd/observer-cloud TestRaiseFloorVerb.

func TestDocumentFloorTableClassAndGrants(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	ctx := context.Background()
	const table = "signed_doc_version_floors"
	var rls, force bool
	if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, table).Scan(&rls, &force); err != nil {
		t.Fatal(err)
	}
	if rls || force {
		t.Errorf("%s (class S) has row-level security enabled", table)
	}
	grants := map[string][]string{"sbci_app": {"SELECT", "INSERT"}, "sbci_worker": {"SELECT"}}
	for _, role := range []string{"sbci_api", "sbci_worker", "sbci_aggregator", "sbci_app", "sbci_staff"} {
		for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			want := false
			for _, g := range grants[role] {
				want = want || g == p
			}
			if got := tablePriv(t, pool, role, table, p); got != want {
				t.Errorf("%s %s on %s = %v, want %v", role, p, table, got, want)
			}
		}
	}
}

// TestDocumentFloorWorkerReadsAndRaceSerialises: the worker role reads a
// floor the operator raised, and a raise racing a document insert on the
// same stream ends with the two consistent: either the insert landed first
// (the raise reads database_ahead) or the raise did (the insert at the
// record's version is refused).
func TestDocumentFloorWorkerReadsAndRaceSerialises(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	ctx := context.Background()
	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatal(err)
	}
	org := provisionTeam(t, newAPIStore(t, pool), makeAccount(t, app)).OrgID
	now := time.Now().UTC()
	in := store.RaiseDocumentFloorsInput{
		RecordSHA256: strings.Repeat("0f", 32), Operator: "ops", Apply: true,
		Entries: []store.DocumentFloorEntry{{Kind: platformcontract.KindEntitlements, Scope: org, Version: 500}},
	}
	var (
		wg        sync.WaitGroup
		res       []store.DocumentFloorResult
		raiseErr  error
		insertErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		res, raiseErr = app.RaiseDocumentFloors(ctx, in, now)
	}()
	go func() {
		defer wg.Done()
		insertErr = app.InsertEntitlementDocument(ctx, org, signEnt(t, org, 500), store.IssuedBySystem, now)
	}()
	wg.Wait()
	if raiseErr != nil {
		t.Fatal(raiseErr)
	}
	switch res[0].Action {
	case store.FloorDatabaseAhead:
		if insertErr != nil {
			t.Fatalf("raise saw the insert, but the insert failed: %v", insertErr)
		}
	case store.FloorRaise:
		if insertErr == nil {
			t.Fatal("the floor was raised to 500 and an insert at 500 was still stored")
		}
	default:
		t.Fatalf("action %s", res[0].Action)
	}
	got, err := worker.DocumentVersionFloor(ctx, platformcontract.KindEntitlements, org)
	if err != nil {
		t.Fatalf("worker read: %v", err)
	}
	if want := map[store.FloorAction]int64{store.FloorRaise: 500, store.FloorDatabaseAhead: 0}[res[0].Action]; got != want {
		t.Fatalf("worker floor = %d, want %d", got, want)
	}
	higher := in
	higher.Entries = []store.DocumentFloorEntry{{Kind: platformcontract.KindEntitlements, Scope: org, Version: 900}}
	if _, err := worker.RaiseDocumentFloors(ctx, higher, now); err == nil {
		t.Fatal("the worker role appended a floor row")
	}
}
