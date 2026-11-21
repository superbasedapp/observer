package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// orgoutbox_test.go proves the M6.4 store seam (cloud 0058-0060) against a
// real PostgreSQL: the idempotent enqueue inside the caller's transaction,
// the lease (two claimers never hold one row; a taken-over lease cannot
// record), per-org order, the fenced outcomes and the create adoption, the
// worker's grants and policies, and the reconciliation findings. They skip
// loudly without SBCI_TEST_PG_DSN (cloudtestpg) and run in the batch gate.

func newWorkerStore(t *testing.T, pool *pgxpool.Pool) *store.Store {
	t.Helper()
	s, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatalf("NewForRole(worker): %v", err)
	}
	return s
}

// outboxFixture is a fresh database with one provisioned org (and so its
// create_tenant row, key = org id).
type outboxFixture struct {
	app, api, worker *store.Store
	pool             *pgxpool.Pool
	owner            string
	org              store.MyOrg
}

func newOutboxFixture(t *testing.T) outboxFixture {
	t.Helper()
	app, pool := newStore(t)
	f := outboxFixture{app: app, api: newAPIStore(t, pool), worker: newWorkerStore(t, pool), pool: pool}
	f.owner = makeAccount(t, app)
	f.org = provisionTeam(t, f.api, f.owner)
	return f
}

// claimNow is a claim time safely after every row's default next_attempt_at
// (the database clock).
func claimNow() time.Time { return time.Now().Add(time.Minute) }

func TestOrgOutboxEnqueueIdempotentInOneTransaction(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()
	in := store.OrgIntent{
		OrgID: f.org.OrgID, Verb: store.OutboxSetState, IdempotencyKey: "state:" + f.org.OrgID + ":1:suspended",
		LifecycleGen: 1, Payload: []byte(`{"tenant_id":"` + f.org.OrgID + `","state":"suspended"}`),
	}
	// Under the api role (INSERT-only on org_outbox), in the account's own
	// transaction: the duplicate in the same transaction is one row, and the
	// provisioning key (the org id) is not written twice either.
	err := f.api.WithAccount(ctx, f.owner, func(ctx context.Context, tx pgx.Tx) error {
		for i, want := range []bool{true, false} {
			got, err := store.EnqueueOrgIntentTx(ctx, tx, in)
			if err != nil || got != want {
				t.Errorf("enqueue %d = %v, %v; want %v", i, got, err, want)
			}
		}
		dup := in
		dup.Verb, dup.IdempotencyKey, dup.LifecycleGen, dup.Payload = store.OutboxCreateTenant, f.org.OrgID, 0, nil
		if got, err := store.EnqueueOrgIntentTx(ctx, tx, dup); err != nil || got {
			t.Errorf("re-enqueue of the provisioning key = %v, %v; want false", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithAccount: %v", err)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_outbox WHERE org_id=$1::uuid`, f.org.OrgID); n != 2 {
		t.Fatalf("org_outbox rows = %d, want 2 (create + one state)", n)
	}
	// A rolled-back transaction leaves no intent behind.
	_ = f.api.WithAccount(ctx, f.owner, func(ctx context.Context, tx pgx.Tx) error {
		in2 := in
		in2.IdempotencyKey = "state:" + f.org.OrgID + ":2:active"
		if _, err := store.EnqueueOrgIntentTx(ctx, tx, in2); err != nil {
			t.Errorf("enqueue: %v", err)
		}
		return errors.New("roll back")
	})
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_outbox WHERE org_id=$1::uuid`, f.org.OrgID); n != 2 {
		t.Fatalf("a rolled-back intent survived: %d rows", n)
	}
	for _, bad := range []store.OrgIntent{
		{OrgID: f.org.OrgID, Verb: "export", IdempotencyKey: "x"},
		{OrgID: f.org.OrgID, Verb: store.OutboxEvict, IdempotencyKey: " "},
		{OrgID: f.org.OrgID, Verb: store.OutboxEvict, IdempotencyKey: "e", LifecycleGen: -1},
		{OrgID: f.org.OrgID, Verb: store.OutboxEvict, IdempotencyKey: "e", Payload: []byte(`{`)},
	} {
		if _, err := f.worker.EnqueueOrgIntent(ctx, bad); !errors.Is(err, store.ErrOrgIntentInvalid) {
			t.Errorf("EnqueueOrgIntent(%+v) = %v", bad, err)
		}
	}
}

func TestOrgOutboxTwoClaimersNeverShareARow(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api, w1, w2 := newAPIStore(t, pool), newWorkerStore(t, pool), newWorkerStore(t, pool)
	ctx := context.Background()
	owner := makeAccount(t, app)
	const orgs = 12
	// One owner holds every org: raise its team org cap (W15-D12, 0094).
	if _, err := app.SetTeamOrgLimit(ctx, owner, orgs, "test: many orgs for one owner", time.Now()); err != nil {
		t.Fatal(err)
	}
	for range orgs {
		provisionTeam(t, api, owner)
	}
	now := claimNow()
	claim := store.OrgOutboxClaim{Now: now, LeaseTTL: time.Minute, Limit: orgs}
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, w := range []*store.Store{w1, w2, w1, w2} {
		wg.Add(1)
		go func(w *store.Store) {
			defer wg.Done()
			<-start
			rows, err := w.ClaimOrgOutbox(ctx, claim)
			if err != nil {
				t.Errorf("ClaimOrgOutbox: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, r := range rows {
				seen[r.OutboxID]++
			}
		}(w)
	}
	close(start)
	wg.Wait()
	if len(seen) != orgs {
		t.Fatalf("claimed %d distinct rows, want all %d", len(seen), orgs)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("row %s was claimed %d times", id, n)
		}
	}
	// Leases are live: nothing more to claim.
	if rows, err := w1.ClaimOrgOutbox(ctx, claim); err != nil || len(rows) != 0 {
		t.Fatalf("re-claim under live leases = %d rows, %v", len(rows), err)
	}
}

func TestOrgOutboxExpiredLeaseIsTakenOverAndFenced(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()
	now := claimNow()
	first, err := f.worker.ClaimOrgOutbox(ctx, store.OrgOutboxClaim{Now: now, LeaseTTL: time.Minute, Limit: 5})
	if err != nil || len(first) != 1 || first[0].Attempts != 1 || first[0].Verb != store.OutboxCreateTenant {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	// The first worker stalls past its lease; a second takes the row over.
	later := now.Add(2 * time.Minute)
	second, err := f.worker.ClaimOrgOutbox(ctx, store.OrgOutboxClaim{Now: later, LeaseTTL: time.Minute, Limit: 5})
	if err != nil || len(second) != 1 || second[0].LeaseToken == first[0].LeaseToken || second[0].Attempts != 2 {
		t.Fatalf("take-over claim = %+v, %v", second, err)
	}
	stale := store.OrgOutboxOutcome{OutboxID: first[0].OutboxID, LeaseToken: first[0].LeaseToken, Result: store.OutboxResultAcked, Now: later}
	if err := f.worker.RecordOrgOutboxOutcome(ctx, stale); !errors.Is(err, store.ErrOrgOutboxLeaseLost) {
		t.Fatalf("stale holder recorded: %v", err)
	}
	fresh := store.OrgOutboxOutcome{
		OutboxID: second[0].OutboxID, LeaseToken: second[0].LeaseToken, Result: store.OutboxResultRetry,
		Now: later, NextAttemptAt: later.Add(time.Hour), ErrorClass: "transport:timeout",
	}
	if err := f.worker.RecordOrgOutboxOutcome(ctx, fresh); err != nil {
		t.Fatalf("current holder: %v", err)
	}
	// Recording twice under one lease is refused (the row left 'sent').
	if err := f.worker.RecordOrgOutboxOutcome(ctx, fresh); !errors.Is(err, store.ErrOrgOutboxLeaseLost) {
		t.Fatalf("second record under one lease: %v", err)
	}
	var state, class string
	if err := f.pool.QueryRow(ctx, `SELECT state, last_error_class FROM org_outbox WHERE outbox_id=$1::uuid`, second[0].OutboxID).Scan(&state, &class); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || class != "transport:timeout" {
		t.Fatalf("row = %s %s", state, class)
	}
	// Backing off: not due before NextAttemptAt.
	if rows, _ := f.worker.ClaimOrgOutbox(ctx, store.OrgOutboxClaim{Now: later.Add(time.Minute), LeaseTTL: time.Minute, Limit: 5}); len(rows) != 0 {
		t.Fatalf("a backing-off row was claimed: %+v", rows)
	}
}

func TestOrgOutboxPerOrgOrderAndCreateAdoption(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()
	if _, err := f.worker.EnqueueOrgIntent(ctx, store.OrgIntent{
		OrgID: f.org.OrgID, Verb: store.OutboxSetState, IdempotencyKey: "state:" + f.org.OrgID + ":2:suspended",
		LifecycleGen: 2, Payload: []byte(`{"tenant_id":"` + f.org.OrgID + `","state":"suspended"}`),
	}); err != nil {
		t.Fatal(err)
	}
	now := claimNow()
	rows, err := f.worker.ClaimOrgOutbox(ctx, store.OrgOutboxClaim{Now: now, LeaseTTL: time.Minute, Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].Verb != store.OutboxCreateTenant || rows[0].HostID != "" {
		t.Fatalf("claim = %+v, %v; want only the create, unplaced", rows, err)
	}
	// Placement: the first host wins, every later caller learns it.
	for _, try := range []string{"host-1", "host-2"} {
		if got, err := f.worker.AssignOrgHost(ctx, f.org.OrgID, try); err != nil || got != "host-1" {
			t.Fatalf("AssignOrgHost(%s) = %q, %v", try, got, err)
		}
	}
	if _, err := f.worker.AssignOrgHost(ctx, "00000000-0000-0000-0000-00000000dead", "host-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("AssignOrgHost(unknown) = %v", err)
	}
	ack := store.OrgOutboxOutcome{
		OutboxID: rows[0].OutboxID, LeaseToken: rows[0].LeaseToken, Result: store.OutboxResultAcked, Now: now,
		HostState: "active", HostGen: 1, AdoptCreate: true,
	}
	if err := f.worker.RecordOrgOutboxOutcome(ctx, ack); err != nil {
		t.Fatalf("ack: %v", err)
	}
	got, err := f.api.GetOrg(ctx, f.owner, f.org.OrgID)
	if err != nil || got.Status != "active" || got.LifecycleGen != 1 || got.HostID != "host-1" {
		t.Fatalf("org after the create ack = %+v, %v", got.Org, err)
	}
	// The create is done: the state intent is now due, and carries the host.
	rows, err = f.worker.ClaimOrgOutbox(ctx, store.OrgOutboxClaim{Now: now, LeaseTTL: time.Minute, Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].Verb != store.OutboxSetState || rows[0].HostID != "host-1" || rows[0].LifecycleGen != 2 {
		t.Fatalf("second claim = %+v, %v", rows, err)
	}
	park := store.OrgOutboxOutcome{OutboxID: rows[0].OutboxID, LeaseToken: rows[0].LeaseToken, Result: store.OutboxResultParked, Now: now, ErrorClass: "refused:invalid"}
	if err := f.worker.RecordOrgOutboxOutcome(ctx, park); err != nil {
		t.Fatalf("park: %v", err)
	}
	if rows, _ := f.worker.ClaimOrgOutbox(ctx, store.OrgOutboxClaim{Now: now, LeaseTTL: time.Minute, Limit: 10}); len(rows) != 0 {
		t.Fatalf("a parked row was claimed: %+v", rows)
	}
	if err := f.worker.RequeueParkedOrgIntent(ctx, park.OutboxID, now); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if err := f.worker.RequeueParkedOrgIntent(ctx, park.OutboxID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("requeue of a pending row = %v", err)
	}
	if rows, _ := f.worker.ClaimOrgOutbox(ctx, store.OrgOutboxClaim{Now: now, LeaseTTL: time.Minute, Limit: 10}); len(rows) != 1 {
		t.Fatalf("the requeued row is not due: %+v", rows)
	}
}

func TestOrgReconcileFindingsAndListing(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()
	now := claimNow()
	views, err := f.worker.ListOrgsForReconcile(ctx, "", 10)
	if err != nil || len(views) != 1 || views[0].OrgID != f.org.OrgID || !views[0].OpenIntent || views[0].Status != "provisioning" {
		t.Fatalf("ListOrgsForReconcile = %+v, %v", views, err)
	}
	if more, err := f.worker.ListOrgsForReconcile(ctx, f.org.OrgID, 10); err != nil || len(more) != 0 {
		t.Fatalf("second page = %+v, %v", more, err)
	}
	served := true
	gen := int64(1)
	corr := &store.OrgIntent{
		OrgID: f.org.OrgID, Verb: store.OutboxSetState, IdempotencyKey: "reconcile:state:" + f.org.OrgID + ":3:active",
		LifecycleGen: 3, Payload: []byte(`{"tenant_id":"` + f.org.OrgID + `","state":"active"}`),
	}
	upd := store.OrgReconcileUpdate{
		OrgID: f.org.OrgID, Now: now, Correction: corr,
		Findings: []store.OrgReconcileFinding{
			{Kind: "state_behind", DesiredState: "active", DesiredGen: 3, Served: &served, HostState: "active", HostGen: &gen, Health: "healthy", CorrectionKey: corr.IdempotencyKey},
			{Kind: "unhealthy", DesiredState: "active", DesiredGen: 3, Served: &served, Health: "degraded"},
		},
	}
	for i, want := range []bool{true, false} {
		upd.Now = now.Add(time.Duration(i) * time.Hour)
		if got, err := f.worker.ApplyOrgReconcile(ctx, upd); err != nil || got != want {
			t.Fatalf("pass %d: ApplyOrgReconcile = %v, %v; want %v", i, got, err, want)
		}
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_reconcile_findings WHERE org_id=$1::uuid AND resolved_at IS NULL AND seen_count=2`, f.org.OrgID); n != 2 {
		t.Fatalf("open findings seen twice = %d, want 2", n)
	}
	// The next pass sees only the health problem: state_behind resolves.
	upd.Findings, upd.Correction, upd.Now = upd.Findings[1:], nil, now.Add(2*time.Hour)
	if _, err := f.worker.ApplyOrgReconcile(ctx, upd); err != nil {
		t.Fatal(err)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_reconcile_findings WHERE org_id=$1::uuid AND kind='state_behind' AND resolved_at IS NOT NULL`, f.org.OrgID); n != 1 {
		t.Fatalf("resolved state_behind = %d", n)
	}
	// In sync: everything resolves; a recurrence opens a new row.
	upd.Findings, upd.Now = nil, now.Add(3*time.Hour)
	if _, err := f.worker.ApplyOrgReconcile(ctx, upd); err != nil {
		t.Fatal(err)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_reconcile_findings WHERE org_id=$1::uuid AND resolved_at IS NULL`, f.org.OrgID); n != 0 {
		t.Fatalf("open findings after an in-sync pass = %d", n)
	}
}

// TestOrgOutboxWorkerAccess pins the M6.4 grants and policies: the worker
// reads every org through its own policy but only the routing columns, may
// write only placement and adoption columns, and the app role's system path
// still sees no org (the membership policies are unchanged for it).
func TestOrgOutboxWorkerAccess(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()
	for col, want := range map[string]bool{
		"org_id": true, "display_name": true, "status": true, "lifecycle_gen": true, "host_id": true,
		"kind": true, "slug": true, "tenancy": false, "created_by": false,
	} {
		if got := columnPriv(t, f.pool, "sbci_worker", "orgs", col, "SELECT"); got != want {
			t.Errorf("sbci_worker SELECT orgs.%s = %v, want %v", col, got, want)
		}
	}
	for col, want := range map[string]bool{
		"host_id": true, "status": true, "lifecycle_gen": true, "updated_at": true,
		"display_name": false, "slug": false, "platform_rail_enabled": false, "tenancy": false,
	} {
		if got := columnPriv(t, f.pool, "sbci_worker", "orgs", col, "UPDATE"); got != want {
			t.Errorf("sbci_worker UPDATE orgs.%s = %v, want %v", col, got, want)
		}
	}
	for _, p := range []string{"INSERT", "DELETE"} {
		if tablePriv(t, f.pool, "sbci_worker", "orgs", p) {
			t.Errorf("sbci_worker holds %s on orgs", p)
		}
	}
	for _, tbl := range []string{"org_members", "org_slugs", "account_profiles"} {
		if tablePriv(t, f.pool, "sbci_worker", tbl, "SELECT") {
			t.Errorf("sbci_worker holds SELECT on %s", tbl)
		}
	}
	for _, role := range []string{"sbci_api", "sbci_app", "sbci_worker"} {
		var ok bool
		if err := f.pool.QueryRow(ctx, `SELECT has_sequence_privilege($1, 'org_outbox_seq', 'USAGE')`, role).Scan(&ok); err != nil || !ok {
			t.Errorf("%s USAGE on org_outbox_seq = %v, %v", role, ok, err)
		}
	}
	countAs := func(s *store.Store) int {
		var n int
		if err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM orgs`).Scan(&n)
		}); err != nil {
			t.Fatalf("count orgs: %v", err)
		}
		return n
	}
	if n := countAs(f.worker); n != 1 {
		t.Errorf("the worker sees %d orgs, want 1", n)
	}
	if n := countAs(f.app); n != 0 {
		t.Errorf("the app role's system path sees %d orgs, want 0 (membership policies only)", n)
	}
}
