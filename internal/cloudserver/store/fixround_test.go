package store_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// submitEvid submits a job carrying evidence bytes, mirroring the jobs-package
// helper, for the store-level fix-round tests.
func submitEvid(t *testing.T, s *store.Store, acct, key string, evidence []byte, now time.Time) store.JobSubmission {
	t.Helper()
	sub, err := s.SubmitJob(context.Background(), store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p", CloudSessionID: "cs-" + key,
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: key, UploadDigest: "sha256:" + key, ContentDigest: "sha256:c",
		BlobRef: "evidence/" + key, SizeBytes: int64(len(evidence)), EvidenceBytes: evidence,
		ConsentGeneration: 0, Now: now,
	})
	if err != nil {
		t.Fatalf("SubmitJob(%s): %v", key, err)
	}
	return sub
}

func blobCount(t *testing.T, s *store.Store, acct string) int {
	t.Helper()
	var n int
	if err := s.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM evidence_blobs WHERE account_id = $1::uuid`, acct).Scan(&n); err != nil {
		t.Fatalf("blob count: %v", err)
	}
	return n
}

// TestFB4NoDeadlockUnderConcurrentReserveRelease stresses the reserve vs
// settle/release paths concurrently on ONE account. Before the FB4 fix the two
// paths acquired the daily/monthly/concurrency counter-row locks in opposite
// orders, which PostgreSQL resolves by aborting a transaction with SQLSTATE
// 40P01. With one canonical lock order (daily→monthly→concurrency→global) no
// deadlock is possible; the test fails if any operation returns 40P01.
func TestFB4NoDeadlockUnderConcurrentReserveRelease(t *testing.T) {
	s, pool := newStore(t)
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 1_000_000, 1_000_000, 1_000_000)
	ctx := context.Background()

	is40P01 := func(err error) bool {
		var pge *pgconn.PgError
		return errors.As(err, &pge) && pge.Code == "40P01"
	}

	const workers, iters = 8, 80
	var wg sync.WaitGroup
	var mu sync.Mutex
	var deadlocks int
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				rid, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, time.Now())
				if err != nil {
					if is40P01(err) {
						mu.Lock()
						deadlocks++
						mu.Unlock()
					}
					continue
				}
				// Alternate settle vs release so both finalize orderings run
				// concurrently against fresh reserves.
				var ferr error
				if i%2 == 0 {
					ferr = s.ReleaseReservation(ctx, acct, rid, false)
				} else {
					ferr = s.SettleReservation(ctx, acct, rid)
				}
				if ferr != nil && is40P01(ferr) {
					mu.Lock()
					deadlocks++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if deadlocks > 0 {
		t.Fatalf("FB4: %d SQLSTATE 40P01 deadlocks under concurrent reserve/settle/release — lock order is not canonical", deadlocks)
	}
}

// TestFA5DialectRecordInvalidatedByRouteMutation proves a store:false
// verification record is bound to the route generation: after SetRouteBinding
// bumps the generation (changing api-version/deployment/endpoint), a previously
// live record no longer verifies the resolved snapshot.
func TestFA5DialectRecordInvalidatedByRouteMutation(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	const routeID = "session_enrichment.luna.v1"

	if err := s.SetRouteDialect(ctx, routeID, "responses_store_false"); err != nil {
		t.Fatalf("SetRouteDialect: %v", err)
	}
	if err := s.AddDialectVerification(ctx, routeID, "responses_store_false", "manual verdict", "op", now.Add(time.Hour)); err != nil {
		t.Fatalf("AddDialectVerification: %v", err)
	}
	route, err := s.RouteByID(ctx, routeID)
	if err != nil {
		t.Fatalf("RouteByID: %v", err)
	}
	if ok, err := s.DialectVerified(ctx, route, now); err != nil || !ok {
		t.Fatalf("record should verify the current snapshot: ok=%v err=%v", ok, err)
	}

	// Mutate the route (bumps generation + changes api-version/deployment).
	if err := s.SetRouteBinding(ctx, routeID, store.RouteBinding{
		TenantID: "t", SubscriptionID: "sub", ARMResourceID: "/r", EndpointAudience: "https://management.azure.com",
		Endpoint: "https://luna.openai.azure.com", APIVersion: "2099-01-01",
	}); err != nil {
		t.Fatalf("SetRouteBinding: %v", err)
	}
	route2, err := s.RouteByID(ctx, routeID)
	if err != nil {
		t.Fatalf("RouteByID after bind: %v", err)
	}
	if route2.Generation == route.Generation {
		t.Fatal("SetRouteBinding did not bump the route generation")
	}
	if ok, err := s.DialectVerified(ctx, route2, now); err != nil || ok {
		t.Fatalf("FA5: stale record must NOT verify the mutated route snapshot: ok=%v err=%v", ok, err)
	}
}

// TestFA5AddDialectRequiresApprover proves non-empty evidence + approver are
// required (FA5).
func TestFA5AddDialectRequiresApprover(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	if err := s.AddDialectVerification(ctx, "session_enrichment.luna.v1", "responses_store_false", "", "op", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("empty evidence accepted")
	}
	if err := s.AddDialectVerification(ctx, "session_enrichment.luna.v1", "responses_store_false", "e", "", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("empty approver accepted")
	}
}

// TestFA7KillSwitchMissingRowFailsClosed proves a DELETED global kill-switch row
// is treated as PAUSED (fail closed) at both the admission check and the
// worker's per-route/global read, rather than reopening admission.
func TestFA7KillSwitchMissingRowFailsClosed(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	// Baseline: seed rows present ⇒ not paused.
	if active, err := s.GlobalKillSwitchActive(ctx); err != nil || active {
		t.Fatalf("baseline global switch: active=%v err=%v", active, err)
	}
	// Delete the global sentinel row (an out-of-band control-plane mutation).
	if _, err := pool.Exec(ctx, `DELETE FROM kill_switches WHERE scope='global' AND key='all'`); err != nil {
		t.Fatalf("delete global switch: %v", err)
	}
	if active, err := s.GlobalKillSwitchActive(ctx); err != nil || !active {
		t.Fatalf("FA7: missing global switch must read as PAUSED (active=true); got active=%v err=%v", active, err)
	}
	ks, err := s.KillSwitches(ctx, "session_enrichment.luna.v1")
	if err != nil {
		t.Fatalf("KillSwitches: %v", err)
	}
	if !ks.GlobalActive {
		t.Fatal("FA7: KillSwitches missing global row must fail closed (GlobalActive=true)")
	}
	// Delete the per-route sentinel too ⇒ RouteActive fails closed.
	if _, err := pool.Exec(ctx, `DELETE FROM kill_switches WHERE scope='route' AND key='session_enrichment.luna.v1'`); err != nil {
		t.Fatalf("delete route switch: %v", err)
	}
	ks2, err := s.KillSwitches(ctx, "session_enrichment.luna.v1")
	if err != nil {
		t.Fatalf("KillSwitches(2): %v", err)
	}
	if !ks2.RouteActive {
		t.Fatal("FA7: KillSwitches missing per-route row must fail closed (RouteActive=true)")
	}
}

// TestFA8CompleteAfterCancelIsNoStore proves a completion whose job was canceled
// (or re-leased) since revalidation stores NOTHING and does not resurrect the
// job — the completion CAS requires state='running' owned by this lease worker
// on an unexpired lease.
func TestFA8CompleteAfterCancelIsNoStore(t *testing.T) {
	s, pool := newStore(t)
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 100, 1000, 100)
	ctx := context.Background()
	now := time.Now()

	submitEvid(t, s, acct, "fa8cancel", []byte(`{"a":1}`), now)
	lj, err := s.LeaseNextJob(ctx, "w1", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil {
		t.Fatalf("lease: %v (lj=%v)", err, lj)
	}
	if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	// The user cancels (deletion path) while the provider call is "in flight".
	if err := s.CancelJob(ctx, acct, lj.JobID, now); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	// The in-flight provider now returns and tries to complete.
	_, committed, err := s.CompleteJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID,
		"w1", lj.LeaseGeneration, "session_enrichment.v2-candidate", []byte(`{"title":"x"}`), store.ResultProvenance{}, now)
	if err != nil {
		t.Fatalf("CompleteJobWithResult: %v", err)
	}
	if committed {
		t.Fatal("FA8: completion after cancel must NOT commit")
	}
	// No result stored; job stays canceled.
	rows, err := s.ListResultsAfter(ctx, acct, 0, 50)
	if err != nil {
		t.Fatalf("ListResultsAfter: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("FA8: canceled job must store no result, got %d", len(rows))
	}
	j, _ := s.GetJob(ctx, acct, lj.JobID)
	if j.State != "canceled" {
		t.Fatalf("FA8: job state=%q, want canceled (not resurrected)", j.State)
	}
}

// TestFA8ReLeaseRaceYieldsOneResult proves that when a lease expires and another
// worker re-leases the job, only the CURRENT lease owner can complete it — the
// original worker's stale completion stores nothing.
func TestFA8ReLeaseRaceYieldsOneResult(t *testing.T) {
	s, pool := newStore(t)
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 100, 1000, 100)
	ctx := context.Background()
	t0 := time.Now()

	submitEvid(t, s, acct, "fa8release", []byte(`{"a":1}`), t0)
	// w1 leases with a SHORT visibility timeout, then it "stalls".
	lj1, err := s.LeaseNextJob(ctx, "w1", []string{store.FeatureSessionEnrichment}, time.Second, t0)
	if err != nil || lj1 == nil {
		t.Fatalf("lease w1: %v", err)
	}
	if err := s.MarkJobRunning(ctx, acct, lj1.JobID, t0); err != nil {
		t.Fatalf("mark running w1: %v", err)
	}
	// The lease expires; w2 re-leases the same job.
	t1 := t0.Add(2 * time.Second)
	lj2, err := s.LeaseNextJob(ctx, "w2", []string{store.FeatureSessionEnrichment}, time.Hour, t1)
	if err != nil || lj2 == nil {
		t.Fatalf("re-lease w2: %v (lj2=%v)", err, lj2)
	}
	if lj2.JobID != lj1.JobID {
		t.Fatalf("re-lease got a different job: %s vs %s", lj2.JobID, lj1.JobID)
	}
	if err := s.MarkJobRunning(ctx, acct, lj2.JobID, t1); err != nil {
		t.Fatalf("mark running w2: %v", err)
	}
	// w1 (stale owner) completes — CAS on lease_worker='w1' fails.
	_, c1, err := s.CompleteJobWithResult(ctx, acct, lj1.JobID, lj1.EvidencePK, lj1.ReservationID,
		"w1", lj1.LeaseGeneration, "session_enrichment.v2-candidate", []byte(`{"title":"stale"}`), store.ResultProvenance{}, t1)
	if err != nil {
		t.Fatalf("w1 complete: %v", err)
	}
	if c1 {
		t.Fatal("FA8: stale lease owner (w1) must NOT commit after re-lease")
	}
	// w2 (current owner) completes — succeeds.
	_, c2, err := s.CompleteJobWithResult(ctx, acct, lj2.JobID, lj2.EvidencePK, lj2.ReservationID,
		"w2", lj2.LeaseGeneration, "session_enrichment.v2-candidate", []byte(`{"title":"fresh"}`), store.ResultProvenance{}, t1)
	if err != nil {
		t.Fatalf("w2 complete: %v", err)
	}
	if !c2 {
		t.Fatal("FA8: current lease owner (w2) should commit")
	}
	rows, _ := s.ListResultsAfter(ctx, acct, 0, 50)
	if len(rows) != 1 {
		t.Fatalf("FA8: re-lease race must yield exactly ONE result, got %d", len(rows))
	}
}

// TestFA8SameWorkerReLeaseRejectsStaleCompletion is the FA8 re-fix: Sol's exact
// residual. When the SAME worker id re-leases an expired job (the default single
// "sbci-worker" deployment), the stale attempt's completion CAS matched on
// state='running', lease_worker, AND the fresh expiry — so lease_worker alone did
// not reject it. The durable lease_generation is what does: the re-lease bumps
// it, so the stale attempt (holding the OLD generation) commits nothing while the
// current lease (new generation) succeeds.
func TestFA8SameWorkerReLeaseRejectsStaleCompletion(t *testing.T) {
	s, pool := newStore(t)
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 100, 1000, 100)
	ctx := context.Background()
	t0 := time.Now()

	submitEvid(t, s, acct, "fa8same", []byte(`{"a":1}`), t0)
	const worker = "sbci-worker" // the SAME default id for both leases
	lj1, err := s.LeaseNextJob(ctx, worker, []string{store.FeatureSessionEnrichment}, time.Second, t0)
	if err != nil || lj1 == nil {
		t.Fatalf("lease #1: %v", err)
	}
	if err := s.MarkJobRunning(ctx, acct, lj1.JobID, t0); err != nil {
		t.Fatalf("mark running #1: %v", err)
	}
	// Lease expires; the SAME worker id re-leases the job.
	t1 := t0.Add(2 * time.Second)
	lj2, err := s.LeaseNextJob(ctx, worker, []string{store.FeatureSessionEnrichment}, time.Hour, t1)
	if err != nil || lj2 == nil {
		t.Fatalf("re-lease #2: %v", err)
	}
	if lj2.JobID != lj1.JobID {
		t.Fatalf("re-lease got a different job")
	}
	if lj2.LeaseGeneration == lj1.LeaseGeneration {
		t.Fatalf("FA8: re-lease did not bump lease_generation (%d == %d)", lj2.LeaseGeneration, lj1.LeaseGeneration)
	}
	if err := s.MarkJobRunning(ctx, acct, lj2.JobID, t1); err != nil {
		t.Fatalf("mark running #2: %v", err)
	}
	// The STALE attempt (same worker id, OLD generation) completes — must fail,
	// because lease_worker matches but lease_generation does not.
	_, c1, err := s.CompleteJobWithResult(ctx, acct, lj1.JobID, lj1.EvidencePK, lj1.ReservationID,
		worker, lj1.LeaseGeneration, "session_enrichment.v2-candidate", []byte(`{"title":"STALE"}`), store.ResultProvenance{}, t1)
	if err != nil {
		t.Fatalf("stale complete: %v", err)
	}
	if c1 {
		t.Fatal("FA8: stale same-worker attempt (old lease_generation) must NOT commit")
	}
	// The current lease (same worker id, new generation) completes — succeeds.
	_, c2, err := s.CompleteJobWithResult(ctx, acct, lj2.JobID, lj2.EvidencePK, lj2.ReservationID,
		worker, lj2.LeaseGeneration, "session_enrichment.v2-candidate", []byte(`{"title":"fresh"}`), store.ResultProvenance{}, t1)
	if err != nil {
		t.Fatalf("fresh complete: %v", err)
	}
	if !c2 {
		t.Fatal("FA8: current lease (new lease_generation) should commit")
	}
	rows, _ := s.ListResultsAfter(ctx, acct, 0, 50)
	if len(rows) != 1 || !strings.Contains(string(rows[0].Result), "fresh") {
		t.Fatalf("FA8: exactly one FRESH result expected, got %d rows: %v", len(rows), rows)
	}
}

// TestFE4DeletionPurgesAllBlobsAndFences proves account deletion (a) removes
// every evidence-blob ciphertext for the account — not just stamps the object
// deleted — and (b) fences the account so a concurrent/subsequent submit cannot
// store surviving evidence.
func TestFE4DeletionPurgesAllBlobsAndFences(t *testing.T) {
	s, pool := newStore(t)
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 100, 1000, 100)
	ctx := context.Background()
	now := time.Now()

	// A job whose evidence blob is NOT tied to a non-terminal job (drive it to a
	// terminal state WITHOUT the normal blob-deleting completion), so the old
	// "stamp the object deleted" path would leave its ciphertext behind.
	sub := submitEvid(t, s, acct, "fe4a", []byte(`{"secret":"bytes"}`), now)
	if _, err := pool.Exec(ctx,
		`UPDATE analysis_jobs SET state='succeeded' WHERE account_id=$1::uuid AND id=$2::uuid`,
		acct, sub.JobID); err != nil {
		t.Fatalf("force succeeded: %v", err)
	}
	// A second, still-queued job (its blob is present too).
	submitEvid(t, s, acct, "fe4b", []byte(`{"more":"bytes"}`), now)
	if got := blobCount(t, s, acct); got != 2 {
		t.Fatalf("precondition: want 2 blobs, got %d", got)
	}

	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}
	if got := blobCount(t, s, acct); got != 0 {
		t.Fatalf("FE4: deletion must leave ZERO blob rows, got %d", got)
	}

	// The account is fenced: a subsequent submit is refused (no surviving blob).
	_, err := s.SubmitJob(ctx, store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p", CloudSessionID: "cs-post", Tool: "codex",
		ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: "post-fence", UploadDigest: "sha256:post", ContentDigest: "sha256:c",
		BlobRef: "evidence/post", SizeBytes: 4, EvidenceBytes: []byte(`{}`), Now: now,
	})
	if !errors.Is(err, store.ErrAccountClosed) {
		t.Fatalf("FE4: submit on a fenced account must return ErrAccountClosed, got %v", err)
	}
	if got := blobCount(t, s, acct); got != 0 {
		t.Fatalf("FE4: fenced submit must store no blob, got %d", got)
	}
}

// TestFE4DeletionAtomicRollbackOnMidwayFailure is the FE4 re-fix regression: the
// whole deletion is ONE transaction, so a failure partway through rolls back
// EVERYTHING — the account is NOT left 'closed' with evidence retained. Before
// the re-fix the fence committed in its own phase, so a later failure closed the
// account (the user could no longer authenticate to retry) while ciphertext
// survived. Here a BEFORE DELETE trigger on evidence_blobs injects a failure
// AFTER the in-tx fence + job-cancel have run; the assertion is that none of it
// stuck, and a retry (trigger removed) completes cleanly.
func TestFE4DeletionAtomicRollbackOnMidwayFailure(t *testing.T) {
	s, pool := newStore(t)
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 100, 1000, 100)
	ctx := context.Background()
	now := time.Now()

	submitEvid(t, s, acct, "fe4-atomic", []byte(`{"secret":"bytes"}`), now)
	if got := blobCount(t, s, acct); got != 1 {
		t.Fatalf("precondition: want 1 blob, got %d", got)
	}

	// Inject a mid-transaction failure: a BEFORE DELETE trigger on evidence_blobs
	// aborts the DELETE step, which runs after the fence + job-cancel inside the
	// single deletion transaction.
	if _, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION sbci_test_fe4_raise() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'injected fe4 failure'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER sbci_test_fe4_trg BEFORE DELETE ON evidence_blobs
		  FOR EACH ROW EXECUTE FUNCTION sbci_test_fe4_raise();`); err != nil {
		t.Fatalf("install fault trigger: %v", err)
	}

	if _, err := s.CreateDeletionRequest(ctx, acct, now); err == nil {
		t.Fatal("expected CreateDeletionRequest to fail with the injected fault")
	}

	// EVERYTHING rolled back: account still active (retryable), blob retained,
	// job still non-terminal, and no deletion_requests row was committed.
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM accounts WHERE account_id=$1::uuid`, acct).Scan(&status); err != nil {
		t.Fatalf("read account status: %v", err)
	}
	if status == "closed" {
		t.Fatal("FE4: a failed deletion must NOT leave the account closed — the user could not re-authenticate to retry")
	}
	if got := blobCount(t, s, acct); got != 1 {
		t.Fatalf("FE4: a failed deletion must retain evidence (rolled back), got %d blobs", got)
	}
	var reqRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deletion_requests WHERE account_id=$1::uuid`, acct).Scan(&reqRows); err != nil {
		t.Fatalf("count deletion_requests: %v", err)
	}
	if reqRows != 0 {
		t.Fatalf("FE4: a rolled-back deletion must leave no request row, got %d", reqRows)
	}

	// Remove the fault and retry — the still-active account deletes cleanly.
	if _, err := pool.Exec(ctx, `DROP TRIGGER sbci_test_fe4_trg ON evidence_blobs; DROP FUNCTION sbci_test_fe4_raise();`); err != nil {
		t.Fatalf("remove fault trigger: %v", err)
	}
	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("retry CreateDeletionRequest: %v", err)
	}
	if got := blobCount(t, s, acct); got != 0 {
		t.Fatalf("FE4: retried deletion must leave ZERO blobs, got %d", got)
	}
}
