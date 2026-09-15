package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// completeResult drives one job for `acct` all the way to a stored result
// (submit → lease → running → complete) and returns its result id. Because it
// completes each job before the next is submitted, only one job is ever queued,
// so LeaseNextJob deterministically returns the just-submitted job for `acct`.
func completeResult(t *testing.T, s *store.Store, acct, worker, key string, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	submitEvid(t, s, acct, key, []byte(`{"a":1}`), now)
	lj, err := s.LeaseNextJob(ctx, worker, []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil {
		t.Fatalf("lease(%s): %v (lj=%v)", key, err, lj)
	}
	if lj.AccountID != acct {
		t.Fatalf("lease returned a job for account %s, want %s", lj.AccountID, acct)
	}
	if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
		t.Fatalf("mark running(%s): %v", key, err)
	}
	rid, committed, err := s.CompleteJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID,
		worker, lj.LeaseGeneration, "session_enrichment.v2-candidate",
		[]byte(`{"title":"`+key+`"}`), store.ResultProvenance{}, now)
	if err != nil || !committed {
		t.Fatalf("complete(%s): err=%v committed=%v", key, err, committed)
	}
	return rid
}

// accountSeqBySeq returns (seq, account_seq) pairs for an account ordered by the
// global seq, read straight from the table (superuser pool bypasses RLS).
func accountSeqBySeq(t *testing.T, pool *pgxpool.Pool, acct string) [][2]int64 {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT seq, account_seq FROM analysis_results WHERE account_id = $1::uuid ORDER BY seq ASC`, acct)
	if err != nil {
		t.Fatalf("read account_seq: %v", err)
	}
	defer rows.Close()
	var out [][2]int64
	for rows.Next() {
		var seq, aseq int64
		if err := rows.Scan(&seq, &aseq); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, [2]int64{seq, aseq})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func assertDense1toN(t *testing.T, pairs [][2]int64, who string) {
	t.Helper()
	for i, p := range pairs {
		want := int64(i + 1)
		if p[1] != want {
			t.Fatalf("%s: row %d (seq=%d) has account_seq=%d, want dense %d (ordered by seq)", who, i, p[0], p[1], want)
		}
	}
}

func TestResultCursorSurvivesRetention(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 1000, 10000, 1000)
	for _, key := range []string{"first", "second"} {
		id := completeResult(t, s, acct, "w1", "cursor-retention-"+key, now)
		backdateResultCreatedAt(t, pool, id, now.Add(-40*24*time.Hour))
	}
	before, err := s.ListResultsAfterAccountSeq(ctx, acct, 0, 50)
	if err != nil || len(before) != 2 {
		t.Fatalf("initial pull: %v, rows=%d", err, len(before))
	}
	cursor := before[1].AccountSeq
	if n, err := s.SweepResultsRetention(ctx, now); err != nil || n != 2 {
		t.Fatalf("retention: %d, %v", n, err)
	}
	id := completeResult(t, s, acct, "w1", "cursor-retention-return", now)
	after, err := s.ListResultsAfterAccountSeq(ctx, acct, cursor, 50)
	if err != nil || len(after) != 1 || after[0].ID != id || after[0].AccountSeq <= cursor {
		t.Fatalf("returning account lost result at cursor %d: %+v, %v", cursor, after, err)
	}
}

// TestW6bBackfillDenseOrderedBySeqPerAccount seeds two accounts with INTERLEAVED
// global-seq results, simulates the pre-0016 world (drop the NOT NULL + unique,
// null every account_seq), runs the migration's EXACT backfill statement, and
// asserts each account's account_seq is a dense 1..N ordered by the original
// global seq — independently per account (E1 / W6b).
func TestW6bBackfillDenseOrderedBySeqPerAccount(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	a := makeAccount(t, s)
	b := makeAccount(t, s)
	setEntitlement(t, pool, a, 1000, 10000, 1000)
	setEntitlement(t, pool, b, 1000, 10000, 1000)

	// Interleave completions so the two accounts' rows alternate in global seq:
	// A, B, A, A, B, B, A.
	order := []string{a, b, a, a, b, b, a}
	for i, acct := range order {
		completeResult(t, s, acct, "w1", "backfill-"+string(rune('a'+i)), now)
	}

	// Simulate pre-migration state, then run the migration's exact backfill.
	if _, err := pool.Exec(ctx, `ALTER TABLE analysis_results DROP CONSTRAINT analysis_results_account_seq_uniq`); err != nil {
		t.Fatalf("drop uniq: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE analysis_results ALTER COLUMN account_seq DROP NOT NULL`); err != nil {
		t.Fatalf("drop not null: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE analysis_results SET account_seq = NULL`); err != nil {
		t.Fatalf("null account_seq: %v", err)
	}
	// The backfill statement copied verbatim from 0016_results_account_seq.sql.
	if _, err := pool.Exec(ctx, `
		WITH ranked AS (
		    SELECT id,
		           row_number() OVER (PARTITION BY account_id ORDER BY seq) AS rn
		      FROM analysis_results
		)
		UPDATE analysis_results r
		   SET account_seq = ranked.rn
		  FROM ranked
		 WHERE r.id = ranked.id`); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE analysis_results ALTER COLUMN account_seq SET NOT NULL`); err != nil {
		t.Fatalf("re-add not null: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE analysis_results ADD CONSTRAINT analysis_results_account_seq_uniq UNIQUE (account_id, account_seq)`); err != nil {
		t.Fatalf("re-add uniq: %v", err)
	}

	pa := accountSeqBySeq(t, pool, a)
	pb := accountSeqBySeq(t, pool, b)
	if len(pa) != 4 {
		t.Fatalf("account A: want 4 results, got %d", len(pa))
	}
	if len(pb) != 3 {
		t.Fatalf("account B: want 3 results, got %d", len(pb))
	}
	assertDense1toN(t, pa, "account A")
	assertDense1toN(t, pb, "account B")
}

// TestW6bAllocatorContinuesPerAccount proves the live allocator (not the
// backfill) mints a dense per-account sequence: A continues 1,2,3 and a second
// account B starts independently at 1 (E1 / W6b).
func TestW6bAllocatorContinuesPerAccount(t *testing.T) {
	s, pool := newStore(t)
	now := time.Now()

	a := makeAccount(t, s)
	setEntitlement(t, pool, a, 1000, 10000, 1000)
	for i := 0; i < 3; i++ {
		completeResult(t, s, a, "w1", "a-"+string(rune('0'+i)), now)
	}
	pa := accountSeqBySeq(t, pool, a)
	assertDense1toN(t, pa, "account A")
	if len(pa) != 3 || pa[2][1] != 3 {
		t.Fatalf("account A allocator did not reach account_seq=3: %v", pa)
	}

	b := makeAccount(t, s)
	setEntitlement(t, pool, b, 1000, 10000, 1000)
	completeResult(t, s, b, "w1", "b-0", now)
	pb := accountSeqBySeq(t, pool, b)
	if len(pb) != 1 || pb[0][1] != 1 {
		t.Fatalf("account B must start at account_seq=1 regardless of A's count, got %v", pb)
	}
}

// TestW6bSideChannelClosure is the whole point of E1: account A's account_seq is
// unaffected by inserts into account B. A's next allocation must not jump by B's
// volume.
func TestW6bSideChannelClosure(t *testing.T) {
	s, pool := newStore(t)
	now := time.Now()

	a := makeAccount(t, s)
	b := makeAccount(t, s)
	setEntitlement(t, pool, a, 1000, 10000, 1000)
	setEntitlement(t, pool, b, 1000, 10000, 1000)

	completeResult(t, s, a, "w1", "a-1", now)
	completeResult(t, s, a, "w1", "a-2", now) // A now at account_seq 2

	for i := 0; i < 5; i++ { // B writes five results in between
		completeResult(t, s, b, "w1", "b-"+string(rune('0'+i)), now)
	}

	completeResult(t, s, a, "w1", "a-3", now) // A's next result
	pa := accountSeqBySeq(t, pool, a)
	if len(pa) != 3 {
		t.Fatalf("account A: want 3 results, got %d", len(pa))
	}
	if pa[2][1] != 3 {
		t.Fatalf("E1 side-channel: A's third result got account_seq=%d — it JUMPED by B's volume; "+
			"the per-account cursor leaks cross-tenant volume", pa[2][1])
	}
}

// TestW6bAccountSeqAllocationTakesTheLock is the DETERMINISTIC concurrency gate
// (mirrors the structural F6/F8 pattern): hold the per-account allocation lock
// from an outside connection and prove a same-account completion BLOCKS on it,
// while a DIFFERENT account's completion does not. This is what proves the lock
// is taken before the MAX(account_seq) read — a racing loop lands milliseconds
// apart and usually reads the committed row, passing even with the lock removed.
func TestW6bAccountSeqAllocationTakesTheLock(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	a := makeAccount(t, s)
	b := makeAccount(t, s)
	setEntitlement(t, pool, a, 1000, 10000, 1000)
	setEntitlement(t, pool, b, 1000, 10000, 1000)

	// Prepare a running job for A and one for B, ready to complete.
	submitEvid(t, s, a, "lock-a", []byte(`{"a":1}`), now)
	ljA, err := s.LeaseNextJob(ctx, "wa", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || ljA == nil || ljA.AccountID != a {
		t.Fatalf("lease A: %v (lj=%v)", err, ljA)
	}
	if err := s.MarkJobRunning(ctx, a, ljA.JobID, now); err != nil {
		t.Fatalf("mark running A: %v", err)
	}
	submitEvid(t, s, b, "lock-b", []byte(`{"a":1}`), now)
	ljB, err := s.LeaseNextJob(ctx, "wb", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || ljB == nil || ljB.AccountID != b {
		t.Fatalf("lease B: %v (lj=%v)", err, ljB)
	}
	if err := s.MarkJobRunning(ctx, b, ljB.JobID, now); err != nil {
		t.Fatalf("mark running B: %v", err)
	}

	// Hold account A's allocation lock from our own connection.
	holder, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire holder conn: %v", err)
	}
	defer holder.Release()
	htx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder tx: %v", err)
	}
	if _, err := htx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`,
		store.ResultsAccountSeqLockKey(a)); err != nil {
		t.Fatalf("take A's allocation lock: %v", err)
	}

	// A's completion must block on the held lock.
	doneA := make(chan error, 1)
	go func() {
		_, committed, e := s.CompleteJobWithResult(ctx, a, ljA.JobID, ljA.EvidencePK, ljA.ReservationID,
			"wa", ljA.LeaseGeneration, "session_enrichment.v2-candidate", []byte(`{"title":"a"}`), store.ResultProvenance{}, now)
		if e == nil && !committed {
			e = errContext("A completion did not commit")
		}
		doneA <- e
	}()
	select {
	case e := <-doneA:
		t.Fatalf("A's completion finished (%v) while A's allocation lock was HELD — the allocator does not "+
			"serialize on the lock, so two same-account completions can collide on account_seq", e)
	case <-time.After(750 * time.Millisecond):
		// Correct: blocked on the lock.
	}

	// A DIFFERENT account's completion must NOT be blocked by A's lock.
	doneB := make(chan error, 1)
	go func() {
		_, committed, e := s.CompleteJobWithResult(ctx, b, ljB.JobID, ljB.EvidencePK, ljB.ReservationID,
			"wb", ljB.LeaseGeneration, "session_enrichment.v2-candidate", []byte(`{"title":"b"}`), store.ResultProvenance{}, now)
		if e == nil && !committed {
			e = errContext("B completion did not commit")
		}
		doneB <- e
	}()
	select {
	case e := <-doneB:
		if e != nil {
			t.Fatalf("B's completion (different account) failed: %v", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("B's completion blocked on A's per-account lock — the lock is too coarse (not per-account)")
	}

	// Release A's lock; A's completion now proceeds.
	if err := htx.Rollback(ctx); err != nil {
		t.Fatalf("release A's lock: %v", err)
	}
	select {
	case e := <-doneA:
		if e != nil {
			t.Fatalf("A's completion failed once the lock was released: %v", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("A's completion never finished after the lock was released")
	}

	pa := accountSeqBySeq(t, pool, a)
	if len(pa) != 1 || pa[0][1] != 1 {
		t.Fatalf("account A: want one result at account_seq=1, got %v", pa)
	}
}

// TestW6bConcurrentSameAccountAllocationsAreConsecutive is the racing smoke test
// that accompanies the deterministic gate: two concurrent completions for the
// SAME account both commit with DISTINCT consecutive account_seq (1 and 2),
// never a collision (the UNIQUE backstop + advisory lock).
func TestW6bConcurrentSameAccountAllocationsAreConsecutive(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	a := makeAccount(t, s)
	setEntitlement(t, pool, a, 1000, 10000, 1000)

	// Two queued+running jobs for the same account.
	type ready struct {
		jobID, evPK, resID string
		gen                int64
		worker             string
	}
	var jobs []ready
	for i, w := range []string{"w1", "w2"} {
		submitEvid(t, s, a, "cc-"+string(rune('0'+i)), []byte(`{"a":1}`), now)
		lj, err := s.LeaseNextJob(ctx, w, []string{store.FeatureSessionEnrichment}, time.Hour, now)
		if err != nil || lj == nil || lj.AccountID != a {
			t.Fatalf("lease %s: %v (lj=%v)", w, err, lj)
		}
		if err := s.MarkJobRunning(ctx, a, lj.JobID, now); err != nil {
			t.Fatalf("mark running %s: %v", w, err)
		}
		jobs = append(jobs, ready{lj.JobID, lj.EvidencePK, lj.ReservationID, lj.LeaseGeneration, w})
	}

	var wg sync.WaitGroup
	errs := make([]error, len(jobs))
	commits := make([]bool, len(jobs))
	start := make(chan struct{})
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j ready) {
			defer wg.Done()
			<-start
			_, committed, e := s.CompleteJobWithResult(ctx, a, j.jobID, j.evPK, j.resID,
				j.worker, j.gen, "session_enrichment.v2-candidate", []byte(`{"title":"cc"}`), store.ResultProvenance{}, now)
			errs[i], commits[i] = e, committed
		}(i, j)
	}
	close(start)
	wg.Wait()

	for i := range jobs {
		if errs[i] != nil || !commits[i] {
			t.Fatalf("completion %d: err=%v committed=%v", i, errs[i], commits[i])
		}
	}
	pa := accountSeqBySeq(t, pool, a)
	if len(pa) != 2 {
		t.Fatalf("want 2 results, got %d", len(pa))
	}
	seen := map[int64]bool{}
	for _, p := range pa {
		if p[1] != 1 && p[1] != 2 {
			t.Fatalf("account_seq out of range: %v", pa)
		}
		if seen[p[1]] {
			t.Fatalf("duplicate account_seq %d — concurrent allocations collided: %v", p[1], pa)
		}
		seen[p[1]] = true
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func errContext(s string) error { return errString(s) }

// The old worker locks a job before inserting a result. Migration 0038 must
// not require the account UPDATE lock held by a concurrent deletion fence.
func TestOldWorkerResultAllocationDoesNotWaitForDeletionFence(t *testing.T) {
	s, pool := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	acct := makeAccount(t, s)
	now := time.Now()
	submitEvid(t, s, acct, "old-worker-lock", []byte(`{"a":1}`), now)
	job, err := s.LeaseNextJob(ctx, "old", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || job == nil {
		t.Fatalf("lease: %v", err)
	}
	completion, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = completion.Rollback(context.Background()) }()
	if _, err := completion.Exec(ctx, `UPDATE analysis_jobs SET state='succeeded' WHERE id=$1::uuid`, job.JobID); err != nil {
		t.Fatal(err)
	}
	deletion, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = deletion.Rollback(context.Background()) }()
	if _, err := deletion.Exec(ctx, `UPDATE accounts SET status='closed' WHERE account_id=$1::uuid`, acct); err != nil {
		t.Fatal(err)
	}
	// An accounts-column allocator blocks here and eventually times out;
	// deletion cannot then acquire the job to finish. Exercise the old MAX
	// proposal under a real worker role and force a retention-reset proposal.
	if _, err := completion.Exec(ctx, `SET LOCAL ROLE sbci_worker`); err != nil {
		t.Fatal(err)
	}
	if _, err := completion.Exec(ctx, `SELECT set_config('sbci.account_id', $1, true)`, acct); err != nil {
		t.Fatal(err)
	}
	for want := int64(1); want <= 2; want++ {
		var got int64
		err := completion.QueryRow(ctx, `INSERT INTO analysis_results (account_id, job_id, result, schema_version, ai_source, account_seq)
            VALUES ($1::uuid, $2::uuid, '{}'::jsonb, 'session_enrichment.v2-candidate', true,
                (SELECT coalesce(max(account_seq),0)+1 FROM analysis_results WHERE account_id=$1::uuid)) RETURNING account_seq`, acct, job.JobID).Scan(&got)
		if err != nil || got != want {
			t.Fatalf("old proposal under deletion fence: got=%d want=%d err=%v", got, want, err)
		}
		if _, err := completion.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		if _, err := completion.Exec(ctx, `DELETE FROM analysis_results WHERE account_id=$1::uuid`, acct); err != nil {
			t.Fatal(err)
		}
		if _, err := completion.Exec(ctx, `SET LOCAL ROLE sbci_worker`); err != nil {
			t.Fatal(err)
		}
	}
}
