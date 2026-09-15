package store_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// completeResultInSession drives one job to a stored result inside a FIXED cloud
// session (so a second call to the same session exercises the regeneration
// supersede path). It completes each job before submitting the next, so the
// lease is deterministic.
func completeResultInSession(t *testing.T, s *store.Store, acct, worker, session, key, title string, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	sub, err := s.SubmitJob(ctx, store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p", CloudSessionID: session,
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: key, UploadDigest: "sha256:" + key, ContentDigest: "sha256:c",
		BlobRef: "evidence/" + key, SizeBytes: 4, EvidenceBytes: []byte(`{"a":1}`),
		ConsentGeneration: 0, Now: now,
	})
	if err != nil {
		t.Fatalf("submit %s: %v", key, err)
	}
	lj, err := s.LeaseNextJob(ctx, worker, []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil || lj.JobID != sub.JobID {
		t.Fatalf("lease %s: %v (lj=%v)", key, err, lj)
	}
	if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
		t.Fatalf("mark running %s: %v", key, err)
	}
	rid, committed, err := s.CompleteJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID,
		worker, lj.LeaseGeneration, "session_enrichment.v2-candidate",
		[]byte(`{"title":"`+title+`","schema_version":"`+"session_enrichment.v2-candidate"+`"}`), store.ResultProvenance{}, now)
	if err != nil || !committed {
		t.Fatalf("complete %s: err=%v committed=%v", key, err, committed)
	}
	return rid
}

func correctionSeqOf(t *testing.T, pool *pgxpool.Pool, acct, rid string) int64 {
	t.Helper()
	var seq int64
	if err := pool.QueryRow(context.Background(),
		`SELECT correction_seq FROM analysis_results WHERE account_id=$1::uuid AND id=$2::uuid`,
		acct, rid).Scan(&seq); err != nil {
		t.Fatalf("read correction_seq: %v", err)
	}
	return seq
}

func revCountOf(t *testing.T, pool *pgxpool.Pool, acct, rid string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM result_revisions WHERE account_id=$1::uuid AND result_id=$2::uuid`,
		acct, rid).Scan(&n); err != nil {
		t.Fatalf("rev count: %v", err)
	}
	return n
}

// TestResultCorrectionAppendOnlyAndETag proves the R6 append-only + ETag model:
// each accepted correction appends a new higher-numbered revision and bumps the
// result's correction_seq by one; a stale If-Match writes nothing and returns
// the current head; and the immutable AI original body is never touched.
func TestResultCorrectionAppendOnlyAndETag(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 1000, 10000, 1000)

	rid := completeResultInSession(t, s, acct, "w1", "cs-1", "k-r1", "AI original", now)
	if got := correctionSeqOf(t, pool, acct, rid); got != 0 {
		t.Fatalf("fresh result correction_seq=%d, want 0", got)
	}

	// Correction #1 at If-Match 0 → revision 1, correction_seq 1.
	o1, err := s.ApplyResultCorrection(ctx, acct, rid, 0, "k1", []byte(`{"title":"edit-1"}`), store.CorrectionSourceNode, now)
	if err != nil {
		t.Fatalf("correction #1: %v", err)
	}
	if o1.RevisionSeq != 1 || o1.CorrectionSeq != 1 || o1.Replayed {
		t.Fatalf("correction #1 outcome=%+v, want rev=1 seq=1 replay=false", o1)
	}

	// Correction #2 at If-Match 1 → revision 2, correction_seq 2.
	o2, err := s.ApplyResultCorrection(ctx, acct, rid, 1, "k2", []byte(`{"description":"edit-2"}`), store.CorrectionSourcePortal, now)
	if err != nil {
		t.Fatalf("correction #2: %v", err)
	}
	if o2.RevisionSeq != 2 || o2.CorrectionSeq != 2 {
		t.Fatalf("correction #2 outcome=%+v, want rev=2 seq=2", o2)
	}
	if got := revCountOf(t, pool, acct, rid); got != 2 {
		t.Fatalf("revision count=%d, want 2", got)
	}

	// A stale If-Match (0, the head is now 2) writes nothing and returns the head.
	o3, err := s.ApplyResultCorrection(ctx, acct, rid, 0, "k3", []byte(`{"title":"stale"}`), store.CorrectionSourceNode, now)
	if !errors.Is(err, store.ErrResultETagMismatch) {
		t.Fatalf("stale If-Match: err=%v, want ErrResultETagMismatch", err)
	}
	if o3.CorrectionSeq != 2 {
		t.Fatalf("stale If-Match returned CorrectionSeq=%d, want the current head 2", o3.CorrectionSeq)
	}
	if got := revCountOf(t, pool, acct, rid); got != 2 {
		t.Fatalf("stale If-Match wrote a revision: count=%d, want 2 (unchanged)", got)
	}

	// The immutable AI original body is untouched by any correction.
	var body string
	if err := pool.QueryRow(ctx, `SELECT result::text FROM analysis_results WHERE account_id=$1::uuid AND id=$2::uuid`,
		acct, rid).Scan(&body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(body, "AI original") || strings.Contains(body, "edit-") {
		t.Fatalf("AI original body was mutated by a correction: %s", body)
	}

	// Revisions come back newest-first with their sources.
	revs, err := s.ListResultRevisions(ctx, acct, rid)
	if err != nil {
		t.Fatalf("ListResultRevisions: %v", err)
	}
	if len(revs) != 2 || revs[0].RevisionSeq != 2 || revs[1].RevisionSeq != 1 {
		t.Fatalf("revisions not newest-first: %+v", revs)
	}
	if revs[0].Source != "portal" || revs[1].Source != "node" {
		t.Fatalf("revision sources wrong: %q, %q", revs[0].Source, revs[1].Source)
	}
}

// TestResultCorrectionIdempotencyReplayBeforeIfMatch proves the ordering that
// makes a retry safe: an idempotency-key replay short-circuits BEFORE the
// If-Match check, so a client retrying the same edit with its now-stale original
// If-Match replays the same revision instead of getting a 412, and no duplicate
// revision is written.
func TestResultCorrectionIdempotencyReplayBeforeIfMatch(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 1000, 10000, 1000)

	rid := completeResultInSession(t, s, acct, "w1", "cs-1", "k-r1", "AI original", now)

	o1, err := s.ApplyResultCorrection(ctx, acct, rid, 0, "same-key", []byte(`{"title":"edit-1"}`), store.CorrectionSourceNode, now)
	if err != nil || o1.RevisionSeq != 1 || o1.Replayed {
		t.Fatalf("first apply outcome=%+v err=%v", o1, err)
	}
	// A second correction advances the head to 2, so the original If-Match (0) is
	// now stale.
	if _, err := s.ApplyResultCorrection(ctx, acct, rid, 1, "other-key", []byte(`{"title":"edit-2"}`), store.CorrectionSourceNode, now); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	// Retry the FIRST correction: same key, its stale If-Match 0. It must REPLAY
	// (not 412), return the original revision number, and the CURRENT head.
	o2, err := s.ApplyResultCorrection(ctx, acct, rid, 0, "same-key", []byte(`{"title":"edit-1"}`), store.CorrectionSourceNode, now)
	if err != nil {
		t.Fatalf("idempotent retry: %v (want a replay, not an error)", err)
	}
	if !o2.Replayed || o2.RevisionSeq != 1 || o2.CorrectionSeq != 2 {
		t.Fatalf("idempotent retry outcome=%+v, want replay=true rev=1 seq=2", o2)
	}
	if got := revCountOf(t, pool, acct, rid); got != 2 {
		t.Fatalf("replay wrote a duplicate revision: count=%d, want 2", got)
	}
}

// TestResultCorrectionConcurrentSingleWinner proves the ETag serializes racing
// editors: with N corrections all presenting If-Match 0, exactly one is accepted
// (appends revision 1, bumps the head to 1) and the rest get ErrResultETagMismatch.
func TestResultCorrectionConcurrentSingleWinner(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 1000, 10000, 1000)

	rid := completeResultInSession(t, s, acct, "w1", "cs-1", "k-r1", "AI original", now)

	const n = 8
	var wg sync.WaitGroup
	var wins, mismatches int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := s.ApplyResultCorrection(ctx, acct, rid, 0, "cc-"+string(rune('a'+i)), []byte(`{"title":"c"}`), store.CorrectionSourceNode, now)
			switch {
			case e == nil:
				atomic.AddInt32(&wins, 1)
			case errors.Is(e, store.ErrResultETagMismatch):
				atomic.AddInt32(&mismatches, 1)
			default:
				t.Errorf("unexpected error: %v", e)
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 || mismatches != n-1 {
		t.Fatalf("concurrent corrections: wins=%d mismatches=%d, want 1/%d", wins, mismatches, n-1)
	}
	if got := revCountOf(t, pool, acct, rid); got != 1 {
		t.Fatalf("more than one correction landed: revision count=%d, want 1", got)
	}
	if got := correctionSeqOf(t, pool, acct, rid); got != 1 {
		t.Fatalf("correction_seq=%d, want exactly 1 after the single winner", got)
	}
}

// TestRegenerationSupersedesPriorSessionResult proves the D21 supersede path: a
// newer result for the same session marks the prior current result superseded
// (pointing superseded_by at the new one) and leaves the new one current, while
// a result in a DIFFERENT session is untouched — the supersession is scoped to
// the session, not the whole account.
func TestRegenerationSupersedesPriorSessionResult(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 1000, 10000, 1000)

	// A result in an UNRELATED session — it must never be superseded.
	other := completeResultInSession(t, s, acct, "w1", "cs-other", "k-other", "unrelated", now)

	r1 := completeResultInSession(t, s, acct, "w1", "cs-regen", "k-r1", "AI v1", now)
	r2 := completeResultInSession(t, s, acct, "w1", "cs-regen", "k-r2", "AI v2", now)

	read := func(rid string) (bool, string) {
		var sup bool
		var by string
		if err := pool.QueryRow(ctx,
			`SELECT superseded, coalesce(superseded_by::text,'') FROM analysis_results WHERE account_id=$1::uuid AND id=$2::uuid`,
			acct, rid).Scan(&sup, &by); err != nil {
			t.Fatalf("read %s: %v", rid, err)
		}
		return sup, by
	}
	if sup, by := read(r1); !sup || by != r2 {
		t.Fatalf("r1 superseded=%v superseded_by=%s, want true / %s", sup, by, r2)
	}
	if sup, _ := read(r2); sup {
		t.Fatal("r2 (the newest) must NOT be superseded")
	}
	if sup, _ := read(other); sup {
		t.Fatal("a result in a different session must never be superseded by a regeneration")
	}

	// A user edit on the superseded r1 still succeeds (history stays editable) and
	// does NOT resurrect it as un-superseded.
	if _, err := s.ApplyResultCorrection(ctx, acct, r1, 0, "edit-old", []byte(`{"title":"kept"}`), store.CorrectionSourcePortal, now); err != nil {
		t.Fatalf("correcting a superseded result should still work: %v", err)
	}
	if sup, _ := read(r1); !sup {
		t.Fatal("correcting a superseded result must not clear its superseded flag")
	}
}

// TestCorrectionRevisionsPurgedOnDeletion proves the W6d deletion-completion
// extension: account deletion PURGES every user-correction revision (and the
// result it belongs to) — no attributable text and no row survives — is
// idempotent on a re-run, and a NEW correction after deletion hits a
// now-nonexistent result (ErrNotFound).
func TestCorrectionRevisionsPurgedOnDeletion(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 1000, 10000, 1000)

	rid := completeResultInSession(t, s, acct, "w1", "cs-1", "k-r1", "AI original", now)
	if _, err := s.ApplyResultCorrection(ctx, acct, rid, 0, "k1", []byte(`{"title":"secret-edit-1"}`), store.CorrectionSourceNode, now); err != nil {
		t.Fatalf("correction #1: %v", err)
	}
	if _, err := s.ApplyResultCorrection(ctx, acct, rid, 1, "k2", []byte(`{"title":"secret-edit-2"}`), store.CorrectionSourcePortal, now); err != nil {
		t.Fatalf("correction #2: %v", err)
	}

	dr, err := s.CreateDeletionRequest(ctx, acct, now)
	if err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}
	if dr.State != "done" {
		t.Fatalf("deletion state=%q, want done", dr.State)
	}

	// Every revision row is GONE — purged, not tombstoned.
	var revRows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM result_revisions WHERE account_id=$1::uuid`,
		acct).Scan(&revRows); err != nil {
		t.Fatalf("scan revisions: %v", err)
	}
	if revRows != 0 {
		t.Fatalf("%d revision row(s) survived deletion; want 0 (purged)", revRows)
	}
	if got := revCountOf(t, pool, acct, rid); got != 0 {
		t.Fatalf("revision rows should be purged: count=%d, want 0", got)
	}

	// Idempotent: a second deletion purges nothing further.
	dr2, err := s.CreateDeletionRequest(ctx, acct, now)
	if err != nil {
		t.Fatalf("CreateDeletionRequest (2nd): %v", err)
	}
	if dr2.PurgedRows != 0 {
		t.Fatalf("2nd PurgedRows=%d, want 0 (idempotent)", dr2.PurgedRows)
	}

	// A NEW correction after deletion targets a purged result → ErrNotFound.
	if _, err := s.ApplyResultCorrection(ctx, acct, rid, 2, "k3", []byte(`{"title":"post-delete"}`), store.CorrectionSourceNode, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("correction after deletion: err=%v, want ErrNotFound", err)
	}
}

// TestSessionsListAndDetail proves the portal Sessions read surface: the list
// carries the effective title + edited/tombstone flags and paginates; the detail
// returns every result newest-first with its revision history and the current
// head (the newest non-superseded result).
func TestSessionsListAndDetail(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 1000, 10000, 1000)

	// Session A: one result, user edited the title.
	rA := completeResultInSession(t, s, acct, "w1", "cs-A", "kA", "AI title A", now)
	if _, err := s.ApplyResultCorrection(ctx, acct, rA, 0, "kA-edit", []byte(`{"title":"user title A"}`), store.CorrectionSourcePortal, now.Add(time.Second)); err != nil {
		t.Fatalf("edit A: %v", err)
	}
	// Session B: two results (a regeneration), no edits.
	completeResultInSession(t, s, acct, "w1", "cs-B", "kB1", "AI B v1", now.Add(2*time.Second))
	completeResultInSession(t, s, acct, "w1", "cs-B", "kB2", "AI B v2", now.Add(3*time.Second))

	page, err := s.ListAccountSessions(ctx, acct, 25, time.Time{}, "")
	if err != nil {
		t.Fatalf("ListAccountSessions: %v", err)
	}
	if len(page.Sessions) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(page.Sessions))
	}
	byID := map[string]store.AccountSessionSummary{}
	for _, it := range page.Sessions {
		byID[it.CloudSessionID] = it
	}
	if a := byID["cs-A"]; a.EffectiveTitle != "user title A" || !a.Edited || a.Tombstoned {
		t.Fatalf("session A summary wrong: %+v (want effective 'user title A', edited)", a)
	}
	if b := byID["cs-B"]; b.EffectiveTitle != "AI B v2" || b.Edited || b.ResultCount != 2 {
		t.Fatalf("session B summary wrong: %+v (want effective 'AI B v2', not edited, 2 results)", b)
	}

	// Detail for B: two results newest-first, head is the non-superseded one.
	det, err := s.GetAccountSession(ctx, acct, "cs-B")
	if err != nil {
		t.Fatalf("GetAccountSession(cs-B): %v", err)
	}
	if len(det.Results) != 2 {
		t.Fatalf("session B detail: want 2 results, got %d", len(det.Results))
	}
	if det.Results[0].Superseded {
		t.Fatal("the first (head) result must be the non-superseded one")
	}
	if det.HeadResultID != det.Results[0].ResultID {
		t.Fatalf("head_result_id=%s, want the first result %s", det.HeadResultID, det.Results[0].ResultID)
	}

	// Pagination: a limit of 1 returns one row + a usable cursor to the next.
	p1, err := s.ListAccountSessions(ctx, acct, 1, time.Time{}, "")
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(p1.Sessions) != 1 || !p1.HasMore {
		t.Fatalf("page 1: got %d rows hasMore=%v, want 1/true", len(p1.Sessions), p1.HasMore)
	}
	p2, err := s.ListAccountSessions(ctx, acct, 1, p1.NextCreatedAt, p1.NextCloudSessionID)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(p2.Sessions) != 1 {
		t.Fatalf("page 2: got %d rows, want 1", len(p2.Sessions))
	}
	if p2.Sessions[0].CloudSessionID == p1.Sessions[0].CloudSessionID {
		t.Fatal("page 2 repeated page 1's row — keyset pagination is broken")
	}
}

// TestGetAccountSessionUnknownIsNotFound proves an unknown pseudonym is a clean
// ErrNotFound (out-of-scope ≡ not found), never a leak or a 500.
func TestGetAccountSessionUnknownIsNotFound(t *testing.T) {
	s, _ := newStore(t)
	acct := makeAccount(t, s)
	if _, err := s.GetAccountSession(context.Background(), acct, "no-such-session"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown session: err=%v, want ErrNotFound", err)
	}
}
