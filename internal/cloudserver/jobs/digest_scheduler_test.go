package jobs_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/foundry"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// digest_scheduler_test.go covers acceptance items 2 and 3 end to end at the
// jobs-package level: the scheduler submits exactly one digest job per
// (account, project, period) that qualifies, a free account gets none, a
// re-run submits nothing new, and the digest executor turns a fake Foundry
// response into a stored project_digest result.

// assignPlusBetaTx assigns plus_beta to acct effective now (jobs-package
// mirror of the store-package test helper of the same shape).
func assignPlusBetaTx(t *testing.T, s *store.Store, acct string, now time.Time) {
	t.Helper()
	if _, err := s.AssignPlan(context.Background(), acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan(plus_beta): %v", err)
	}
}

// makeSecondAccount creates a second, distinct account against the SAME store
// (and so the SAME database) as the account setup(t) returned. setup(t) mints
// a brand-new DATABASE every call (cloudtestpg.NewDB), so a second setup(t)
// call would put the two accounts in unrelated databases — defeating a
// cross-tenant test like TestDigestSchedulerEndToEnd, whose whole point is
// that ListProjectDigestCandidates's SECURITY DEFINER scan sees both accounts
// in ONE pass and filters one out by plan. The subject must differ from
// setup's own "w" or Exchange resolves back to the SAME account.
func makeSecondAccount(t *testing.T, s *store.Store) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	nonce, err := s.MintNonce(ctx, store.DefaultNonceTTL, now)
	if err != nil {
		t.Fatalf("MintNonce: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	res, err := s.Exchange(ctx, store.ExchangeInput{Provider: "dev", Subject: "w2", PublicKey: pub, RawNonce: nonce, Now: now})
	if err != nil {
		t.Fatalf("Exchange (second account): %v", err)
	}
	return res.AccountID
}

func TestDigestSchedulerEndToEnd(t *testing.T) {
	s, pool, plus := setup(t)
	ctx := context.Background()
	now := time.Now()
	assignPlusBetaTx(t, s, plus, now)

	// SAME store as plus (see makeSecondAccount's doc comment) — a second
	// setup(t) would create an unrelated database and the free account would
	// never be visible to the candidate scan run against s below.
	free := makeSecondAccount(t, s)

	monday, _ := store.WeekBoundsUTC(now)
	prevMonday := monday.AddDate(0, 0, -7)
	mid := prevMonday.Add(24 * time.Hour)

	seedThreeEnriched := func(acct string) {
		for i := 0; i < 3; i++ {
			key := acct + "-seed-" + string(rune('a'+i))
			// Submit/lease/complete against the REAL wall clock: the lease CAS in
			// completeJobWithResultTx checks lease_expires_at against
			// clock_timestamp(), not the caller's now, so a backdated now here
			// would make the completion's own CAS fail (committed=false). Backdate
			// only created_at afterward to land the row in the previous ISO week.
			sub := submit(t, s, acct, key, now)
			lj, err := s.LeaseNextJob(ctx, "w1", []string{store.FeatureSessionEnrichment}, time.Hour, now)
			if err != nil || lj == nil || lj.JobID != sub.JobID {
				t.Fatalf("lease(%s): %v (lj=%v)", key, err, lj)
			}
			if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
				t.Fatalf("mark running(%s): %v", key, err)
			}
			rid, committed, err := s.CompleteJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID,
				"w1", lj.LeaseGeneration, "session_enrichment.v2-candidate",
				[]byte(`{"title":"`+key+`"}`), store.ResultProvenance{}, now)
			if err != nil || !committed {
				t.Fatalf("complete(%s): err=%v committed=%v", key, err, committed)
			}
			if _, err := pool.Exec(ctx, `UPDATE analysis_results SET created_at=$2 WHERE id=$1::uuid`, rid, mid); err != nil {
				t.Fatalf("backdate(%s): %v", key, err)
			}
		}
	}
	seedThreeEnriched(plus)
	seedThreeEnriched(free)

	// submit() defaults every session to CloudProjectID "p", so both accounts
	// have exactly one qualifying project.
	// Admission pre-check first (review 2026-09-15): with NO credential source
	// / attestor wired, and with a credential source that reports absent, the
	// scheduler submits nothing - so no reservation, evidence or canonical key
	// is spent on a job that could only park at the lease.
	for name, cfg := range map[string]jobs.DigestSchedulerConfig{
		"nothing wired":      {},
		"credential absent":  {Credentials: jobs.StaticCredentials{}, Attestor: verifiedAttestor{}},
		"attestation failed": {Credentials: jobs.StaticCredentials{Key: "k"}, Attestor: jobs.UnverifiedAttestor{}},
		"refusing attestor":  {Credentials: jobs.StaticCredentials{Key: "k"}, Attestor: jobs.RefusingAttestor{Reason: "conflict"}},
	} {
		n0, err := jobs.RunDigestSchedulerOnce(ctx, s, now, cfg)
		if err != nil {
			t.Fatalf("RunDigestSchedulerOnce(%s): %v", name, err)
		}
		if n0 != 0 {
			t.Fatalf("RunDigestSchedulerOnce(%s) submitted %d, want 0 (fail closed before any SubmitDigestJob)", name, n0)
		}
		u, err := s.Usage(ctx, plus, store.FeatureProjectDigest, now)
		if err != nil {
			t.Fatalf("Usage(plus) after %s: %v", name, err)
		}
		if u.DailyUsed != 0 {
			t.Fatalf("%s: plus daily_used = %d, want 0 (no reservation may be spent when admission fails)", name, u.DailyUsed)
		}
	}

	admitted := jobs.DigestSchedulerConfig{Credentials: jobs.StaticCredentials{Key: "k"}, Attestor: verifiedAttestor{}}
	n, err := jobs.RunDigestSchedulerOnce(ctx, s, now, admitted)
	if err != nil {
		t.Fatalf("RunDigestSchedulerOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("submitted %d digest jobs, want exactly 1 (the plus_beta account's one project)", n)
	}

	// The free account got none: its usage shows no project_digest reservation.
	freeUsage, err := s.Usage(ctx, free, store.FeatureProjectDigest, now)
	if err != nil {
		t.Fatalf("Usage(free): %v", err)
	}
	if freeUsage.DailyUsed != 0 {
		t.Fatalf("free account's project_digest daily_used = %d, want 0", freeUsage.DailyUsed)
	}
	plusUsage, err := s.Usage(ctx, plus, store.FeatureProjectDigest, now)
	if err != nil {
		t.Fatalf("Usage(plus): %v", err)
	}
	if plusUsage.DailyUsed != 1 {
		t.Fatalf("plus account's project_digest daily_used = %d, want 1", plusUsage.DailyUsed)
	}

	// Re-running the scheduler submits nothing new (the job is already queued;
	// SubmitDigestJob's canonical-key fast path returns the existing job).
	n2, err := jobs.RunDigestSchedulerOnce(ctx, s, now, admitted)
	if err != nil {
		t.Fatalf("RunDigestSchedulerOnce (2): %v", err)
	}
	if n2 != 0 {
		// RunDigestSchedulerOnce counts every SubmitDigestJob call that did not
		// error, INCLUDING an idempotent hit — assert no SECOND reservation was
		// consumed instead, which is the property that actually matters.
		plusUsage2, err := s.Usage(ctx, plus, store.FeatureProjectDigest, now)
		if err != nil {
			t.Fatalf("Usage(plus, 2): %v", err)
		}
		if plusUsage2.DailyUsed != 1 {
			t.Fatalf("re-running the scheduler consumed a second reservation: daily_used=%d, want 1", plusUsage2.DailyUsed)
		}
	}
}

// TestDigestExecutorHappyPathE2E mirrors TestExecutorHappyPathE2E (the Luna
// executor's own E2E test) for the digest executor: a fake Foundry response
// is turned into a stored project_digest result with the project/period
// linkage, settling exactly one reservation.
func TestDigestExecutorHappyPathE2E(t *testing.T) {
	s, _, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	assignPlusBetaTx(t, s, acct, now)

	evidence := []byte(`{"schema_version":"project_digest_evidence.v1","project_pseudonym":"proj-1",` +
		`"period_start":"2026-04-06","period_end":"2026-04-12","sessions":[{"cloud_session_id":"s1","title":"did work"}]}`)
	if _, err := s.SubmitDigestJob(ctx, store.SubmitDigestJobInput{
		AccountID: acct, CloudProjectID: "proj-1", PeriodStart: "2026-04-06", PeriodEnd: "2026-04-12",
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		EvidenceBytes: evidence, BlobRef: "digest/proj-1/2026-04-06",
		UploadDigest: "sha256:digeste2e", ContentDigest: "sha256:digeste2e",
		SizeBytes: int64(len(evidence)), Now: now,
	}); err != nil {
		t.Fatalf("SubmitDigestJob: %v", err)
	}

	provider := &foundry.FakeProvider{Response: foundry.Response{
		Content: `{"headline":"Steady progress on proj-1","themes":["refactor"],"cost_trend":"",` +
			`"recurring_error_classes":[],"unfinished_threads":[],"suggested_next_session":"",` +
			`"confidence":"low","limitations":["structural evidence only"]}`,
		TokensIn: 20, TokensOut: 10,
	}}
	blobs := store.NewPGBlobStore(s)
	exec := jobs.NewDigestExecutor(s, blobs, provider)
	w := jobs.NewWorker(jobs.Config{WorkerID: "w1", LeaseFor: time.Hour, Classes: []string{store.FeatureProjectDigest}},
		jobs.NewPGQueue(s), s, verifiedAttestor{}, jobs.StaticCredentials{Key: "k"},
		map[string]jobs.Executor{store.FeatureProjectDigest: exec})

	out, err := w.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "succeeded" {
		t.Fatalf("digest job state = %s, want succeeded (out=%+v)", out.State, out)
	}

	rows, err := s.ListResultsAfterAccountSeq(ctx, acct, 0, 50)
	if err != nil {
		t.Fatalf("ListResultsAfterAccountSeq: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 stored result, got %d", len(rows))
	}
	r := rows[0]
	if r.Kind != store.ResultKindProjectDigest {
		t.Errorf("kind = %q, want %q", r.Kind, store.ResultKindProjectDigest)
	}
	if r.CloudProjectID != "proj-1" {
		t.Errorf("cloud_project_id = %q, want %q", r.CloudProjectID, "proj-1")
	}
	if r.PeriodStart != "2026-04-06" || r.PeriodEnd != "2026-04-12" {
		t.Errorf("period = %s..%s, want 2026-04-06..2026-04-12", r.PeriodStart, r.PeriodEnd)
	}

	// Exactly one project_digest user unit was consumed.
	snap, err := s.Usage(ctx, acct, store.FeatureProjectDigest, now)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if snap.DailyUsed != 1 {
		t.Fatalf("project_digest daily_used = %d, want 1", snap.DailyUsed)
	}
}

func TestDigestDispatchRechecksCurrentPlan(t *testing.T) {
	s, pool, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	assignPlusBetaTx(t, s, acct, now)
	if _, err := s.SubmitDigestJob(ctx, store.SubmitDigestJobInput{
		AccountID: acct, CloudProjectID: "proj-1", PeriodStart: "2026-04-06", PeriodEnd: "2026-04-12",
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		EvidenceBytes: []byte(`{"schema_version":"project_digest_evidence.v1"}`), BlobRef: "digest/revoked",
		UploadDigest: "sha256:revoked", ContentDigest: "sha256:revoked", SizeBytes: 10, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM account_plans WHERE account_id = $1::uuid`, acct); err != nil {
		t.Fatal(err)
	}
	provider := &foundry.FakeProvider{}
	executor := jobs.NewDigestExecutor(s, store.NewPGBlobStore(s), provider)
	w := jobs.NewWorker(jobs.Config{WorkerID: "w1", LeaseFor: time.Hour, Classes: []string{store.FeatureProjectDigest}},
		jobs.NewPGQueue(s), s, verifiedAttestor{}, jobs.StaticCredentials{Key: "k"},
		map[string]jobs.Executor{store.FeatureProjectDigest: executor})
	out, err := w.ProcessOnce(ctx, now)
	if err != nil || out.State != "parked" || out.Reason != store.ReasonEntitlementRevoked || len(provider.Requests) != 0 {
		t.Fatalf("digest dispatched without Plus: %+v, requests=%d, err=%v", out, len(provider.Requests), err)
	}
	snap, err := s.Usage(ctx, acct, store.FeatureProjectDigest, now)
	if err != nil || snap.DailyUsed != 0 {
		t.Fatalf("refused digest retained reservation: %+v, %v", snap, err)
	}
}

// TestDigestJobFailsClosedWithNoWiredExecutor pins W5's executor-dispatch
// table: a worker with NO project_digest entry fails a leased digest job
// terminal (executor_missing) rather than declining forever or silently
// succeeding.
func TestDigestJobFailsClosedWithNoWiredExecutor(t *testing.T) {
	s, _, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	assignPlusBetaTx(t, s, acct, now)

	if _, err := s.SubmitDigestJob(ctx, store.SubmitDigestJobInput{
		AccountID: acct, CloudProjectID: "proj-2", PeriodStart: "2026-05-04", PeriodEnd: "2026-05-10",
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		EvidenceBytes: []byte(`{"schema_version":"project_digest_evidence.v1"}`),
		BlobRef:       "digest/proj-2/2026-05-04", UploadDigest: "sha256:missing", ContentDigest: "sha256:missing",
		SizeBytes: 10, Now: now,
	}); err != nil {
		t.Fatalf("SubmitDigestJob: %v", err)
	}

	// A worker configured to lease project_digest jobs but wired with NO
	// executor for that feature (only the default map's session_enrichment
	// entry survives when a caller passes an explicit map missing it).
	w := jobs.NewWorker(jobs.Config{WorkerID: "w1", LeaseFor: time.Hour, Classes: []string{store.FeatureProjectDigest}},
		jobs.NewPGQueue(s), s, verifiedAttestor{}, jobs.StaticCredentials{Key: "k"},
		map[string]jobs.Executor{})

	out, err := w.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "failed" || out.Reason != store.ReasonExecutorMissing {
		t.Fatalf("want failed/executor_missing, got %+v", out)
	}
}
