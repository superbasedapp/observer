package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// digest_test.go pins the W5 project-digest seam (cloud-intelligence
// value-upgrade plan 2026-09-15): the cross-tenant candidate scan, the
// idempotent submit path, the completion linkage (kind/project_pk/period),
// the per-plan results-retention sweep, the Usage snapshot's digest fields,
// the correction refusal for a digest row, and the content-free session
// metrics snapshot captured at submit time.

// backdateResultCreatedAt sets an analysis_results row's created_at directly
// (the superuser pool bypasses RLS), mirroring retention_test.go's pattern of
// backdating a clock column a store method never lets a caller set directly.
func backdateResultCreatedAt(t *testing.T, pool *pgxpool.Pool, resultID string, at time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE analysis_results SET created_at = $2 WHERE id = $1::uuid`, resultID, at); err != nil {
		t.Fatalf("backdate result %s: %v", resultID, err)
	}
}

// completeDigestJob drives a project_digest job for acct all the way to a
// stored result (submit -> lease -> running -> complete), mirroring
// completeResult (results_w6b_test.go) for the digest feature.
func completeDigestJob(t *testing.T, s *store.Store, acct, worker, cloudProjectID, periodStart, periodEnd string, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	evidence := []byte(fmt.Sprintf(
		`{"schema_version":"project_digest_evidence.v1","project_pseudonym":%q,"period_start":%q,"period_end":%q,"sessions":[]}`,
		cloudProjectID, periodStart, periodEnd,
	))
	uploadDigest := "sha256:digest-" + cloudProjectID + "-" + periodStart
	if _, err := s.SubmitDigestJob(ctx, store.SubmitDigestJobInput{
		AccountID: acct, CloudProjectID: cloudProjectID, PeriodStart: periodStart, PeriodEnd: periodEnd,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		EvidenceBytes: evidence, BlobRef: "digest/" + cloudProjectID + "/" + periodStart,
		UploadDigest: uploadDigest, ContentDigest: uploadDigest,
		SizeBytes: int64(len(evidence)), Now: now,
	}); err != nil {
		t.Fatalf("SubmitDigestJob: %v", err)
	}
	lj, err := s.LeaseNextJob(ctx, worker, []string{store.FeatureProjectDigest}, time.Hour, now)
	if err != nil || lj == nil {
		t.Fatalf("lease digest job: %v (lj=%v)", err, lj)
	}
	if lj.AccountID != acct {
		t.Fatalf("lease returned a job for account %s, want %s", lj.AccountID, acct)
	}
	if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	resultJSON := []byte(fmt.Sprintf(
		`{"headline":"h","themes":[],"cost_trend":"","recurring_error_classes":[],`+
			`"unfinished_threads":[],"suggested_next_session":"","session_count":0,`+
			`"period_start":%q,"period_end":%q,"confidence":"low","limitations":[],`+
			`"schema_version":"project_digest.v1"}`,
		periodStart, periodEnd,
	))
	rid, committed, err := s.CompleteDigestJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID,
		worker, lj.LeaseGeneration, "project_digest.v1", resultJSON, store.ResultProvenance{},
		cloudProjectID, periodStart, periodEnd, now)
	if err != nil || !committed {
		t.Fatalf("CompleteDigestJobWithResult: err=%v committed=%v", err, committed)
	}
	return rid
}

// assignPlusBeta assigns the plus_beta plan to acct, effective immediately.
func assignPlusBeta(t *testing.T, s *store.Store, acct string, now time.Time) {
	t.Helper()
	if _, err := s.AssignPlan(context.Background(), acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan(plus_beta): %v", err)
	}
}

// TestSessionMetricsCapturedContentFreeAtSubmit pins W5's cloud_sessions.metrics
// capture: it is written on submit, and it carries ONLY the documented
// structural keys (never an excerpt, path, or action target).
func TestSessionMetricsCapturedContentFreeAtSubmit(t *testing.T) {
	s, pool := newStore(t)
	acct := makeAccount(t, s)
	now := time.Now()
	metrics := []byte(`{"duration_seconds":120,"started_at_bucket":"2026-01-01T00:00:00Z",` +
		`"tokens_in":10,"tokens_out":5,"cache_read":1,"cost_usd":0.01,"error_rate":0,` +
		`"actions_total":3,"outcomes":{"tests_run":1,"tests_passed":1,"build":"passed"}}`)
	if _, err := s.SubmitJob(context.Background(), store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p1", CloudSessionID: "s1",
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: "metrics-1", UploadDigest: "sha256:metrics-1", ContentDigest: "sha256:c",
		BlobRef: "b", SizeBytes: 1, Metrics: metrics, Now: now,
	}); err != nil {
		t.Fatalf("SubmitJob: %v", err)
	}

	var raw []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT metrics FROM cloud_sessions WHERE account_id = $1::uuid AND cloud_session_id = 's1'`,
		acct).Scan(&raw); err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("metrics was not stored on cloud_sessions at submit time")
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal metrics: %v", err)
	}
	allowed := map[string]bool{
		"duration_seconds": true, "started_at_bucket": true, "tokens_in": true,
		"tokens_out": true, "cache_read": true, "cost_usd": true, "error_rate": true,
		"actions_total": true, "outcomes": true, "activity_mix": true,
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("cloud_sessions.metrics carries undocumented key %q — potential content leak", k)
		}
	}

	// A second submit with NO metrics leaves the stored snapshot unchanged
	// (coalesce), never clobbering it with an empty one.
	if _, err := s.SubmitJob(context.Background(), store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p1", CloudSessionID: "s1",
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: "metrics-1-again", UploadDigest: "sha256:metrics-1-again", ContentDigest: "sha256:c",
		BlobRef: "b2", SizeBytes: 1, Now: now,
	}); err != nil {
		t.Fatalf("SubmitJob (no metrics): %v", err)
	}
	var raw2 []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT metrics FROM cloud_sessions WHERE account_id = $1::uuid AND cloud_session_id = 's1'`,
		acct).Scan(&raw2); err != nil {
		t.Fatalf("read metrics (2): %v", err)
	}
	if len(raw2) == 0 {
		t.Fatal("an empty-metrics submit clobbered the previously stored snapshot")
	}
}

// TestListProjectDigestCandidatesFiltersByPlanAndCount is acceptance item 2:
// a plus_beta account with 3 enriched sessions in the previous ISO week
// becomes exactly one candidate; a free account with the SAME shape never
// does (digest_weekly gates it out); and completing a digest for a period
// removes that (account, project) from future candidate scans for that
// period (idempotent scheduling).
func TestListProjectDigestCandidatesFiltersByPlanAndCount(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	monday, _ := store.WeekBoundsUTC(now)
	periodStart := monday.AddDate(0, 0, -7)
	periodEnd := monday.AddDate(0, 0, -1)
	mid := periodStart.Add(24 * time.Hour)

	plus := makeAccount(t, s)
	assignPlusBeta(t, s, plus, now)
	free := makeAccount(t, s)

	for _, acct := range []string{plus, free} {
		for i := 0; i < 3; i++ {
			// Complete against the REAL wall clock (the lease CAS in
			// completeJobWithResultTx checks lease_expires_at against
			// clock_timestamp(), not the caller's now), then backdate only
			// created_at to land the row in the previous ISO week.
			rid := completeResult(t, s, acct, "w1", fmt.Sprintf("cand-%s-%d", acct, i), now)
			backdateResultCreatedAt(t, pool, rid, mid)
		}
	}

	cands, err := s.ListProjectDigestCandidates(ctx, periodStart, periodEnd, periodStart, monday, 3, 200, now)
	if err != nil {
		t.Fatalf("ListProjectDigestCandidates: %v", err)
	}
	var gotPlus, gotFree bool
	for _, c := range cands {
		switch c.AccountID {
		case plus:
			gotPlus = true
			if c.SessionCount != 3 {
				t.Errorf("plus_beta session_count = %d, want 3", c.SessionCount)
			}
			if c.CloudProjectID != "p" {
				t.Errorf("cloud_project_id = %q, want %q", c.CloudProjectID, "p")
			}
		case free:
			gotFree = true
		}
	}
	if !gotPlus {
		t.Fatal("a plus_beta account with 3 enriched sessions in the previous week did not appear as a candidate")
	}
	if gotFree {
		t.Fatal("a free account appeared as a candidate — digest_weekly must gate it out")
	}

	// Completing a digest for plus/period removes it from a re-run of the scan
	// for the SAME period (a re-running scheduler submits nothing new).
	completeDigestJob(t, s, plus, "w1", "p", periodStart.Format("2006-01-02"), periodEnd.Format("2006-01-02"), now)
	cands2, err := s.ListProjectDigestCandidates(ctx, periodStart, periodEnd, periodStart, monday, 3, 200, now)
	if err != nil {
		t.Fatalf("ListProjectDigestCandidates (2): %v", err)
	}
	for _, c := range cands2 {
		if c.AccountID == plus {
			t.Fatal("plus_beta account is still a candidate after its digest for this exact period was completed")
		}
	}
}

// TestSubmitDigestJobIdempotent proves SubmitDigestJob is idempotent by
// canonical key: a second submit for the SAME (account, project, period,
// route/prompt) returns the existing job and consumes no second reservation.
func TestSubmitDigestJobIdempotent(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)
	assignPlusBeta(t, s, acct, now)

	in := store.SubmitDigestJobInput{
		AccountID: acct, CloudProjectID: "p", PeriodStart: "2026-01-05", PeriodEnd: "2026-01-11",
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		EvidenceBytes: []byte(`{"schema_version":"project_digest_evidence.v1"}`),
		BlobRef:       "digest/p/2026-01-05", UploadDigest: "sha256:idem", ContentDigest: "sha256:idem",
		SizeBytes: 10, Now: now,
	}
	first, err := s.SubmitDigestJob(ctx, in)
	if err != nil {
		t.Fatalf("SubmitDigestJob (1): %v", err)
	}
	if first.Existing {
		t.Fatal("first submit reported Existing=true")
	}
	second, err := s.SubmitDigestJob(ctx, in)
	if err != nil {
		t.Fatalf("SubmitDigestJob (2): %v", err)
	}
	if !second.Existing {
		t.Fatal("second submit for the same (account, project, period) did not report Existing=true")
	}
	if second.JobID != first.JobID {
		t.Fatalf("second submit minted a NEW job %s, want the existing %s", second.JobID, first.JobID)
	}

	snap, err := s.Usage(ctx, acct, store.FeatureProjectDigest, now)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if snap.DailyUsed != 1 {
		t.Fatalf("daily_used = %d after two idempotent submits, want 1 (no second reservation)", snap.DailyUsed)
	}
}

func TestSubmitDigestJobRechecksCurrentPlan(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)
	assignPlusBeta(t, s, acct, now)
	// Simulate the plan loss after the scheduler selected a Plus candidate.
	if _, err := pool.Exec(ctx, `DELETE FROM account_plans WHERE account_id = $1::uuid`, acct); err != nil {
		t.Fatal(err)
	}
	_, err := s.SubmitDigestJob(ctx, store.SubmitDigestJobInput{
		AccountID: acct, CloudProjectID: "p", PeriodStart: "2026-01-05", PeriodEnd: "2026-01-11",
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		EvidenceBytes: []byte(`{"schema_version":"project_digest_evidence.v1"}`),
		BlobRef:       "digest/p/no-plan", UploadDigest: "sha256:no-plan", ContentDigest: "sha256:no-plan", SizeBytes: 10, Now: now,
	})
	if !errors.Is(err, store.ErrNoEntitlement) {
		t.Fatalf("digest submitted after losing Plus: %v", err)
	}
	for _, table := range []string{"analysis_jobs", "evidence_objects", "usage_reservations"} {
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE account_id = $1::uuid", acct).Scan(&count); err != nil || count != 0 {
			t.Fatalf("refused digest left %s rows=%d: %v", table, count, err)
		}
	}
}

// TestCompleteDigestJobWithResultStampsKindAndLinkage is (part of) acceptance
// item 3: the stored analysis_results row for a project_digest job carries
// kind=project_digest, its project pseudonym, and its period — and a plain
// session-enrichment row's Kind/CloudProjectID/PeriodStart/PeriodEnd stay
// ResultKindSessionEnrichment/empty, read back through the SAME
// ListResultsAfterAccountSeq projection the /v1/results handler uses.
func TestCompleteDigestJobWithResultStampsKindAndLinkage(t *testing.T) {
	s, _ := newStore(t)
	now := time.Now()
	acct := makeAccount(t, s)
	assignPlusBeta(t, s, acct, now)

	sessionRid := completeResult(t, s, acct, "w1", "linkage-session", now)
	digestRid := completeDigestJob(t, s, acct, "w1", "p", "2026-02-02", "2026-02-08", now)
	if sessionRid == digestRid {
		t.Fatal("session and digest results share an id")
	}

	rows, err := s.ListResultsAfterAccountSeq(context.Background(), acct, 0, 50)
	if err != nil {
		t.Fatalf("ListResultsAfterAccountSeq: %v", err)
	}
	var sawSession, sawDigest bool
	for _, r := range rows {
		switch r.ID {
		case sessionRid:
			sawSession = true
			if r.Kind != store.ResultKindSessionEnrichment {
				t.Errorf("session row kind = %q, want %q", r.Kind, store.ResultKindSessionEnrichment)
			}
			if r.CloudProjectID != "" || r.PeriodStart != "" || r.PeriodEnd != "" {
				t.Errorf("session row carries digest linkage: project=%q start=%q end=%q", r.CloudProjectID, r.PeriodStart, r.PeriodEnd)
			}
		case digestRid:
			sawDigest = true
			if r.Kind != store.ResultKindProjectDigest {
				t.Errorf("digest row kind = %q, want %q", r.Kind, store.ResultKindProjectDigest)
			}
			if r.CloudProjectID != "p" {
				t.Errorf("digest row cloud_project_id = %q, want %q", r.CloudProjectID, "p")
			}
			if r.PeriodStart != "2026-02-02" || r.PeriodEnd != "2026-02-08" {
				t.Errorf("digest row period = %s..%s, want 2026-02-02..2026-02-08", r.PeriodStart, r.PeriodEnd)
			}
		}
	}
	if !sawSession || !sawDigest {
		t.Fatalf("did not see both results: session=%v digest=%v", sawSession, sawDigest)
	}
}

// TestSweepResultsRetentionRespectsPlan is acceptance item 4: a 40-day-old
// free result is deleted, a 40-day-old Plus result is kept (Plus's
// results_retention_days is 365, migration 0037).
func TestSweepResultsRetentionRespectsPlan(t *testing.T) {
	s, pool := newStore(t)
	now := time.Now()
	old := now.Add(-40 * 24 * time.Hour)

	free := makeAccount(t, s)
	plus := makeAccount(t, s)
	assignPlusBeta(t, s, plus, now)

	// Complete against the REAL wall clock (see the comment in
	// TestListProjectDigestCandidatesFiltersByPlanAndCount), then backdate only
	// created_at to the 40-day-old instant the retention sweep is pinned on.
	freeRid := completeResult(t, s, free, "w1", "ret-free", now)
	backdateResultCreatedAt(t, pool, freeRid, old)
	plusRid := completeResult(t, s, plus, "w1", "ret-plus", now)
	backdateResultCreatedAt(t, pool, plusRid, old)

	deleted, err := s.SweepResultsRetention(context.Background(), now)
	if err != nil {
		t.Fatalf("SweepResultsRetention: %v", err)
	}
	if deleted < 1 {
		t.Fatalf("SweepResultsRetention deleted %d rows, want at least 1 (the free result)", deleted)
	}

	var freeCount, plusCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM analysis_results WHERE id = $1::uuid`, freeRid).Scan(&freeCount); err != nil {
		t.Fatalf("count free result: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM analysis_results WHERE id = $1::uuid`, plusRid).Scan(&plusCount); err != nil {
		t.Fatalf("count plus result: %v", err)
	}
	if freeCount != 0 {
		t.Errorf("free account's 40-day-old result survived the sweep")
	}
	if plusCount != 1 {
		t.Errorf("Plus account's 40-day-old result was deleted (retention is 365 days)")
	}
}

// TestUsageSnapshotDigestFields pins the W5 additions to UsageSnapshot:
// digest_weekly, results_retention_days, and (only when digest_weekly)
// digests_this_week.
func TestUsageSnapshotDigestFields(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	free := makeAccount(t, s)
	freeSnap, err := s.Usage(ctx, free, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("Usage(free): %v", err)
	}
	if freeSnap.DigestWeekly {
		t.Error("free plan reports digest_weekly=true")
	}
	if freeSnap.ResultsRetentionDays != 30 {
		t.Errorf("free results_retention_days = %d, want 30", freeSnap.ResultsRetentionDays)
	}
	if freeSnap.DigestsThisWeek != 0 {
		t.Errorf("free digests_this_week = %d, want 0", freeSnap.DigestsThisWeek)
	}

	plus := makeAccount(t, s)
	assignPlusBeta(t, s, plus, now)
	plusSnap, err := s.Usage(ctx, plus, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("Usage(plus, before digest): %v", err)
	}
	if !plusSnap.DigestWeekly {
		t.Error("plus_beta plan reports digest_weekly=false")
	}
	if plusSnap.ResultsRetentionDays != 365 {
		t.Errorf("plus results_retention_days = %d, want 365", plusSnap.ResultsRetentionDays)
	}
	if plusSnap.DigestsThisWeek != 0 {
		t.Errorf("plus digests_this_week = %d before any digest, want 0", plusSnap.DigestsThisWeek)
	}

	completeDigestJob(t, s, plus, "w1", "p", "2026-01-05", "2026-01-11", now)
	plusSnap2, err := s.Usage(ctx, plus, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("Usage(plus, after digest): %v", err)
	}
	if plusSnap2.DigestsThisWeek != 1 {
		t.Errorf("plus digests_this_week = %d after one digest completed now, want 1", plusSnap2.DigestsThisWeek)
	}
}

// TestApplyResultCorrectionRefusesDigest is part of acceptance item 3's
// surrounding contract: PATCH .../correction on a project_digest result is
// refused (ErrResultNotCorrectable), never silently accepted.
func TestApplyResultCorrectionRefusesDigest(t *testing.T) {
	s, _ := newStore(t)
	now := time.Now()
	acct := makeAccount(t, s)
	assignPlusBeta(t, s, acct, now)
	rid := completeDigestJob(t, s, acct, "w1", "p", "2026-03-02", "2026-03-08", now)

	_, err := s.ApplyResultCorrection(context.Background(), acct, rid, 0, "idem-digest-1",
		[]byte(`{"title":"nope"}`), store.CorrectionSourcePortal, now)
	if err == nil {
		t.Fatal("correcting a project_digest result succeeded, want ErrResultNotCorrectable")
	}
	if !errors.Is(err, store.ErrResultNotCorrectable) {
		t.Fatalf("err = %v, want store.ErrResultNotCorrectable", err)
	}
}

// TestResolveRouteForFeatureFallsBackToSessionEnrichment pins W5's
// documented fallback: project_digest has no operator-seeded route of its
// own, so it resolves the session_enrichment route (same deployment, same
// binding).
func TestResolveRouteForFeatureFallsBackToSessionEnrichment(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	want, err := s.ResolveRoute(ctx, store.FeatureSessionEnrichment)
	if err != nil {
		t.Fatalf("ResolveRoute(session_enrichment): %v", err)
	}
	got, err := s.ResolveRouteForFeature(ctx, store.FeatureProjectDigest)
	if err != nil {
		t.Fatalf("ResolveRouteForFeature(project_digest): %v", err)
	}
	if got.RouteID != want.RouteID {
		t.Fatalf("ResolveRouteForFeature(project_digest) = %q, want the session_enrichment route %q", got.RouteID, want.RouteID)
	}
}
