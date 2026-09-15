package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// results_w5_test.go pins acceptance item 3's wire half: GET /v1/results
// carries kind, cloud_project_id, and period_start/period_end for a
// project_digest record, plus the digest body in the additive digest_result
// field — and that PATCH .../correction refuses a digest record with 409
// not_correctable.

// seedDigestResult assigns accountID the plus_beta plan and drives one
// project_digest job to a stored result via the store (submit -> lease ->
// running -> complete), mirroring seedResult's shape for the digest feature.
func seedDigestResult(t *testing.T, h *harness, accountID, cloudProjectID, periodStart, periodEnd string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	if _, err := h.store.AssignPlan(ctx, accountID, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan(plus_beta): %v", err)
	}
	evidence := []byte(`{"schema_version":"project_digest_evidence.v1"}`)
	if _, err := h.store.SubmitDigestJob(ctx, store.SubmitDigestJobInput{
		AccountID: accountID, CloudProjectID: cloudProjectID, PeriodStart: periodStart, PeriodEnd: periodEnd,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		EvidenceBytes: evidence, BlobRef: "digest/" + cloudProjectID + "/" + periodStart,
		UploadDigest: "sha256:wire-digest-" + cloudProjectID, ContentDigest: "sha256:wire-digest-" + cloudProjectID,
		SizeBytes: int64(len(evidence)), Now: now,
	}); err != nil {
		t.Fatalf("SubmitDigestJob: %v", err)
	}
	lj, err := h.store.LeaseNextJob(ctx, "w1", []string{store.FeatureProjectDigest}, time.Hour, now)
	if err != nil || lj == nil {
		t.Fatalf("lease digest job: %v (lj=%v)", err, lj)
	}
	if err := h.store.MarkJobRunning(ctx, accountID, lj.JobID, now); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	resultJSON := []byte(`{"headline":"Wire test digest","themes":["testing"],"cost_trend":"",` +
		`"recurring_error_classes":[],"unfinished_threads":[],"suggested_next_session":"",` +
		`"session_count":1,"period_start":"` + periodStart + `","period_end":"` + periodEnd + `",` +
		`"confidence":"low","limitations":[],"schema_version":"project_digest.v1"}`)
	_, committed, err := h.store.CompleteDigestJobWithResult(ctx, accountID, lj.JobID, lj.EvidencePK, lj.ReservationID,
		"w1", lj.LeaseGeneration, "project_digest.v1", resultJSON, store.ResultProvenance{},
		cloudProjectID, periodStart, periodEnd, now)
	if err != nil || !committed {
		t.Fatalf("CompleteDigestJobWithResult: err=%v committed=%v", err, committed)
	}
}

// TestResultsWireCarriesDigestKindProjectAndPeriod is acceptance item 3's
// wire half.
func TestResultsWireCarriesDigestKindProjectAndPeriod(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "digest-wire")
	seedDigestResult(t, h, c.accountID, "proj-wire", "2026-06-01", "2026-06-07")

	page := getResults(t, c, "")
	if len(page.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(page.Results))
	}
	r := page.Results[0]
	if r.Kind != "project_digest" {
		t.Errorf("kind = %q, want %q", r.Kind, "project_digest")
	}
	if r.CloudProjectID != "proj-wire" {
		t.Errorf("cloud_project_id = %q, want %q", r.CloudProjectID, "proj-wire")
	}
	if r.PeriodStart != "2026-06-01" || r.PeriodEnd != "2026-06-07" {
		t.Errorf("period = %s..%s, want 2026-06-01..2026-06-07", r.PeriodStart, r.PeriodEnd)
	}
	if r.DigestResult == nil {
		t.Fatal("digest_result is nil for a project_digest record")
	}
	if r.DigestResult.Headline != "Wire test digest" {
		t.Errorf("digest headline = %q, want %q", r.DigestResult.Headline, "Wire test digest")
	}
}

// TestResultsWireSessionEnrichmentUnaffected proves the additive fields are a
// no-op for an ordinary session-enrichment record: Kind defaults to
// session_enrichment and the digest-only fields stay empty/nil.
func TestResultsWireSessionEnrichmentUnaffected(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "session-wire")
	raiseCaps(t, h, c.accountID)
	seedResult(t, h, c.accountID, "sess-wire-1")

	page := getResults(t, c, "")
	if len(page.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(page.Results))
	}
	r := page.Results[0]
	if r.Kind != "" && r.Kind != "session_enrichment" {
		t.Errorf("kind = %q, want empty or session_enrichment", r.Kind)
	}
	if r.CloudProjectID != "" || r.PeriodStart != "" || r.PeriodEnd != "" {
		t.Errorf("session-enrichment record carries digest linkage: project=%q start=%q end=%q",
			r.CloudProjectID, r.PeriodStart, r.PeriodEnd)
	}
	if r.DigestResult != nil {
		t.Error("digest_result is set on a session-enrichment record")
	}
}

// TestCorrectionRefusesDigestRecord pins the API half of
// store.ErrResultNotCorrectable: PATCH /v1/results/{id}/correction on a
// project_digest result is refused with 409 not_correctable.
func TestCorrectionRefusesDigestRecord(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "digest-correction")
	seedDigestResult(t, h, c.accountID, "proj-correct", "2026-07-06", "2026-07-12")

	page := getResults(t, c, "")
	if len(page.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(page.Results))
	}
	resultID := page.Results[0].ResultID
	etag := page.Results[0].ETag

	req := c.signedReq("PATCH", "/v1/results/"+resultID+"/correction", []byte(`{"title":"nope"}`))
	req.Header.Set("If-Match", etag)
	req.Header.Set("Idempotency-Key", "correction-attempt-1")
	resp := c.do(req)
	if resp.StatusCode != 409 {
		t.Fatalf("correction on a digest record: status=%d body=%s, want 409", resp.StatusCode, readAll(resp))
	}
}
