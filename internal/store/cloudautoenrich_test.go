package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// seedCandidateSession creates a personal-authority session with actionCount
// actions ending at lastActionAt, and stamps sessions.total_actions to match
// (ListCloudAutoEnrichCandidates reads the counter column, not COUNT(actions),
// mirroring how the rest of the codebase treats total_actions as the
// authoritative count many adapters never otherwise populate).
func seedCandidateSession(t *testing.T, s *Store, id string, startedAt, lastActionAt time.Time, actionCount int) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/cloud/auto-enrich", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: id, ProjectID: pid, Tool: "codex", StartedAt: startedAt, TotalActions: actionCount,
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	if eligible, err := s.EligibleForPersonalCloud(ctx, id); err != nil || !eligible {
		t.Fatalf("precondition: session %q must be eligible (eligible=%v err=%v)", id, eligible, err)
	}
	var actions []models.Action
	for i := 0; i < actionCount; i++ {
		ts := lastActionAt.Add(-time.Duration(actionCount-1-i) * time.Minute)
		actions = append(actions, models.Action{
			SessionID: id, ProjectID: pid, Timestamp: ts, ActionType: "tool_call", Tool: "codex",
			SourceFile: "seed", SourceEventID: fmt.Sprintf("%s-%d", id, i),
		})
	}
	if len(actions) > 0 {
		if _, err := s.InsertActions(ctx, actions); err != nil {
			t.Fatalf("InsertActions: %v", err)
		}
	}
}

// TestListCloudAutoEnrichCandidates pins the eligibility rule end to end:
// quiet-window age, minActions floor, the since floor, and the two
// already-handled exclusions (a live outbox item, an existing result).
func TestListCloudAutoEnrichCandidates(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	quietFor := 10 * time.Minute

	// Eligible: quiet long enough, enough actions.
	seedCandidateSession(t, s, "sess-quiet", now.Add(-time.Hour), now.Add(-20*time.Minute), 5)
	// Too fresh: last action inside the quiet window.
	seedCandidateSession(t, s, "sess-fresh", now.Add(-time.Hour), now.Add(-1*time.Minute), 5)
	// Too few actions.
	seedCandidateSession(t, s, "sess-thin", now.Add(-time.Hour), now.Add(-20*time.Minute), 1)
	// Started before `since` — never a candidate even though otherwise
	// eligible (turning background on must never reach into history).
	seedCandidateSession(t, s, "sess-too-old", now.Add(-48*time.Hour), now.Add(-20*time.Minute), 5)

	// Already has a live outbox item — excluded.
	seedCandidateSession(t, s, "sess-outboxed", now.Add(-time.Hour), now.Add(-20*time.Minute), 5)
	receipt := seedReceipt(t, s, "sha256:auto-enrich-outboxed")
	if _, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
		SessionID: "sess-outboxed", EvidenceContentDigest: "sha256:ec", UploadDigest: "sha256:auto-enrich-outboxed",
		ReceiptID: receipt,
	}); err != nil {
		t.Fatalf("EnqueueCloudOutbox: %v", err)
	}

	// Already has a cancelled outbox item — NOT excluded (cancelled doesn't
	// block a fresh attempt).
	seedCandidateSession(t, s, "sess-cancelled", now.Add(-time.Hour), now.Add(-20*time.Minute), 5)
	cancelledReceipt := seedReceipt(t, s, "sha256:auto-enrich-cancelled")
	cancelledJob, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
		SessionID: "sess-cancelled", EvidenceContentDigest: "sha256:ec2", UploadDigest: "sha256:auto-enrich-cancelled",
		ReceiptID: cancelledReceipt,
	})
	if err != nil {
		t.Fatalf("EnqueueCloudOutbox (cancelled): %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE cloud_outbox SET state = 'cancelled' WHERE id = ?`, cancelledJob); err != nil {
		t.Fatalf("force cancelled: %v", err)
	}

	// Already has a result — excluded.
	seedCandidateSession(t, s, "sess-resulted", now.Add(-time.Hour), now.Add(-20*time.Minute), 5)
	if _, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID: "sess-resulted", SchemaVersion: "session_enrichment.v2-candidate", ResultJSON: `{"title":"x"}`,
	}); err != nil {
		t.Fatalf("UpsertCloudResult: %v", err)
	}

	since := now.Add(-24 * time.Hour)
	got, err := s.ListCloudAutoEnrichCandidates(ctx, since, quietFor, 3, 25, now)
	if err != nil {
		t.Fatalf("ListCloudAutoEnrichCandidates: %v", err)
	}
	var ids []string
	for _, c := range got {
		ids = append(ids, c.SessionID)
	}
	want := map[string]bool{"sess-quiet": true, "sess-cancelled": true}
	if len(ids) != len(want) {
		t.Fatalf("candidates = %v, want exactly %v", ids, want)
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected candidate %q", id)
		}
	}

	// limit is honored.
	limited, err := s.ListCloudAutoEnrichCandidates(ctx, since, quietFor, 3, 1, now)
	if err != nil {
		t.Fatalf("ListCloudAutoEnrichCandidates (limit 1): %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("limited candidates = %d, want 1", len(limited))
	}
}

// forceCloudOutboxSent directly sets an outbox row's state to 'sent' and
// stamps its updated_at, bypassing the normal send state machine so a test
// can construct an aged `sent` row without driving a real send.
func forceCloudOutboxSent(t *testing.T, database *sql.DB, outboxID string, updatedAt time.Time) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(),
		`UPDATE cloud_outbox SET state = 'sent', updated_at = ? WHERE id = ?`,
		cloudFormatTime(updatedAt), outboxID); err != nil {
		t.Fatalf("force sent: %v", err)
	}
}

// enqueueOutboxForSession enqueues one live cloud_outbox row (kind
// session_evidence, the default) for sessionID, bound to a freshly-seeded
// receipt, and returns the outbox row id.
func enqueueOutboxForSession(t *testing.T, s *Store, sessionID, digestSuffix string) string {
	t.Helper()
	ctx := context.Background()
	receipt := seedReceipt(t, s, "sha256:"+digestSuffix)
	id, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
		SessionID: sessionID, EvidenceContentDigest: "sha256:ec-" + digestSuffix,
		UploadDigest: "sha256:" + digestSuffix, ReceiptID: receipt,
	})
	if err != nil {
		t.Fatalf("EnqueueCloudOutbox: %v", err)
	}
	return id
}

// TestListCloudAutoEnrichCandidatesStaleSentResubmit pins the stale-sent
// re-submit rule (a hosted job that PARKED pre-flip has its evidence deleted
// server-side, so the only re-run path is a node re-submit): a `sent` row
// old enough that its result should long since have arrived makes the
// session a candidate again, a fresh `sent` row still excludes it, and
// cloudSentRowCap bounds how many old `sent` rows are tolerated before the
// session is excluded regardless of age.
func TestListCloudAutoEnrichCandidatesStaleSentResubmit(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	quietFor := 10 * time.Minute
	since := now.Add(-24 * time.Hour)
	startedAt := now.Add(-2 * time.Hour)
	lastActionAt := now.Add(-time.Hour)

	// A 2-day-old sent row with no result IS a candidate again.
	seedCandidateSession(t, s, "sess-stale-sent", startedAt, lastActionAt, 5)
	staleID := enqueueOutboxForSession(t, s, "sess-stale-sent", "stale")
	forceCloudOutboxSent(t, database, staleID, now.Add(-48*time.Hour))

	// A 1-hour-old sent row (well inside cloudSentResultGrace) is NOT a
	// candidate — its result may still be on the way.
	seedCandidateSession(t, s, "sess-fresh-sent", startedAt, lastActionAt, 5)
	freshID := enqueueOutboxForSession(t, s, "sess-fresh-sent", "fresh")
	forceCloudOutboxSent(t, database, freshID, now.Add(-time.Hour))

	// 3 old sent rows hit cloudSentRowCap and stay excluded even though each
	// individually is old enough.
	seedCandidateSession(t, s, "sess-capped-sent", startedAt, lastActionAt, 5)
	for i := 0; i < cloudSentRowCap; i++ {
		id := enqueueOutboxForSession(t, s, "sess-capped-sent", fmt.Sprintf("capped-%d", i))
		forceCloudOutboxSent(t, database, id, now.Add(-72*time.Hour))
	}

	got, err := s.ListCloudAutoEnrichCandidates(ctx, since, quietFor, 3, 25, now)
	if err != nil {
		t.Fatalf("ListCloudAutoEnrichCandidates: %v", err)
	}
	var ids []string
	for _, c := range got {
		ids = append(ids, c.SessionID)
	}
	want := map[string]bool{"sess-stale-sent": true}
	if len(ids) != len(want) {
		t.Fatalf("candidates = %v, want exactly %v", ids, want)
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected candidate %q", id)
		}
	}
}

// TestListCloudAutoEnrichCandidatesSkipTableExcludes pins the durable
// cloud_enrich_skips exclusion (item 2 of the 2026-09-16 follow-up): a
// session with a live (not-yet-due) skip row is excluded, and one whose
// next_at has already passed is a candidate again.
func TestListCloudAutoEnrichCandidatesSkipTableExcludes(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	quietFor := 10 * time.Minute
	since := now.Add(-24 * time.Hour)
	startedAt := now.Add(-time.Hour)
	lastActionAt := now.Add(-20 * time.Minute)

	seedCandidateSession(t, s, "sess-skip-live", startedAt, lastActionAt, 5)
	if err := s.RecordCloudEnrichSkip(ctx, "sess-skip-live", "consent_spawn_failed", now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("RecordCloudEnrichSkip: %v", err)
	}

	seedCandidateSession(t, s, "sess-skip-expired", startedAt, lastActionAt, 5)
	if err := s.RecordCloudEnrichSkip(ctx, "sess-skip-expired", "consent_spawn_failed", now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("RecordCloudEnrichSkip: %v", err)
	}

	got, err := s.ListCloudAutoEnrichCandidates(ctx, since, quietFor, 3, 25, now)
	if err != nil {
		t.Fatalf("ListCloudAutoEnrichCandidates: %v", err)
	}
	var ids []string
	for _, c := range got {
		ids = append(ids, c.SessionID)
	}
	want := map[string]bool{"sess-skip-expired": true}
	if len(ids) != len(want) {
		t.Fatalf("candidates = %v, want exactly %v", ids, want)
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected candidate %q", id)
		}
	}
}

// TestCloudSyncLastRoundTrip pins RecordCloudSyncLast/GetCloudSyncLast: no
// row yet, a round trip, and a re-record overwrites (status snapshot, not a
// history log).
func TestCloudSyncLastRoundTrip(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	if _, ok, err := s.GetCloudSyncLast(ctx); err != nil || ok {
		t.Fatalf("precondition: no row expected, ok=%v err=%v", ok, err)
	}

	started := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	finished := started.Add(3 * time.Second)
	if err := s.RecordCloudSyncLast(ctx, CloudSyncLast{
		StartedAt: started, FinishedAt: finished, OK: true, Sent: 2, WaitingProvider: 1, Results: 3,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, ok, err := s.GetCloudSyncLast(ctx)
	if err != nil || !ok {
		t.Fatalf("Get after record: ok=%v err=%v", ok, err)
	}
	if !got.OK || got.Sent != 2 || got.WaitingProvider != 1 || got.Results != 3 || got.SignInExpired {
		t.Fatalf("Get after record = %+v", got)
	}
	if !got.StartedAt.Equal(started) || !got.FinishedAt.Equal(finished) {
		t.Fatalf("timestamps not round-tripped: %+v", got)
	}

	// Re-record overwrites rather than appending a second row.
	if err := s.RecordCloudSyncLast(ctx, CloudSyncLast{
		StartedAt: finished, FinishedAt: finished.Add(time.Second), OK: false, Failed: 1,
		SignInExpired: true, ErrorClass: "sign_in_expired",
	}); err != nil {
		t.Fatalf("Record (second): %v", err)
	}
	got2, ok, err := s.GetCloudSyncLast(ctx)
	if err != nil || !ok {
		t.Fatalf("Get after second record: ok=%v err=%v", ok, err)
	}
	if got2.OK || got2.Failed != 1 || !got2.SignInExpired || got2.ErrorClass != "sign_in_expired" {
		t.Fatalf("Get after second record = %+v", got2)
	}
}

// TestCloudSyncLastPlanFieldsRoundTrip pins migration 118's plan columns:
// unset on a fresh record (zero value: "" name/label, nil pointers), a full
// round trip once a usage fetch succeeded, and that an unknown pointer field
// (a usage fetch that failed on this run, or an older row) reads back nil
// rather than a fabricated zero.
func TestCloudSyncLastPlanFieldsRoundTrip(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	started := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

	// A sync that never reached a successful usage fetch: plan fields stay
	// at their zero value / nil, never fabricated.
	if err := s.RecordCloudSyncLast(ctx, CloudSyncLast{
		StartedAt: started, FinishedAt: started.Add(time.Second), OK: true, Sent: 1,
	}); err != nil {
		t.Fatalf("Record (no plan): %v", err)
	}
	got, ok, err := s.GetCloudSyncLast(ctx)
	if err != nil || !ok {
		t.Fatalf("Get (no plan): ok=%v err=%v", ok, err)
	}
	if got.PlanName != "" || got.PlanLabel != "" {
		t.Fatalf("expected unset plan name/label, got %+v", got)
	}
	if got.DigestWeekly != nil || got.ResultsRetentionDays != nil || got.DailyCap != nil || got.MonthlyCap != nil {
		t.Fatalf("expected nil plan pointers when unknown, got %+v", got)
	}

	// A sync whose usage fetch succeeded: every plan field round-trips.
	digestWeekly := 1
	retentionDays := 30
	dailyCap := 50
	monthlyCap := 500
	if err := s.RecordCloudSyncLast(ctx, CloudSyncLast{
		StartedAt: started, FinishedAt: started.Add(2 * time.Second), OK: true, Sent: 1,
		PlanName: "plus", PlanLabel: "Plus",
		DigestWeekly: &digestWeekly, ResultsRetentionDays: &retentionDays,
		DailyCap: &dailyCap, MonthlyCap: &monthlyCap,
	}); err != nil {
		t.Fatalf("Record (with plan): %v", err)
	}
	got2, ok, err := s.GetCloudSyncLast(ctx)
	if err != nil || !ok {
		t.Fatalf("Get (with plan): ok=%v err=%v", ok, err)
	}
	if got2.PlanName != "plus" || got2.PlanLabel != "Plus" {
		t.Fatalf("plan name/label = %q/%q, want plus/Plus", got2.PlanName, got2.PlanLabel)
	}
	if got2.DigestWeekly == nil || *got2.DigestWeekly != 1 {
		t.Fatalf("digest_weekly = %v, want 1", got2.DigestWeekly)
	}
	if got2.ResultsRetentionDays == nil || *got2.ResultsRetentionDays != 30 {
		t.Fatalf("results_retention_days = %v, want 30", got2.ResultsRetentionDays)
	}
	if got2.DailyCap == nil || *got2.DailyCap != 50 {
		t.Fatalf("daily_cap = %v, want 50", got2.DailyCap)
	}
	if got2.MonthlyCap == nil || *got2.MonthlyCap != 500 {
		t.Fatalf("monthly_cap = %v, want 500", got2.MonthlyCap)
	}

	// A later run whose usage fetch failed reverts the plan fields to
	// unknown (nil) rather than leaving the previous run's numbers stale —
	// RecordCloudSyncLast always overwrites the full singleton row.
	if err := s.RecordCloudSyncLast(ctx, CloudSyncLast{
		StartedAt: started, FinishedAt: started.Add(3 * time.Second), OK: true, Sent: 1,
	}); err != nil {
		t.Fatalf("Record (plan drops back to unknown): %v", err)
	}
	got3, ok, err := s.GetCloudSyncLast(ctx)
	if err != nil || !ok {
		t.Fatalf("Get (plan dropped): ok=%v err=%v", ok, err)
	}
	if got3.PlanName != "" || got3.DigestWeekly != nil {
		t.Fatalf("expected plan fields to reset to unknown, got %+v", got3)
	}
}

// TestListCloudResultsSince pins the ordering, the since filter, and that a
// superseded result is excluded.
func TestListCloudResultsSince(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()

	older := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)

	oldID, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID: "sess-a", SchemaVersion: "session_enrichment.v2-candidate", ResultJSON: `{"title":"Old title"}`,
		ReceivedAt: older,
	})
	if err != nil {
		t.Fatalf("UpsertCloudResult (old): %v", err)
	}
	newID, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID: "sess-b", SchemaVersion: "session_enrichment.v2-candidate", ResultJSON: `{"title":"New title"}`,
		ReceivedAt: newer,
	})
	if err != nil {
		t.Fatalf("UpsertCloudResult (new): %v", err)
	}

	// A superseded row for sess-c must never appear.
	firstC, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID: "sess-c", SchemaVersion: "session_enrichment.v2-candidate", ResultJSON: `{"title":"stale"}`,
		ReceivedAt: newer,
	})
	if err != nil {
		t.Fatalf("UpsertCloudResult (sess-c v1): %v", err)
	}
	if _, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID: "sess-c", SchemaVersion: "session_enrichment.v2-candidate", ResultJSON: `{"title":"fresh"}`,
		ReceivedAt: newer.Add(time.Minute),
	}); err != nil {
		t.Fatalf("UpsertCloudResult (sess-c v2): %v", err)
	}
	var supersededBy string
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(superseded_by,'') FROM cloud_results WHERE id = ?`, firstC).
		Scan(&supersededBy); err != nil || supersededBy == "" {
		t.Fatalf("precondition: sess-c v1 must be superseded, got %q err=%v", supersededBy, err)
	}

	// since = older (exclusive on '>') so only the newer two are eligible;
	// newest first.
	got, err := s.ListCloudResultsSince(ctx, older, 50)
	if err != nil {
		t.Fatalf("ListCloudResultsSince: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("results = %d, want 2 (got %+v)", len(got), got)
	}
	if got[0].SessionID == "sess-b" {
		// sess-b and the fresh sess-c row share received_at=newer/newer+1m;
		// the fresh sess-c row is strictly newer so it sorts first.
		t.Fatalf("expected the freshest (sess-c) result first, got %q", got[0].SessionID)
	}
	seen := map[string]bool{}
	for _, r := range got {
		seen[r.SessionID] = true
		if r.SessionID == "sess-a" {
			t.Fatalf("sess-a (received_at == since) must be excluded by the '>' bound")
		}
	}
	if !seen["sess-b"] || !seen["sess-c"] {
		t.Fatalf("missing expected sessions in %+v", got)
	}

	// since = -infinity-ish (zero time) surfaces everything current,
	// including sess-a, still excluding the superseded row.
	all, err := s.ListCloudResultsSince(ctx, time.Time{}, 50)
	if err != nil {
		t.Fatalf("ListCloudResultsSince (all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("all results = %d, want 3", len(all))
	}
	for _, r := range all {
		if r.ResultID == firstC {
			t.Fatalf("superseded result %q leaked into ListCloudResultsSince", firstC)
		}
	}
	if newID == "" || oldID == "" {
		t.Fatal("sanity: ids must be non-empty")
	}
}
