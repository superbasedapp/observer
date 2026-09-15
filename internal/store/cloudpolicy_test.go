package store

import (
	"context"
	"testing"
	"time"
)

// TestCloudEnrichPolicyRoundTrip pins Get/SetCloudEnrichPolicy: no row yet,
// round-trip every field, and re-set upserts rather than duplicating.
func TestCloudEnrichPolicyRoundTrip(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	if _, ok, err := s.GetCloudEnrichPolicy(ctx); err != nil {
		t.Fatalf("Get (no row): %v", err)
	} else if ok {
		t.Fatal("Get (no row): ok=true, want false")
	}

	if err := s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{
		Level:         CloudEnrichTitles,
		Background:    true,
		PolicyVersion: "1",
		Source:        "cli",
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := s.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		t.Fatalf("Get after set: ok=%v err=%v", ok, err)
	}
	if got.Level != CloudEnrichTitles || !got.Background || got.PolicyVersion != "1" || got.Source != "cli" {
		t.Fatalf("Get after set = %+v", got)
	}
	if got.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt was not stamped")
	}

	// Re-set (a different level, background off) upserts the same singleton
	// row rather than adding a second one.
	if err := s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{
		Level:         CloudEnrichExcerpts,
		Background:    false,
		PolicyVersion: "1",
		Source:        "dashboard",
	}); err != nil {
		t.Fatalf("Set (second): %v", err)
	}
	got2, ok, err := s.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		t.Fatalf("Get after second set: ok=%v err=%v", ok, err)
	}
	if got2.Level != CloudEnrichExcerpts || got2.Background || got2.Source != "dashboard" {
		t.Fatalf("Get after second set = %+v", got2)
	}
}

// TestCloudEnrichPolicySinceTransitions pins migration 117's `since` rule:
// stamped on an off->on transition, carried forward while staying on
// (a level or background tweak alone must not reset it), and cleared to the
// zero time going ->off.
func TestCloudEnrichPolicySinceTransitions(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	// No row yet: Since is the zero value.
	if _, ok, err := s.GetCloudEnrichPolicy(ctx); err != nil || ok {
		t.Fatalf("precondition: no row expected, ok=%v err=%v", ok, err)
	}

	// off -> on: since is stamped.
	if err := s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{
		Level: CloudEnrichTitles, Background: true, PolicyVersion: "1", Source: "cli",
	}); err != nil {
		t.Fatalf("Set (on): %v", err)
	}
	first, ok, err := s.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		t.Fatalf("Get after first on: ok=%v err=%v", ok, err)
	}
	if first.Since.IsZero() {
		t.Fatal("Since was not stamped on the off->on transition")
	}
	firstSince := first.Since

	// Staying on (a level change, excerpts) must carry `since` forward
	// unchanged.
	time.Sleep(2 * time.Millisecond) // guarantee updated_at would differ if it leaked into since
	if err := s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{
		Level: CloudEnrichExcerpts, Background: false, PolicyVersion: "1", Source: "dashboard",
	}); err != nil {
		t.Fatalf("Set (stay on, tweak): %v", err)
	}
	second, ok, err := s.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		t.Fatalf("Get after tweak: ok=%v err=%v", ok, err)
	}
	if !second.Since.Equal(firstSince) {
		t.Fatalf("Since changed while staying on: got %v, want %v (unchanged)", second.Since, firstSince)
	}

	// -> off clears it.
	if err := s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{
		Level: CloudEnrichOff, Background: false, PolicyVersion: "1", Source: "cli",
	}); err != nil {
		t.Fatalf("Set (off): %v", err)
	}
	third, ok, err := s.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		t.Fatalf("Get after off: ok=%v err=%v", ok, err)
	}
	if !third.Since.IsZero() {
		t.Fatalf("Since was not cleared going ->off: %v", third.Since)
	}

	// on again after having been off: since is stamped fresh (not reusing
	// the pre-off value).
	if err := s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{
		Level: CloudEnrichTitles, Background: true, PolicyVersion: "1", Source: "cli",
	}); err != nil {
		t.Fatalf("Set (on again): %v", err)
	}
	fourth, ok, err := s.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		t.Fatalf("Get after on-again: ok=%v err=%v", ok, err)
	}
	if fourth.Since.IsZero() {
		t.Fatal("Since was not re-stamped on a fresh off->on transition")
	}
}

// TestCloudEnrichPolicyInvalidLevelRefused pins the closed level vocabulary.
func TestCloudEnrichPolicyInvalidLevelRefused(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	if err := s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{Level: "bogus"}); err == nil {
		t.Fatal("expected an error for an unknown level, got nil")
	}
	if _, ok, err := s.GetCloudEnrichPolicy(ctx); err != nil || ok {
		t.Fatalf("a refused Set must not have written a row: ok=%v err=%v", ok, err)
	}
}

// TestCloudEnrichPolicyPurposeName pins the level -> purpose mapping.
func TestCloudEnrichPolicyPurposeName(t *testing.T) {
	cases := []struct {
		level  CloudEnrichLevel
		want   string
		wantOK bool
	}{
		{CloudEnrichOff, "", false},
		{CloudEnrichTitles, "structural_activity_insights", true},
		{CloudEnrichExcerpts, "bounded_context_enrichment", true},
	}
	for _, tc := range cases {
		got, ok := (CloudEnrichPolicy{Level: tc.level}).PurposeName()
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("PurposeName(%q) = (%q, %v), want (%q, %v)", tc.level, got, ok, tc.want, tc.wantOK)
		}
	}
}

// TestFindCloudOutboxByReceipt pins the lookup: found for a bound receipt,
// not-found for an unbound one.
func TestFindCloudOutboxByReceipt(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	seedEligibleSession(t, s, "sess-find")
	receiptID := seedReceipt(t, s, "sha256:find")
	jobID, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
		SessionID:             "sess-find",
		EvidenceContentDigest: "sha256:ec",
		UploadDigest:          "sha256:find",
		ReceiptID:             receiptID,
	})
	if err != nil {
		t.Fatalf("EnqueueCloudOutbox: %v", err)
	}

	item, ok, err := s.FindCloudOutboxByReceipt(ctx, receiptID)
	if err != nil || !ok {
		t.Fatalf("FindCloudOutboxByReceipt: ok=%v err=%v", ok, err)
	}
	if item.ID != jobID || item.SessionID != "sess-find" || item.Kind != CloudOutboxKindSessionEvidence {
		t.Fatalf("FindCloudOutboxByReceipt = %+v", item)
	}

	if _, ok, err := s.FindCloudOutboxByReceipt(ctx, "rcpt_does_not_exist"); err != nil || ok {
		t.Fatalf("unbound receipt: ok=%v err=%v", ok, err)
	}
}

// TestCancelPendingCloudSessionEvidence pins: a pending per-upload item is
// cancelled and its receipt invalidated; a sent item is left completely
// untouched (state, receipt liveness).
func TestCancelPendingCloudSessionEvidence(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()

	seedEligibleSession(t, s, "sess-pending")
	pendingReceipt := seedReceipt(t, s, "sha256:pending")
	pendingJob, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
		SessionID:             "sess-pending",
		EvidenceContentDigest: "sha256:ec-pending",
		UploadDigest:          "sha256:pending",
		ReceiptID:             pendingReceipt,
	})
	if err != nil {
		t.Fatalf("Enqueue (pending): %v", err)
	}

	seedEligibleSession(t, s, "sess-sent")
	sentReceipt := seedReceipt(t, s, "sha256:sent")
	sentJob, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
		SessionID:             "sess-sent",
		EvidenceContentDigest: "sha256:ec-sent",
		UploadDigest:          "sha256:sent",
		ReceiptID:             sentReceipt,
	})
	if err != nil {
		t.Fatalf("Enqueue (sent): %v", err)
	}
	// MarkCloudOutboxSent only accepts a `sending` item (the real path is
	// PrepareCloudOutboxSend); force the transitional state directly since
	// this test only cares about the terminal `sent` state being untouched.
	if _, err := database.ExecContext(ctx, `UPDATE cloud_outbox SET state = 'sending' WHERE id = ?`, sentJob); err != nil {
		t.Fatalf("force sending state: %v", err)
	}
	if err := s.MarkCloudOutboxSent(ctx, sentJob); err != nil {
		t.Fatalf("MarkCloudOutboxSent: %v", err)
	}

	n, err := s.CancelPendingCloudSessionEvidence(ctx)
	if err != nil {
		t.Fatalf("CancelPendingCloudSessionEvidence: %v", err)
	}
	if n != 1 {
		t.Fatalf("cancelled = %d, want 1", n)
	}

	gotPending, ok, err := s.GetCloudOutbox(ctx, pendingJob)
	if err != nil || !ok {
		t.Fatalf("GetCloudOutbox (pending): ok=%v err=%v", ok, err)
	}
	if gotPending.State != CloudOutboxCancelled {
		t.Fatalf("pending job state = %q, want cancelled", gotPending.State)
	}
	pendingRcpt, ok, err := s.GetCloudConsentReceipt(ctx, pendingReceipt)
	if err != nil || !ok {
		t.Fatalf("GetCloudConsentReceipt (pending): ok=%v err=%v", ok, err)
	}
	if pendingRcpt.InvalidatedAt == nil {
		t.Fatal("the pending item's receipt must be invalidated")
	}

	gotSent, ok, err := s.GetCloudOutbox(ctx, sentJob)
	if err != nil || !ok {
		t.Fatalf("GetCloudOutbox (sent): ok=%v err=%v", ok, err)
	}
	if gotSent.State != CloudOutboxSent {
		t.Fatalf("sent job state = %q, want unchanged sent", gotSent.State)
	}
	sentRcpt, ok, err := s.GetCloudConsentReceipt(ctx, sentReceipt)
	if err != nil || !ok {
		t.Fatalf("GetCloudConsentReceipt (sent): ok=%v err=%v", ok, err)
	}
	if sentRcpt.InvalidatedAt != nil {
		t.Fatal("a sent item's receipt must be left live")
	}

	// Idempotent: nothing left to cancel.
	if n, err := s.CancelPendingCloudSessionEvidence(ctx); err != nil || n != 0 {
		t.Fatalf("second call: n=%d err=%v, want 0/nil", n, err)
	}
}

// TestListCloudLedgerOrderedAndContentFree pins: newest-first ordering, the
// total receipt count independent of limit, per-receipt outbox items, and the
// current result attached for a session-evidence receipt.
func TestListCloudLedgerOrderedAndContentFree(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	seedEligibleSession(t, s, "sess-a")
	seedEligibleSession(t, s, "sess-b")

	older, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
		AccountPseudonym: "acct", Purpose: "structural_activity_insights",
		UploadDigest: "sha256:older", CreatedAt: time.Now().UTC().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("insert older receipt: %v", err)
	}
	newer, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
		AccountPseudonym: "acct", Purpose: "bounded_context_enrichment",
		UploadDigest: "sha256:newer", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("insert newer receipt: %v", err)
	}

	jobA, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
		SessionID: "sess-a", EvidenceContentDigest: "sha256:ec-a",
		UploadDigest: "sha256:older", ReceiptID: older,
	})
	if err != nil {
		t.Fatalf("enqueue A: %v", err)
	}
	if _, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID: "sess-a", SchemaVersion: "v1", ResultJSON: `{"title":"secret task name"}`,
		Provenance: CloudResultProvenance{ModelRoute: "route-x", Tokens: 42, CostUSD: 0.01},
		ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertCloudResult: %v", err)
	}

	entries, total, err := s.ListCloudLedger(ctx, 10)
	if err != nil {
		t.Fatalf("ListCloudLedger: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].Receipt.ID != newer || entries[1].Receipt.ID != older {
		t.Fatalf("order = [%s, %s], want newest first [%s, %s]",
			entries[0].Receipt.ID, entries[1].Receipt.ID, newer, older)
	}
	if !entries[0].Receipt.Live {
		t.Fatal("a fresh receipt must read live")
	}
	if len(entries[1].Items) != 1 || entries[1].Items[0].ID != jobA {
		t.Fatalf("older entry items = %+v, want [%s]", entries[1].Items, jobA)
	}
	if entries[1].Result == nil {
		t.Fatal("older entry must carry its session's current result")
	}
	if entries[1].Result.ModelRoute != "route-x" || entries[1].Result.Tokens != 42 {
		t.Fatalf("result provenance = %+v", entries[1].Result)
	}
	// Content-free by construction: CloudLedgerResult has no field that could
	// carry result_json/title text — this is a type-level guarantee, not a
	// runtime one, but assert the id/session are the only identifying fields.
	if entries[1].Result.ID == "" || entries[1].Result.SessionID != "sess-a" {
		t.Fatalf("result identity = %+v", entries[1].Result)
	}
	// The newer (no outbox item) entry has no result.
	if entries[0].Result != nil {
		t.Fatalf("newer entry (no outbox item) must carry no result, got %+v", entries[0].Result)
	}

	// limit is respected but total count is independent of it.
	limited, total2, err := s.ListCloudLedger(ctx, 1)
	if err != nil {
		t.Fatalf("ListCloudLedger (limit 1): %v", err)
	}
	if len(limited) != 1 || total2 != 2 {
		t.Fatalf("limited = %d entries, total2 = %d, want 1/2", len(limited), total2)
	}
	if limited[0].Receipt.ID != newer {
		t.Fatalf("limited[0] = %s, want newest %s", limited[0].Receipt.ID, newer)
	}
}
