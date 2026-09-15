package store

import (
	"context"
	"testing"
	"time"
)

// t0PromptReconsider anchors all timestamps in these tests so TTL math
// is deterministic (the t0Guard precedent in guard_test.go).
var t0PromptReconsider = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

func promptReconsiderFixture(fp, sessionID string, warnedAt, expiresAt time.Time) PromptReconsiderRow {
	return PromptReconsiderRow{
		Fingerprint: fp,
		SessionID:   sessionID,
		Tool:        "claude-code",
		Detectors:   "credit_card,us_ssn",
		WarnedAt:    warnedAt,
		ExpiresAt:   expiresAt,
	}
}

func TestPromptReconsider_InsertThenLookup_Hit(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	row := promptReconsiderFixture("fp-1", "sess-1", t0PromptReconsider, t0PromptReconsider.Add(30*time.Minute))
	if err := s.RecordPromptWarned(ctx, row); err != nil {
		t.Fatalf("RecordPromptWarned: %v", err)
	}

	got, ok, err := s.LookupPromptReconsider(ctx, "fp-1", t0PromptReconsider.Add(time.Minute))
	if err != nil {
		t.Fatalf("LookupPromptReconsider: %v", err)
	}
	if !ok {
		t.Fatal("LookupPromptReconsider ok = false, want true (fresh row)")
	}
	if got.SessionID != "sess-1" || got.Detectors != "credit_card,us_ssn" || got.Tool != "claude-code" {
		t.Errorf("LookupPromptReconsider row = %+v, want session=sess-1 detectors=credit_card,us_ssn tool=claude-code", got)
	}
	if !got.ConfirmedAt.IsZero() {
		t.Errorf("ConfirmedAt = %v, want zero (never confirmed)", got.ConfirmedAt)
	}
}

func TestPromptReconsider_LookupUnknownFingerprint_Miss(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	_, ok, err := s.LookupPromptReconsider(ctx, "does-not-exist", t0PromptReconsider)
	if err != nil {
		t.Fatalf("LookupPromptReconsider: %v", err)
	}
	if ok {
		t.Fatal("LookupPromptReconsider ok = true for an unknown fingerprint, want false")
	}
}

func TestPromptReconsider_LookupExpiredRow_Miss(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	row := promptReconsiderFixture("fp-expired", "sess-1", t0PromptReconsider, t0PromptReconsider.Add(30*time.Minute))
	if err := s.RecordPromptWarned(ctx, row); err != nil {
		t.Fatalf("RecordPromptWarned: %v", err)
	}

	// Look up well past expiry.
	_, ok, err := s.LookupPromptReconsider(ctx, "fp-expired", t0PromptReconsider.Add(time.Hour))
	if err != nil {
		t.Fatalf("LookupPromptReconsider: %v", err)
	}
	if ok {
		t.Fatal("LookupPromptReconsider ok = true for an expired row, want false (miss)")
	}
}

func TestPromptReconsider_ConfirmFreshRow_Found(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	row := promptReconsiderFixture("fp-confirm", "sess-1", t0PromptReconsider, t0PromptReconsider.Add(30*time.Minute))
	if err := s.RecordPromptWarned(ctx, row); err != nil {
		t.Fatalf("RecordPromptWarned: %v", err)
	}

	confirmAt := t0PromptReconsider.Add(2 * time.Minute)
	found, err := s.ConfirmPromptReconsider(ctx, "fp-confirm", confirmAt)
	if err != nil {
		t.Fatalf("ConfirmPromptReconsider: %v", err)
	}
	if !found {
		t.Fatal("ConfirmPromptReconsider found = false, want true (fresh row)")
	}

	// Re-lookup (bypassing the expiry check by using a time still inside
	// the TTL) to confirm confirmed_at was actually stamped.
	got, ok, err := s.LookupPromptReconsider(ctx, "fp-confirm", confirmAt)
	if err != nil {
		t.Fatalf("LookupPromptReconsider: %v", err)
	}
	if !ok {
		t.Fatal("LookupPromptReconsider ok = false after confirm, want true")
	}
	if got.ConfirmedAt.IsZero() {
		t.Error("ConfirmedAt is zero after ConfirmPromptReconsider, want set")
	}
	if !got.ConfirmedAt.Equal(confirmAt) {
		t.Errorf("ConfirmedAt = %v, want %v", got.ConfirmedAt, confirmAt)
	}
}

func TestPromptReconsider_ConfirmUnknownFingerprint_NotFoundNoError(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	found, err := s.ConfirmPromptReconsider(ctx, "never-warned", t0PromptReconsider)
	if err != nil {
		t.Fatalf("ConfirmPromptReconsider: %v", err)
	}
	if found {
		t.Fatal("ConfirmPromptReconsider found = true for an unknown fingerprint, want false")
	}
}

func TestPromptReconsider_ConfirmExpiredRow_FailClosedNotFound(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	row := promptReconsiderFixture("fp-expired-confirm", "sess-1", t0PromptReconsider, t0PromptReconsider.Add(30*time.Minute))
	if err := s.RecordPromptWarned(ctx, row); err != nil {
		t.Fatalf("RecordPromptWarned: %v", err)
	}

	found, err := s.ConfirmPromptReconsider(ctx, "fp-expired-confirm", t0PromptReconsider.Add(time.Hour))
	if err != nil {
		t.Fatalf("ConfirmPromptReconsider: %v", err)
	}
	if found {
		t.Fatal("ConfirmPromptReconsider found = true for an expired row, want false (fail-closed)")
	}
}

func TestPromptReconsider_RecordPromptWarned_ReplacesExistingRow(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	fp := "fp-replace"
	first := promptReconsiderFixture(fp, "sess-1", t0PromptReconsider, t0PromptReconsider.Add(30*time.Minute))
	if err := s.RecordPromptWarned(ctx, first); err != nil {
		t.Fatalf("RecordPromptWarned (first): %v", err)
	}
	if _, err := s.ConfirmPromptReconsider(ctx, fp, t0PromptReconsider.Add(time.Minute)); err != nil {
		t.Fatalf("ConfirmPromptReconsider: %v", err)
	}

	// Re-warn (e.g. the grant expired and the same fingerprint is seen
	// again) — INSERT OR REPLACE semantics must reset warned_at/
	// expires_at and clear confirmed_at back to NULL.
	secondWarnedAt := t0PromptReconsider.Add(time.Hour)
	secondExpiresAt := secondWarnedAt.Add(30 * time.Minute)
	second := promptReconsiderFixture(fp, "sess-2", secondWarnedAt, secondExpiresAt)
	second.Detectors = "aws_key"
	if err := s.RecordPromptWarned(ctx, second); err != nil {
		t.Fatalf("RecordPromptWarned (second): %v", err)
	}

	got, ok, err := s.LookupPromptReconsider(ctx, fp, secondWarnedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("LookupPromptReconsider: %v", err)
	}
	if !ok {
		t.Fatal("LookupPromptReconsider ok = false after replace, want true")
	}
	if got.SessionID != "sess-2" || got.Detectors != "aws_key" {
		t.Errorf("row after replace = %+v, want session=sess-2 detectors=aws_key", got)
	}
	if !got.ConfirmedAt.IsZero() {
		t.Errorf("ConfirmedAt after replace = %v, want zero (cleared)", got.ConfirmedAt)
	}
	if !got.WarnedAt.Equal(secondWarnedAt) {
		t.Errorf("WarnedAt after replace = %v, want %v", got.WarnedAt, secondWarnedAt)
	}
}

func TestPrunePromptReconsider_RemovesOnlyExpiredRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	live := promptReconsiderFixture("fp-live", "sess-1", t0PromptReconsider, t0PromptReconsider.Add(30*time.Minute))
	expired := promptReconsiderFixture("fp-gone", "sess-2", t0PromptReconsider.Add(-time.Hour), t0PromptReconsider.Add(-30*time.Minute))
	if err := s.RecordPromptWarned(ctx, live); err != nil {
		t.Fatalf("RecordPromptWarned (live): %v", err)
	}
	if err := s.RecordPromptWarned(ctx, expired); err != nil {
		t.Fatalf("RecordPromptWarned (expired): %v", err)
	}

	removed, err := s.PrunePromptReconsider(ctx, t0PromptReconsider)
	if err != nil {
		t.Fatalf("PrunePromptReconsider: %v", err)
	}
	if removed != 1 {
		t.Fatalf("PrunePromptReconsider removed = %d, want 1", removed)
	}

	if _, ok, err := s.LookupPromptReconsider(ctx, "fp-gone", t0PromptReconsider); err != nil || ok {
		t.Errorf("fp-gone still present after prune: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.LookupPromptReconsider(ctx, "fp-live", t0PromptReconsider); err != nil || !ok {
		t.Errorf("fp-live missing after prune: ok=%v err=%v", ok, err)
	}
}

// TestPromptReconsider_SubSecondBoundary_ConfirmAfterExpiryFailsClosed
// pins the F8 fix (round-2 review): warned_at/confirmed_at/expires_at
// are now INTEGER unix-nanoseconds columns, not the package's usual
// RFC3339Nano TEXT stamp. RFC3339Nano trims a trailing zero fraction —
// a WHOLE-SECOND time formats with NO fractional digits at all
// ("...T12:00:30Z") while a time 500ms later formats WITH one
// ("...T12:00:30.5Z"). Lexicographically "...Z" sorts AFTER "...0.5Z"
// (Z=0x5A > .=0x2E) even though it is chronologically EARLIER — which
// used to make ConfirmPromptReconsider's `expires_at > ?` SQL
// comparison evaluate BACKWARDS across exactly this kind of boundary,
// incorrectly confirming a resend that arrived AFTER the TTL expired.
func TestPromptReconsider_SubSecondBoundary_ConfirmAfterExpiryFailsClosed(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	warnedAt := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 9, 7, 12, 0, 30, 0, time.UTC) // exactly on the second — zero ns
	pastExpiry := expiresAt.Add(500 * time.Millisecond)        // 500ms later — carries a fraction

	row := promptReconsiderFixture("fp-boundary-after", "sess-1", warnedAt, expiresAt)
	if err := s.RecordPromptWarned(ctx, row); err != nil {
		t.Fatalf("RecordPromptWarned: %v", err)
	}
	found, err := s.ConfirmPromptReconsider(ctx, "fp-boundary-after", pastExpiry)
	if err != nil {
		t.Fatalf("ConfirmPromptReconsider: %v", err)
	}
	if found {
		t.Fatal("ConfirmPromptReconsider found = true for a resend 500ms PAST a whole-second expiry, want false (fail-closed)")
	}

	// Symmetric sanity check: a resend BEFORE expiry (same boundary
	// shape) must still confirm normally.
	row2 := promptReconsiderFixture("fp-boundary-before", "sess-1", warnedAt, expiresAt)
	if err := s.RecordPromptWarned(ctx, row2); err != nil {
		t.Fatalf("RecordPromptWarned (2): %v", err)
	}
	beforeExpiry := expiresAt.Add(-500 * time.Millisecond)
	found2, err := s.ConfirmPromptReconsider(ctx, "fp-boundary-before", beforeExpiry)
	if err != nil {
		t.Fatalf("ConfirmPromptReconsider (2): %v", err)
	}
	if !found2 {
		t.Fatal("ConfirmPromptReconsider found = false for a resend 500ms BEFORE expiry, want true")
	}
}

// TestPrunePromptReconsider_SubSecondBoundary pins the same F8 fix for
// PrunePromptReconsider's `expires_at < ?` comparison: a row whose
// expires_at sits exactly on a whole second must still be recognized
// as expired (and pruned) by a `now` 500ms later, even though the old
// RFC3339Nano TEXT comparison would have sorted the whole-second
// expires_at as "greater than" the fractional-second now and left the
// expired row un-pruned.
func TestPrunePromptReconsider_SubSecondBoundary(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	warnedAt := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 9, 7, 12, 0, 30, 0, time.UTC) // exactly on the second
	pastExpiry := expiresAt.Add(500 * time.Millisecond)

	row := promptReconsiderFixture("fp-prune-boundary", "sess-1", warnedAt, expiresAt)
	if err := s.RecordPromptWarned(ctx, row); err != nil {
		t.Fatalf("RecordPromptWarned: %v", err)
	}
	removed, err := s.PrunePromptReconsider(ctx, pastExpiry)
	if err != nil {
		t.Fatalf("PrunePromptReconsider: %v", err)
	}
	if removed != 1 {
		t.Fatalf("PrunePromptReconsider removed = %d, want 1 (the whole-second-expiry row is 500ms expired)", removed)
	}
}

// Part B item 4 (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md):
// the `observer guard prompt status`/`clear` CLI seams.

func TestCountPromptReconsider_TotalAndExpired(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	live := promptReconsiderFixture("fp-live", "sess-1", t0PromptReconsider, t0PromptReconsider.Add(30*time.Minute))
	expired := promptReconsiderFixture("fp-expired", "sess-2", t0PromptReconsider, t0PromptReconsider.Add(time.Minute))
	if err := s.RecordPromptWarned(ctx, live); err != nil {
		t.Fatalf("RecordPromptWarned live: %v", err)
	}
	if err := s.RecordPromptWarned(ctx, expired); err != nil {
		t.Fatalf("RecordPromptWarned expired: %v", err)
	}

	now := t0PromptReconsider.Add(10 * time.Minute) // past "expired"'s TTL, before "live"'s
	total, exp, err := s.CountPromptReconsider(ctx, now)
	if err != nil {
		t.Fatalf("CountPromptReconsider: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if exp != 1 {
		t.Errorf("expired = %d, want 1", exp)
	}
}

func TestDeletePromptReconsider_RemovesRegardlessOfExpiry(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	// A LIVE (non-expired) row — DeletePromptReconsider must remove it
	// too, unlike PrunePromptReconsider which only sweeps expired rows.
	row := promptReconsiderFixture("fp-1", "sess-1", t0PromptReconsider, t0PromptReconsider.Add(30*time.Minute))
	if err := s.RecordPromptWarned(ctx, row); err != nil {
		t.Fatalf("RecordPromptWarned: %v", err)
	}
	existed, err := s.DeletePromptReconsider(ctx, "fp-1")
	if err != nil {
		t.Fatalf("DeletePromptReconsider: %v", err)
	}
	if !existed {
		t.Fatalf("DeletePromptReconsider existed = false, want true")
	}
	_, ok, err := s.LookupPromptReconsider(ctx, "fp-1", t0PromptReconsider.Add(time.Minute))
	if err != nil {
		t.Fatalf("LookupPromptReconsider: %v", err)
	}
	if ok {
		t.Errorf("row still present after DeletePromptReconsider")
	}

	// Unknown fingerprint: existed=false, no error.
	existed, err = s.DeletePromptReconsider(ctx, "fp-never-existed")
	if err != nil {
		t.Fatalf("DeletePromptReconsider unknown: %v", err)
	}
	if existed {
		t.Errorf("DeletePromptReconsider existed = true for an unknown fingerprint")
	}
}

func TestDeleteAllPromptReconsider_EmptiesTable(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	for i, fp := range []string{"fp-a", "fp-b", "fp-c"} {
		row := promptReconsiderFixture(fp, "sess-1", t0PromptReconsider, t0PromptReconsider.Add(time.Duration(i+1)*time.Minute))
		if err := s.RecordPromptWarned(ctx, row); err != nil {
			t.Fatalf("RecordPromptWarned %s: %v", fp, err)
		}
	}
	removed, err := s.DeleteAllPromptReconsider(ctx)
	if err != nil {
		t.Fatalf("DeleteAllPromptReconsider: %v", err)
	}
	if removed != 3 {
		t.Errorf("removed = %d, want 3", removed)
	}
	total, _, err := s.CountPromptReconsider(ctx, t0PromptReconsider)
	if err != nil {
		t.Fatalf("CountPromptReconsider: %v", err)
	}
	if total != 0 {
		t.Errorf("total after DeleteAllPromptReconsider = %d, want 0", total)
	}
}
