package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/scoring"
)

// scoreSessionAt runs the REAL scorer (the one writer of the score columns)
// over sessionID with its clock pinned to at, so the wire reads exactly what
// production writes.
func scoreSessionAt(ctx context.Context, t *testing.T, s *Store, sessionID string, at time.Time) {
	t.Helper()
	sc := scoring.New(s.db).WithNow(func() time.Time { return at })
	scores, err := sc.ScoreSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("ScoreSession: %v", err)
	}
	if err := sc.Write(ctx, scores); err != nil {
		t.Fatalf("Write: %v", err)
	}
}

// TestSelectSessionQualityRows pins what ships: only sessions the scorer
// wrote AND stamped, inside the scored_at window, with a fixed-width stamp,
// the formula weights, and NULL columns kept nil (never 0).
func TestSelectSessionQualityRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	locSeedSession(ctx, t, s, "/repo-q", "sess-scored")
	locSeedSession(ctx, t, s, "/repo-q", "sess-unscored")
	locSeedSession(ctx, t, s, "/repo-q", "sess-old-score")
	locSeedSession(ctx, t, s, "/repo-q", "sess-pre137")
	scoreSessionAt(ctx, t, s, "sess-scored", now.Add(-time.Minute))
	scoreSessionAt(ctx, t, s, "sess-old-score", now.AddDate(0, 0, -(sessionQualityWindowDays+1)))
	// A score written before agent migration 137: no stamp, so it cannot be
	// ordered on the server and stays node-local.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET quality_score = 0.5, redundancy_ratio = 0.2, error_rate = 0.1 WHERE id = 'sess-pre137'`); err != nil {
		t.Fatal(err)
	}

	rows, err := s.SelectSessionQualityRows(ctx, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectSessionQualityRows: %v", err)
	}
	if len(rows) != 1 || rows[0].SessionID != "sess-scored" {
		t.Fatalf("rows = %+v, want exactly sess-scored (unscored, out-of-window and unstamped sessions ship nothing)", rows)
	}
	r := rows[0]
	if len(r.ScoredAt) != len(sessionQualityStampLayout) || !strings.HasSuffix(r.ScoredAt, "Z") {
		t.Errorf("ScoredAt = %q, want the fixed-width layout %q", r.ScoredAt, sessionQualityStampLayout)
	}
	if r.WeightRedundancy != scoring.WeightRedundancy || r.WeightError != scoring.WeightError ||
		r.WeightExploration != scoring.WeightExploration || r.WeightContinuity != scoring.WeightContinuity {
		t.Errorf("weights = %v/%v/%v/%v, want the scorer's constants", r.WeightRedundancy, r.WeightError, r.WeightExploration, r.WeightContinuity)
	}
	if r.RedundancyRatio == nil || r.ErrorRate == nil || r.ExplorationEfficiency == nil || r.ContinuityScore == nil {
		t.Errorf("a scored row must carry all four components: %+v", r)
	}
	if r.ScoredActionCount == nil || *r.ScoredActionCount != 1 {
		t.Errorf("ScoredActionCount = %v, want 1", r.ScoredActionCount)
	}
	// No cache events for this session, so the wasteful/necessary split was
	// never computed: nil on the wire, never 0.
	if r.StaleReadsWasteful != nil || r.StaleReadsNecessary != nil || r.RedundancyRatioWasteful != nil {
		t.Errorf("uncomputed split must stay nil, got %v/%v/%v", r.StaleReadsWasteful, r.StaleReadsNecessary, r.RedundancyRatioWasteful)
	}
}

// TestSessionQualityShipsAfterSessionRowAlreadyPushed is the reason the wire
// exists: the session row ships on the rowid cursor BEFORE the scorer runs,
// and the score must still go out on a later push; an unchanged score is then
// skipped by the snapshot gate, and a re-score ships again.
func TestSessionQualityShipsAfterSessionRowAlreadyPushed(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	locSeedSession(ctx, t, s, "/repo-late", "sess-late")

	push := func(cur PushCursor) PushBatch {
		t.Helper()
		b, err := s.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince: %v", err)
		}
		return b
	}

	first := push(PushCursor{})
	if len(first.Sessions) != 1 || len(first.SessionQuality) != 0 {
		t.Fatalf("first push: sessions=%d quality=%d, want 1/0 (not scored yet)", len(first.Sessions), len(first.SessionQuality))
	}
	s.CommitPushedSnapshots()

	scoreSessionAt(ctx, t, s, "sess-late", time.Now().UTC().Add(-time.Minute))
	second := push(first.Cursor)
	if len(second.Sessions) != 0 {
		t.Fatalf("second push re-shipped the session row (%d), want 0", len(second.Sessions))
	}
	if len(second.SessionQuality) != 1 || second.SessionQuality[0].SessionID != "sess-late" {
		t.Fatalf("second push quality = %+v, want the late score for sess-late", second.SessionQuality)
	}
	if got := second.SessionQuality[0]; got.OrgID != "org-1" || got.UserEmail != "dev@acme.example" {
		t.Errorf("attribution = %q/%q, want the pusher's", got.OrgID, got.UserEmail)
	}
	firstStamp := second.SessionQuality[0].ScoredAt
	s.CommitPushedSnapshots()

	if third := push(second.Cursor); len(third.SessionQuality) != 0 {
		t.Fatalf("unchanged score re-shipped (%d rows); the snapshot gate should skip it", len(third.SessionQuality))
	}
	s.CommitPushedSnapshots()

	scoreSessionAt(ctx, t, s, "sess-late", time.Now().UTC())
	fourth := push(second.Cursor)
	if len(fourth.SessionQuality) != 1 || fourth.SessionQuality[0].ScoredAt <= firstStamp {
		t.Fatalf("re-score quality = %+v, want one row stamped after %s", fourth.SessionQuality, firstStamp)
	}
}

// TestSelectSessionQualityRowsHonoursScope: a session in a denied project
// ships no score, exactly as its sessions row ships nothing.
func TestSelectSessionQualityRowsHonoursScope(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	locSeedSession(ctx, t, s, "/repo-allowed", "sess-allowed")
	locSeedSession(ctx, t, s, "/repo-denied", "sess-denied")
	at := time.Now().UTC().Add(-time.Minute)
	scoreSessionAt(ctx, t, s, "sess-allowed", at)
	scoreSessionAt(ctx, t, s, "sess-denied", at)

	rows, err := s.SelectSessionQualityRows(ctx, ScopeOptions{ProjectRootDenylist: []string{"/repo-denied"}})
	if err != nil {
		t.Fatalf("SelectSessionQualityRows: %v", err)
	}
	if len(rows) != 1 || rows[0].SessionID != "sess-allowed" {
		t.Fatalf("rows = %+v, want only sess-allowed", rows)
	}
	rows, err = s.SelectSessionQualityRows(ctx, ScopeOptions{ProjectRootAllowlist: []string{"/nowhere"}})
	if err != nil {
		t.Fatalf("SelectSessionQualityRows: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("an allowlist that matches nothing shipped %d rows, want 0", len(rows))
	}
}

// TestSessionQualityStampOrdersLexically pins the fixed-width layout the
// server's newest-wins guard depends on: a plain string comparison of two
// normalized stamps equals the time comparison, even where the RFC3339Nano
// originals (which drop trailing zeros) would mis-order.
func TestSessionQualityStampOrdersLexically(t *testing.T) {
	t.Parallel()
	earlier, _ := sessionQualityStamp("2026-09-27T10:00:00Z")
	later, _ := sessionQualityStamp("2026-09-27T10:00:00.1Z")
	if !(earlier < later) {
		t.Fatalf("normalized %q !< %q", earlier, later)
	}
	if "2026-09-27T10:00:00Z" < "2026-09-27T10:00:00.1Z" {
		t.Fatal("precondition: the raw RFC3339Nano pair should mis-order lexically")
	}
	if _, ok := sessionQualityStamp("not a time"); ok {
		t.Fatal("an unparseable stamp must not normalize")
	}
}
