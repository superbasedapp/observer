package store

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Review 2026-09-29 (lane H-WIRE) regressions for the per-session rate-limit
// window cursor wire (lane F-WIRE).

// TestMigration146SeedsLimitSnapshotCursorForAnEnrolledUpgrade is finding 2:
// a node enrolled BEFORE the limit-snapshot cursor key existed has every other
// cursor key but not that one, LoadPushCursor read it as 0, and the first push
// after the upgrade shipped the pre-enrolment window history. Agent migration
// 148 seeds the key at the current head for such a node, never moves an
// existing key, and leaves a never-enrolled node alone.
func TestMigration146SeedsLimitSnapshotCursorForAnEnrolledUpgrade(t *testing.T) {
	t.Parallel()
	body, err := fs.ReadFile(migrations.Files, "146_limit_cursor_seed_and_commit_local_author.sql")
	if err != nil {
		t.Fatalf("read migration 146: %v", err)
	}
	// Part 1 only: part 2 is a one-shot ALTER TABLE the store already ran.
	part1, _, ok := strings.Cut(string(body), "-- PART 2")
	if !ok {
		t.Fatal("migration 146 lost its PART 2 marker")
	}
	apply := func(t *testing.T, s *Store) {
		t.Helper()
		if _, err := s.db.ExecContext(context.Background(), part1); err != nil {
			t.Fatalf("apply migration 146: %v", err)
		}
	}
	dropKey := func(t *testing.T, s *Store) {
		t.Helper()
		if _, err := s.db.ExecContext(context.Background(), `DELETE FROM schema_meta WHERE key = ?`, pushCursorKeyLimitSnapshots); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("enrolled before the key existed: seeded at head, nothing pre-enrolment ships", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		ctx := context.Background()
		seedSessionLimitSnapshots(t, s) // sessions + windows all exist BEFORE enrolment
		enrol, err := s.CurrentMaxIDs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SavePushCursor(ctx, enrol); err != nil {
			t.Fatal(err)
		}
		dropKey(t, s) // the pre-upgrade agent never wrote it
		// The defect, pinned: without the seed the cursor reads 0 and the
		// whole pre-enrolment log ships.
		pre, err := s.LoadPushCursor(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if pre.LimitSnapshots != 0 {
			t.Fatalf("precondition: missing key read as %d, want 0", pre.LimitSnapshots)
		}
		apply(t, s)
		cur, err := s.LoadPushCursor(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if head := limitSnapshotHead(t, s); cur.LimitSnapshots != head || head == 0 {
			t.Fatalf("seeded cursor = %d, want the head %d", cur.LimitSnapshots, head)
		}
		b, err := s.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example", ShareOptions{LimitGauge: true}, ScopeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if n := len(b.SessionLimitSnapshots); n != 0 {
			t.Fatalf("upgraded enrolled node shipped %d pre-enrolment window rows: %+v", n, b.SessionLimitSnapshots)
		}
		// Idempotent: a second run, after a new window landed, does not move
		// the seeded key.
		u := 0.9
		if err := s.InsertLimitSnapshot(ctx, models.LimitSnapshot{ScopeHash: "x", Provider: "anthropic", SessionID: "s1", ObservedAt: time.Now().UTC(), Window5hUtil: &u}); err != nil {
			t.Fatal(err)
		}
		apply(t, s)
		again, err := s.LoadPushCursor(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if again.LimitSnapshots != cur.LimitSnapshots {
			t.Fatalf("a second run moved the key %d -> %d", cur.LimitSnapshots, again.LimitSnapshots)
		}
		post, err := s.SelectUnpushedSince(ctx, again, 1<<20, "org-1", "dev@acme.example", ShareOptions{LimitGauge: true}, ScopeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(post.SessionLimitSnapshots) != 1 {
			t.Fatalf("the post-upgrade window did not ship: %+v", post.SessionLimitSnapshots)
		}
	})

	t.Run("an existing key is never moved", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		ctx := context.Background()
		seedSessionLimitSnapshots(t, s)
		c := PushCursor{Sessions: 1, LimitSnapshots: 2}
		if err := s.SavePushCursor(ctx, c); err != nil {
			t.Fatal(err)
		}
		apply(t, s)
		got, err := s.LoadPushCursor(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got.LimitSnapshots != 2 {
			t.Fatalf("existing key moved to %d", got.LimitSnapshots)
		}
	})

	t.Run("a never-enrolled node gets no key (enrolment seeds it)", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		ctx := context.Background()
		seedSessionLimitSnapshots(t, s)
		apply(t, s)
		v, err := s.readMeta(ctx, pushCursorKeyLimitSnapshots)
		if err != nil {
			t.Fatal(err)
		}
		if v != "" {
			t.Fatalf("never-enrolled node was seeded: %q", v)
		}
	})
}

// TestSessionLimitSnapshotBeforeItsSessionRowShipsOnceTheRowLands is finding
// 6: the proxy can record a window before the session row lands; the walk
// used to consume it as unlinked and it never shipped. A settling row (unknown
// session id, observed inside the settle window) now stops the walk
// unconsumed; an OLD unlinked row is still consumed as before.
func TestSessionLimitSnapshotBeforeItsSessionRowShipsOnceTheRowLands(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	cur, err := s.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u := 0.42
	old := time.Now().UTC().Add(-2 * limitSnapshotSettleWindow)
	for _, snap := range []models.LimitSnapshot{
		// An abandoned id, observed long ago: consumed as unlinked, as today.
		{ScopeHash: "x", Provider: "anthropic", SessionID: "gone", ObservedAt: old, Window5hUtil: &u},
		// A fresh window whose session row has not landed yet.
		{ScopeHash: "x", Provider: "anthropic", SessionID: "late", ObservedAt: time.Now().UTC(), Window5hUtil: &u},
	} {
		if err := s.InsertLimitSnapshot(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}
	share := ShareOptions{LimitGauge: true}
	b1, err := s.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b1.SessionLimitSnapshots) != 0 {
		t.Fatalf("first push shipped %+v, want nothing (no linked row yet)", b1.SessionLimitSnapshots)
	}
	if b1.Cursor.LimitSnapshots != cur.LimitSnapshots+1 {
		t.Fatalf("cursor = %d, want %d (the old unlinked row consumed, the settling row held)",
			b1.Cursor.LimitSnapshots, cur.LimitSnapshots+1)
	}
	p, err := s.UpsertProject(ctx, "/tmp/late", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: "late", ProjectID: p, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	b2, err := s.SelectUnpushedSince(ctx, b1.Cursor, 1<<20, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b2.SessionLimitSnapshots) != 1 || b2.SessionLimitSnapshots[0].SessionID != "late" {
		t.Fatalf("the window for 'late' never shipped after its session row landed: %+v", b2.SessionLimitSnapshots)
	}
	if head := limitSnapshotHead(t, s); b2.Cursor.LimitSnapshots != head {
		t.Fatalf("cursor = %d, want the head %d", b2.Cursor.LimitSnapshots, head)
	}
}

// TestSelectSessionLimitSnapshotsSettleWindowBoundary pins the settle rule at
// the candidate level: unknown session + inside the window = settling; past
// the window, an empty session id, or a known session = not settling.
func TestSelectSessionLimitSnapshotsSettleWindowBoundary(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	p, err := s.UpsertProject(ctx, "/tmp/known", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: "known", ProjectID: p, Tool: models.ToolClaudeCode, StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	u := 0.1
	cases := []struct {
		session  string
		at       time.Time
		settling bool
	}{
		{"unknown", now.Add(-time.Minute), true},
		{"unknown", now.Add(-limitSnapshotSettleWindow - time.Minute), false},
		{"", now, false},
		{"known", now, false},
	}
	for _, c := range cases {
		if err := s.InsertLimitSnapshot(ctx, models.LimitSnapshot{ScopeHash: "x", Provider: "anthropic", SessionID: c.session, ObservedAt: c.at, Window5hUtil: &u}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.selectSessionLimitSnapshotsAt(ctx, 0, 100, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(cases) {
		t.Fatalf("got %d candidates, want %d", len(got), len(cases))
	}
	for i, c := range cases {
		if got[i].Settling != c.settling {
			t.Errorf("row %d (session %q, age %s): settling = %v, want %v", i, c.session, now.Sub(c.at), got[i].Settling, c.settling)
		}
	}
}
