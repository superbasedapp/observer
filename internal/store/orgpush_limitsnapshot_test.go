package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Lane F-WIRE: the per-session rate-limit window cursor wire
// (PushBatch.SessionLimitSnapshots / PushCursor.LimitSnapshots).

// limitCand builds one coalescer candidate.
func limitCand(id int64, session, provider string, observedAt int64, linked bool) LimitSnapshotCandidate {
	return LimitSnapshotCandidate{
		ID:     id,
		Linked: linked,
		Row: orgcontract.SessionLimitSnapshotRow{
			SessionID: session, Tool: "claude-code", Provider: provider,
			LocalID: id, ObservedAt: observedAt,
		},
	}
}

// settlingCand builds an unlinked candidate still inside the settle window.
func settlingCand(id int64, session, provider string, observedAt int64) LimitSnapshotCandidate {
	c := limitCand(id, session, provider, observedAt, false)
	c.Row.Tool = ""
	c.Settling = true
	return c
}

// capAdmit is a reserve-if-fits admitter with a hard byte cap and no
// first-row exemption (orgpush's closure adds that exemption on top).
func capAdmit(max int64) func(int64) bool {
	var used int64
	return func(extra int64) bool {
		if extra > 0 && used+extra > max {
			return false
		}
		used += extra
		return true
	}
}

func unlimitedAdmit(int64) bool { return true }

// TestCoalesceSessionLimitSnapshots is the rule table for the coalescer: one
// case per consumption rule.
func TestCoalesceSessionLimitSnapshots(t *testing.T) {
	t.Parallel()
	oneRow := jsonSize(limitCand(1, "s1", "anthropic", 100, true).Row)
	grown := limitCand(2, "s1", "anthropic", 200, true)
	u := 0.5
	grown.Row.Window5hUtil, grown.Row.Window7dUtil = &u, &u

	type want struct {
		ids    []int64 // LocalIDs shipped, in output order
		cursor int64
	}
	cases := []struct {
		name   string
		cands  []LimitSnapshotCandidate
		cursor int64
		admit  func(int64) bool
		want   want
	}{
		{
			name: "nothing scanned keeps the input cursor", cursor: 7,
			admit: unlimitedAdmit, want: want{cursor: 7},
		},
		{
			name: "unlinked rows are consumed and ship nothing", cursor: 0,
			cands: []LimitSnapshotCandidate{
				limitCand(1, "", "anthropic", 100, false),
				limitCand(2, "ghost", "anthropic", 110, false),
			},
			admit: unlimitedAdmit, want: want{cursor: 2},
		},
		{
			name: "newest per (session, provider) wins", cursor: 0,
			cands: []LimitSnapshotCandidate{
				limitCand(1, "s1", "anthropic", 100, true),
				limitCand(2, "s1", "anthropic", 200, true),
				limitCand(3, "s1", "openai", 150, true),
				limitCand(4, "s2", "anthropic", 50, true),
				limitCand(5, "", "anthropic", 300, false),
			},
			admit: unlimitedAdmit, want: want{ids: []int64{2, 3, 4}, cursor: 5},
		},
		{
			name: "a later id with an older observed_at is consumed but does not replace", cursor: 0,
			cands: []LimitSnapshotCandidate{
				limitCand(1, "s1", "anthropic", 200, true),
				limitCand(2, "s1", "anthropic", 100, true),
			},
			admit: unlimitedAdmit, want: want{ids: []int64{1}, cursor: 2},
		},
		{
			name: "an observed_at tie goes to the higher local id", cursor: 0,
			cands: []LimitSnapshotCandidate{
				limitCand(1, "s1", "anthropic", 100, true),
				limitCand(2, "s1", "anthropic", 100, true),
			},
			admit: unlimitedAdmit, want: want{ids: []int64{2}, cursor: 2},
		},
		{
			name: "a new key that does not fit stops the walk unconsumed", cursor: 0,
			cands: []LimitSnapshotCandidate{
				limitCand(1, "s1", "anthropic", 100, true),
				limitCand(2, "s2", "anthropic", 100, true),
				limitCand(3, "s1", "anthropic", 300, true),
			},
			admit: capAdmit(oneRow), want: want{ids: []int64{1}, cursor: 1},
		},
		{
			name: "unlinked rows before the budget stop are still consumed", cursor: 0,
			cands: []LimitSnapshotCandidate{
				limitCand(1, "s1", "anthropic", 100, true),
				limitCand(2, "", "anthropic", 100, false),
				limitCand(3, "s2", "anthropic", 100, true),
			},
			admit: capAdmit(oneRow), want: want{ids: []int64{1}, cursor: 2},
		},
		{
			name: "a replacement that grows past the budget stops unconsumed", cursor: 0,
			cands: []LimitSnapshotCandidate{
				limitCand(1, "s1", "anthropic", 100, true),
				grown,
			},
			admit: capAdmit(oneRow), want: want{ids: []int64{1}, cursor: 1},
		},
		{
			name: "a settling row stops the walk unconsumed (review 2026-09-29 finding 6)", cursor: 0,
			cands: []LimitSnapshotCandidate{
				limitCand(1, "s1", "anthropic", 100, true),
				settlingCand(2, "late", "anthropic", 110),
				limitCand(3, "s2", "anthropic", 120, true),
			},
			admit: unlimitedAdmit, want: want{ids: []int64{1}, cursor: 1},
		},
		{
			name: "a settling row first keeps the input cursor", cursor: 4,
			cands: []LimitSnapshotCandidate{
				settlingCand(5, "late", "anthropic", 110),
			},
			admit: unlimitedAdmit, want: want{cursor: 4},
		},
		{
			name: "the walk resumes above the input cursor", cursor: 10,
			cands: []LimitSnapshotCandidate{
				limitCand(11, "s1", "anthropic", 100, true),
			},
			admit: unlimitedAdmit, want: want{ids: []int64{11}, cursor: 11},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rows, next := coalesceSessionLimitSnapshots(tc.cands, tc.cursor, tc.admit)
			if next != tc.want.cursor {
				t.Errorf("cursor = %d, want %d", next, tc.want.cursor)
			}
			var got []int64
			for _, r := range rows {
				got = append(got, r.LocalID)
			}
			if len(got) != len(tc.want.ids) {
				t.Fatalf("shipped ids = %v, want %v", got, tc.want.ids)
			}
			for i := range got {
				if got[i] != tc.want.ids[i] {
					t.Fatalf("shipped ids = %v, want %v", got, tc.want.ids)
				}
			}
		})
	}
}

// seedSessionLimitSnapshots seeds two projects, two sessions and a snapshot log
// covering every consumption rule. It returns the cursor to push from: every
// other cursor wire already at its high-water mark, so the batch carries only
// the limit windows.
func seedSessionLimitSnapshots(t *testing.T, s *Store) PushCursor {
	t.Helper()
	ctx := context.Background()
	pa, err := s.UpsertProject(ctx, "/tmp/limit-a", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	pb, err := s.UpsertProject(ctx, "/tmp/limit-b", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	for _, sess := range []models.Session{
		{ID: "s1", ProjectID: pa, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC()},
		{ID: "s2", ProjectID: pb, Tool: models.ToolCodex, StartedAt: time.Now().UTC()},
	} {
		if err := s.UpsertSession(ctx, sess); err != nil {
			t.Fatalf("UpsertSession: %v", err)
		}
	}
	cur, err := s.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatalf("CurrentMaxIDs: %v", err)
	}
	base := time.Unix(1790000000, 0).UTC()
	u1, u2, u3 := 0.1, 0.2, 0.3
	r5 := int64(1790012000)
	for _, snap := range []models.LimitSnapshot{
		{ScopeHash: "scope-x", Provider: "anthropic", SessionID: "s1", ObservedAt: base, Window5hUtil: &u1},
		{ScopeHash: "scope-x", Provider: "anthropic", SessionID: "s1", ObservedAt: base.Add(time.Minute), Window5hUtil: &u2},
		{ScopeHash: "scope-x", Provider: "openai", SessionID: "s2", ObservedAt: base, Window7dUtil: &u1},
		{ScopeHash: "scope-x", Provider: "anthropic", SessionID: "", ObservedAt: base.Add(2 * time.Minute), Window5hUtil: &u3},
		{ScopeHash: "scope-x", Provider: "anthropic", SessionID: "ghost", ObservedAt: base.Add(2 * time.Minute), Window5hUtil: &u3},
		{ScopeHash: "scope-x", Provider: "anthropic", SessionID: "s1", ObservedAt: base.Add(3 * time.Minute), Window5hUtil: &u3, Window5hReset: &r5, Status: "allowed"},
	} {
		if err := s.InsertLimitSnapshot(ctx, snap); err != nil {
			t.Fatalf("InsertLimitSnapshot: %v", err)
		}
	}
	return cur
}

func limitSnapshotHead(t *testing.T, s *Store) int64 {
	t.Helper()
	id, err := s.limitSnapshotHeadID(context.Background())
	if err != nil {
		t.Fatalf("limitSnapshotHeadID: %v", err)
	}
	return id
}

// TestSelectUnpushedSince_SessionLimitSnapshotsCoalesce drives the whole
// cursor wire through SelectUnpushedSince: coalescing, unlinked consumption,
// the cursor, the second push, and the gate.
func TestSelectUnpushedSince_SessionLimitSnapshotsCoalesce(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	cur := seedSessionLimitSnapshots(t, s)
	head := limitSnapshotHead(t, s)

	// Gate closed: no opt-in and no raw-content posture ships nothing and
	// leaves the cursor where it was.
	closed, err := s.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (closed): %v", err)
	}
	if len(closed.SessionLimitSnapshots) != 0 || closed.Cursor.LimitSnapshots != cur.LimitSnapshots {
		t.Fatalf("zero ShareOptions shipped %d rows / cursor %d, want none / %d",
			len(closed.SessionLimitSnapshots), closed.Cursor.LimitSnapshots, cur.LimitSnapshots)
	}

	for _, share := range []ShareOptions{{LimitGauge: true}, {FullContent: true}} {
		batch, err := s.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example", share, ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince: %v", err)
		}
		if batch.Cursor.LimitSnapshots != head {
			t.Errorf("%+v: cursor = %d, want the head %d (the unlinked tail is consumed)", share, batch.Cursor.LimitSnapshots, head)
		}
		if got := len(batch.SessionLimitSnapshots); got != 2 {
			t.Fatalf("%+v: shipped %d rows, want 2 (s1/anthropic newest + s2/openai): %+v", share, got, batch.SessionLimitSnapshots)
		}
		if batch.RowCount() != 2 {
			t.Errorf("RowCount = %d, want the 2 limit rows counted like any cursor wire", batch.RowCount())
		}
		byKey := map[string]orgcontract.SessionLimitSnapshotRow{}
		for _, r := range batch.SessionLimitSnapshots {
			byKey[r.SessionID+"/"+r.Provider] = r
		}
		a := byKey["s1/anthropic"]
		if a.LocalID != head || a.Tool != models.ToolClaudeCode || a.ObservedAt != 1790000180 ||
			a.Window5hUtil == nil || *a.Window5hUtil != 0.3 || a.Window5hReset == nil || *a.Window5hReset != 1790012000 ||
			a.Window7dUtil != nil || a.OrgID != "org-1" || a.UserEmail != "dev@acme.example" {
			t.Errorf("s1/anthropic = %+v, want the newest observation (id %d) with its tool and stamps", a, head)
		}
		o := byKey["s2/openai"]
		if o.Tool != models.ToolCodex || o.Window7dUtil == nil || *o.Window7dUtil != 0.1 || o.Window5hUtil != nil {
			t.Errorf("s2/openai = %+v, want the codex window with 5h absent", o)
		}
	}

	// Second push: only rows above the saved cursor ship.
	next := cur
	next.LimitSnapshots = head
	later := 0.9
	if err := s.InsertLimitSnapshot(ctx, models.LimitSnapshot{
		ScopeHash: "scope-x", Provider: "openai", SessionID: "s2",
		ObservedAt: time.Unix(1790000500, 0).UTC(), Window7dUtil: &later,
	}); err != nil {
		t.Fatalf("InsertLimitSnapshot: %v", err)
	}
	b2, err := s.SelectUnpushedSince(ctx, next, 1<<20, "org-1", "dev@acme.example", ShareOptions{LimitGauge: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (second): %v", err)
	}
	if len(b2.SessionLimitSnapshots) != 1 || b2.SessionLimitSnapshots[0].SessionID != "s2" ||
		*b2.SessionLimitSnapshots[0].Window7dUtil != 0.9 || b2.Cursor.LimitSnapshots != head+1 {
		t.Fatalf("second push = %+v cursor %d, want only the new s2 row and cursor %d",
			b2.SessionLimitSnapshots, b2.Cursor.LimitSnapshots, head+1)
	}
}

// TestSelectUnpushedSince_SessionLimitSnapshotsScoped pins that an
// out-of-scope session's windows are consumed but never shipped.
func TestSelectUnpushedSince_SessionLimitSnapshotsScoped(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	cur := seedSessionLimitSnapshots(t, s)
	batch, err := s.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example",
		ShareOptions{LimitGauge: true}, ScopeOptions{ProjectRootDenylist: []string{"/tmp/limit-b"}})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.SessionLimitSnapshots) != 1 || batch.SessionLimitSnapshots[0].SessionID != "s1" {
		t.Fatalf("scoped push shipped %+v, want only s1 (s2's project is denied)", batch.SessionLimitSnapshots)
	}
	if head := limitSnapshotHead(t, s); batch.Cursor.LimitSnapshots != head {
		t.Errorf("cursor = %d, want %d: out-of-scope rows are consumed like unlinked ones", batch.Cursor.LimitSnapshots, head)
	}
}

// TestSelectUnpushedSince_SessionLimitSnapshotsBudgetStops pins the budget
// rule end to end: at a budget too small for a second row, the first row
// still ships (forward progress) and the walk stops BEFORE the next new key
// without consuming it, so the next push picks it up.
func TestSelectUnpushedSince_SessionLimitSnapshotsBudgetStops(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	cur := seedSessionLimitSnapshots(t, s)
	first := cur.LimitSnapshots + 1

	b1, err := s.SelectUnpushedSince(ctx, cur, 1, "org-1", "dev@acme.example", ShareOptions{LimitGauge: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	// ids: first (s1 a), first+1 (s1 a, replaces - negative-or-zero delta
	// is always admitted), first+2 (s2 openai, a NEW key that does not fit).
	if len(b1.SessionLimitSnapshots) != 1 || b1.SessionLimitSnapshots[0].SessionID != "s1" {
		t.Fatalf("tight budget shipped %+v, want the single s1 row", b1.SessionLimitSnapshots)
	}
	if b1.Cursor.LimitSnapshots >= first+2 {
		t.Fatalf("cursor = %d consumed the s2 row (id %d) that did not fit", b1.Cursor.LimitSnapshots, first+2)
	}

	b2, err := s.SelectUnpushedSince(ctx, b1.Cursor, 1<<20, "org-1", "dev@acme.example", ShareOptions{LimitGauge: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (drain): %v", err)
	}
	keys := map[string]bool{}
	for _, r := range b2.SessionLimitSnapshots {
		keys[r.SessionID+"/"+r.Provider] = true
	}
	if !keys["s2/openai"] || !keys["s1/anthropic"] {
		t.Fatalf("drain push shipped %+v, want the deferred s2 row and s1's newer window", b2.SessionLimitSnapshots)
	}
	if head := limitSnapshotHead(t, s); b2.Cursor.LimitSnapshots != head {
		t.Errorf("drain cursor = %d, want %d", b2.Cursor.LimitSnapshots, head)
	}
}

// TestPushCursorLimitSnapshotsPersists pins enrolment seeding and the
// schema_meta round-trip of the new cursor key, including the CAS path.
func TestPushCursorLimitSnapshotsPersists(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedSessionLimitSnapshots(t, s)
	head := limitSnapshotHead(t, s)
	if head == 0 {
		t.Fatal("fixture wrote no snapshots")
	}

	seeded, err := s.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatalf("CurrentMaxIDs: %v", err)
	}
	if seeded.LimitSnapshots != head {
		t.Fatalf("CurrentMaxIDs.LimitSnapshots = %d, want the head %d", seeded.LimitSnapshots, head)
	}

	if err := s.SavePushCursor(ctx, seeded); err != nil {
		t.Fatalf("SavePushCursor: %v", err)
	}
	loaded, err := s.LoadPushCursor(ctx)
	if err != nil {
		t.Fatalf("LoadPushCursor: %v", err)
	}
	if loaded != seeded {
		t.Fatalf("round-trip = %+v, want %+v", loaded, seeded)
	}

	moved := loaded
	moved.LimitSnapshots = head + 5
	ok, err := s.SavePushCursorIfUnchanged(ctx, loaded, moved)
	if err != nil || !ok {
		t.Fatalf("SavePushCursorIfUnchanged = %v, %v; want saved", ok, err)
	}
	again, err := s.LoadPushCursor(ctx)
	if err != nil {
		t.Fatalf("LoadPushCursor: %v", err)
	}
	if again.LimitSnapshots != head+5 {
		t.Fatalf("LimitSnapshots after CAS = %d, want %d", again.LimitSnapshots, head+5)
	}
	// A stale expectation that differs ONLY in the new field is refused.
	ok, err = s.SavePushCursorIfUnchanged(ctx, loaded, moved)
	if err != nil || ok {
		t.Fatalf("stale CAS = %v, %v; want refused", ok, err)
	}
}
