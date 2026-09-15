package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/processobs"
)

func TestLaunchSeed_InsertPendingClaimRoundtrip(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.InsertLaunchSeed(ctx, processobs.LaunchSeed{PID: 4242, Tool: "opencode", CWD: "/proj"}); err != nil {
		t.Fatalf("InsertLaunchSeed: %v", err)
	}
	pending, err := s.PendingLaunchSeeds(ctx, time.Hour)
	if err != nil {
		t.Fatalf("PendingLaunchSeeds: %v", err)
	}
	if len(pending) != 1 || pending[0].PID != 4242 || pending[0].Tool != "opencode" || pending[0].CWD != "/proj" {
		t.Fatalf("pending = %+v, want one opencode seed for pid 4242", pending)
	}

	claimed, err := s.ClaimLaunchSeed(ctx, 4242)
	if err != nil || !claimed {
		t.Fatalf("ClaimLaunchSeed = (%v, %v), want claimed", claimed, err)
	}
	again, err := s.ClaimLaunchSeed(ctx, 4242)
	if err != nil || again {
		t.Fatalf("second ClaimLaunchSeed = (%v, %v), want false (row gone)", again, err)
	}
	pending, err = s.PendingLaunchSeeds(ctx, time.Hour)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after claim = (%+v, %v), want empty", pending, err)
	}
}

func TestLaunchSeed_UpsertReplacesRecycledPID(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.InsertLaunchSeed(ctx, processobs.LaunchSeed{PID: 7, Tool: "pi", CWD: "/old"}); err != nil {
		t.Fatalf("InsertLaunchSeed: %v", err)
	}
	if err := s.InsertLaunchSeed(ctx, processobs.LaunchSeed{PID: 7, Tool: "opencode", CWD: "/new"}); err != nil {
		t.Fatalf("InsertLaunchSeed (recycled pid): %v", err)
	}
	pending, err := s.PendingLaunchSeeds(ctx, time.Hour)
	if err != nil {
		t.Fatalf("PendingLaunchSeeds: %v", err)
	}
	if len(pending) != 1 || pending[0].Tool != "opencode" || pending[0].CWD != "/new" {
		t.Fatalf("pending = %+v, want the recycled-pid upsert to replace in place", pending)
	}
}

func TestLaunchSeed_ClaimIsIdempotentDelete(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.InsertLaunchSeed(ctx, processobs.LaunchSeed{PID: 9, Tool: "goose", CWD: "/proj"}); err != nil {
		t.Fatalf("InsertLaunchSeed: %v", err)
	}
	for i := 0; i < 2; i++ {
		claimed, err := s.ClaimLaunchSeed(ctx, 9)
		if err != nil {
			t.Fatalf("ClaimLaunchSeed pass %d: %v", i, err)
		}
		if (i == 0) != claimed {
			t.Fatalf("ClaimLaunchSeed pass %d claimed = %v, want %v", i, claimed, i == 0)
		}
	}
}

func TestLaunchSeed_ExpireStaleRemovesOnlyOldRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.InsertLaunchSeed(ctx, processobs.LaunchSeed{PID: 11, Tool: "grok", CWD: "/proj"}); err != nil {
		t.Fatalf("InsertLaunchSeed: %v", err)
	}
	// Nothing is stale yet inside a generous window.
	n, err := s.ExpireStaleLaunchSeeds(ctx, time.Hour)
	if err != nil || n != 0 {
		t.Fatalf("ExpireStaleLaunchSeeds(fresh) = (%d, %v), want 0 removed", n, err)
	}
	// A TTL of zero expires everything.
	n, err = s.ExpireStaleLaunchSeeds(ctx, 0)
	if err != nil || n != 1 {
		t.Fatalf("ExpireStaleLaunchSeeds(0) = (%d, %v), want 1 removed", n, err)
	}
}

func TestRecentSessionRefsForLaunchMatch(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	projectID, err := s.UpsertProject(ctx, "/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		"sess-launch-1", projectID, "opencode", timestamp(time.Now().UTC().Add(-time.Minute))); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	refs, err := s.RecentSessionRefsForLaunchMatch(ctx, 60)
	if err != nil {
		t.Fatalf("RecentSessionRefsForLaunchMatch: %v", err)
	}
	found := false
	for _, ref := range refs {
		if ref.SessionID == "sess-launch-1" {
			found = true
			if ref.Tool != "opencode" || ref.ProjectRoot != "/proj" {
				t.Fatalf("ref = %+v, want tool opencode + root /proj", ref)
			}
			if ref.StartedAt.IsZero() {
				t.Fatal("ref.StartedAt zero — parseStamp failed")
			}
		}
	}
	if !found {
		t.Fatalf("refs = %+v, want sess-launch-1 present", refs)
	}
}

// TestLaunchSeed_RunIDRoundtrip pins that migration 091's column survives the
// write/read cycle in BOTH shapes — the dashboard launch that carries a run and
// the bare-shell launch that honestly carries none.
func TestLaunchSeed_RunIDRoundtrip(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.InsertLaunchSeed(ctx, processobs.LaunchSeed{PID: 11, Tool: "opencode", CWD: "/a", RunID: "run-A"}); err != nil {
		t.Fatalf("InsertLaunchSeed(with run): %v", err)
	}
	if err := s.InsertLaunchSeed(ctx, processobs.LaunchSeed{PID: 22, Tool: "opencode", CWD: "/b"}); err != nil {
		t.Fatalf("InsertLaunchSeed(bare shell): %v", err)
	}
	pending, err := s.PendingLaunchSeeds(ctx, time.Hour)
	if err != nil {
		t.Fatalf("PendingLaunchSeeds: %v", err)
	}
	byPID := map[int]processobs.LaunchSeed{}
	for _, p := range pending {
		byPID[p.PID] = p
	}
	if got := byPID[11].RunID; got != "run-A" {
		t.Errorf("pid 11 RunID = %q, want run-A", got)
	}
	if got := byPID[22].RunID; got != "" {
		t.Errorf("pid 22 RunID = %q, want \"\" — a launch with no run must not acquire one", got)
	}
}

// TestLaunchSeedRunSessions covers the boundary rules the pure matcher relies
// on and deliberately does NOT re-check: the confidence gate and one-session-
// per-run resolution.
func TestLaunchSeedRunSessions(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

	// run-strong: two correlations; the stronger one must win.
	mustCorrelate(t, s, TerminalCorrelation{RunID: "run-strong", SessionID: "sess-weak", Confidence: 0.55, Source: "marker", ObservedAt: at})
	mustCorrelate(t, s, TerminalCorrelation{RunID: "run-strong", SessionID: "sess-oob", Confidence: 0.95, Source: "oob", ObservedAt: at.Add(time.Minute)})
	// run-weak: only a below-gate heuristic correlation — must contribute nothing.
	mustCorrelate(t, s, TerminalCorrelation{RunID: "run-weak", SessionID: "sess-guess", Confidence: 0.40, Source: "heuristic", ObservedAt: at})

	got, err := s.LaunchSeedRunSessions(ctx, []string{"run-strong", "run-weak", "run-absent", ""}, 0.50)
	if err != nil {
		t.Fatalf("LaunchSeedRunSessions: %v", err)
	}
	if got["run-strong"] != "sess-oob" {
		t.Errorf("run-strong = %q, want sess-oob (strongest correlation wins)", got["run-strong"])
	}
	if _, ok := got["run-weak"]; ok {
		t.Errorf("run-weak = %q, want ABSENT: a below-gate guess must never become HIGH-confidence identity", got["run-weak"])
	}
	if _, ok := got["run-absent"]; ok {
		t.Error("run-absent must contribute nothing")
	}

	empty, err := s.LaunchSeedRunSessions(ctx, nil, 0.50)
	if err != nil || len(empty) != 0 {
		t.Fatalf("LaunchSeedRunSessions(nil) = (%v, %v), want empty and no error", empty, err)
	}
}

func mustCorrelate(t *testing.T, s *Store, c TerminalCorrelation) {
	t.Helper()
	if err := s.UpsertCorrelation(context.Background(), c); err != nil {
		t.Fatalf("UpsertCorrelation(%s→%s): %v", c.RunID, c.SessionID, err)
	}
}
