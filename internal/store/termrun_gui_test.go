package store

import (
	"testing"
	"time"
)

// TestTerminalRunGUIColumnsRoundTrip pins migration 108: the three GUI-launch
// facts (pid / wrap_applied / wrap_note) survive both write paths — the insert
// (a caller that already knows them) and the post-spawn stamp (the GUI launch
// path, which learns the pid only after the child exists).
func TestTerminalRunGUIColumnsRoundTrip(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)

	launched := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	if err := st.InsertTerminalRun(ctx, TerminalRun{
		RunID:      "run-gui",
		Tool:       "vscode",
		Kind:       "gui",
		LaunchedAt: launched,
	}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}

	// Pre-stamp: the honest zero — no pid, no wrap claim.
	got, ok, err := st.LoadTerminalRun(ctx, "run-gui")
	if err != nil || !ok {
		t.Fatalf("LoadTerminalRun ok=%v err=%v", ok, err)
	}
	if got.PID != nil || got.WrapApplied || got.WrapNote != "" {
		t.Errorf("pre-spawn row must carry no pid/wrap facts, got %+v", got)
	}

	if err := st.StampTerminalRunSpawn(ctx, "run-gui", 4321, true, "cold-start only"); err != nil {
		t.Fatalf("StampTerminalRunSpawn: %v", err)
	}
	got, ok, err = st.LoadTerminalRun(ctx, "run-gui")
	if err != nil || !ok {
		t.Fatalf("LoadTerminalRun ok=%v err=%v", ok, err)
	}
	if got.PID == nil || *got.PID != 4321 {
		t.Errorf("pid = %v, want 4321", got.PID)
	}
	if !got.WrapApplied || got.WrapNote != "cold-start only" {
		t.Errorf("wrap = (%v, %q), want (true, %q)", got.WrapApplied, got.WrapNote, "cold-start only")
	}

	// The insert path carries the same three facts for a caller that knows them.
	pid := 99
	if err := st.InsertTerminalRun(ctx, TerminalRun{
		RunID: "run-gui-2", Tool: "cursor-ide", Kind: "gui", LaunchedAt: launched,
		PID: &pid, WrapApplied: false, WrapNote: "native backend is hard-wired",
	}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}
	got, _, err = st.LoadTerminalRun(ctx, "run-gui-2")
	if err != nil {
		t.Fatalf("LoadTerminalRun: %v", err)
	}
	if got.PID == nil || *got.PID != 99 || got.WrapApplied || got.WrapNote != "native backend is hard-wired" {
		t.Errorf("insert-path row = %+v", got)
	}
}

// TestTerminalRunNonGUIKindsCarryNoPID pins the honest zero for every existing
// kind: a PTY run's identity is its handle, so its row must keep pid NULL and
// wrap_applied false — the new columns add no claim to the runs that predate
// them.
func TestTerminalRunNonGUIKindsCarryNoPID(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	for _, kind := range []string{"fresh", "handoff", "attach", "resume", "ssh"} {
		if err := st.InsertTerminalRun(ctx, TerminalRun{RunID: "r-" + kind, Tool: "claude-code", Kind: kind}); err != nil {
			t.Fatalf("InsertTerminalRun(%s): %v", kind, err)
		}
		got, ok, err := st.LoadTerminalRun(ctx, "r-"+kind)
		if err != nil || !ok {
			t.Fatalf("LoadTerminalRun(%s) ok=%v err=%v", kind, ok, err)
		}
		if got.PID != nil || got.WrapApplied || got.WrapNote != "" {
			t.Errorf("kind %s carried GUI facts: %+v", kind, got)
		}
	}
}

// TestStampTerminalRunSpawnRefusesNonPositivePID pins the honesty guard: a
// bogus pid is refused rather than stored, so the NULL the insert wrote stays
// the truthful answer.
func TestStampTerminalRunSpawnRefusesNonPositivePID(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	if err := st.InsertTerminalRun(ctx, TerminalRun{RunID: "r", Tool: "vscode", Kind: "gui"}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}
	if err := st.StampTerminalRunSpawn(ctx, "r", 0, true, "x"); err == nil {
		t.Fatal("StampTerminalRunSpawn(pid=0) = nil, want an error")
	}
	got, _, err := st.LoadTerminalRun(ctx, "r")
	if err != nil {
		t.Fatalf("LoadTerminalRun: %v", err)
	}
	if got.PID != nil || got.WrapApplied {
		t.Errorf("refused stamp must leave the row untouched, got %+v", got)
	}
}
