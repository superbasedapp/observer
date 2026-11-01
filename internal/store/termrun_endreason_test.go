package store

import (
	"context"
	"testing"
	"time"
)

// TestStampTerminalRunEndReasonSurvivesTheExit (lane sbx-p2e, finding 5): the
// floor's end reason is stamped on a live run, the exit that follows keeps
// it, and a run already ended or already carrying a reason is left alone.
func TestStampTerminalRunEndReasonSurvivesTheExit(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"run-live", "run-ended", "run-shutdown"} {
		if err := s.InsertTerminalRun(ctx, TerminalRun{RunID: id, Tool: "claude-code", Kind: "fresh", LaunchedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.EndTerminalRun(ctx, "run-ended", time.Now(), 0, EndReasonChildExit); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StampLiveNonAttachRunsShutdown(ctx); err != nil {
		t.Fatal(err)
	}
	// run-live and run-shutdown were both stamped by the sweep above; insert
	// a fresh live run for the stamp itself.
	if err := s.InsertTerminalRun(ctx, TerminalRun{RunID: "run-floor", Tool: "claude-code", Kind: "fresh", LaunchedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.StampTerminalRunEndReason(ctx, "run-floor", EndReasonOrgFloorHooksDrifted); err != nil || !ok {
		t.Fatalf("stamp a live run: %v %v", ok, err)
	}
	if err := s.EndTerminalRun(ctx, "run-floor", time.Now(), -1, EndReasonChildExit); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"run-ended", "run-shutdown"} {
		if ok, err := s.StampTerminalRunEndReason(ctx, id, EndReasonOrgFloorHooksDrifted); err != nil || ok {
			t.Fatalf("%s: a run already ended or with a reason was stamped: %v %v", id, ok, err)
		}
	}
	runs, err := s.ListTerminalRuns(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"run-floor": EndReasonOrgFloorHooksDrifted, "run-ended": EndReasonChildExit, "run-shutdown": EndReasonDaemonShutdown}
	for _, r := range runs {
		if w, ok := want[r.RunID]; ok && r.EndReason != w {
			t.Errorf("%s: end reason %q, want %q", r.RunID, r.EndReason, w)
		}
	}
}
