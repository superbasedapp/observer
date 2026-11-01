package store

import (
	"context"
	"testing"
	"time"
)

// TestEndTerminalRunGoneEndsOnce (live check 2026-10-22, D7): a run whose
// process is gone is ended with its reason exactly once, its exit code left
// unknown; a run already ended is untouched; a launcher that was in fact
// alive still records its exit code afterwards and the reason stays.
func TestEndTerminalRunGoneEndsOnce(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"run-gone", "run-done", "run-late"} {
		if err := s.InsertTerminalRun(ctx, TerminalRun{RunID: id, Tool: "claude-code", Kind: "fresh", LaunchedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.EndTerminalRun(ctx, "run-done", time.Now(), 0, EndReasonChildExit); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.EndTerminalRunGone(ctx, "run-gone", EndReasonProcessGone, time.Time{}); err != nil || !ok {
		t.Fatalf("first end: %v %v", ok, err)
	}
	if ok, err := s.EndTerminalRunGone(ctx, "run-gone", EndReasonProcessGone, time.Time{}); err != nil || ok {
		t.Fatalf("second end acted again: %v %v", ok, err)
	}
	if ok, err := s.EndTerminalRunGone(ctx, "run-done", EndReasonProcessGone, time.Time{}); err != nil || ok {
		t.Fatalf("an ended run was ended again: %v %v", ok, err)
	}
	if ok, err := s.EndTerminalRunGone(ctx, "", EndReasonProcessGone, time.Time{}); err != nil || ok {
		t.Fatalf("an empty id: %v %v", ok, err)
	}
	if ok, err := s.EndTerminalRunGone(ctx, "run-late", EndReasonProcessGone, time.Time{}); err != nil || !ok {
		t.Fatalf("run-late: %v %v", ok, err)
	}
	if err := s.EndTerminalRun(ctx, "run-late", time.Now(), 3, EndReasonChildExit); err != nil {
		t.Fatal(err)
	}
	runs, err := s.ListTerminalRuns(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range runs {
		switch r.RunID {
		case "run-gone":
			seen++
			if r.EndedAt == nil || r.ExitCode != nil || r.EndReason != EndReasonProcessGone {
				t.Errorf("run-gone: ended %v exit %v reason %q", r.EndedAt, r.ExitCode, r.EndReason)
			}
		case "run-done":
			seen++
			if r.EndReason != EndReasonChildExit || r.ExitCode == nil || *r.ExitCode != 0 {
				t.Errorf("run-done changed: exit %v reason %q", r.ExitCode, r.EndReason)
			}
		case "run-late":
			seen++
			if r.EndReason != EndReasonProcessGone || r.ExitCode == nil || *r.ExitCode != 3 {
				t.Errorf("run-late: exit %v reason %q", r.ExitCode, r.EndReason)
			}
		}
	}
	if seen != 3 {
		t.Fatalf("listed %d of 3 runs", seen)
	}
}
