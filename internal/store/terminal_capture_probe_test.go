package store

import (
	"context"
	"testing"
	"time"
)

// TestProbeTerminalActivitySeesACaptureLowering (plans decision log P-040,
// lane sbx-p2d): lowering a live run's capture moves the org activity probe,
// so the run's wire row (capture_degraded and the resealed digest) re-ships
// on the next push, not at the hourly floor. A later lowering that only adds
// missed heartbeats moves it again, and so does one that only adds a cause
// (audit finding F3); a probe with nothing new does not move.
func TestProbeTerminalActivitySeesACaptureLowering(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	iso := TerminalRunIsolation{Class: "process", Stack: []string{"bwrap"}, CaptureLevel: "full", CaptureOrigin: "sandboxed", EvidenceDigest: "d0"}
	if err := s.InsertTerminalRun(ctx, TerminalRun{RunID: "run-p", Tool: "claude-code", Kind: "fresh", LaunchedAt: time.Now().UTC(), Isolation: iso}); err != nil {
		t.Fatal(err)
	}
	probe := func() string {
		t.Helper()
		p, err := s.probeTerminalActivity(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	reseal := func(string, TerminalRunIsolation) string { return "d1" }

	before := probe()
	if again := probe(); again != before {
		t.Fatalf("the probe moved with nothing new: %q then %q", before, again)
	}
	if _, err := s.LowerTerminalRunCapture(ctx, "run-p", TerminalRunCaptureHealth{Causes: "hooks_drifted"}, reseal); err != nil {
		t.Fatal(err)
	}
	lowered := probe()
	if lowered == before {
		t.Fatalf("a capture lowering did not move the probe: %q", lowered)
	}
	if _, err := s.LowerTerminalRunCapture(ctx, "run-p", TerminalRunCaptureHealth{Causes: "hooks_drifted", MissedHeartbeats: 2}, reseal); err != nil {
		t.Fatal(err)
	}
	if missed := probe(); missed == lowered {
		t.Fatalf("more missed heartbeats did not move the probe: %q", missed)
	}
	// A second cause on a run already lowered, with no new missed
	// heartbeat, moves it again (the causes are resealed into the digest,
	// a wire field).
	missed := probe()
	if _, err := s.LowerTerminalRunCapture(ctx, "run-p", TerminalRunCaptureHealth{Causes: "refused", MissedHeartbeats: 2}, reseal); err != nil {
		t.Fatal(err)
	}
	if caused := probe(); caused == missed {
		t.Fatalf("a second cause did not move the probe: %q", caused)
	}
	// The same lowering again changes nothing, so the probe holds.
	held := probe()
	if _, err := s.LowerTerminalRunCapture(ctx, "run-p", TerminalRunCaptureHealth{Causes: "hooks_drifted,refused", MissedHeartbeats: 2}, reseal); err != nil {
		t.Fatal(err)
	}
	if again := probe(); again != held {
		t.Fatalf("a repeated lowering moved the probe: %q then %q", held, again)
	}
}
