package store

import (
	"context"
	"testing"
	"time"
)

// TestTerminalRunIsolationRoundTrip: the G19 evidence written at launch
// (migration 179) reaches the org wire row unchanged, and a run that
// recorded nothing reads back empty, never a default.
func TestTerminalRunIsolationRoundTrip(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	iso := TerminalRunIsolation{
		Class: "process", Stack: []string{"bwrap"}, EgressTier: "internet",
		CaptureLevel: "full", CaptureRule: "C6", CaptureOrigin: "sandboxed", CaptureDegraded: true,
		NativeSandboxState: "not_applicable", Verification: "live", KeyCustody: "host_bound",
		EvidenceDigest: "aa",
	}
	if err := s.InsertTerminalRun(ctx, TerminalRun{RunID: "run-sbx", Tool: "claude-code", Kind: "fresh", LaunchedAt: now, Isolation: iso}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertTerminalRun(ctx, TerminalRun{RunID: "run-old", Tool: "codex", Kind: "fresh", LaunchedAt: now.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.SelectTerminalRunRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows", len(rows))
	}
	r := rows[0]
	if r.RunID != "run-sbx" || r.IsolationClass != "process" || r.Stack != "bwrap" || r.EgressTier != "internet" ||
		r.CaptureLevel != "full" || r.CaptureRule != "C6" || r.CaptureOrigin != "sandboxed" || !r.CaptureDegraded ||
		r.NativeSandboxState != "not_applicable" || r.Verification != "live" || r.KeyCustody != "host_bound" || r.EvidenceDigest != "aa" {
		t.Fatalf("sandboxed row %+v", r)
	}
	o := rows[1]
	if o.IsolationClass != "" || o.CaptureLevel != "" || o.CaptureDegraded || o.EvidenceDigest != "" {
		t.Fatalf("a run that recorded nothing reads back %+v", o)
	}
}

// TestLowerTerminalRunCapture (P-032, migration 186): a lowering sets
// capture_degraded, adds causes once, only raises the missed-heartbeat
// count, reseals the digest through the injected seam (and only for a run
// that recorded evidence), and never undoes itself.
func TestLowerTerminalRunCapture(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	iso := TerminalRunIsolation{
		Class: "process", Stack: []string{"bwrap"}, CaptureLevel: "full", CaptureOrigin: "sandboxed", EvidenceDigest: "before",
		EvidenceProducer: "terminal_run", EvidenceComponent: "terminals.sandbox", EvidenceComponentVersion: "v1",
	}
	if err := s.InsertTerminalRun(ctx, TerminalRun{RunID: "run-l", Tool: "claude-code", Kind: "fresh", Isolation: iso}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertTerminalRun(ctx, TerminalRun{RunID: "run-bare", Tool: "codex", Kind: "fresh"}); err != nil {
		t.Fatal(err)
	}
	var sealed []TerminalRunIsolation
	reseal := func(id string, got TerminalRunIsolation) string {
		sealed = append(sealed, got)
		return "after-" + id
	}
	if ok, err := s.LowerTerminalRunCapture(ctx, "run-l", TerminalRunCaptureHealth{Causes: "refused,dropped", MissedHeartbeats: 3}, reseal); err != nil || !ok {
		t.Fatalf("lower: %v %v", ok, err)
	}
	if ok, err := s.LowerTerminalRunCapture(ctx, "run-l", TerminalRunCaptureHealth{Causes: "dropped,hooks_drifted", MissedHeartbeats: 1}, reseal); err != nil || !ok {
		t.Fatalf("lower again: %v %v", ok, err)
	}
	h, ok, err := s.LoadTerminalRunCaptureHealth(ctx, "run-l")
	if err != nil || !ok || h.Causes != "refused,dropped,hooks_drifted" || h.MissedHeartbeats != 3 {
		t.Fatalf("health %+v %v %v", h, ok, err)
	}
	if len(sealed) != 2 || !sealed[0].CaptureDegraded || sealed[0].EvidenceComponent != "terminals.sandbox" || sealed[0].Stack[0] != "bwrap" {
		t.Fatalf("resealed over %+v", sealed)
	}
	rows, err := s.SelectTerminalRunRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.RunID == "run-l" && (!r.CaptureDegraded || r.EvidenceDigest != "after-run-l") {
			t.Fatalf("lowered row %+v", r)
		}
	}
	// A run with no evidence is lowered without inventing a digest.
	if _, err := s.LowerTerminalRunCapture(ctx, "run-bare", TerminalRunCaptureHealth{Causes: "replayed"}, reseal); err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 2 {
		t.Fatal("a run with no evidence was resealed")
	}
	if ok, err := s.LowerTerminalRunCapture(ctx, "no-such-run", TerminalRunCaptureHealth{Causes: "refused"}, reseal); ok || err != nil {
		t.Fatalf("an unknown run: %v %v", ok, err)
	}
}
