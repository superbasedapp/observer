package store

import (
	"testing"
	"time"
)

// TestTerminalRunInitiatorRoundTrip pins migration 220 (lane cli-2): the
// initiator and parent session a launch recorded come back from both read
// seams, and a row that recorded none reads "".
func TestTerminalRunInitiatorRoundTrip(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	rows := []TerminalRun{
		{RunID: "run-agent", Tool: "codex", Kind: "fresh", LaunchedAt: at, Initiator: "agent", ParentSessionID: "sess-parent"},
		{RunID: "run-cli", Tool: "claude-code", Kind: "fresh", LaunchedAt: at.Add(time.Minute), Initiator: "human_cli"},
		{RunID: "run-old", Tool: "claude-code", Kind: "fresh", LaunchedAt: at.Add(2 * time.Minute)},
	}
	for _, r := range rows {
		if err := st.InsertTerminalRun(ctx, r); err != nil {
			t.Fatalf("InsertTerminalRun(%s): %v", r.RunID, err)
		}
	}
	for _, want := range rows {
		got, ok, err := st.LoadTerminalRun(ctx, want.RunID)
		if err != nil || !ok {
			t.Fatalf("LoadTerminalRun(%s) = %v, %v", want.RunID, ok, err)
		}
		if got.Initiator != want.Initiator || got.ParentSessionID != want.ParentSessionID {
			t.Errorf("LoadTerminalRun(%s) origin = %q/%q, want %q/%q", want.RunID, got.Initiator, got.ParentSessionID, want.Initiator, want.ParentSessionID)
		}
	}
	list, err := st.ListTerminalRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListTerminalRuns: %v", err)
	}
	byID := map[string]TerminalRunSummary{}
	for _, s := range list {
		byID[s.RunID] = s
	}
	for _, want := range rows {
		got := byID[want.RunID]
		if got.Initiator != want.Initiator || got.ParentSessionID != want.ParentSessionID {
			t.Errorf("ListTerminalRuns %s origin = %q/%q, want %q/%q", want.RunID, got.Initiator, got.ParentSessionID, want.Initiator, want.ParentSessionID)
		}
	}
}
