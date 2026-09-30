package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestCursorUsageEvidence ingests the node-1 row shape (hook prompt +
// session lifecycle, and the debug-log evidence rows for one turn that never
// finished after three failed attempts) and checks the loaded evidence.
func TestCursorUsageEvidence(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	const sid = "c0c0c001-0000-4000-8000-000000000001"
	at := time.Date(2026, 9, 27, 11, 13, 23, 0, time.UTC)
	ev := func(id, src string, action, raw, errMsg string) models.ToolEvent {
		return models.ToolEvent{
			SessionID: sid, ProjectRoot: root, Timestamp: at, Tool: models.ToolCursor, SourceFile: src, SourceEventID: id,
			ActionType: action, RawToolName: raw, ErrorMessage: errMsg, Success: errMsg == "", Model: "default",
		}
	}
	events := []models.ToolEvent{
		ev(sid+":sessionStart", "cursor:hook", models.ActionSessionStart, "sessionStart", ""),
		ev("g1:beforeSubmitPrompt", "cursor:hook", models.ActionUserPrompt, "beforeSubmitPrompt", ""),
		ev(cursorusage.SourceEventAttemptPrefix+"a1", "cli.log", models.ActionAPIError, "LostConnection", "attempt 0 failed"),
		ev(cursorusage.SourceEventAttemptPrefix+"a2", "cli.log", models.ActionAPIError, "LostConnection", "attempt 1 failed"),
		ev(cursorusage.SourceEventTurnPrefix+"t1:unfinished", "cli.log", models.ActionTurnAborted, cursorusage.RawToolTurnUnfinished, "the session ended while Cursor was still retrying"),
	}
	if _, err := st.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := st.CursorUsageEvidence(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	want := cursorusage.Evidence{Prompts: 1, UnfinishedTurns: 1, FailedAttempts: 2, LatestTurnDetail: "the session ended while Cursor was still retrying"}
	if got != want {
		t.Fatalf("evidence = %+v, want %+v", got, want)
	}
	if cursorusage.Classify(got) != cursorusage.ReasonUnfinishedTurn {
		t.Fatalf("classified %s", cursorusage.Classify(got))
	}
	empty, err := st.CursorUsageEvidence(ctx, "no-such-session")
	if err != nil || empty != (cursorusage.Evidence{}) {
		t.Fatalf("unknown session: %+v %v", empty, err)
	}
}

// TestCursorUsageEvidence_ResponseHookRows pins the afterAgentResponse
// count to the row shape the cursor hook actually writes (assistant_message,
// raw_tool_name cursor.assistant_response, source_event_id
// <generation>:afterAgentResponse). Before the fold moved onto
// source_event_id the count matched raw_tool_name = 'afterAgentResponse',
// which no writer produces, so it was always 0.
func TestCursorUsageEvidence_ResponseHookRows(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	const sid = "c0c0c001-0000-4000-8000-000000000002"
	at := time.Date(2026, 9, 27, 11, 13, 23, 0, time.UTC)
	events := []models.ToolEvent{
		{SessionID: sid, ProjectRoot: root, Timestamp: at, Tool: models.ToolCursor, SourceFile: "cursor:hook", SourceEventID: "g1:beforeSubmitPrompt", ActionType: models.ActionUserPrompt, RawToolName: "beforeSubmitPrompt", Success: true},
		{SessionID: sid, ProjectRoot: root, Timestamp: at.Add(time.Second), Tool: models.ToolCursor, SourceFile: "cursor:hook", SourceEventID: "g1:afterAgentResponse", ActionType: models.ActionAssistantMessage, RawToolName: "cursor.assistant_response", Target: "done", Success: true},
	}
	if _, err := st.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := st.CursorUsageEvidence(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if got != (cursorusage.Evidence{Prompts: 1, ResponseHooks: 1}) {
		t.Fatalf("evidence = %+v", got)
	}
	if cursorusage.Classify(got) != cursorusage.ReasonResponseWithoutUsage {
		t.Fatalf("classified %s", cursorusage.Classify(got))
	}
}

// TestUpsertSession_PlaceholderModelNeverDowngrades pins the Auto-mode
// rule: "default"/"auto" fills an empty model and is replaced by a concrete
// one, but never overwrites a concrete model already recorded.
func TestUpsertSession_PlaceholderModelNeverDowngrades(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	for i, step := range []struct{ write, want string }{
		{"default", "default"},
		{"", "default"},
		{"cursor-grok-4.5-high", "cursor-grok-4.5-high"},
		{"default", "cursor-grok-4.5-high"},
		{"AUTO", "cursor-grok-4.5-high"},
		{"composer-2.5", "composer-2.5"},
	} {
		if err := s.UpsertSession(ctx, models.Session{ID: "auto-sess", ProjectID: pid, Tool: models.ToolCursor, Model: step.write, StartedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := db.QueryRow(`SELECT COALESCE(model, '') FROM sessions WHERE id = 'auto-sess'`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != step.want {
			t.Fatalf("step %d write %q: model = %q, want %q", i, step.write, got, step.want)
		}
	}
}
