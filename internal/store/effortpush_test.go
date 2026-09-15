package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// W3.6 (org-parity): ActionRow.effort_level is extracted at push time from the
// node's actions.metadata JSON and ships in every tier (content-free closed
// vocabulary); an action with no effort signal ships an empty value.
func TestSelectUnpushedSince_EffortLevelExtracted(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s-eff", ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	if _, err := s.InsertActions(ctx, []models.Action{
		{
			SessionID: "s-eff", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "eff-1",
			Metadata: &models.ActionMetadata{EffortLevel: "high"},
		},
		{
			SessionID: "s-eff", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "go test", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "eff-2",
		},
	}); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}

	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.Actions) != 2 {
		t.Fatalf("actions = %d, want 2", len(batch.Actions))
	}
	byEvent := map[string]string{}
	for _, a := range batch.Actions {
		byEvent[a.SourceEventID] = a.EffortLevel
	}
	if byEvent["eff-1"] != "high" {
		t.Errorf("eff-1 effort_level = %q, want high (extracted from metadata JSON)", byEvent["eff-1"])
	}
	if byEvent["eff-2"] != "" {
		t.Errorf("eff-2 effort_level = %q, want empty (no effort signal captured)", byEvent["eff-2"])
	}
}

// W-A (org session-detail parity): ActionRow.stop_reason is extracted at push
// time from the node's actions.metadata JSON ($.stop_reason) exactly like
// effort_level, so JSONL (non-proxied) turns carry a stop reason on the wire;
// an action with no stop_reason captured ships an empty value.
func TestSelectUnpushedSince_StopReasonExtracted(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s-stop", ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	if _, err := s.InsertActions(ctx, []models.Action{
		{
			SessionID: "s-stop", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "stop-1",
			Metadata: &models.ActionMetadata{StopReason: "end_turn"},
		},
		{
			SessionID: "s-stop", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "go test", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "stop-2",
		},
	}); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}

	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	byEvent := map[string]string{}
	for _, a := range batch.Actions {
		byEvent[a.SourceEventID] = a.StopReason
	}
	if byEvent["stop-1"] != "end_turn" {
		t.Errorf("stop-1 stop_reason = %q, want end_turn (extracted from metadata JSON)", byEvent["stop-1"])
	}
	if byEvent["stop-2"] != "" {
		t.Errorf("stop-2 stop_reason = %q, want empty (no stop reason captured)", byEvent["stop-2"])
	}
}

// W-A (org session-detail parity): ActionRow.message_id and
// TokenUsageRow.message_id ship the node's actions.message_id /
// token_usage.message_id so the org message-metrics rollup can bucket tool
// calls and token/cost columns by message instead of by the per-adapter
// source_event_id. Content-free; empty when the node recorded none.
func TestSelectUnpushedSince_MessageIDShipsOnActionsAndTokenUsage(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s-mid", ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	if _, err := s.Ingest(ctx,
		[]models.ToolEvent{
			{
				SourceFile: "m.jsonl", SourceEventID: "act-mid", SessionID: "s-mid",
				ProjectRoot: "/tmp/proj", Timestamp: time.Now().UTC(), Tool: models.ToolClaudeCode,
				ActionType: models.ActionReadFile, Target: "a.go", Success: true,
				MessageID: "msg_wire_1",
			},
		},
		[]models.TokenEvent{
			{
				SourceFile: "m.jsonl", SourceEventID: "tok-mid", SessionID: "s-mid",
				ProjectRoot: "/tmp/proj", Timestamp: time.Now().UTC(), Tool: models.ToolClaudeCode,
				Model: "claude", InputTokens: 100, OutputTokens: 50, MessageID: "msg_wire_1",
				Source: "jsonl", Reliability: "unreliable",
			},
		},
		IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}

	var actMsg string
	for _, a := range batch.Actions {
		if a.SourceEventID == "act-mid" {
			actMsg = a.MessageID
		}
	}
	if actMsg != "msg_wire_1" {
		t.Errorf("action message_id = %q, want msg_wire_1", actMsg)
	}

	var tuMsg string
	for _, u := range batch.TokenUsage {
		if u.SourceEventID == "tok-mid" {
			tuMsg = u.MessageID
		}
	}
	if tuMsg != "msg_wire_1" {
		t.Errorf("token_usage message_id = %q, want msg_wire_1", tuMsg)
	}
}
