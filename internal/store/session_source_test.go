package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestSessionSourceReplayPreservesEvidence(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	project := t.TempDir()
	at := time.Date(2026, 9, 10, 1, 0, 0, 0, time.UTC)
	e := models.ToolEvent{SessionID: "parent", ProjectRoot: project, Tool: models.ToolClaudeCode, SourceFile: "/project/parent/subagents/agent-a.jsonl", SourceEventID: "call-a", MessageID: "msg-a", ActionType: models.ActionReadFile, IsSidechain: true, Timestamp: at, Success: false, ErrorMessage: "failed", ToolOutput: "captured output"}
	tk := models.TokenEvent{SessionID: e.SessionID, ProjectRoot: project, Tool: e.Tool, SourceFile: e.SourceFile, SourceEventID: "msg-a", MessageID: "msg-a", Source: models.TokenSourceJSONL, Timestamp: at, InputTokens: 2, OutputTokens: 20, CacheReadTokens: 100, EstimatedCostUSD: 0.25, IsSidechain: true}
	if _, err := s.Ingest(ctx, []models.ToolEvent{e}, []models.TokenEvent{tk}, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var oldID int64
	if err := database.QueryRow(`SELECT id FROM actions WHERE source_event_id='call-a'`).Scan(&oldID); err != nil {
		t.Fatal(err)
	}
	obs := models.ToolAccountObservation{SessionID: "parent", Tool: e.Tool, BindingKind: "tool_call", BindingID: "call-a", Role: "assistant", Email: "first@example.invalid", Source: "fixture", Scope: "profile", Stage: "activity", ObservedAt: at}
	if err := s.RecordToolAccounts(ctx, []models.ToolAccountObservation{obs}); err != nil {
		t.Fatal(err)
	}
	apiID, err := s.InsertAPITurn(ctx, models.APITurn{SessionID: "parent", RequestID: "msg-a", Provider: "anthropic", Model: "claude-sonnet-4-6", Timestamp: at, InputTokens: 2, OutputTokens: 20})
	if err != nil {
		t.Fatal(err)
	}
	e.SessionID, tk.SessionID = "parent:agent:a", "parent:agent:a"
	e.IsSidechain, tk.IsSidechain = false, false
	lin := models.SessionLineage{SessionID: e.SessionID, ParentThreadID: "parent", ForkedFromID: "parent", ThreadSource: "subagent", SourceFile: e.SourceFile, AgentID: "a"}
	for range 2 {
		if _, err := s.Ingest(ctx, []models.ToolEvent{e}, []models.TokenEvent{tk}, IngestOptions{SessionLineages: []models.SessionLineage{lin}}); err != nil {
			t.Fatal(err)
		}
	}
	var id int64
	var output, session string
	var side, success int
	if err := database.QueryRow(`SELECT id,session_id,raw_tool_output,is_sidechain,success FROM actions WHERE source_event_id='call-a'`).Scan(&id, &session, &output, &side, &success); err != nil {
		t.Fatal(err)
	}
	if id != oldID || session != e.SessionID || output != "captured output" || side != 0 || success != 0 {
		t.Fatalf("lost evidence: %d %s %s %d %d", id, session, output, side, success)
	}
	var count, input, read int
	var cost float64
	if err := database.QueryRow(`SELECT COUNT(*),SUM(input_tokens),SUM(cache_read_tokens),SUM(estimated_cost_usd) FROM token_usage`).Scan(&count, &input, &read, &cost); err != nil {
		t.Fatal(err)
	}
	if count != 1 || input != 2 || read != 100 || cost != 0.25 {
		t.Fatalf("duplicate usage: %d %d %d %f", count, input, read, cost)
	}
	var apiOwner string
	if err := database.QueryRow(`SELECT session_id FROM api_turns WHERE id=?`, apiID).Scan(&apiOwner); err != nil || apiOwner != e.SessionID {
		t.Fatalf("early proxy response remains on parent: %s %v", apiOwner, err)
	}
	owner, err := s.transcriptChildForRequest(ctx, "parent", "msg-a")
	if err != nil || owner != e.SessionID {
		t.Fatalf("late proxy attribution: %s %v", owner, err)
	}
	for _, r := range []string{"unknown", ""} {
		owner, err = s.transcriptChildForRequest(ctx, "parent", r)
		if err != nil || owner != "parent" {
			t.Fatalf("unmatched request moved: %s %v", owner, err)
		}
	}
	// Evidence from before and after the transfer must bind only by the
	// exact tool-call key. A current parent login is never a fallback.
	obs.Email = "second@example.invalid"
	if err := s.RecordToolAccounts(ctx, []models.ToolAccountObservation{obs}); err != nil {
		t.Fatal(err)
	}
	accounts, err := s.LoadMessageAccounts(ctx, e.SessionID, e.Tool)
	if err != nil || accounts["assistant:msg-a"].Status != "conflict" {
		t.Fatalf("lost accounts: %+v %v", accounts, err)
	}
	parentAccounts, err := s.LoadMessageAccounts(ctx, "parent", e.Tool)
	if err != nil || len(parentAccounts) != 0 {
		t.Fatalf("leaked child identity to parent: %+v %v", parentAccounts, err)
	}
	if err := s.UpsertClaudecodeEffort(ctx, "parent", "call-a", "high", "PostToolUse"); err != nil {
		t.Fatal(err)
	}
	var effort string
	if err := database.QueryRow(`SELECT json_extract(metadata,'$.effort_level') FROM actions WHERE id=?`, id).Scan(&effort); err != nil || effort != "high" {
		t.Fatalf("late effort: %s %v", effort, err)
	}
	children, err := s.ChildSubagentsForSession(ctx, "parent")
	if err != nil || len(children) != 1 || children[0].AgentID != "a" || children[0].ActionCount != 1 || children[0].ErrorCount != 1 || children[0].OutputTokens != 20 {
		t.Fatalf("child summary: %+v %v", children, err)
	}
}
