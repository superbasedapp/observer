package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedExtra populates the DB with a richer mix to exercise the new tools.
func seedExtra(t *testing.T) (*Server, string) {
	t.Helper()
	s, database, _ := testServer(t)
	st := store.New(database)
	idx := indexing.New(database, 0)
	ctx := context.Background()
	root := t.TempDir()
	now := time.Now().UTC()

	events := []models.ToolEvent{
		// Session A: a couple of edits + a failing test + a passing test.
		{
			SourceFile: "a", SourceEventID: "a1", SessionID: "sess-A", ProjectRoot: root,
			Timestamp: now.Add(-30 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionEditFile, Target: "x.go", Success: true,
		},
		{
			SourceFile: "a", SourceEventID: "a2", SessionID: "sess-A", ProjectRoot: root,
			Timestamp: now.Add(-25 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "go test ./...",
			Success: false, ErrorMessage: "FAIL TestX expected 1 got 2",
			ToolOutput: "FAIL TestX want 1 got 2",
		},
		{
			SourceFile: "a", SourceEventID: "a3", SessionID: "sess-A", ProjectRoot: root,
			Timestamp: now.Add(-20 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionEditFile, Target: "x.go", Success: true,
		},
		{
			SourceFile: "a", SourceEventID: "a4", SessionID: "sess-A", ProjectRoot: root,
			Timestamp: now.Add(-15 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "go test ./...",
			Success: true, ToolOutput: "PASS",
		},
		// User prompt
		{
			SourceFile: "a", SourceEventID: "a5", SessionID: "sess-A", ProjectRoot: root,
			Timestamp: now.Add(-10 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionUserPrompt, Target: "fix the failing TestX",
			Success: true,
		},
		// A repeated read action — first marks a hot file, second is stale
		// because the indexer/freshness aren't running here. We'll write
		// freshness columns directly below.
		{
			SourceFile: "a", SourceEventID: "a6", SessionID: "sess-A", ProjectRoot: root,
			Timestamp: now.Add(-5 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "y.go", Success: true,
		},
	}
	if _, err := st.Ingest(ctx, events, nil, store.IngestOptions{
		RecordFailures: true, Indexer: idx,
	}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	// Mark a couple of read rows as stale + changed_by_self for the
	// redundancy_report path.
	if _, err := database.ExecContext(ctx,
		`UPDATE actions SET freshness = 'stale' WHERE source_event_id = 'a6'`); err != nil {
		t.Fatal(err)
	}
	// Insert one api_turns row so cost summary returns data.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
			input_tokens, output_tokens, cost_usd)
		 VALUES (?, (SELECT id FROM projects WHERE root_path = ?), ?, 'anthropic', 'claude-sonnet-4', 100, 50, 0.0123)`,
		"sess-A", root, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	return s, root
}

func TestTool_GetActionDetails(t *testing.T) {
	s, _ := seedExtra(t)
	parsed := callTool(t, s, "get_action_details", map[string]any{
		"action_ids": []int{1, 2},
	})
	if parsed["count"] == nil {
		t.Fatalf("missing count: %v", parsed)
	}
	if int(parsed["count"].(float64)) < 1 {
		t.Errorf("expected at least one row")
	}
}

func TestTool_GetFailureContext(t *testing.T) {
	s, _ := seedExtra(t)
	parsed := callTool(t, s, "get_failure_context", map[string]any{
		"command": "go test ./...",
	})
	if parsed["command_hash"] == "" {
		t.Errorf("command_hash empty")
	}
	failures := parsed["failures"].([]any)
	if len(failures) < 1 {
		t.Errorf("expected at least 1 failure: %v", parsed)
	}
	if int(failures[0].(map[string]any)["retry_count"].(float64)) != 0 {
		t.Errorf("first failure retry_count: %v", failures[0])
	}
}

func TestTool_GetLastTestResult(t *testing.T) {
	s, root := seedExtra(t)
	parsed := callTool(t, s, "get_last_test_result", map[string]any{
		"project_root": root,
	})
	if !parsed["found"].(bool) {
		t.Fatalf("expected found=true: %v", parsed)
	}
	// Most recent test was the PASSing one (a4).
	if !parsed["success"].(bool) {
		t.Errorf("expected success=true, latest is the PASS: %v", parsed)
	}
	if parsed["command"] != "go test ./..." {
		t.Errorf("command: %v", parsed["command"])
	}
}

func TestTool_GetCostSummary_ByModel(t *testing.T) {
	s, root := seedExtra(t)
	parsed := callTool(t, s, "get_cost_summary", map[string]any{
		"group_by":     "model",
		"days":         30,
		"project_root": root,
	})
	rows := parsed["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("rows: %d (want 1)", len(rows))
	}
	first := rows[0].(map[string]any)
	if first["key"] != "claude-sonnet-4" {
		t.Errorf("key: %v", first["key"])
	}
	if int(first["input_tokens"].(float64)) != 100 || int(first["output_tokens"].(float64)) != 50 {
		t.Errorf("tokens: %v", first)
	}
	if cost, _ := first["cost_usd"].(float64); cost <= 0 {
		t.Errorf("cost_usd: %v", first["cost_usd"])
	}
}

func TestTool_GetCostSummary_RejectsBadGroup(t *testing.T) {
	s, _ := seedExtra(t)
	resp := rpcCall(t, s, "tools/call", 1, map[string]any{
		"name":      "get_cost_summary",
		"arguments": map[string]any{"group_by": "invalid"},
	})
	result := resp["result"].(map[string]any)
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Errorf("expected isError for bad group_by")
	}
}

func TestTool_CheckCommandFreshness_NeverRun(t *testing.T) {
	s, _ := seedExtra(t)
	parsed := callTool(t, s, "check_command_freshness", map[string]any{
		"command": "echo nonexistent",
	})
	if !parsed["never_run"].(bool) {
		t.Errorf("expected never_run=true: %v", parsed)
	}
}

func TestTool_CheckCommandFreshness_HasHistory(t *testing.T) {
	s, root := seedExtra(t)
	parsed := callTool(t, s, "check_command_freshness", map[string]any{
		"command":      "go test ./...",
		"project_root": root,
	})
	if parsed["never_run"].(bool) {
		t.Errorf("expected never_run=false: %v", parsed)
	}
	if !parsed["last_success"].(bool) {
		t.Errorf("most recent run was the PASS — expected last_success=true: %v", parsed)
	}
}

func TestTool_GetSessionRecoveryContext(t *testing.T) {
	s, _ := seedExtra(t)
	parsed := callTool(t, s, "get_session_recovery_context", map[string]any{
		"session_id": "sess-A",
	})
	if parsed["session_id"] != "sess-A" {
		t.Errorf("session_id: %v", parsed["session_id"])
	}
	counts := parsed["counts"].(map[string]any)
	if int(counts["total_actions"].(float64)) != 6 {
		t.Errorf("total_actions: %v (want 6)", counts["total_actions"])
	}
	if int(counts["failures"].(float64)) != 1 {
		t.Errorf("failures: %v (want 1)", counts["failures"])
	}
	if parsed["last_user_prompt"] != "fix the failing TestX" {
		t.Errorf("last_user_prompt: %v", parsed["last_user_prompt"])
	}
	edited := parsed["recent_edited_files"].([]any)
	if len(edited) != 1 || edited[0] != "x.go" {
		t.Errorf("recent_edited_files: %v", edited)
	}
}

func TestTool_GetProjectPatterns(t *testing.T) {
	s, root := seedExtra(t)
	parsed := callTool(t, s, "get_project_patterns", map[string]any{
		"project_root": root,
	})
	hot := parsed["hot_files"].([]any)
	if len(hot) < 1 {
		t.Errorf("hot_files empty: %v", parsed)
	}
	commands := parsed["common_commands"].([]any)
	if len(commands) < 1 {
		t.Errorf("common_commands empty")
	}
	first := commands[0].(map[string]any)
	if first["key"] != "go test ./..." {
		t.Errorf("first command: %v", first)
	}
	if int(first["count"].(float64)) != 2 {
		t.Errorf("expected count=2 for go test: %v", first)
	}
}

func TestTool_GetProjectPatterns_UnknownProject(t *testing.T) {
	s, _ := seedExtra(t)
	parsed := callTool(t, s, "get_project_patterns", map[string]any{
		"project_root": "/never/heard",
	})
	if hot := parsed["hot_files"].([]any); len(hot) != 0 {
		t.Errorf("expected empty hot_files: %v", hot)
	}
}

func TestTool_GetRedundancyReport(t *testing.T) {
	s, root := seedExtra(t)
	parsed := callTool(t, s, "get_redundancy_report", map[string]any{
		"project_root": root,
	})
	if int(parsed["stale_reads"].(float64)) != 1 {
		t.Errorf("stale_reads: %v (want 1)", parsed["stale_reads"])
	}
	// The session ran "go test ./..." twice → repeated_commands = 1.
	if int(parsed["repeated_commands"].(float64)) != 1 {
		t.Errorf("repeated_commands: %v (want 1)", parsed["repeated_commands"])
	}
}

// Smoke test: tools/list now returns 21 tools (12 spec §11.2 + the
// G33 list_actions_around tool added in v1.4.43+ for three-layer
// progressive disclosure + get_suggestions, the advisor's in-session
// surface added with §15.7 Phase 3 + get_model_recommendation and
// get_routing_status, the model-routing P0 advisory pair per
// model-routing spec §R17.5 + cache_status, the cache-expiry warning
// surface — docs/plans/cache-expiry-warning-and-keepwarm-plan-2026-06-25.md
// + search_symbols, the codeintel Tier-C project-wide symbol search
// + get_output_composition, the Output Composition (Verbosity) session
// read tool — docs/plans/output-composition-verbosity-plan-2026-06-30.md
// + continue_session, the session-handoff MCP lane, and
// get_session_message, the message-addressable handoff pull —
// docs/session-handoff.md).
func TestServer_ToolsListReturnsTwentyTwo(t *testing.T) {
	// 22 always-on tools as of get_session_tasks (docs/task-tracking.md
	// "Phase 2") — was 21; conditional tools (get_file/get_symbols/
	// get_relations/retrieve_stashed) are separate and untouched.
	s, _, _ := testServer(t)
	resp := rpcCall(t, s, "tools/list", 1, nil)
	tools := resp["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 22 {
		t.Errorf("tools count: %d (want 22)", len(tools))
	}
}
