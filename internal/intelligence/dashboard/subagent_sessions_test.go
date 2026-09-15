package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestSubagentSessionsMessagesAndConcurrentOwnership(t *testing.T) {
	srv, root := newTestServer(t)
	st := store.New(srv.db())
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	parent := models.ToolEvent{SessionID: "parent", ProjectRoot: root, SourceFile: "parent.jsonl", SourceEventID: "parent-msg", MessageID: "parent-msg", Tool: models.ToolClaudeCode, ActionType: models.ActionAssistantMessage, RawToolName: "claudecode.assistant_text", ToolOutput: "Main transcript", Timestamp: base, Success: true}
	batch := parent
	batch.SourceEventID, batch.MessageID, batch.ActionType, batch.Timestamp = "batch", "", models.ActionPostToolBatch, base.Add(time.Second)
	if _, err := st.Ingest(ctx, []models.ToolEvent{parent, batch}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	for i, agent := range []string{"alpha", "beta"} {
		e := parent
		e.SessionID = "parent:agent:" + agent
		e.SourceFile = agent + ".jsonl"
		e.SourceEventID, e.MessageID = "msg-"+agent, "msg-"+agent
		e.Metadata = &models.ActionMetadata{AgentID: agent, IsSubagent: true}
		e.ToolOutput = "Agent " + agent + " transcript"
		tk := models.TokenEvent{SessionID: e.SessionID, ProjectRoot: root, SourceFile: e.SourceFile, SourceEventID: e.MessageID, MessageID: e.MessageID, Tool: e.Tool, Model: "claude-sonnet-4-6", Timestamp: base, Source: models.TokenSourceJSONL, InputTokens: int64(10 + i), OutputTokens: int64(20 + i), CacheReadTokens: 100, CacheCreationTokens: 50}
		lin := models.SessionLineage{SessionID: e.SessionID, ParentThreadID: "parent", ForkedFromID: "parent", ThreadSource: "subagent"}
		start := parent
		start.SourceEventID, start.MessageID, start.ActionType = agent+":start", "", models.ActionSubagentStart
		start.Metadata = &models.ActionMetadata{AgentID: agent}
		start.Target = "Explore"
		if _, err := st.Ingest(ctx, []models.ToolEvent{e, start}, []models.TokenEvent{tk}, store.IngestOptions{SessionLineages: []models.SessionLineage{lin}}); err != nil {
			t.Fatal(err)
		}
	}
	stop := parent
	stop.SourceEventID, stop.MessageID, stop.ActionType, stop.Timestamp = "alpha:stop", "", models.ActionSubagentStop, base.Add(5*time.Second)
	stop.Metadata = &models.ActionMetadata{AgentID: "alpha"}
	stop.Target = "A final response is not an agent type"
	orphan := stop
	orphan.SourceEventID, orphan.Metadata = "orphan:stop", &models.ActionMetadata{AgentID: "orphan"}
	orphan.ToolOutput = "Captured final hook output"
	spawn := parent
	spawn.SourceEventID, spawn.MessageID, spawn.ActionType = "spawn", "", models.ActionSpawnSubagent
	if _, err := st.Ingest(ctx, []models.ToolEvent{stop, orphan, spawn}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	get := func(path string) []byte {
		t.Helper()
		r := httptest.NewRecorder()
		srv.Handler().ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != 200 {
			t.Fatalf("%s: %d %s", path, r.Code, r.Body.String())
		}
		return r.Body.Bytes()
	}
	var subs SessionSubagentsResponse
	if err := json.Unmarshal(get("/api/session/parent/subagents"), &subs); err != nil {
		t.Fatal(err)
	}
	if subs.Total != 3 {
		t.Fatalf("duplicate/missing runtimes: %+v", subs)
	}
	for _, r := range subs.Subagents {
		if r.ID == "orphan" {
			if !r.HookOnly || r.Open || r.SessionID != "" || r.Type != "" || r.Label != "orphan" || r.ActionCount != 0 || r.StopActionID == 0 {
				t.Fatalf("hook-only runtime mislabeled: %+v", r)
			}
			var body struct {
				Output string `json:"raw_tool_output"`
			}
			if err := json.Unmarshal(get(fmt.Sprintf("/api/action/%d/full_text", r.StopActionID)), &body); err != nil || body.Output != orphan.ToolOutput {
				t.Fatalf("hook output lost: %+v %v", body, err)
			}
			continue
		}
		if r.SessionID != "parent:agent:"+r.ID || r.Type != "Explore" || r.ActionCount != 1 || r.CacheReadTokens != 100 || r.CacheCreationTokens != 50 || r.Open != (r.ID == "beta") {
			t.Fatalf("mixed concurrent agents: %+v", r)
		}
	}
	for _, sid := range []string{"parent", "parent:agent:alpha", "parent:agent:beta"} {
		var payload struct {
			Messages []struct {
				MessageID string `json:"message_id"`
				Input     int64
				ToolCalls []struct {
					ActionType    string `json:"action_type"`
					HasFullOutput bool   `json:"has_full_output"`
				} `json:"tool_calls"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(get("/api/session/"+sid+"/messages"), &payload); err != nil {
			t.Fatal(err)
		}
		for _, m := range payload.Messages {
			for _, a := range m.ToolCalls {
				if a.ActionType == models.ActionPostToolBatch {
					t.Fatal("batch notification impersonates an assistant message")
				}
			}
			if sid == "parent" && (m.MessageID == "msg-alpha" || m.MessageID == "msg-beta") {
				t.Fatal("child transcript leaked into parent")
			}
		}
		if sid != "parent" && (len(payload.Messages) != 1 || payload.Messages[0].Input < 10 || !payload.Messages[0].ToolCalls[0].HasFullOutput) {
			t.Fatalf("child lost content/usage: %+v", payload)
		}
	}
	var batchCount int
	if err := srv.db().QueryRow(`SELECT COUNT(*) FROM actions WHERE action_type='post_tool_batch'`).Scan(&batchCount); err != nil || batchCount != 1 {
		t.Fatalf("raw hook evidence lost: %d %v", batchCount, err)
	}
}

func TestLifecycleOnlySubagentsPreservesInlineFallback(t *testing.T) {
	for _, tc := range []struct {
		name string
		refs []models.SubagentActionRef
		ok   bool
	}{
		{"empty", nil, true},
		{"inline activity", []models.SubagentActionRef{{ActionType: models.ActionReadFile, IsSidechain: true}}, false},
		{"anonymous spawn", []models.SubagentActionRef{{ActionType: models.ActionSpawnSubagent}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := lifecycleOnlySubagents(tc.refs)
			if ok != tc.ok {
				t.Fatalf("fallback decision = %v, want %v", ok, tc.ok)
			}
		})
	}
}
