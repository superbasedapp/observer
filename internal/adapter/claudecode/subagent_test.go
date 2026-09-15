package claudecode

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestSubagentTranscriptSessions(t *testing.T) {
	for _, tc := range []struct {
		name, fileAgent, lineAgent string
		child                      bool
	}{
		{"native", "a123", "a123", true},
		{"legacy without field", "a123", "", true},
		{"conflicting identity", "a123", "a456", false},
		{"compaction snapshot", "acompact-123", "acompact-123", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "project", "parent", "subagents", "agent-"+tc.fileAgent+".jsonl")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			lines := []string{
				fmt.Sprintf(`{"type":"user","uuid":"u1","sessionId":"parent","agentId":%q,"isSidechain":true,"entrypoint":"cli","cwd":"/project","timestamp":"2026-09-10T01:00:00Z","message":{"role":"user","content":"Inspect the module"}}`, tc.lineAgent),
				fmt.Sprintf(`{"type":"assistant","uuid":"a1","sessionId":"parent","agentId":%q,"isSidechain":true,"entrypoint":"cli","cwd":"/project","timestamp":"2026-09-10T01:00:01Z","message":{"id":"msg-1","role":"assistant","model":"claude-sonnet-4-6","usage":{"input_tokens":2,"output_tokens":20,"cache_read_input_tokens":100},"content":[{"type":"text","text":"Inspecting"},{"type":"tool_use","id":"call-1","name":"Read","input":{"file_path":"/project/a.go"}}]}}`, tc.lineAgent),
			}
			body := strings.Join(lines, "\n") + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			a := NewWithOptions(nil, root)
			res, err := a.ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatal(err)
			}
			want := "parent"
			if tc.child {
				want = subagentSessionID("parent", tc.fileAgent)
			}
			if len(res.ToolEvents) != 3 || len(res.TokenEvents) != 1 {
				t.Fatalf("missing transcript: %+v", res)
			}
			for _, e := range res.ToolEvents {
				if e.SessionID != want || e.IsSidechain == tc.child {
					t.Fatalf("bad action ownership: %+v", e)
				}
			}
			if res.TokenEvents[0].SessionID != want || res.TokenEvents[0].IsSidechain == tc.child {
				t.Fatalf("bad usage ownership: %+v", res.TokenEvents)
			}
			if !tc.child {
				if len(res.SessionLineages) != 0 {
					t.Fatal("unsafe lineage")
				}
				return
			}
			if len(res.SessionLineages) != 1 || res.SessionLineages[0].SourceFile != path || res.SessionSurfaces[0].SessionID != want || res.CacheObservations[0].SessionID != want {
				t.Fatalf("sidecars: %+v", res)
			}
			messages, err := a.ReadTranscriptFull(context.Background(), models.Session{ID: want}, nil)
			if err != nil || len(messages) != 2 {
				t.Fatalf("child transcript hidden: %+v %v", messages, err)
			}
			// The tool result arrives in a later polling chunk and still updates
			// the original source key, independent of normalized session identity.
			result := fmt.Sprintf(`{"type":"user","uuid":"r1","sessionId":"parent","agentId":%q,"isSidechain":true,"cwd":"/project","timestamp":"2026-09-10T01:00:02Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-1","content":"result body"}]}}`+"\n", tc.lineAgent)
			if err := os.WriteFile(path, []byte(body+result), 0o600); err != nil {
				t.Fatal(err)
			}
			chunk, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
			if err != nil || len(chunk.OutcomeUpdates) != 1 || chunk.OutcomeUpdates[0].SourceEventID != "call-1" || chunk.OutcomeUpdates[0].ToolOutput != "result body" {
				t.Fatalf("late result: %+v %v", chunk, err)
			}
		})
	}
}
