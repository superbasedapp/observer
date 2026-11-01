package hook

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookliveness"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestFU127HandlersKeySessionsConsistently pins FU-127 for the three hosts
// the Mac round named, on their real payload shapes: every handler a host's
// events reach reads the same session id, and the transcript path and the
// project resolve where a handler reads them.
//
//   - Antigravity (agy CLI, App, IDE): camelCase conversationId,
//     transcriptPath, toolCall (round 4 rows 13, 14, 33); workspacePaths and
//     hookEventName as the agy docs and the existing fixtures spell them.
//     PreInvocation reads the prompt from the transcript the payload names;
//     PreToolUse keys on conversationId with workspacePaths as the root.
//   - ZCode: both sessionId and session_id (round 3 batch 1, round 4 row 6).
//     One rule when both are present: session_id wins (hookliveness
//     sessionKeys), as the prompt gate and the claude-json tool gate read.
//   - Devin: the Claude-style PreToolUse keys on session_id, the Cascade
//     pre_* events on trajectory_id (their only id key).
//
// The activity record (hookliveness.PayloadSessionID, which the failure and
// unclassified records share) must name the same id as the gate.
func TestFU127HandlersKeySessionsConsistently(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, "brain", "agy-c1", ".system_generated", "logs", "transcript_full.jsonl")
	if err := os.MkdirAll(filepath.Dir(transcript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transcript, []byte(`{"type":"USER_INPUT","source":"USER_EXPLICIT","content":"<USER_REQUEST>\nRun the shell command echo mac-tool-deny\n</USER_REQUEST>"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	type gate struct {
		tool, dialect, event string
	}
	for _, tc := range []struct {
		name        string
		body        string
		prompt      string // prompt dialect ("" for a tool-gate event)
		wantPrompt  string // prompt text the prompt dialect resolves
		gate        gate   // tool-gate dialect ("" for a prompt event)
		wantSession string
		wantCwd     string
		wantRoot    string
	}{
		{
			name:   "antigravity PreInvocation",
			body:   `{"conversationId":"agy-c1","transcriptPath":"` + transcript + `","invocationNum":0,"hookEventName":"PreInvocation"}`,
			prompt: PromptDialectAntigravityPreInvocation, wantPrompt: "Run the shell command echo mac-tool-deny",
			wantSession: "agy-c1",
		},
		{
			name:        "antigravity PreToolUse",
			body:        `{"conversationId":"agy-c1","workspacePaths":["/Users/lume/superbasedtest"],"transcriptPath":"` + transcript + `","hookEventName":"PreToolUse","toolCall":{"name":"run_command","args":{"CommandLine":"echo mac-tool-deny"}}}`,
			gate:        gate{models.ToolAntigravityCLI, ToolGateDialectAntigravity, "PreToolUse"},
			wantSession: "agy-c1", wantRoot: "/Users/lume/superbasedtest",
		},
		{
			name:   "zcode UserPromptSubmit, both spellings",
			body:   `{"session_id":"z1","sessionId":"z1","hook_event_name":"UserPromptSubmit","cwd":"/Users/lume/superbasedtest","prompt":"Run the shell command echo mac-tool-deny"}`,
			prompt: PromptDialectZcode, wantPrompt: "Run the shell command echo mac-tool-deny",
			wantSession: "z1",
		},
		{
			name:        "zcode PreToolUse, both spellings",
			body:        `{"sessionId":"z1","session_id":"z1","hook_event_name":"PreToolUse","cwd":"/Users/lume/superbasedtest","tool_name":"Bash","tool_input":{"command":"echo mac-tool-deny"}}`,
			gate:        gate{models.ToolZcode, ToolGateDialectClaudeJSON, "PreToolUse"},
			wantSession: "z1", wantCwd: "/Users/lume/superbasedtest",
		},
		{
			// Should the two spellings ever differ, every handler picks
			// session_id, whatever the document order.
			name:        "zcode PreToolUse, spellings disagree",
			body:        `{"sessionId":"camel","session_id":"snake","hook_event_name":"PreToolUse","cwd":"/r","tool_name":"Bash","tool_input":{"command":"echo hi"}}`,
			gate:        gate{models.ToolZcode, ToolGateDialectClaudeJSON, "PreToolUse"},
			wantSession: "snake", wantCwd: "/r",
		},
		{
			name:   "zcode UserPromptSubmit, spellings disagree",
			body:   `{"sessionId":"camel","session_id":"snake","prompt":"hi"}`,
			prompt: PromptDialectZcode, wantPrompt: "hi",
			wantSession: "snake",
		},
		{
			name:        "devin PreToolUse (Claude-style)",
			body:        `{"hook_event_name":"PreToolUse","session_id":"devin-s1","prompt_id":"p1","cwd":"/Users/lume/superbasedtest","tool_name":"exec","tool_input":{"command":"echo mac-tool-deny"}}`,
			gate:        gate{models.ToolDevin, ToolGateDialectClaudeJSON, "PreToolUse"},
			wantSession: "devin-s1", wantCwd: "/Users/lume/superbasedtest",
		},
		{
			name:        "devin pre_run_command (Cascade)",
			body:        `{"agent_action_name":"pre_run_command","trajectory_id":"traj-1","execution_id":"e1","timestamp":"2026-10-28T10:30:00Z","tool_info":{"command_line":"echo mac-tool-deny","cwd":"/Users/lume/superbasedtest"}}`,
			gate:        gate{models.ToolDevin, ToolGateDialectCascade, "pre_run_command"},
			wantSession: "traj-1", wantCwd: "/Users/lume/superbasedtest",
		},
		{
			name:   "devin pre_user_prompt (Cascade)",
			body:   `{"agent_action_name":"pre_user_prompt","trajectory_id":"traj-1","execution_id":"e0","tool_info":{"user_prompt":"Run the shell command echo mac-tool-deny"}}`,
			prompt: PromptDialectCascade, wantPrompt: "Run the shell command echo mac-tool-deny",
			wantSession: "traj-1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hookliveness.PayloadSessionID([]byte(tc.body)); got != tc.wantSession {
				t.Errorf("activity session %q, want %q", got, tc.wantSession)
			}
			if tc.prompt != "" {
				d, ok := promptDialects[tc.prompt]
				if !ok {
					t.Fatalf("no prompt dialect %q", tc.prompt)
				}
				prompt, sid, ok, _ := d.extract([]byte(tc.body))
				if !ok || sid != tc.wantSession || prompt != tc.wantPrompt {
					t.Errorf("prompt gate: prompt %q session %q ok=%v, want %q / %q", prompt, sid, ok, tc.wantPrompt, tc.wantSession)
				}
				return
			}
			evs, ok := ToolGateEvents(tc.gate.tool, tc.gate.dialect, tc.gate.event, []byte(tc.body))
			if !ok || len(evs) != 1 {
				t.Fatalf("tool gate: %d events ok=%v, want one judged event", len(evs), ok)
			}
			e := evs[0]
			if e.SessionID != tc.wantSession || e.Cwd != tc.wantCwd || e.ProjectRoot != tc.wantRoot {
				t.Errorf("tool gate: session %q cwd %q root %q, want %q / %q / %q", e.SessionID, e.Cwd, e.ProjectRoot, tc.wantSession, tc.wantCwd, tc.wantRoot)
			}
		})
	}
}
