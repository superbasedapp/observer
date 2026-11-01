package main

import (
	"io"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hookspool"
)

// agyAppTranscript / agyIDETranscript / agyCLITranscript are the
// transcriptPath values the vendor's app_data_dir table gives each surface
// (antigravity.google/docs/hooks?tab=ide).
const (
	agyAppTranscript = `/home/u/.gemini/antigravity/brain/c1/.system_generated/logs/transcript.jsonl`
	agyIDETranscript = `C:\\Users\\u\\.gemini\\antigravity-ide\\brain\\c2\\.system_generated\\logs\\transcript.jsonl`
	agyCLITranscript = `/home/u/.gemini/antigravity-cli/brain/c3/.system_generated/logs/transcript_full.jsonl`
)

// TestHookSurfaceBinding: one case per registered binding the Antigravity
// App and IDE share (the agy tool gate and the PreInvocation prompt gate),
// for each surface, plus the CLI's own payload and a tool no surface row
// names (surface-gap W-2c). A surface hit is served with the antigravity
// row's own wired binding in the same dialect, and its activity record
// carries antigravity.
func TestHookSurfaceBinding(t *testing.T) {
	for _, tc := range []struct {
		name       string
		tool       string
		event      string
		transcript string
		want       string
		wantOK     bool
	}{
		{"app tool gate", "antigravity-cli", "PreToolUse", agyAppTranscript, "antigravity", true},
		{"ide tool gate", "antigravity-cli", "PreToolUse", agyIDETranscript, "antigravity", true},
		{"app prompt gate", "antigravity-cli", "PreInvocation", agyAppTranscript, "antigravity", true},
		{"ide prompt gate", "antigravity-cli", "PreInvocation", agyIDETranscript, "antigravity", true},
		{"cli own tool gate", "antigravity-cli", "PreToolUse", agyCLITranscript, "antigravity-cli", false},
		{"cli own prompt gate", "antigravity-cli", "PreInvocation", agyCLITranscript, "antigravity-cli", false},
		{"no surface row for the tool", "gemini-cli", "BeforeTool", agyAppTranscript, "gemini-cli", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetHookActivity()
			t.Cleanup(resetHookActivity)
			b, ok := resolveHookBinding(tc.tool, tc.event)
			if !ok {
				t.Fatalf("no %s binding for %s", tc.tool, tc.event)
			}
			body := []byte(`{"conversationId":"c","transcriptPath":"` + tc.transcript + `","toolCall":{"name":"run_command","args":{"CommandLine":"ls"}}}`)
			got, sb, ok := hookSurfaceBinding(tc.tool, b, body)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("hookSurfaceBinding = %q,%v want %q,%v", got, ok, tc.want, tc.wantOK)
			}
			if !ok {
				if sb.NativeEvent != b.NativeEvent || sb.Dialect != b.Dialect {
					t.Fatalf("a miss must hand back the registered binding, got %+v", sb)
				}
				return
			}
			if !sb.Wired || sb.ReplayedVia != tc.tool || sb.Dialect != b.Dialect || sb.Cap != b.Cap {
				t.Fatalf("surface binding %+v does not ride %s's %s binding %+v", sb, tc.tool, tc.event, b)
			}
			var recs []hookspool.Record
			emitHookActivity(tc.tool, tc.event, "", io.Discard, recordingActivityDeps(nil, &recs))
			if len(recs) != 1 || recs[0].Tool != tc.want || recs[0].HookEvent != tc.event {
				t.Fatalf("activity %+v, want one record under %s %s", recs, tc.want, tc.event)
			}
		})
	}
}

// TestForeignHookActivity: one case per foreign verdict action (surface-gap
// FU-53). A host the claude-code receiver serves as its own call is counted
// under the host's tool, native event and session; a host whose own Observer
// hook already counts the call, and an unidentified host, are not counted.
func TestForeignHookActivity(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		wantTool  string
		wantEvent string
		wantSess  string
	}{
		{"kimchi reroute", `{"session_id":"019a1b2c-3d4e-7f00-8000-000000000001","transcript_path":null,"hook_event_name":"UserPromptSubmit","prompt":"hi"}`, "kimchi", "UserPromptSubmit", "019a1b2c-3d4e-7f00-8000-000000000001"},
		{"cortex reroute", `{"session_id":"a39b","transcript_path":"/home/u/.snowflake/cortex/conversations/a39b.json","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`, "cortex-code", "PreToolUse", "a39b"},
		{"deepseek reroute", `{"session_id":"d1","transcript_path":"","hook_event_name":"PreToolUse","cwd":"/r","tool_name":"bash","tool_input":{"command":"ls"}}`, "deepseek", "PreToolUse", "d1"},
		{"grok dispatch", `{"session_id":"g1","sessionId":"g1","hook_event_name":"SessionEnd","hookEventName":"session_end"}`, "grok", "SessionEnd", "g1"},
		{"cursor neutral", `{"session_id":"c1","hook_event_name":"preToolUse","cursor_version":"2026.10.01"}`, "", "", ""},
		{"cursor reroute", `{"session_id":"c1","hook_event_name":"preToolUse","cursor_version":"2026.10.01"}`, "cursor", "preToolUse", "c1"},
		{"cursor lifecycle reroute unserved", `{"session_id":"c1","hook_event_name":"sessionEnd","cursor_version":"2026.10.01"}`, "", "", ""},
		{"unidentified noop", `{"sessionId":"x1","hook_event_name":"Stop"}`, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetHookActivity()
			t.Cleanup(resetHookActivity)
			// The cursor rows answer neutral only while Observer's cursor
			// registration holds the step (FU-122).
			registered := func(string, string) bool { return tc.name == "cursor neutral" }
			v := hook.ClassifyClaudeHookPayloadHost([]byte(tc.body), hook.ForeignHostEnv{OwnGateRegistered: registered})
			if !v.Foreign {
				t.Fatalf("fixture not foreign: %+v", v)
			}
			noteForeignHookActivity(v, []byte(tc.body))
			var recs []hookspool.Record
			emitHookActivity("claude-code", "pre-tool", "", io.Discard, recordingActivityDeps(nil, &recs))
			if tc.wantTool == "" {
				if len(recs) != 0 {
					t.Fatalf("records %+v, want none", recs)
				}
				return
			}
			if len(recs) != 1 {
				t.Fatalf("records %+v, want one", recs)
			}
			r := recs[0]
			if r.Tool != tc.wantTool || r.HookEvent != tc.wantEvent || r.SessionID != tc.wantSess {
				t.Fatalf("record %+v, want %s %s session %q", r, tc.wantTool, tc.wantEvent, tc.wantSess)
			}
		})
	}
}
