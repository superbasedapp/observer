package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// The 2026-10-21 wave's tool-gate and prompt dialects, pinned against the
// payloads the hook probe captured live (docs/guard.md "Live grounding:
// 2026-10-21 wave").

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// TestToolGateWaveDialects judges each wave payload: the targets the gate
// sees, the session it keys, and the dialect's exact block.
func TestToolGateWaveDialects(t *testing.T) {
	claudeDeny := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":%q}}` + "\n"
	for _, r := range []struct {
		toolGateRow
		session string
	}{
		{toolGateRow: toolGateRow{
			name: "deepagents Claude-named Bash", tool: models.ToolDeepAgentsCode, dialect: ToolGateDialectClaudeWire, event: "PreToolUse",
			body: toolPayload("s1", "Bash", map[string]any{"command": "rm -rf ~/x"}), denyOn: "rm -rf",
			wantStdout: fmt.Sprintf(claudeDeny, ruleReason), wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		}, session: "s1"},
		{toolGateRow: toolGateRow{
			name: "vtcode exec_command deny", tool: models.ToolVTCode, dialect: ToolGateDialectVTCode, event: "PreToolUse",
			body: toolPayload("s1", "exec_command", map[string]any{"command": "rm -rf ~/x"}), denyOn: "rm -rf",
			wantStdout: fmt.Sprintf(claudeDeny, ruleReason), wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		}, session: "s1"},
		{toolGateRow: toolGateRow{
			name: "vtcode allow is silent", tool: models.ToolVTCode, dialect: ToolGateDialectVTCode, event: "PreToolUse",
			body: toolPayload("s1", "exec_command", map[string]any{"command": "ls"}), denyOn: "rm -rf",
			wantTargets: []string{"ls"}, wantKind: policy.KindShellExec,
		}, session: "s1"},
		{toolGateRow: toolGateRow{
			name: "dirac preToolUse.parameters", tool: models.ToolDirac, dialect: ToolGateDialectDirac, event: "PreToolUse",
			body: mustMarshal(map[string]any{
				"hookName": "PreToolUse", "taskId": "1792584662340", "workspaceRoots": []string{"/home/u/proj"},
				"preToolUse": map[string]any{"toolName": "execute_command", "parameters": map[string]any{"command": "rm -rf ~/x"}},
			}), denyOn: "rm -rf",
			wantStdout: fmt.Sprintf(`{"cancel":true,"errorMessage":%q}`+"\n", ruleReason), wantStderr: wantStderrBlock(ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		}, session: "1792584662340"},
		{toolGateRow: toolGateRow{
			name: "autohand run_command, no session", tool: models.ToolAutohand, dialect: ToolGateDialectAutohand, event: "pre-tool",
			body: mustMarshal(map[string]any{
				"cwd": "/home/u/proj", "hook_event_name": "pre-tool", "tool_name": "run_command",
				"tool_input": map[string]any{"command": "rm -rf ~/x"}, "tool_use_id": "call_1",
			}), denyOn: "rm -rf",
			wantStdout: fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", ruleReason), wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		}},
		{toolGateRow: toolGateRow{
			name: "kimchi bash pre-gate", tool: models.ToolKimchi, dialect: ToolGateDialectKimchiBash, event: "tool_call",
			body: mustMarshal(map[string]any{"tool_name": "bash", "input": map[string]any{"command": "rm -rf ~/x"}, "cwd": "/home/u/proj"}), denyOn: "rm -rf",
			wantExit: 2, wantStderr: wantStderrBlock(ruleReason), wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		}},
	} {
		t.Run(r.name, func(t *testing.T) {
			ev := &targetEvaluator{denyOn: r.denyOn, askOn: r.askOn}
			var out, errb bytes.Buffer
			res := HandleToolGate(ToolGateRequest{
				Tool: r.tool, Dialect: r.dialect, NativeEvent: r.event, Label: r.tool + ":" + r.event, Body: r.body,
			}, ev, nil, &out, &errb)
			if out.String() != r.wantStdout {
				t.Errorf("stdout = %q\nwant     %q", out.String(), r.wantStdout)
			}
			blocks := r.wantStdout != "" || r.wantExit != 0
			if res.Replied != blocks || res.ExitCode != r.wantExit {
				t.Errorf("Replied=%v ExitCode=%d", res.Replied, res.ExitCode)
			}
			if r.wantStderr != "" && errb.String() != r.wantStderr {
				t.Errorf("stderr = %q, want %q", errb.String(), r.wantStderr)
			}
			var targets []string
			for _, e := range ev.seen {
				targets = append(targets, e.Target)
				if e.Kind != r.wantKind || e.Tool != r.tool || e.SessionID != r.session {
					t.Errorf("event %+v: want kind %q, tool %s, session %q", e, r.wantKind, r.tool, r.session)
				}
			}
			if strings.Join(targets, "|") != strings.Join(r.wantTargets, "|") {
				t.Errorf("judged targets %v, want %v", targets, r.wantTargets)
			}
		})
	}
}

// TestPromptWaveDialects pins the two new prompt dialects: Dirac reads
// userPromptSubmit.prompt and cancels the task; Autohand reads instruction.
func TestPromptWaveDialects(t *testing.T) {
	block := guard.PromptVerdict{
		Verdict: policy.Verdict{Decision: policy.DecisionDeny, RuleID: "R-190", Reason: "secret"},
		Outcome: guard.PromptOutcomeBlocked,
	}
	dirac := mustMarshal(map[string]any{"hookName": "UserPromptSubmit", "taskId": "t1", "userPromptSubmit": map[string]any{"prompt": "use sk-x"}})
	autohand := mustMarshal(map[string]any{"hook_event_name": "pre-prompt", "session_id": "a1", "instruction": "use sk-x"})
	for _, tc := range []struct {
		name, dialect, event string
		body                 []byte
		verdict              guard.PromptVerdict
		wantSession          string
		wantStdout           func(string) bool
		wantExit             int
	}{
		{
			name: "dirac block cancels", dialect: PromptDialectDirac, event: "UserPromptSubmit", body: dirac, verdict: block, wantSession: "t1",
			wantStdout: func(s string) bool { return strings.HasPrefix(s, `{"cancel":true,"errorMessage":`) },
		},
		{
			name: "dirac allow is silent", dialect: PromptDialectDirac, event: "UserPromptSubmit", body: dirac, verdict: allowVerdict(), wantSession: "t1",
			wantStdout: func(s string) bool { return s == "" },
		},
		{
			name: "autohand block", dialect: PromptDialectAutohand, event: "pre-prompt", body: autohand, verdict: block, wantSession: "a1",
			wantStdout: func(s string) bool { return strings.HasPrefix(s, `{"decision":"block","reason":`) },
		},
		{
			name: "autohand allow is the empty object", dialect: PromptDialectAutohand, event: "pre-prompt", body: autohand, verdict: allowVerdict(), wantSession: "a1",
			wantStdout: func(s string) bool { return s == "{}\n" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A finding, so the once-per-prompt Dirac seam judges it.
			stub := &stubPromptEvaluator{verdict: tc.verdict, secrets: []policy.SecretFinding{{Type: "test", Certain: true}}}
			var out bytes.Buffer
			handled, _, _ := HandlePromptSubmitGuarded("x", tc.dialect, tc.event, tc.body, false, stub, nil, &out, io.Discard)
			if !handled {
				t.Fatal("not handled")
			}
			if !tc.wantStdout(out.String()) {
				t.Errorf("stdout %q", out.String())
			}
			if stub.lastEvent.SessionID != tc.wantSession {
				t.Errorf("session %q, want %q", stub.lastEvent.SessionID, tc.wantSession)
			}
		})
	}
	// Dirac sends an empty prompt on its duplicate first fire: nothing is
	// judged and nothing is written.
	stub := &stubPromptEvaluator{verdict: block}
	var out bytes.Buffer
	empty := mustMarshal(map[string]any{"hookName": "UserPromptSubmit", "taskId": "t1", "userPromptSubmit": map[string]any{"prompt": ""}})
	_, _, code := HandlePromptSubmitGuarded("dirac", PromptDialectDirac, "UserPromptSubmit", empty, false, stub, nil, &out, io.Discard)
	if out.Len() != 0 || code != 0 {
		t.Errorf("empty dirac prompt: stdout %q exit %d", out.String(), code)
	}
}

// TestForeignHostWaveRows: Cortex Code and Kimchi payloads on the Claude
// Code hook path are rerouted to their own rows; Claude Code's own payload
// is not.
func TestForeignHostWaveRows(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, tc := range []struct {
		name   string
		body   map[string]any
		getenv func(string) string
		want   string // "" = genuine Claude Code
	}{
		{name: "claude code", body: map[string]any{"session_id": "4f1c2b9e-1111-4222-8333-444455556666", "transcript_path": "/home/u/.claude/projects/p/4f1c.jsonl", "hook_event_name": "PreToolUse", "prompt_id": "x"}},
		{name: "cortex wsl", body: map[string]any{"session_id": "a39bdc0c-15cf-4ba3-b8df-ebd66e087a42", "transcript_path": "/home/u/.snowflake/cortex/conversations/a39bdc0c-15cf-4ba3-b8df-ebd66e087a42.json", "hook_event_name": "PreToolUse"}, want: "cortex-code"},
		{name: "cortex windows", body: map[string]any{"session_id": "d300a0e5-eb8a-4952-a588-a7db48c284e7", "transcript_path": `C:\Users\u\.snowflake\cortex\conversations\d300a0e5-eb8a-4952-a588-a7db48c284e7.json`, "hook_event_name": "UserPromptSubmit"}, want: "cortex-code"},
		{name: "kimchi by env", body: map[string]any{"session_id": "019a0000-0000-4000-8000-000000000000", "transcript_path": nil, "hook_event_name": "UserPromptSubmit"}, getenv: env(map[string]string{"KIMCHI_HOOK_EVENT": "UserPromptSubmit"}), want: "kimchi"},
		{name: "kimchi by uuidv7 (env lost)", body: map[string]any{"session_id": "019a1b2c-3d4e-7f00-8000-000000000001", "transcript_path": nil, "hook_event_name": "PreToolUse"}, want: "kimchi"},
		{name: "null transcript alone is not kimchi", body: map[string]any{"session_id": "4f1c2b9e-1111-4222-8333-444455556666", "transcript_path": nil, "hook_event_name": "PreToolUse"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ClassifyClaudeHookPayloadEnv(mustMarshal(tc.body), tc.getenv)
			if tc.want == "" {
				if v.Foreign {
					t.Fatalf("classified as %+v", v)
				}
				return
			}
			if !v.Foreign || v.Tool != tc.want || v.Action != ForeignReroute || v.Step != tc.body["hook_event_name"] {
				t.Fatalf("verdict %+v, want a reroute to %s", v, tc.want)
			}
		})
	}
}
