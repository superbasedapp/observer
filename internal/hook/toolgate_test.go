package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// targetEvaluator answers by target: a deny for any target containing
// denyOn, an ask for any containing askOn, else allow. It records every
// event it judged.
type targetEvaluator struct {
	denyOn, askOn string
	seen          []policy.Event
}

func (e *targetEvaluator) EvaluateHook(ev policy.Event) (guard.ActionVerdict, bool) {
	e.seen = append(e.seen, ev)
	d := policy.DecisionAllow
	switch {
	case e.denyOn != "" && strings.Contains(ev.Target, e.denyOn):
		d = policy.DecisionDeny
	case e.askOn != "" && strings.Contains(ev.Target, e.askOn):
		d = policy.DecisionAsk
	}
	v := guard.ActionVerdict{
		Input: guard.ActionInput{SessionID: ev.SessionID, Tool: ev.Tool, ActionType: ev.ActionType, Target: ev.Target},
		Kind:  ev.Kind,
		Verdict: policy.Verdict{
			Decision: d, RuleID: "R-101", Severity: policy.SeverityCritical,
			Reason: "blocked thing.", Advice: "Do this instead.", Source: "builtin",
		},
	}
	return v, d >= policy.DecisionFlag
}

func toolPayload(session, tool string, input map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{
		"session_id": session, "cwd": "/home/u/proj", "hook_event_name": "PreToolUse",
		"tool_name": tool, "tool_input": input,
	})
	return b
}

const ruleReason = "blocked thing. Do this instead."

// confirmLine is ExplainDegradedAsk's leading sentence for a shell command
// (KindShellExec) in session s1.
func confirmLine(what string) string {
	return "observer: R-101 needs your confirmation before " + what + " runs, and this tool cannot ask you, so it was blocked. To allow it, the developer (not the agent) runs `observer guard approve R-101 --session s1` (or approves it on the Observer dashboard Security page), then lets the agent retry the identical call. "
}

// TestConfirmLineMatchesGuard pins the expected-reply helper the dialect rows
// build on to the guard's own sentence, so a wording change in
// guard.ConfirmBlockLine fails here first instead of in every row.
func TestConfirmLineMatchesGuard(t *testing.T) {
	av := guard.ActionVerdict{
		Input:   guard.ActionInput{SessionID: "s1", Tool: models.ToolCodex, Target: "rm -rf ~/x"},
		Kind:    policy.KindShellExec,
		Verdict: policy.Verdict{Decision: policy.DecisionAsk, RuleID: "R-101", Reason: "blocked thing."},
	}
	got, want := strings.TrimSpace(guard.ConfirmBlockLine(av, "s1")), strings.TrimSpace(confirmLine("this command"))
	if got != want {
		t.Errorf("guard.ConfirmBlockLine = %q\nconfirmLine          = %q", got, want)
	}
}

// toolGateRow is one dialect fixture of toolGateDialectRows.
type toolGateRow struct {
	name, tool, dialect, event string
	body                       []byte
	denyOn, askOn              string
	wantStdout                 string // "" = nothing written (allow)
	wantExit                   int    // the exit code that carries the block (0 = a stdout reply)
	wantStderr                 string // checked when set: the exact stderr of a stderr-reason host
	wantTargets                []string
	wantKind                   policy.EventKind
}

// toolGateDialectRows is the shared per-dialect fixture table (one deny,
// ask and allow fixture per tool-gate dialect): TestToolGateDialects pins
// the reply bytes over it, and the request-access test (request-grants G4)
// reuses its deny rows so every dialect family is covered.
func toolGateDialectRows() []toolGateRow {
	codexBash := toolPayload("s1", "Bash", map[string]any{"command": "rm -rf ~/x"})
	patch := "*** Begin Patch\n*** Add File: notes.txt\n+hi\n*** Update File: ~/.ssh/x\n@@\n-a\n+b\n*** End Patch\n"
	codexPatch := toolPayload("s1", "apply_patch", map[string]any{"command": patch})
	codexMCP := toolPayload("s1", "mcp__evil__exfil", map[string]any{"q": "x"})
	claudeJSONDeny := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":%q}}` + "\n"
	return []toolGateRow{
		{
			name: "codex Bash deny", tool: models.ToolCodex, dialect: ToolGateDialectClaudeJSON, event: "PreToolUse",
			body: codexBash, denyOn: "rm -rf",
			wantStdout:  fmt.Sprintf(claudeJSONDeny, ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "codex Bash ask degrades to deny with the confirm line", tool: models.ToolCodex, dialect: ToolGateDialectClaudeJSON, event: "PreToolUse",
			body: codexBash, askOn: "rm -rf",
			wantStdout:  fmt.Sprintf(claudeJSONDeny, confirmLine("this command")+ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "codex Bash allow", tool: models.ToolCodex, dialect: ToolGateDialectClaudeJSON, event: "PreToolUse",
			body: toolPayload("s1", "Bash", map[string]any{"command": "ls"}), denyOn: "rm -rf",
			wantTargets: []string{"ls"}, wantKind: policy.KindShellExec,
		},
		{
			name: "codex apply_patch judges every file in the patch", tool: models.ToolCodex, dialect: ToolGateDialectClaudeJSON, event: "PreToolUse",
			body: codexPatch, denyOn: ".ssh",
			wantStdout:  fmt.Sprintf(claudeJSONDeny, ruleReason),
			wantTargets: []string{"notes.txt", "~/.ssh/x"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "codex MCP tool judged by name", tool: models.ToolCodex, dialect: ToolGateDialectClaudeJSON, event: "PreToolUse",
			body: codexMCP, denyOn: "mcp__evil",
			wantStdout:  fmt.Sprintf(claudeJSONDeny, ruleReason),
			wantTargets: []string{"mcp__evil__exfil"}, wantKind: policy.KindMCPCall,
		},
		{
			name: "qwen native ask", tool: models.ToolQwenCode, dialect: ToolGateDialectClaudeJSON, event: "PreToolUse",
			body: toolPayload("s1", "run_shell_command", map[string]any{"command": "rm -rf ~/x"}), askOn: "rm -rf",
			wantStdout:  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"blocked thing. Do this instead."}}` + "\n",
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "droid Create deny", tool: models.ToolDroid, dialect: ToolGateDialectClaudeJSON, event: "PreToolUse",
			body: toolPayload("s1", "Create", map[string]any{"file_path": "/home/u/.ssh/x", "content": "k"}), denyOn: ".ssh",
			wantStdout:  fmt.Sprintf(claudeJSONDeny, ruleReason),
			wantTargets: []string{"/home/u/.ssh/x"}, wantKind: policy.KindFileAccess,
		},
		{
			// Live on qodercli 1.1.65 an ask under --yolo ran the command,
			// so Qoder's binding lists no ask: an enforced ask degrades to
			// a deny that says how to confirm.
			name: "qoder Write ask degrades to deny", tool: models.ToolQoder, dialect: ToolGateDialectClaudeJSON, event: "PreToolUse",
			body: toolPayload("s1", "Write", map[string]any{"file_path": "/home/u/.ssh/x"}), askOn: ".ssh",
			wantStdout:  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"observer: R-101 needs your confirmation before this file access runs, and this tool cannot ask you, so it was blocked. To allow it, the developer (not the agent) runs ` + "`observer guard approve R-101 --session s1`" + ` (or approves it on the Observer dashboard Security page), then lets the agent retry the identical call. blocked thing. Do this instead."}}` + "\n",
			wantTargets: []string{"/home/u/.ssh/x"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "gemini deny", tool: models.ToolGeminiCLI, dialect: ToolGateDialectGemini, event: "BeforeTool",
			body: toolPayload("s1", "write_file", map[string]any{"file_path": "/home/u/.ssh/x"}), denyOn: ".ssh",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q,"systemMessage":%q}`+"\n", ruleReason, ruleReason),
			wantTargets: []string{"/home/u/.ssh/x"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "gemini ask degrades to deny with the confirm line", tool: models.ToolGeminiCLI, dialect: ToolGateDialectGemini, event: "BeforeTool",
			body: toolPayload("s1", "run_shell_command", map[string]any{"command": "rm -rf ~/x"}), askOn: "rm -rf",
			wantStdout: fmt.Sprintf(`{"decision":"deny","reason":%q,"systemMessage":%q}`+"\n",
				confirmLine("this command")+ruleReason, confirmLine("this command")+ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "cursor preToolUse Write deny", tool: models.ToolCursor, dialect: ToolGateDialectCursor, event: "preToolUse",
			body:        []byte(`{"conversation_id":"s1","cwd":"/home/u/proj","workspace_roots":["/home/u/proj"],"hook_event_name":"preToolUse","tool_name":"Write","tool_input":{"file_path":"/home/u/.ssh/x"}}`),
			denyOn:      ".ssh",
			wantStdout:  fmt.Sprintf(`{"permission":"deny","continue":true,"user_message":%q,"agent_message":%q}`+"\n", ruleReason, ruleReason),
			wantTargets: []string{"/home/u/.ssh/x"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "cursor preToolUse Grep judged as a read of its root", tool: models.ToolCursor, dialect: ToolGateDialectCursor, event: "preToolUse",
			body:        []byte(`{"conversation_id":"s1","hook_event_name":"preToolUse","tool_name":"Grep","tool_input":{"pattern":"k","path":"/home/u/.ssh"}}`),
			denyOn:      ".ssh",
			wantStdout:  fmt.Sprintf(`{"permission":"deny","continue":true,"user_message":%q,"agent_message":%q}`+"\n", ruleReason, ruleReason),
			wantTargets: []string{"/home/u/.ssh"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "cursor preToolUse Shell is gated by beforeShellExecution, not here", tool: models.ToolCursor, dialect: ToolGateDialectCursor, event: "preToolUse",
			body:   []byte(`{"conversation_id":"s1","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"rm -rf ~/x"}}`),
			denyOn: "rm -rf",
		},
		{
			// FU-122: the same Cursor payload reaching Observer's Claude Code
			// hooks with Observer's cursor hooks absent judges the shell too.
			name: "cursor Claude-hook replay Shell deny", tool: models.ToolCursor, dialect: ToolGateDialectCursorReplay, event: "preToolUse",
			body:        []byte(`{"conversation_id":"s1","cursor_version":"3.4.1","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"rm -rf ~/x"}}`),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"permission":"deny","continue":true,"user_message":%q,"agent_message":%q}`+"\n", ruleReason, ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "cursor Claude-hook replay Write deny", tool: models.ToolCursor, dialect: ToolGateDialectCursorReplay, event: "preToolUse",
			body:        []byte(`{"conversation_id":"s1","cursor_version":"3.4.1","hook_event_name":"preToolUse","tool_name":"Write","tool_input":{"file_path":"/home/u/.ssh/x"}}`),
			denyOn:      ".ssh",
			wantStdout:  fmt.Sprintf(`{"permission":"deny","continue":true,"user_message":%q,"agent_message":%q}`+"\n", ruleReason, ruleReason),
			wantTargets: []string{"/home/u/.ssh/x"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "claude Bash deny (HandleGuarded's dialect)", tool: models.ToolClaudeCode, dialect: ToolGateDialectClaudeCode, event: "PreToolUse",
			body: toolPayload("s1", "Bash", map[string]any{"command": "rm -rf ~/x"}), denyOn: "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"block","reason":%q,"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":%q}}`+"\n", ruleReason, ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			// The native ask is the modern field ALONE: a legacy
			// decision:block beside it turned the ask into a block (live
			// audit 2026-10-15).
			name: "claude Bash native ask", tool: models.ToolClaudeCode, dialect: ToolGateDialectClaudeCode, event: "PreToolUse",
			body: toolPayload("s1", "Bash", map[string]any{"command": "rm -rf ~/x"}), askOn: "rm -rf",
			wantStdout:  fmt.Sprintf(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":%q}}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		// Hook-parity Lanes A4-A6 (2026-10-03): one deny (and, where the
		// binding declares it, a native ask) per new dialect row.
		{
			name: "antigravity run_command deny", tool: models.ToolAntigravityCLI, dialect: ToolGateDialectAntigravity, event: "PreToolUse",
			body:        []byte(`{"conversationId":"s1","workspacePaths":["/home/u/proj"],"hookEventName":"PreToolUse","toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf ~/x","Cwd":"/home/u/proj"}}}`),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			// The test binary has no agy ancestor, so the ask probe answers
			// "no native ask" (TestAgyToolGateAskFollowsHost covers the
			// interactive host's force_ask).
			name: "antigravity ask degrades to deny without an interactive agy host", tool: models.ToolAntigravityCLI, dialect: ToolGateDialectAntigravity, event: "PreToolUse",
			body:        []byte(`{"conversationId":"s1","workspacePaths":["/home/u/proj"],"toolCall":{"name":"write_to_file","args":{"TargetFile":"/home/u/.ssh/x","CodeContent":"k"}}}`),
			askOn:       ".ssh",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", confirmLine("this file access")+ruleReason),
			wantTargets: []string{"/home/u/.ssh/x"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "grok deny", tool: models.ToolGrok, dialect: ToolGateDialectGrok, event: "PreToolUse",
			body:        []byte(`{"hookEventName":"pre_tool_use","sessionId":"s1","cwd":"/home/u/proj","workspaceRoot":"/home/u/proj","toolName":"run_terminal_command","toolInput":{"command":"rm -rf ~/x"}}`),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "grok ask degrades to deny (live: ask ran under --always-approve)", tool: models.ToolGrok, dialect: ToolGateDialectGrok, event: "PreToolUse",
			body:        []byte(`{"sessionId":"s1","workspaceRoot":"/home/u/proj","toolName":"run_terminal_command","toolInput":{"command":"rm -rf ~/x"}}`),
			askOn:       "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", confirmLine("this command")+ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "copilot-cli deny reads the JSON-string toolArgs", tool: models.ToolCopilotCLI, dialect: ToolGateDialectCopilotCLI, event: "preToolUse",
			body:        []byte(`{"sessionId":"s1","timestamp":1,"cwd":"/home/u/proj","toolName":"bash","toolArgs":"{\"command\":\"rm -rf ~/x\"}"}`),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"permissionDecision":"deny","permissionDecisionReason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "copilot-cli native ask", tool: models.ToolCopilotCLI, dialect: ToolGateDialectCopilotCLI, event: "preToolUse",
			body:        []byte(`{"sessionId":"s1","cwd":"/home/u/proj","toolName":"bash","toolArgs":{"command":"rm -rf ~/x"}}`),
			askOn:       "rm -rf",
			wantStdout:  fmt.Sprintf(`{"permissionDecision":"ask","permissionDecisionReason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "vibe ask degrades to deny with the confirm line", tool: models.ToolMistralCode, dialect: ToolGateDialectVibe, event: "pre_tool",
			body:        []byte(`{"session_id":"s1","transcript_path":"/t","cwd":"/home/u/proj","hook_event_name":"pre_tool","tool_name":"bash","tool_call_id":"c1","tool_input":{"command":"rm -rf ~/x"}}`),
			askOn:       "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", confirmLine("this command")+ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "goose block", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body:        []byte(`{"session_id":"s1","working_dir":"/home/u/proj","hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"rm -rf ~/x"}}`),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"block","reason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			// Guard-fix lane B: the live Cline CLI tool vocabulary and operand
			// shapes (fix/live-ground-2026-10-04's operandList, first seen on
			// the file hook) now reach Observer through the plugin's
			// beforeTool envelope. Another model sent the batch field as ONE
			// bare string (poolside/laguna-xs-2.1 via -P nvidia, node 1).
			name: "cline plugin run_commands single string", tool: models.ToolClineCLI, dialect: ToolGateDialectClinePlugin, event: "beforeTool",
			body:        []byte(`{"session_id":"s1","cwd":"/tmp/lgcl/work","tool_name":"run_commands","tool_input":{"commands":"rm -rf ~/x","description":"Remove ~/x directory recursively"}}`),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "cline plugin run_commands object elements", tool: models.ToolClineCLI, dialect: ToolGateDialectClinePlugin, event: "beforeTool",
			body:        []byte(`{"session_id":"s1","cwd":"/home/u/proj","tool_name":"run_commands","tool_input":{"commands":[{"command":"rm -rf ~/x"}]}}`),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			// T-342: the extension's vocabulary (execute_command) reaching the
			// cline-cli gate is still judged.
			name: "cline plugin, extension vocabulary", tool: models.ToolClineCLI, dialect: ToolGateDialectClinePlugin, event: "beforeTool",
			body:        []byte(`{"session_id":"s1","cwd":"/home/u/proj","tool_name":"execute_command","tool_input":{"command":"rm -rf ~/x"}}`),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			// Guard-fix lane B: the Cline plugin's beforeTool envelope (the
			// shim's normalized shape), the CLI's batched run_commands.
			name: "cline plugin skip, run_commands batch", tool: models.ToolClineCLI, dialect: ToolGateDialectClinePlugin, event: "beforeTool",
			body:        []byte(`{"host":"cline-cli","event":"beforeTool","session_id":"s1","cwd":"/home/u/proj","pid":7,"tool_name":"run_commands","tool_input":{"commands":["ls -la .","rm -rf ~/x"]},"call_id":"call_1"}`),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", ruleReason),
			wantTargets: []string{"ls -la .", "rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			// The plugin maps an ask onto Cline's own y/N approval.
			name: "cline plugin native ask", tool: models.ToolClineCLI, dialect: ToolGateDialectClinePlugin, event: "beforeTool",
			body:        []byte(`{"host":"cline-cli","event":"beforeTool","session_id":"s1","cwd":"/home/u/proj","tool_name":"read_files","tool_input":{"files":[{"path":"/home/u/.ssh/id_rsa"}]}}`),
			askOn:       ".ssh",
			wantStdout:  `{"decision":"ask","reason":"blocked thing. Do this instead."}` + "\n",
			wantTargets: []string{"/home/u/.ssh/id_rsa"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "poolside snake_case deny", tool: models.ToolPoolside, dialect: ToolGateDialectPoolside, event: "PreToolUse",
			body:        toolPayload("s1", "shell", map[string]any{"command": "rm -rf ~/x"}),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"hook_specific_output":{"permission_decision":"deny","permission_decision_reason":%q}}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "junie native ask", tool: models.ToolJunie, dialect: ToolGateDialectJunie, event: "PreToolUse",
			body:        toolPayload("s1", "bash", map[string]any{"command": "rm -rf ~/x"}),
			askOn:       "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"ask","reason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "crush deny", tool: models.ToolCrush, dialect: ToolGateDialectCrush, event: "PreToolUse",
			body:        toolPayload("s1", "bash", map[string]any{"command": "rm -rf ~/x"}),
			denyOn:      "rm -rf",
			wantStdout:  fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "cascade pre_run_command blocks by exit 2 with the reason alone on stderr", tool: models.ToolDevin, dialect: ToolGateDialectCascade, event: "pre_run_command",
			body:     []byte(`{"agent_action_name":"pre_run_command","trajectory_id":"s1","execution_id":"e1","timestamp":"2026-10-03T00:00:00Z","tool_info":{"command_line":"rm -rf ~/x","cwd":"/home/u/proj"}}`),
			denyOn:   "rm -rf",
			wantExit: 2, wantStderr: wantStderrBlock(ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "cascade pre_write_code", tool: models.ToolDevin, dialect: ToolGateDialectCascade, event: "pre_write_code",
			body:     []byte(`{"agent_action_name":"pre_write_code","trajectory_id":"s1","tool_info":{"file_path":"/home/u/.ssh/x","edits":[{"old_string":"a","new_string":"b"}]}}`),
			denyOn:   ".ssh",
			wantExit: 2, wantStderr: wantStderrBlock(ruleReason),
			wantTargets: []string{"/home/u/.ssh/x"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "cascade pre_mcp_tool_use judged by the server and tool name", tool: models.ToolDevin, dialect: ToolGateDialectCascade, event: "pre_mcp_tool_use",
			body:     []byte(`{"agent_action_name":"pre_mcp_tool_use","trajectory_id":"s1","tool_info":{"mcp_server_name":"evil","mcp_tool_name":"exfil","mcp_tool_arguments":{"q":"x"}}}`),
			denyOn:   "mcp__evil",
			wantExit: 2, wantStderr: wantStderrBlock(ruleReason),
			wantTargets: []string{"mcp__evil__exfil"}, wantKind: policy.KindMCPCall,
		},
		{
			name: "cascade allow writes nothing", tool: models.ToolDevin, dialect: ToolGateDialectCascade, event: "pre_read_code",
			body:        []byte(`{"agent_action_name":"pre_read_code","trajectory_id":"s1","tool_info":{"file_path":"/home/u/proj/a.go"}}`),
			denyOn:      ".ssh",
			wantTargets: []string{"/home/u/proj/a.go"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "kimi-code PreToolUse blocks by exit 2 with the reason alone on stderr", tool: models.ToolKimiCode, dialect: ToolGateDialectKimi, event: "PreToolUse",
			body:     toolPayload("s1", "Bash", map[string]any{"command": "rm -rf ~/x"}),
			denyOn:   "rm -rf",
			wantExit: 2, wantStderr: wantStderrBlock(ruleReason),
			wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "kimi-code allow writes nothing", tool: models.ToolKimiCode, dialect: ToolGateDialectKimi, event: "PreToolUse",
			body:        toolPayload("s1", "Bash", map[string]any{"command": "ls -la"}),
			denyOn:      "rm -rf",
			wantTargets: []string{"ls -la"}, wantKind: policy.KindShellExec,
		},
		{
			name: "unknown tool is never a violation", tool: models.ToolCodex, dialect: ToolGateDialectClaudeJSON, event: "PreToolUse",
			body: toolPayload("s1", "update_plan", map[string]any{"plan": "rm -rf ~/x"}), denyOn: "rm -rf",
		},
	}
}

// TestToolGateDialects is the shared tool-gate dialect table test (hook-
// parity Lane A): per dialect, a deny fixture produces the vendor's
// documented reply bytes, an ask produces the native ask where the binding
// declares one and a deny WITH the confirm explanation where it does not,
// and an allow fixture writes nothing (the caller writes the dialect's
// documented allow, pinned here too).
func TestToolGateDialects(t *testing.T) {
	rows := toolGateDialectRows()
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			ev := &targetEvaluator{denyOn: r.denyOn, askOn: r.askOn}
			var out, errb bytes.Buffer
			persisted := 0
			res := HandleToolGate(ToolGateRequest{
				Tool: r.tool, Dialect: r.dialect, NativeEvent: r.event, Label: r.tool + ":" + r.event, Body: r.body,
			}, ev, func(guard.ActionVerdict) { persisted++ }, &out, &errb)
			if out.String() != r.wantStdout {
				t.Errorf("stdout = %q\nwant     %q", out.String(), r.wantStdout)
			}
			blocks := r.wantStdout != "" || r.wantExit != 0
			if res.Replied != blocks || res.ExitCode != r.wantExit {
				t.Errorf("Replied=%v ExitCode=%d", res.Replied, res.ExitCode)
			}
			var targets []string
			for _, e := range ev.seen {
				targets = append(targets, e.Target)
				if e.Kind != r.wantKind || e.Tool != r.tool || e.SessionID != "s1" || !e.Caps.PreExecution || !e.Caps.CanBlock {
					t.Errorf("event %+v: want kind %s, tool %s, session s1, a pre-execution blocking channel", e, r.wantKind, r.tool)
				}
			}
			if strings.Join(targets, "|") != strings.Join(r.wantTargets, "|") {
				t.Errorf("judged targets %v, want %v", targets, r.wantTargets)
			}
			if r.wantStderr != "" && errb.String() != r.wantStderr {
				t.Errorf("stderr = %q, want %q", errb.String(), r.wantStderr)
			}
			if blocks && persisted != 1 {
				t.Errorf("persisted %d verdicts on a block, want 1", persisted)
			}
		})
	}
}

// TestToolGateAllowReplies pins each dialect's documented allow.
func TestToolGateAllowReplies(t *testing.T) {
	for dialect, want := range map[string]string{
		ToolGateDialectClaudeCode: "", // the receiver owns approve / rewrite
		ToolGateDialectClaudeJSON: "{}\n",
		ToolGateDialectGemini:     "{}\n",
		ToolGateDialectCursor:     `{"permission":"allow","continue":true}` + "\n",
		// FU-122: the Claude-hook replay answers on Cursor's own wire.
		ToolGateDialectCursorReplay: `{"permission":"allow","continue":true}` + "\n",
		// Hook-parity Lanes A4-A6. An explicit allow that would skip the
		// host's own permission prompt (Copilot CLI "allow") is never
		// written: the empty object is "no decision". On agy an empty
		// object DENIES (live, agy 1.2.16), so its allow is silence.
		ToolGateDialectAntigravity: "",
		ToolGateDialectGrok:        `{"decision":"allow"}` + "\n", // "allow only means not blocked"
		ToolGateDialectCopilotCLI:  "{}\n",
		ToolGateDialectVibe:        "{}\n",
		ToolGateDialectJunie:       "{}\n",
		ToolGateDialectCrush:       "{}\n",
		// Silent allows: the documented allow is an empty stdout.
		ToolGateDialectGoose:    "",
		ToolGateDialectCline:    "",
		ToolGateDialectPoolside: "",
		ToolGateDialectCascade:  "",
		ToolGateDialectKiro:     "",
		ToolGateDialectKimi:     "",
		// The Cline plugin transport: anything but deny / ask / modify is an
		// allow to the plugin, which then returns undefined.
		ToolGateDialectClinePlugin: `{"decision":"allow"}` + "\n",
		// The 2026-10-21 wave (live): Deep Agents / Kimchi / Cortex read
		// the empty object as no decision; Autohand must never see
		// {"decision":"allow"}; VT Code echoes any stdout into the TUI and
		// Dirac / Kimchi's bash gate take an empty stdout.
		ToolGateDialectClaudeWire: "{}\n",
		ToolGateDialectAutohand:   "{}\n",
		ToolGateDialectVTCode:     "",
		ToolGateDialectDirac:      "",
		ToolGateDialectKimchiBash: "",
	} {
		var out bytes.Buffer
		WriteToolGateAllow(dialect, &out)
		if out.String() != want {
			t.Errorf("%s allow = %q, want %q", dialect, out.String(), want)
		}
		if silent := want == "" && dialect != ToolGateDialectClaudeCode; ToolGateAllowWritesStdout(dialect) == silent {
			t.Errorf("%s: ToolGateAllowWritesStdout = %v, want %v", dialect, !silent, !silent)
		}
	}
	if len(ToolGateDialects()) != 23 {
		t.Errorf("ToolGateDialects = %v: a new row needs an allow and a deny fixture here and in TestToolGateDialects", ToolGateDialects())
	}
}

// TestToolGateTruncatedPayload: a truncated body is held under enforcement
// (ask where the channel asks, deny where it cannot) and passes through
// untouched otherwise.
func TestToolGateTruncatedPayload(t *testing.T) {
	for _, tc := range []struct {
		name, tool, dialect, event string
		enforcing                  bool
		wantPermission             string
	}{
		{"qwen asks", models.ToolQwenCode, ToolGateDialectClaudeJSON, "PreToolUse", true, "ask"},
		{"codex cannot ask, denies", models.ToolCodex, ToolGateDialectClaudeJSON, "PreToolUse", true, "deny"},
		{"claude asks", models.ToolClaudeCode, ToolGateDialectClaudeCode, "PreToolUse", true, "ask"},
		{"agy cannot ask, denies", models.ToolAntigravityCLI, ToolGateDialectAntigravity, "PreToolUse", true, "deny"},
		{"copilot-cli asks", models.ToolCopilotCLI, ToolGateDialectCopilotCLI, "preToolUse", true, "ask"},
		{"goose cannot ask, blocks", models.ToolGoose, ToolGateDialectGoose, "PreToolUse", true, "block"},
		{"not enforcing writes nothing", models.ToolCodex, ToolGateDialectClaudeJSON, "PreToolUse", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			res := HandleToolGate(ToolGateRequest{
				Tool: tc.tool, Dialect: tc.dialect, NativeEvent: tc.event, Label: "t", Body: []byte(`{"tool_na`),
				Truncated: true, Enforcing: tc.enforcing,
			}, &targetEvaluator{}, nil, &out, &bytes.Buffer{})
			if tc.wantPermission == "" {
				if res.Replied || out.Len() != 0 {
					t.Fatalf("not enforcing: Replied=%v stdout=%q", res.Replied, out.String())
				}
				return
			}
			if !res.Replied || !strings.Contains(out.String(), `"`+tc.wantPermission+`"`) || !strings.Contains(out.String(), "exceeded the size") {
				t.Errorf("stdout = %q, want a %s carrying the truncation reason", out.String(), tc.wantPermission)
			}
		})
	}
}

// TestToolGateBlockMatchesFailClosed: a tool-gate dialect's fail-closed
// reply (the watchdog / crash / config path) is the dialect's own deny.
func TestToolGateBlockMatchesFailClosed(t *testing.T) {
	for _, d := range ToolGateDialects() {
		fc, ok := BuildFailClosedReply(d, "why")
		want, _ := toolGateBlockFor(d, "PreToolUse", guard.Emission{Permission: "deny", Enforced: true, Reason: "why"})
		if !ok || fc.ExitCode != want.exitCode || fc.StderrReason != want.stderrReason {
			t.Errorf("%s: fail-closed = %+v ok=%v, want the dialect's deny %+v", d, fc, ok, want)
			continue
		}
		if !bytes.Equal(fc.Stdout, want.stdout) {
			t.Errorf("%s: fail-closed %q, deny %q", d, fc.Stdout, want.stdout)
		}
		// Every deny is carried by SOMETHING: a stdout reply or a
		// non-zero exit (an exit-code host parses no stdout).
		if len(fc.Stdout) == 0 && fc.ExitCode == 0 {
			t.Errorf("%s: fail-closed deny carries nothing", d)
		}
	}
}

// TestToolGateExitCodeDialects pins the exit-code-only rows (Cascade, Kiro
// CLI): a deny is exit 2 with NOTHING on stdout and the reason alone, under
// the DEC-1 header line, on stderr (the host shows stderr as the block
// reason, T-048), and the
// truncated-payload hold takes the same shape.
func TestToolGateExitCodeDialects(t *testing.T) {
	for _, d := range []string{ToolGateDialectCascade, ToolGateDialectKiro, ToolGateDialectKimi} {
		b, ok := toolGateBlockFor(d, "pre_run_command", guard.Emission{Permission: "deny", Enforced: true, Reason: "why"})
		if !ok || b.exitCode != 2 || len(b.stdout) != 0 || !b.stderrReason {
			t.Errorf("%s: block = %+v ok=%v, want exit 2, empty stdout, stderr reason", d, b, ok)
		}
		if !ToolGateDialectStderrReason(d) || ToolGateAllowWritesStdout(d) {
			t.Errorf("%s: want a stderr-reason, silent-allow dialect", d)
		}
	}
	var out, errb bytes.Buffer
	res := HandleToolGate(ToolGateRequest{
		Tool: models.ToolDevin, Dialect: ToolGateDialectCascade, NativeEvent: "pre_run_command", Label: "t",
		Body: []byte(`{"tool_info":{"comm`), Truncated: true, Enforcing: true,
	}, &targetEvaluator{}, nil, &out, &errb)
	if !res.Replied || res.ExitCode != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "exceeded the size") {
		t.Errorf("truncated cascade: res=%+v stdout=%q stderr=%q, want exit 2 with the reason on stderr", res, out.String(), errb.String())
	}
}
