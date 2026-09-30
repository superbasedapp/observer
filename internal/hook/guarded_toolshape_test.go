package hook

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestBuildClaudeCodeEvent_ExecAndReadToolsEvaluated is the SR27-D1
// regression (security review 2026-09-27). A Claude Code tool with no row
// in claudeToolShape is approved WITHOUT evaluation, so before the fix a
// prompt-injected agent could route around every shell deny by calling
// Monitor (runs `command` as a background script) or the Windows-native
// PowerShell tool instead of Bash, and around the sensitive-read rules via
// Grep's `path`; NotebookEdit's real operand (notebook_path) was never read.
func TestBuildClaudeCodeEvent_ExecAndReadToolsEvaluated(t *testing.T) {
	t.Parallel()
	mk := func(tool string, input map[string]any) []byte {
		b, _ := json.Marshal(map[string]any{
			"session_id": "s1", "cwd": "/home/u/proj",
			"tool_name": tool, "tool_input": input,
		})
		return b
	}
	cases := []struct {
		name        string
		body        []byte
		wantKind    policy.EventKind
		wantAction  string
		wantTarget  string
		wantDialect policy.Dialect
	}{
		{
			"Monitor", mk("Monitor", map[string]any{"command": "rm -rf ~", "description": "x"}),
			policy.KindShellExec, "run_command", "rm -rf ~", "",
		},
		{
			"PowerShell", mk("PowerShell", map[string]any{"command": "Remove-Item -Recurse ~"}),
			policy.KindShellExec, "run_command", "Remove-Item -Recurse ~", policy.DialectPowerShell,
		},
		{
			"pwsh", mk("pwsh", map[string]any{"command": "Remove-Item -Recurse ~"}),
			policy.KindShellExec, "run_command", "Remove-Item -Recurse ~", policy.DialectPowerShell,
		},
		{
			"Grep", mk("Grep", map[string]any{"pattern": ".", "path": "/home/u/.ssh/id_rsa", "output_mode": "content"}),
			policy.KindFileAccess, "read_file", "/home/u/.ssh/id_rsa", "",
		},
		{
			"NotebookEdit", mk("NotebookEdit", map[string]any{"notebook_path": "/home/u/.observer/x.ipynb"}),
			policy.KindFileAccess, "edit_file", "/home/u/.observer/x.ipynb", "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev, ok := BuildClaudeCodeEvent(tc.body)
			if !ok {
				t.Fatalf("%s payload was not evaluable (approved unevaluated)", tc.name)
			}
			if ev.Kind != tc.wantKind || ev.ActionType != tc.wantAction || ev.Target != tc.wantTarget || ev.Dialect != tc.wantDialect {
				t.Errorf("event = kind=%s action=%s target=%q dialect=%q", ev.Kind, ev.ActionType, ev.Target, ev.Dialect)
			}
		})
	}

	// End to end through HandleGuarded: a deny verdict for Monitor now blocks.
	var out bytes.Buffer
	blocked, _ := HandleGuarded("claude-code:pre-tool",
		preToolBody("Monitor", "rm -rf ~"),
		stubEvaluator{v: verdictWith(policy.DecisionDeny, "R-101"), worthy: true},
		func(guard.ActionVerdict) {}, &out, &bytes.Buffer{})
	if !blocked {
		t.Fatalf("Monitor `rm -rf ~` with a deny verdict was not blocked (reply %s)", out.String())
	}
}
