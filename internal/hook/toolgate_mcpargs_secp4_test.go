//go:build !sbo_omit_adapter_cursor

package hook

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestMCPToolArgsPerHost (audit SEC-P4 F5): the reference git server's
// git_commit reaches the commit gate's placement column with its repo_path
// on every host whose MCP payload is grounded, read from the path that
// host's own decoder reads its tool input from (the dialect rows of
// toolGateDialects; Cursor's beforeMCPExecution payload struct in
// internal/adapter/cursor). A host left out is named in docs/code-security.md.
func TestMCPToolArgsPerHost(t *testing.T) {
	rows := []struct {
		host    string
		dialect string
		target  string
		body    string
	}{
		{"claude-code (tool_input)", ToolGateDialectClaudeCode, "mcp__git__git_commit", `{"tool_name":"mcp__git__git_commit","tool_input":{"repo_path":"/o"}}`},
		{"gemini (tool_input)", ToolGateDialectGemini, "mcp__git__git_commit", `{"tool_name":"git_commit","tool_input":{"repo_path":"/o"}}`},
		{"copilot-cli (toolArgs string)", ToolGateDialectCopilotCLI, "mcp__git__git_commit", `{"toolName":"git_commit","toolArgs":"{\"repo_path\":\"/o\"}"}`},
		{"cline (tool_call.input)", ToolGateDialectCline, "mcp__git__git_commit", `{"tool_call":{"name":"mcp__git__git_commit","input":{"repo_path":"/o"}}}`},
		{"antigravity (toolCall.args)", ToolGateDialectAntigravity, "mcp__git__git_commit", `{"toolCall":{"name":"git_commit","args":{"repo_path":"/o"}}}`},
		{"goose (tool_input)", ToolGateDialectGoose, "mcp__git__git_commit", `{"tool_name":"git__git_commit","tool_input":{"repo_path":"/o"}}`},
		{"kiro (tool_input)", ToolGateDialectKiro, "mcp__git__git_commit", `{"tool_name":"mcp_git_git_commit","tool_input":{"repo_path":"/o"}}`},
	}
	for _, r := range rows {
		t.Run(r.host, func(t *testing.T) {
			d, ok := toolGateDialects[r.dialect]
			if !ok {
				t.Fatalf("no dialect %s", r.dialect)
			}
			raw := mcpToolInputRaw([]byte(r.body), d.mcpArgs)
			ev := &policy.Event{Kind: policy.KindMCPCall, Target: r.target, Raw: raw, Cwd: "/r"}
			assertMCPPlacedAt(t, ev, "/o")
		})
	}
	t.Run("cursor beforeMCPExecution (input, server:tool)", func(t *testing.T) {
		body := []byte(`{"hook_event_name":"beforeMCPExecution","conversation_id":"c1","generation_id":"g1","workspace_roots":["/r"],"server_name":"git","tool_name":"git_commit","input":{"repo_path":"/o"}}`)
		pe, ok := BuildCursorEvent("beforeMCPExecution", body, nil)
		if !ok || pe.Kind != policy.KindMCPCall {
			t.Fatalf("BuildCursorEvent: %+v ok=%v", pe, ok)
		}
		pe.Raw = mcpToolInputRaw(body, nil)
		assertMCPPlacedAt(t, &pe, "/o")
	})
	t.Run("a payload without the arguments reads unknown", func(t *testing.T) {
		raw := mcpToolInputRaw([]byte(`{"tool_call":{"name":"mcp__git__git_commit"}}`), toolGateDialects[ToolGateDialectCline].mcpArgs)
		locs := policy.GitWriteLocations(&policy.MatchContext{Event: &policy.Event{Kind: policy.KindMCPCall, Target: "mcp__git__git_commit", Raw: raw, Cwd: "/r"}, Cfg: &policy.Config{}})
		if len(locs) != 1 || !locs[0].Unknown {
			t.Fatalf("locations %+v, want one unknown", locs)
		}
	})
}

func assertMCPPlacedAt(t *testing.T, ev *policy.Event, dir string) {
	t.Helper()
	locs := policy.GitWriteLocations(&policy.MatchContext{Event: ev, Cfg: &policy.Config{}})
	if len(locs) != 1 || locs[0].Unknown || strings.Join(locs[0].Dirs, ",") != dir {
		t.Fatalf("locations %+v (raw %s), want placed at %s", locs, ev.Raw, dir)
	}
}
