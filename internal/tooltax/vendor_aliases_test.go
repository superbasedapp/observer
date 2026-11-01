package tooltax_test

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// TestMCPNameFromSingleUnderscore pins the one-underscore MCP alias crush
// and Kiro CLI V3 emit (gfiD, 2026-10-15).
func TestMCPNameFromSingleUnderscore(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"mcp_github_create_pull_request", "mcp__github__create_pull_request", true},
		{"mcp_postgres_query", "mcp__postgres__query", true},
		{"mcp_srv", "mcp__srv", true},
		{"mcp__srv__tool", "", false}, // already canonical
		{"mcp_", "", false},
		{"list_mcp_resources", "", false},
		{"bash", "", false},
	} {
		got, ok := tooltax.MCPNameFromSingleUnderscore(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("MCPNameFromSingleUnderscore(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
		if ok {
			if _, _, isMCP := tooltax.MCPIdentity(got); !isMCP {
				t.Errorf("%q: canonical %q is not in the mcp__ namespace", tc.in, got)
			}
		}
	}
}

// TestMCPNameFromExtension pins Goose's `<extension>__<tool>` alias.
func TestMCPNameFromExtension(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"github__create_issue", "mcp__github__create_issue", true},
		{"developer__shell", "mcp__developer__shell", true},
		{"mcp__srv__tool", "", false},
		{"__tool", "", false},
		{"ext__", "", false},
		{"shell", "", false},
	} {
		got, ok := tooltax.MCPNameFromExtension(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("MCPNameFromExtension(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestVendorResearchRows pins the rows the gfiD vendor research added.
func TestVendorResearchRows(t *testing.T) {
	for _, tc := range []struct {
		tool, native, want string
	}{
		{"kiro-cli", "glob", tooltax.ActionSearchFiles},
		{"kiro-cli", "grep", tooltax.ActionSearchText},
		{"kiro-cli", "code", tooltax.ActionSearchText},
		{"kiro-cli", "subagent", tooltax.ActionSpawnSubagent},
		{"kiro-cli", "use_aws", tooltax.ActionRunCommand},
		{"kiro-cli", "knowledge", tooltax.ActionHarnessCall},
		{"kiro-cli", "goal", tooltax.ActionHarnessCall},
		{"kiro-cli", "mcp_postgres_query", tooltax.ActionMCPCall},
		{"goose", "tree", tooltax.ActionSearchFiles},
		{"goose", "read_image", tooltax.ActionReadFile},
		{"goose", "execute_bash", tooltax.ActionRunCommand},
		{"goose", "execute_typescript", tooltax.ActionRunCommand},
		{"goose", "computercontroller__computer_control", tooltax.ActionRunCommand},
		{"crush", "web_fetch", tooltax.ActionWebFetch},
		{"crush", "agentic_fetch", tooltax.ActionWebFetch},
		{"crush", "web_search", tooltax.ActionWebSearch},
		{"crush", "job_output", tooltax.ActionAgentControl},
		{"crush", "job_kill", tooltax.ActionAgentControl},
		{"crush", "mcp_github_create_pull_request", tooltax.ActionMCPCall},
	} {
		got, ok := tooltax.ResolveActionType(tc.tool, tc.native)
		if !ok || got != tc.want {
			t.Errorf("Resolve(%s, %s) = (%q, %v), want %q", tc.tool, tc.native, got, ok, tc.want)
		}
	}
}
