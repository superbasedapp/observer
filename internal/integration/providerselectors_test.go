package integration

import (
	"strings"
	"testing"
)

// TestProviderSelectorEnvKeys pins the Claude Code backend switches (CC-10):
// the Claude Platform on AWS and Mantle selectors were missing from both
// consumers before the table existed.
func TestProviderSelectorEnvKeys(t *testing.T) {
	cases := []struct {
		tool string
		want []string
	}{
		{"claude-code", []string{"CLAUDE_CODE_USE_ANTHROPIC_AWS", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_MANTLE", "CLAUDE_CODE_USE_VERTEX"}},
		{"claude-code-windows", []string{"CLAUDE_CODE_USE_ANTHROPIC_AWS", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_MANTLE", "CLAUDE_CODE_USE_VERTEX"}},
		{"codex", nil},
		{"no-such-tool", nil},
	}
	for _, tc := range cases {
		got := ProviderSelectorEnvKeys(tc.tool)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("ProviderSelectorEnvKeys(%q) = %v, want %v", tc.tool, got, tc.want)
		}
	}
	// A copy: a caller appending to it must not change the table.
	got := ProviderSelectorEnvKeys("claude-code")
	got[0] = "MUTATED"
	if ProviderSelectorEnvKeys("claude-code")[0] == "MUTATED" {
		t.Fatal("ProviderSelectorEnvKeys returned the table itself, not a copy")
	}
}

// TestProviderSelectorsAreSwitchesOnly pins that only on/off selectors are
// listed: a base-URL override only applies once its selector is on.
func TestProviderSelectorsAreSwitchesOnly(t *testing.T) {
	for tool, keys := range providerSelectorEnvKeys {
		if _, ok := For(tool); !ok {
			t.Errorf("selector row %q names no registry row", tool)
		}
		for _, k := range keys {
			if strings.HasSuffix(k, "_BASE_URL") {
				t.Errorf("%s: %s is a base-URL override, not a selector", tool, k)
			}
		}
	}
}

// TestRouteTradeoff pins the CC-11 consent sentence: Claude Code's route
// costs Remote Control, and the consent must say so.
func TestRouteTradeoff(t *testing.T) {
	for _, tool := range []string{"claude-code", "claude-code-windows"} {
		got := RouteTradeoff(tool)
		if !strings.Contains(got, "Remote Control") || !strings.Contains(got, "api.anthropic.com") {
			t.Errorf("RouteTradeoff(%q) = %q, want the Remote Control trade-off", tool, got)
		}
	}
	// Claude Desktop's gateway route (CC-1b): credential, cloud
	// environments and Remote Control.
	if got := RouteTradeoff("cowork"); !strings.Contains(got, "credential") || !strings.Contains(got, "cloud environments") ||
		!strings.Contains(got, "Remote Control") {
		t.Errorf("RouteTradeoff(cowork) = %q, want the gateway-mode trade-off", got)
	}
	if got := RouteTradeoff("codex"); got != "" {
		t.Errorf("RouteTradeoff(codex) = %q, want none grounded", got)
	}
	for tool := range routeTradeoffs {
		if _, ok := For(tool); !ok {
			t.Errorf("trade-off row %q names no registry row", tool)
		}
	}
}
