package diag

import (
	"strings"
	"testing"
)

// TestNativePluginSideReportsAnUnnamedMCPConfig pins FU-130 for the
// claude-code.plugin row: with a relative CLAUDE_CONFIG_DIR the user MCP
// config has no path, and the side says why (the variable named, never its
// value) instead of skipping the MCP half silently.
func TestNativePluginSideReportsAnUnnamedMCPConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "relative-claude")
	s := nativePluginSide(home)
	if !strings.Contains(s.Unnamed, "CLAUDE_CONFIG_DIR") || strings.Contains(s.Unnamed, "relative-claude") {
		t.Errorf("Unnamed = %q, want the variable named and its value withheld", s.Unnamed)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	if s := nativePluginSide(home); s.Unnamed != "" {
		t.Errorf("a resolved MCP config has Unnamed = %q", s.Unnamed)
	}
}
