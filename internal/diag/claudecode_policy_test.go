package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

func withClaudeManagedPolicy(t *testing.T, p hook.ClaudeManagedPolicy) {
	t.Helper()
	prev := claudeManagedPolicyRead
	claudeManagedPolicyRead = func() hook.ClaudeManagedPolicy { return p }
	t.Cleanup(func() { claudeManagedPolicyRead = prev })
}

// TestCheckClaudeCodeManagedPolicy pins the doctor rows of the Claude Code
// policy reader (S-9, CC-6): quiet without a policy, WARN when a managed
// allowlist refuses the user-scope MCP entry Observer registered, and OK
// when the policy leaves Observer's wiring alone.
func TestCheckClaudeCodeManagedPolicy(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"),
		[]byte(`{"mcpServers":{"observer":{"command":"/usr/local/bin/observer","args":["serve"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := hook.ClaudeManagedPathSet{
		Settings:  filepath.Join(t.TempDir(), "managed-settings.json"),
		DropInDir: filepath.Join(t.TempDir(), "managed-settings.d"),
		MCP:       filepath.Join(t.TempDir(), "managed-mcp.json"),
	}
	fileWith := func(body string) hook.ClaudeManagedPolicy {
		if err := os.WriteFile(paths.Settings, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		src, mcp := hook.ReadClaudeManagedFiles(paths)
		return hook.ClaudeManagedPolicy{Sources: []hook.ClaudePolicySource{src}, ManagedMCP: mcp}
	}

	withClaudeManagedPolicy(t, hook.ClaudeManagedPolicy{})
	if got := checkClaudeCodeManagedPolicy(home, nil); got.Status != StatusOK || !strings.Contains(got.Message, "no Claude Code managed policy") {
		t.Fatalf("no policy: %+v", got)
	}

	withClaudeManagedPolicy(t, fileWith(`{"allowManagedMcpServersOnly":true,"allowedMcpServers":[{"serverCommand":["npx","-y","other"]}]}`))
	got := checkClaudeCodeManagedPolicy(home, nil)
	if got.Status != StatusWarn || !strings.Contains(strings.Join(got.Details, "\n"), `{"serverCommand":["/usr/local/bin/observer","serve"]}`) {
		t.Fatalf("locked allowlist refusing Observer: %+v", got)
	}

	withClaudeManagedPolicy(t, fileWith(`{"allowedMcpServers":[{"serverCommand":["/usr/local/bin/observer","serve"]}]}`))
	if got := checkClaudeCodeManagedPolicy(home, nil); got.Status != StatusOK {
		t.Fatalf("allowlist admitting Observer: %+v", got)
	}
}

// TestClaudeGlobalConfigPathFollowsClaudeConfigDir pins CC-8 for the doctor
// readers (MAC-4): with CLAUDE_CONFIG_DIR set, Claude Code keeps
// .claude.json inside that directory, so the managed-policy check and the
// MCP-registration check read the entry Observer wrote there.
func TestClaudeGlobalConfigPathFollowsClaudeConfigDir(t *testing.T) {
	home := t.TempDir()
	moved := filepath.Join(t.TempDir(), "profile")
	if got, want := claudeGlobalConfigPath(home, nil), filepath.Join(home, ".claude.json"); got != want {
		t.Errorf("unset: %s, want %s", got, want)
	}
	env := func(k string) string {
		if k == "CLAUDE_CONFIG_DIR" {
			return moved
		}
		return ""
	}
	if got, want := claudeGlobalConfigPath(home, env), filepath.Join(moved, ".claude.json"); got != want {
		t.Errorf("relocated: %s, want %s", got, want)
	}
	if err := os.MkdirAll(moved, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moved, ".claude.json"),
		[]byte(`{"mcpServers":{"observer":{"command":"/usr/local/bin/observer","args":["serve"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkMCPRegistrations(home, "/usr/local/bin/observer", "/usr/local/bin/observer", env, false)
	if !strings.Contains(c.Message+strings.Join(c.Details, "\n"), "claude-code") || strings.Contains(strings.Join(c.Details, "\n"), "absent: claude-code") {
		t.Logf("check: %+v", c)
	}
}
