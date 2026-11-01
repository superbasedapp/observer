package diag

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
)

// claudeManagedPolicyRead is the policy reader seam (a test injects one; the
// default reads this host's sources through internal/hook, which returns no
// policy inside a test binary).
var claudeManagedPolicyRead = hook.ReadClaudeManagedPolicy

// checkClaudeCodeManagedPolicy reports what this machine's Claude Code
// managed policy does to Observer's own wiring (surface-gap CC-5, S-9 and
// the CC-6 doctor half): a source Claude Code ignores under first-wins, a
// policyHelper that replaces the managed settings, a managed-mcp.json that
// takes exclusive MCP control, and a managed allowlist or denylist that
// refuses Observer's user-scope MCP server. The rows come from the one rule
// table in internal/hook (ClaudeManagedPolicy.Findings); the paths come
// from the agentconfig FileRow, so a Windows node reads C:\Program Files\
// ClaudeCode, the HKLM / HKCU Settings value and the drop-ins. Nothing here
// changes a file; gaps are WARN, never FAIL.
func checkClaudeCodeManagedPolicy(homeDir string, getenv func(string) string) Check {
	const name = "claude-code.managed-policy"
	policy := claudeManagedPolicyRead()
	if !policy.Deployed() {
		return Check{Name: name, Status: StatusOK, Message: "no Claude Code managed policy on this machine"}
	}
	var observer *hook.ClaudeMCPEntry
	if homeDir != "" {
		if e, ok, err := readJSONMCPEntry(claudeGlobalConfigPath(homeDir, getenv)); err == nil && ok {
			observer = &hook.ClaudeMCPEntry{Name: mcpregister.ServerName, Command: e.command, Args: e.args}
		}
	}
	findings := policy.Findings(observer)
	var details []string
	status := StatusOK
	for _, f := range findings {
		if f.Severity == hook.ClaudePolicyWarn {
			status = StatusWarn
		}
		details = append(details, f.Message)
	}
	var where []string
	for _, s := range policy.Sources {
		where = append(where, "source: "+s.Location)
	}
	if policy.ManagedMCP.Found {
		where = append(where, "source: "+policy.ManagedMCP.Path)
	}
	msg := fmt.Sprintf("Claude Code managed policy found (%d source(s)): nothing in it drops Observer's wiring", len(where))
	if status == StatusWarn {
		msg = fmt.Sprintf("Claude Code managed policy found (%d source(s)): it drops or blocks part of Observer's wiring - see below", len(where))
	}
	return Check{Name: name, Status: status, Message: msg, Details: append(details, where...)}
}

// claudeGlobalConfigArtifact is the agentconfig FileRow of Claude Code's
// ~/.claude.json; its relocation rule (CLAUDE_CONFIG_DIR, CC-8) says where
// the file is.
const claudeGlobalConfigArtifact = "claude-code/global-config"

// claudeGlobalConfigPath resolves Claude Code's global config (where the
// user-scope MCP servers, Observer's included, live) under homeDir with
// getenv's relocation variables (nil reads none), falling back to the
// vendor default when the row does not resolve (unreachable while it
// exists).
func claudeGlobalConfigPath(homeDir string, getenv func(string) string) string {
	got, err := agentconfig.ResolveArtifact(claudeGlobalConfigArtifact, agentconfig.PathEnv{GOOS: runtime.GOOS, Home: homeDir, Getenv: getenv})
	if err != nil || got.Status != agentconfig.PathResolved || got.Path == "" {
		return filepath.Join(homeDir, ".claude.json")
	}
	return filepath.Clean(got.Path)
}
