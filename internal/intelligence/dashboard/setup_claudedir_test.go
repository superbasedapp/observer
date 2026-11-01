package dashboard

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestClaudeCredentialsPathFollowsTheOneResolver pins FU-138's dashboard
// half: the sign-in probe resolves through agentconfig.ClaudeConfigDir, so a
// relative CLAUDE_CONFIG_DIR / ANTHROPIC_CONFIG_DIR names no file (never a
// path joined against the daemon's working directory, never the ~/.claude
// default), an absolute one wins, and with none set the home default applies.
func TestClaudeCredentialsPathFollowsTheOneResolver(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	abs := filepath.Join(t.TempDir(), "cfg")
	rel := filepath.Join("rel", "cfg")
	if runtime.GOOS == "windows" {
		// A rooted path without a drive is not absolute on Windows.
		rel = `\rooted-no-drive`
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"default", nil, filepath.Join(home, ".claude", ".credentials.json")},
		{"absolute CLAUDE_CONFIG_DIR", map[string]string{"CLAUDE_CONFIG_DIR": abs}, filepath.Join(abs, ".credentials.json")},
		{"absolute ANTHROPIC_CONFIG_DIR", map[string]string{"ANTHROPIC_CONFIG_DIR": abs}, filepath.Join(abs, ".credentials.json")},
		{"relative CLAUDE_CONFIG_DIR", map[string]string{"CLAUDE_CONFIG_DIR": rel}, ""},
		{"relative ANTHROPIC_CONFIG_DIR", map[string]string{"ANTHROPIC_CONFIG_DIR": rel}, ""},
		{"relative CLAUDE_CONFIG_DIR beats an absolute ANTHROPIC_CONFIG_DIR", map[string]string{"CLAUDE_CONFIG_DIR": rel, "ANTHROPIC_CONFIG_DIR": abs}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := claudeCredentialsPathFor(home, func(k string) string { return tc.env[k] })
			if got != tc.want {
				t.Errorf("claudeCredentialsPathFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSetupClaudeRelativeConfigDirReadsNoSignIn: end to end through the
// handler, a relative CLAUDE_CONFIG_DIR with a sign-in file at the ~/.claude
// default reads no sign-in at all (the default is not what claude reads).
func TestSetupClaudeRelativeConfigDirReadsNoSignIn(t *testing.T) {
	withFakeClaudeHome(t, `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-default-home"}}`)
	t.Setenv("CLAUDE_CONFIG_DIR", "relative-claude-dir")
	if got := resolveClaudeCredentialsPath(); got != "" {
		t.Errorf("resolveClaudeCredentialsPath = %q, want \"\" for a relative CLAUDE_CONFIG_DIR", got)
	}
	if hasOAuthAccessToken(resolveClaudeCredentialsPath()) {
		t.Error("the default-home sign-in was read under a relative CLAUDE_CONFIG_DIR")
	}
}
