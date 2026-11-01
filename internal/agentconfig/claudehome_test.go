package agentconfig

import "testing"

// TestClaudeConfigDir pins the one Claude config directory resolver
// (FU-131, FU-138): the variable order, the relative-value refusal, the home
// default, and the absolute check by the row OS's own path syntax (FU-143),
// so a Windows resolution judged on Linux accepts C:\x and refuses /x.
func TestClaudeConfigDir(t *testing.T) {
	for _, tc := range []struct {
		name        string
		goos, home  string
		env         map[string]string
		wantDir     string
		wantRefused string
	}{
		{"linux default", "linux", "/home/dev", nil, "/home/dev/.claude", ""},
		{"linux CLAUDE_CONFIG_DIR", "linux", "/home/dev", map[string]string{"CLAUDE_CONFIG_DIR": "/opt/cfg"}, "/opt/cfg", ""},
		{"linux trimmed value", "linux", "/home/dev", map[string]string{"CLAUDE_CONFIG_DIR": " /opt/cfg "}, "/opt/cfg", ""},
		{"linux ANTHROPIC_CONFIG_DIR", "linux", "/home/dev", map[string]string{"ANTHROPIC_CONFIG_DIR": "/opt/anth"}, "/opt/anth", ""},
		{"CLAUDE_CONFIG_DIR wins", "linux", "/home/dev", map[string]string{"CLAUDE_CONFIG_DIR": "/opt/cfg", "ANTHROPIC_CONFIG_DIR": "/opt/anth"}, "/opt/cfg", ""},
		{"relative CLAUDE_CONFIG_DIR is refused", "linux", "/home/dev", map[string]string{"CLAUDE_CONFIG_DIR": "cfg", "ANTHROPIC_CONFIG_DIR": "/opt/anth"}, "", "CLAUDE_CONFIG_DIR"},
		{"relative ANTHROPIC_CONFIG_DIR is refused", "linux", "/home/dev", map[string]string{"ANTHROPIC_CONFIG_DIR": "./x"}, "", "ANTHROPIC_CONFIG_DIR"},
		{"a Windows path is relative on linux", "linux", "/home/dev", map[string]string{"CLAUDE_CONFIG_DIR": `C:\cfg`}, "", "CLAUDE_CONFIG_DIR"},
		{"no home, no variable", "linux", "", nil, "", ""},
		{"no home, a variable", "linux", "", map[string]string{"CLAUDE_CONFIG_DIR": "/opt/cfg"}, "/opt/cfg", ""},
		{"windows default", "windows", `C:\Users\dev`, nil, `C:\Users\dev\.claude`, ""},
		{"windows drive value", "windows", `C:\Users\dev`, map[string]string{"CLAUDE_CONFIG_DIR": `D:\cfg`}, `D:\cfg`, ""},
		{"windows UNC value", "windows", `C:\Users\dev`, map[string]string{"CLAUDE_CONFIG_DIR": `\\srv\share\cfg`}, `\\srv\share\cfg`, ""},
		{"windows refuses a POSIX root", "windows", `C:\Users\dev`, map[string]string{"CLAUDE_CONFIG_DIR": "/x"}, "", "CLAUDE_CONFIG_DIR"},
		{"windows refuses a drive-relative value", "windows", `C:\Users\dev`, map[string]string{"CLAUDE_CONFIG_DIR": `C:cfg`}, "", "CLAUDE_CONFIG_DIR"},
		{"darwin default", "darwin", "/Users/dev", nil, "/Users/dev/.claude", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := PathEnv{GOOS: tc.goos, Home: tc.home, Getenv: func(k string) string { return tc.env[k] }}
			dir, refused := ClaudeConfigDir(e)
			if dir != tc.wantDir || refused != tc.wantRefused {
				t.Errorf("ClaudeConfigDir = (%q, %q), want (%q, %q)", dir, refused, tc.wantDir, tc.wantRefused)
			}
		})
	}
	if got := ClaudeConfigDirEnvs(); len(got) != 2 || got[0] != relocClaudeConfigDir.Env {
		t.Errorf("ClaudeConfigDirEnvs = %v, want CLAUDE_CONFIG_DIR first", got)
	}
}
