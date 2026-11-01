package agentconfig

import "testing"

func TestHomeRelativeDir(t *testing.T) {
	cases := []struct {
		id, goos, want string
		ok             bool
	}{
		{"devin/cascade-user-hooks", "windows", ".codeium/windsurf", true},
		{"devin/user-config", "windows", "AppData/Roaming/devin", true},
		{"devin/user-config", "linux", ".config/devin", true},
		{"antigravity-cli/user-hooks", "windows", ".gemini/config", true},
		{"claude-code/user-settings", "linux", ".claude", true},
		{"codex/user-config", "linux", ".codex", true},
		{"no-such/artifact", "linux", "", false},
	}
	for _, c := range cases {
		got, ok := HomeRelativeDir(c.id, c.goos)
		if got != c.want || ok != c.ok {
			t.Errorf("HomeRelativeDir(%q, %q) = %q, %v; want %q, %v", c.id, c.goos, got, ok, c.want, c.ok)
		}
	}
}
