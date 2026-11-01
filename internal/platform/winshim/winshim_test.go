package winshim

import "testing"

// TestCommandFor pins the rewrite table: only a leading bare npm or npx
// changes, and only on Windows.
func TestCommandFor(t *testing.T) {
	cases := []struct {
		name, command, goos, want string
	}{
		{"npm on windows", "npm i -g @superbased/observer@1.36.0", "windows", "npm.cmd i -g @superbased/observer@1.36.0"},
		{"npx on windows", "npx -y @superbased/observer serve", "windows", "npx.cmd -y @superbased/observer serve"},
		{"bare npm on windows", "npm", "windows", "npm.cmd"},
		{"npm on linux", "npm install -g @openai/codex", "linux", "npm install -g @openai/codex"},
		{"npx on darwin", "npx @superbased/observer", "darwin", "npx @superbased/observer"},
		{"already cmd", "npm.cmd install -g cline", "windows", "npm.cmd install -g cline"},
		{"other tool", "pip install -U superbased-observer", "windows", "pip install -U superbased-observer"},
		{"npm-like prefix", "npmx install", "windows", "npmx install"},
		{"winget", "winget install SST.opencode", "windows", "winget install SST.opencode"},
		{"empty", "", "windows", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CommandFor(tc.command, tc.goos); got != tc.want {
				t.Errorf("CommandFor(%q, %q) = %q, want %q", tc.command, tc.goos, got, tc.want)
			}
		})
	}
}
