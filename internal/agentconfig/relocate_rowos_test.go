package agentconfig

import "testing"

// TestRelocationAbsoluteFollowsTheRowOS pins the FU-143 ruling: a relocation
// value is judged absolute by the path syntax of the OS whose row is
// resolved (PathEnv.GOOS), never by the host's filepath.IsAbs, so the answer
// is the same on every host: a Windows row accepts a drive or UNC value and
// refuses a POSIX root, a Linux or macOS row the reverse. Through
// ResolveArtifact (the writers' entry), ClaudeConfigDir (the readers') and a
// file-naming rule (Cline's CLINE_MCP_SETTINGS_PATH).
func TestRelocationAbsoluteFollowsTheRowOS(t *testing.T) {
	homes := map[string]string{"linux": "/home/u", "darwin": "/Users/u", "windows": `C:\Users\u`}
	for _, tc := range []struct {
		goos, value string
		abs         bool
	}{
		{"windows", `C:\cfg`, true},
		{"windows", `c:/cfg`, true},
		{"windows", `\\srv\share\cfg`, true},
		{"windows", `//srv/share/cfg`, true},
		{"windows", "/cfg", false},
		{"windows", `\cfg`, false},
		{"windows", `C:cfg`, false},
		{"windows", "cfg", false},
		{"linux", "/cfg", true},
		{"linux", `C:\cfg`, false},
		{"linux", `\\srv\share\cfg`, false},
		{"linux", "cfg", false},
		{"darwin", "/cfg", true},
		{"darwin", `C:\cfg`, false},
	} {
		t.Run(tc.goos+" "+tc.value, func(t *testing.T) {
			e := PathEnv{GOOS: tc.goos, Home: homes[tc.goos], Getenv: func(k string) string {
				switch k {
				case "CLAUDE_CONFIG_DIR", "CLINE_MCP_SETTINGS_PATH":
					return tc.value
				}
				return ""
			}}
			got, err := ResolveArtifact("claude-code/user-settings", e)
			if err != nil {
				t.Fatal(err)
			}
			if tc.abs {
				if got.Status != PathResolved || got.RelocatedBy != "CLAUDE_CONFIG_DIR" || got.Path != e.Join(tc.value, "settings.json") {
					t.Errorf("ResolveArtifact = %+v, want the value accepted", got)
				}
			} else if got.Status != PathRelocationUnresolved || got.RelocatedBy != "CLAUDE_CONFIG_DIR" || got.Path != "" {
				t.Errorf("ResolveArtifact = %+v, want the value refused as relative", got)
			}

			dir, refused := ClaudeConfigDir(e)
			if tc.abs != (dir != "" && refused == "") {
				t.Errorf("ClaudeConfigDir = (%q, %q), want accepted %v", dir, refused, tc.abs)
			}

			cline, err := ResolveArtifact("cline/mcp-settings", e)
			if err != nil {
				t.Fatal(err)
			}
			if tc.abs != (cline.Status == PathResolved && cline.RelocatedBy == "CLINE_MCP_SETTINGS_PATH") {
				t.Errorf("cline/mcp-settings = %+v, want accepted %v", cline, tc.abs)
			}
		})
	}
}
