package agentconfig

import "testing"

// TestCodexSystemAndManagedPathsPerOS pins the Codex system and managed
// rows with GOOS set explicitly per OS (surface-gap review S-7). Codex reads
// a system config.toml on Windows too (%ProgramData%\OpenAI\Codex\config.toml,
// vendor source codex-rs/config/src/loader/mod.rs); the catalogue named it
// for Linux and macOS only, so the Windows row resolved to no_os.
func TestCodexSystemAndManagedPathsPerOS(t *testing.T) {
	rows := fileRowsByID()
	for _, tc := range []struct {
		id, goos, home, programData string
		want                        string
	}{
		{"codex/system-config", "linux", "/home/u", "", "/etc/codex/config.toml"},
		{"codex/system-config", "darwin", "/Users/u", "", "/etc/codex/config.toml"},
		{"codex/system-config", "windows", `C:\Users\u`, "", `C:\ProgramData\OpenAI\Codex\config.toml`},
		{"codex/system-config", "windows", `C:\Users\u`, `D:\PD`, `D:\PD\OpenAI\Codex\config.toml`},
		{"codex/requirements", "linux", "/home/u", "", "/etc/codex/requirements.toml"},
		{"codex/requirements", "darwin", "/Users/u", "", "/etc/codex/requirements.toml"},
		{"codex/requirements", "windows", `C:\Users\u`, "", `C:\ProgramData\OpenAI\Codex\requirements.toml`},
		{"codex/managed-config", "linux", "/home/u", "", "/etc/codex/managed_config.toml"},
		{"codex/managed-config", "darwin", "/Users/u", "", "/etc/codex/managed_config.toml"},
		{"codex/managed-config", "windows", `C:\Users\u`, "", `C:\Users\u\.codex\managed_config.toml`},
	} {
		t.Run(tc.id+"/"+tc.goos+"/"+tc.programData, func(t *testing.T) {
			f, ok := rows[tc.id]
			if !ok {
				t.Fatalf("no row %s", tc.id)
			}
			got := ResolvePath(f, PathEnv{GOOS: tc.goos, Home: tc.home, Getenv: func(k string) string {
				if k == "ProgramData" {
					return tc.programData
				}
				return ""
			}})
			if got.Status != PathResolved || got.Path != tc.want {
				t.Errorf("ResolvePath(%s, %s) = %+v, want %q", tc.id, tc.goos, got, tc.want)
			}
		})
	}
}
