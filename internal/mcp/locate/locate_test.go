package locate

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestLocations pins the locator table — these paths are the contract
// both mcp.Registrar and guard/mcpsec program against; a change here
// is a change to where observer believes each client keeps its MCP
// config and must be deliberate.
func TestLocations(t *testing.T) {
	t.Parallel()
	home := filepath.Join("h", "ome")
	want := []Location{
		{Client: "claude-code", Path: filepath.Join(home, ".claude.json"), Format: FormatMCPServersJSON, InstallDir: filepath.Join(home, ".claude")},
		{Client: "cursor", Path: filepath.Join(home, ".cursor", "mcp.json"), Format: FormatMCPServersJSON, InstallDir: filepath.Join(home, ".cursor")},
		{Client: "codex", Path: filepath.Join(home, ".codex", "config.toml"), Format: FormatCodexTOML, InstallDir: filepath.Join(home, ".codex")},
		{Client: "opencode", Path: filepath.Join(home, ".config", "opencode", "opencode.json"), Format: FormatOpenCodeJSON, InstallDir: filepath.Join(home, ".config", "opencode")},
		{
			Client: "cline", Path: filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json"), Format: FormatMCPServersJSON,
			InstallDir: filepath.Join(home, ".cline", "data"), LegacyPath: ClineLegacySettingsPath(home, runtime.GOOS),
		},
		{Client: "droid", Path: filepath.Join(home, ".factory", "mcp.json"), Format: FormatMCPServersJSON, InstallDir: filepath.Join(home, ".factory")},
		{Client: "command-code", Path: filepath.Join(home, ".commandcode", "mcp.json"), Format: FormatMCPServersJSON, InstallDir: filepath.Join(home, ".commandcode")},
	}
	got := LocationsEnv(home, nil)
	if len(got) != len(want) {
		t.Fatalf("Locations: got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Locations[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestForClient covers the lookup and the unknown-client miss.
func TestForClient(t *testing.T) {
	t.Parallel()
	loc, ok := ForClient("cursor", "h")
	if !ok || loc.Path != filepath.Join("h", ".cursor", "mcp.json") || loc.Format != FormatMCPServersJSON {
		t.Errorf("ForClient(cursor) = %+v, %v", loc, ok)
	}
	if _, ok := ForClient("not-a-client", "h"); ok {
		t.Error("ForClient(not-a-client) reported ok")
	}
}

// TestClineMCPSettingsPath pins the S-6 retarget: every current Cline client
// reads the shared ~/.cline/data/settings/cline_mcp_settings.json, relocated
// by CLINE_MCP_SETTINGS_PATH > CLINE_DATA_DIR > CLINE_DIR, on every OS. The
// old table pointed at VS Code globalStorage, which the extension migrates
// once and never reads again (red on the old code).
func TestClineMCPSettingsPath(t *testing.T) {
	t.Parallel()
	type row struct {
		name string
		env  map[string]string
		want string
	}
	for _, os := range []struct {
		goos, home, abs, file, sep string
	}{
		{"linux", "/home/u", "/opt/cl", "/opt/m.json", "/"},
		{"darwin", "/Users/u", "/opt/cl", "/opt/m.json", "/"},
		{"windows", `C:\Users\u`, `D:\cl`, `D:\m.json`, `\`},
	} {
		j := func(parts ...string) string {
			out := parts[0]
			for _, p := range parts[1:] {
				out += os.sep + p
			}
			return out
		}
		for _, tc := range []row{
			{"default", nil, j(os.home, ".cline", "data", "settings", "cline_mcp_settings.json")},
			{"file variable", map[string]string{"CLINE_MCP_SETTINGS_PATH": os.file, "CLINE_DIR": os.abs}, os.file},
			{"data dir", map[string]string{"CLINE_DATA_DIR": os.abs, "CLINE_DIR": "/elsewhere"}, j(os.abs, "settings", "cline_mcp_settings.json")},
			{"cline home", map[string]string{"CLINE_DIR": os.abs}, j(os.abs, "data", "settings", "cline_mcp_settings.json")},
		} {
			env := tc.env
			got, _ := ClineMCPSettingsPath(os.home, os.goos, func(k string) string { return env[k] })
			if got != tc.want {
				t.Errorf("%s/%s: got %q, want %q", os.goos, tc.name, got, tc.want)
			}
		}
		if got, want := clineDataDirOf(os.home, os.goos, func(k string) string {
			return map[string]string{"CLINE_MCP_SETTINGS_PATH": os.file}[k]
		}), j(os.home, ".cline", "data"); got != want {
			t.Errorf("%s: ClineDataDir ignores the MCP file variable: got %q, want %q", os.goos, got, want)
		}
	}
	if got, want := ClineLegacySettingsPath("/h", "linux"), "/h/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"; got != filepath.FromSlash(want) {
		t.Errorf("legacy path = %q, want %q", got, want)
	}
}

// clineDataDirOf is ClineDataDir's directory alone.
func clineDataDirOf(home, goos string, getenv func(string) string) string {
	d, _ := ClineDataDir(home, goos, getenv)
	return d
}
