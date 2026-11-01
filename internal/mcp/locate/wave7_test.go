package locate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestClineHelpersRefuseUnresolvedRelocation pins FU-130: a relative
// CLINE_* value names no file, so the Cline helpers return no path instead
// of the vendor default and report the variable, as Location.Reason does.
func TestClineHelpersRefuseUnresolvedRelocation(t *testing.T) {
	home := t.TempDir()
	for _, env := range []string{"CLINE_DIR", "CLINE_DATA_DIR", "CLINE_MCP_SETTINGS_PATH"} {
		t.Run(env, func(t *testing.T) {
			getenv := func(k string) string {
				if k == env {
					return "relative/dir"
				}
				return ""
			}
			if got, unresolved := ClineMCPSettingsPath(home, runtime.GOOS, getenv); got != "" || unresolved != env {
				t.Errorf("ClineMCPSettingsPath = (%q, %q), want (\"\", %q)", got, unresolved, env)
			}
			if env != "CLINE_MCP_SETTINGS_PATH" {
				if got, unresolved := ClineDataDir(home, runtime.GOOS, getenv); got != "" || unresolved != env {
					t.Errorf("ClineDataDir = (%q, %q), want (\"\", %q)", got, unresolved, env)
				}
			} else if got, unresolved := ClineDataDir(home, runtime.GOOS, getenv); got == "" || unresolved != "" {
				// The data dir does not follow the MCP file's own variable.
				t.Errorf("ClineDataDir under %s = (%q, %q), want the default data dir", env, got, unresolved)
			}
			loc, _ := ForClientEnv("cline", home, getenv)
			if !strings.Contains(loc.Reason(), env) {
				t.Errorf("Reason() = %q, want it to name %s", loc.Reason(), env)
			}
		})
	}
	if got, unresolved := ClineMCPSettingsPath(home, runtime.GOOS, nil); got == "" || unresolved != "" {
		t.Errorf("with no variable the default must still resolve: (%q, %q)", got, unresolved)
	}
	if loc, _ := ForClientEnv("cline", home, nil); loc.Reason() != "" {
		t.Errorf("a resolved location has a Reason: %q", loc.Reason())
	}
}

// TestLocationsUsePinnedHomeRule pins FU-129: a home that is not this
// process's own never reads the process environment.
func TestLocationsUsePinnedHomeRule(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(t.TempDir(), "elsewhere"))
	loc, ok := ForClient("claude-code", home)
	if !ok {
		t.Fatal("no claude-code row")
	}
	if !strings.HasPrefix(loc.Path, home) {
		t.Errorf("ForClient read the process CLAUDE_CONFIG_DIR for a pinned home: %q", loc.Path)
	}
	for _, l := range Locations(home) {
		if l.Path != "" && !strings.HasPrefix(l.Path, home) {
			t.Errorf("Locations(%s) resolved %s outside the home: %q", home, l.Client, l.Path)
		}
	}
}

// TestForWSLHome pins the Windows to WSL twin location: the Linux layout
// under the given home, no environment, the daemon's own separators.
func TestForWSLHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "me")
	loc, ok := ForWSLHome("cline", home)
	if !ok {
		t.Fatal("no cline row")
	}
	want := filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json")
	if loc.Path != want {
		t.Errorf("Path = %q, want %q", loc.Path, want)
	}
	if loc.LegacyPath != filepath.Join(home, ".vscode-server", "data", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json") {
		t.Errorf("LegacyPath = %q (want the VS Code Server layout)", loc.LegacyPath)
	}
	if _, ok := ForWSLHome("no-such-client", home); ok {
		t.Error("unknown client resolved")
	}
	_ = os.Remove(home)
}
