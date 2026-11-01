package hook

import (
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestUnstatedShellAltDialect pins the boundary rule that asks for a
// PowerShell reading beside the POSIX one (PSRULES lane, JSP-6 live half):
// only a shell event whose host does not state its shell, on a Windows
// working directory. One row per input shape.
func TestUnstatedShellAltDialect(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		kind    policy.EventKind
		dialect policy.Dialect
		cwd     string
		want    policy.Dialect
	}{
		{"generic shell, drive letter backslash", policy.KindShellExec, "", `C:\Users\u\proj`, policy.DialectPowerShell},
		{"generic shell, drive letter slash", policy.KindShellExec, "", `d:/work/proj`, policy.DialectPowerShell},
		{"generic shell, UNC", policy.KindShellExec, "", `\\server\share\proj`, policy.DialectPowerShell},
		{"generic shell, POSIX directory", policy.KindShellExec, "", "/home/u/proj", ""},
		{"generic shell, WSL mount of a Windows drive", policy.KindShellExec, "", "/mnt/c/Users/u/proj", ""},
		{"generic shell, no directory", policy.KindShellExec, "", "", ""},
		{"stated PowerShell needs no second reading", policy.KindShellExec, policy.DialectPowerShell, `C:\proj`, ""},
		{"stated cmd keeps its own reading", policy.KindShellExec, policy.DialectCmd, `C:\proj`, ""},
		{"file access is not a shell command", policy.KindFileAccess, "", `C:\proj`, ""},
		{"a drive-relative path is not a directory", policy.KindShellExec, "", `C:proj`, ""},
	}
	for _, tc := range cases {
		if got := unstatedShellAltDialect(tc.kind, tc.dialect, tc.cwd); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestToolGateWindowsShellGetsPowerShellReading pins the seam: a Codex
// `Bash` call on a Windows working directory reaches the engine with the
// PowerShell reading requested, and the same call on a POSIX directory does
// not (Codex 0.144.4 on Windows ran its Bash tool through Windows
// PowerShell 5.1, JSP-6 live half).
func TestToolGateWindowsShellGetsPowerShellReading(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cwd  string
		want policy.Dialect
	}{
		{"windows directory", `C:\Users\u\proj`, policy.DialectPowerShell},
		{"posix directory", "/home/u/proj", ""},
	} {
		body, err := json.Marshal(map[string]any{
			"session_id": "s1", "cwd": tc.cwd, "hook_event_name": "PreToolUse",
			"tool_name": "Bash", "tool_input": map[string]any{"command": "git commit `\n --no-verify -m x"},
		})
		if err != nil {
			t.Fatal(err)
		}
		evs, _, ok, _ := extractGenericToolEvents(ToolGateRequest{Tool: models.ToolCodex, Dialect: ToolGateDialectClaudeJSON, NativeEvent: "PreToolUse", Body: body}, nil)
		if !ok || len(evs) != 1 {
			t.Fatalf("%s: ok=%v events=%d", tc.name, ok, len(evs))
		}
		if evs[0].Kind != policy.KindShellExec || evs[0].Dialect != "" || evs[0].AltDialect != tc.want {
			t.Errorf("%s: kind %q dialect %q alt %q, want shell / posix / %q", tc.name, evs[0].Kind, evs[0].Dialect, evs[0].AltDialect, tc.want)
		}
	}
}
