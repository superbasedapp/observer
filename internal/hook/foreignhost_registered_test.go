package hook

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCopilotHooks writes a Copilot CLI hooks file under home with one
// preToolUse handler carrying the given fields.
func writeCopilotHooks(t *testing.T, home string, handler string) {
	t.Helper()
	dir := filepath.Join(home, ".copilot", "hooks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"version":1,"hooks":{"preToolUse":[` + handler + `],"userPromptSubmitted":[` + handler + `]}}`
	if err := os.WriteFile(filepath.Join(dir, "superbased-observer.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestOwnGateRegisteredWindowsNeedsPowerShell pins audit follow-up 3:
// Copilot CLI on Windows runs a handler's "powershell" field, so a
// bash-only Observer file (written before the 2026-10-20 fix) reads as
// absent there and present everywhere else; a powershell field naming an
// Observer hook invocation (the native "& observer.exe" form or the
// wsl.exe bridge) reads as present; one naming another command does not.
func TestOwnGateRegisteredWindowsNeedsPowerShell(t *testing.T) {
	const bash = `"type":"command","bash":"/usr/local/bin/observer hook copilot-cli preToolUse","timeoutSec":30`
	for _, tc := range []struct {
		name    string
		goos    string
		handler string
		want    bool
	}{
		{"bash only, linux", "linux", `{` + bash + `}`, true},
		{"bash only, windows", "windows", `{` + bash + `}`, false},
		{"native powershell, windows", "windows", `{` + bash + `,"powershell":"& 'C:/Program Files/Observer/observer.exe' hook copilot-cli preToolUse"}`, true},
		{"backslash powershell, windows", "windows", `{` + bash + `,"powershell":"& C:\\Users\\u\\observer.exe hook copilot-cli preToolUse"}`, true},
		{"wsl bridge powershell, windows", "windows", `{` + bash + `,"powershell":"wsl.exe -d Ubuntu -e /usr/local/bin/observer hook copilot-cli preToolUse --config /home/u/.observer/config.toml"}`, true},
		{"foreign powershell, windows", "windows", `{` + bash + `,"powershell":"& C:/tools/audit.exe preToolUse"}`, false},
		{"powershell for another tool, windows", "windows", `{` + bash + `,"powershell":"& C:/x/observer.exe hook claude-code preToolUse"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeCopilotHooks(t, home, tc.handler)
			got := OwnGateRegistered(Options{HomeDir: home, BinaryPath: "/usr/local/bin/observer", GOOS: tc.goos})("copilot-cli", "PreToolUse")
			if got != tc.want {
				t.Fatalf("OwnGateRegistered = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestObserverRunCommand: one case per accepted and refused shape of the
// PowerShell command recogniser.
func TestObserverRunCommand(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want bool
	}{
		{"& C:/o/observer.exe hook copilot-cli preToolUse", true},
		// WINNODE2 item 10: the registered command ends with an explicit
		// exit so PowerShell reports observer's own exit code.
		{"& 'C:/Program Files/Observer/observer.exe' hook copilot-cli preToolUse; exit $LASTEXITCODE", true},
		{"C:/o/observer.exe hook copilot-cli preToolUse", true},
		{"wsl.exe -d 'My Distro' -e /usr/bin/observer hook copilot-cli preToolUse", true},
		{"wsl -d Ubuntu -- /usr/bin/observer hook copilot-cli preToolUse", true},
		{"wsl.exe -d Ubuntu /usr/bin/observer hook copilot-cli preToolUse", false},
		{"& C:/o/observer.exe hook cursor preToolUse", false},
		{"& C:/o/other.exe hook copilot-cli preToolUse", false},
		{"", false},
	} {
		if got := observerRunCommand(tc.cmd, "copilot-cli"); got != tc.want {
			t.Errorf("observerRunCommand(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}
