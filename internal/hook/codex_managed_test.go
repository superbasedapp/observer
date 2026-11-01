package hook

import (
	"strings"
	"testing"
)

func TestCodexManagedHookScripts(t *testing.T) {
	for _, tc := range []struct {
		name, bin, binWin  string
		wantPOSIX, wantWin string
		wantErr            bool
	}{
		{name: "bare observer on PATH", wantPOSIX: "exec observer hook codex \"$@\"\n", wantWin: "\r\nobserver hook codex %*\r\nexit /b %ERRORLEVEL%\r\n"},
		{name: "POSIX path with a space is quoted", bin: "/opt/my tools/observer", wantPOSIX: "exec '/opt/my tools/observer' hook codex \"$@\"\n", wantWin: "\r\n\"/opt/my tools/observer\" hook codex %*\r\n"},
		{
			name: "Windows binary of its own", bin: "/usr/local/bin/observer", binWin: `C:\Program Files\Observer\observer.exe`,
			wantPOSIX: "exec /usr/local/bin/observer hook codex", wantWin: "\r\n\"C:\\Program Files\\Observer\\observer.exe\" hook codex %*\r\n",
		},
		{name: "a % in the Windows binary is refused", binWin: `C:\%USERPROFILE%\observer.exe`, wantErr: true},
		{name: "a quote in the Windows binary is refused", binWin: `C:\a"b\observer.exe`, wantErr: true},
		{name: "a line break in the binary is refused", bin: "/opt/obs\nrm -rf /", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			posix, win, err := CodexManagedHookScripts(tc.bin, tc.binWin)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("CodexManagedHookScripts: %v", err)
			}
			if !strings.HasPrefix(posix, "#!/bin/sh\n") || !strings.Contains(posix, tc.wantPOSIX) {
				t.Errorf("POSIX script:\n%s\nwant %q", posix, tc.wantPOSIX)
			}
			if !strings.HasPrefix(win, "@echo off\r\n") || !strings.Contains(win, tc.wantWin) {
				t.Errorf("Windows script:\n%q\nwant %q", win, tc.wantWin)
			}
			if strings.Contains(strings.ReplaceAll(win, "\r\n", ""), "\n") {
				t.Errorf("Windows script has a bare LF: %q", win)
			}
		})
	}
}

func TestIsObserverCodexManagedHookCommand(t *testing.T) {
	for cmd, want := range map[string]bool{
		"/etc/codex/hooks/" + CodexManagedHookScriptPOSIX + " PreToolUse":                      true,
		`"C:\ProgramData\OpenAI\Codex\hooks\` + CodexManagedHookScriptWindows + `" PreToolUse`: true,
		"/usr/local/bin/observer hook codex PreToolUse":                                        true,
		"python3 /etc/codex/hooks/policy.py":                                                   false,
	} {
		if got := IsObserverCodexManagedHookCommand(cmd); got != want {
			t.Errorf("IsObserverCodexManagedHookCommand(%q) = %v, want %v", cmd, got, want)
		}
	}
}
