package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/winshell"
)

func TestWindowsHookShellChecks(t *testing.T) {
	warning := integration.WindowsHookShellWarning("vtcode-windows")
	base := hook.WindowsShellReport{
		Target: "vtcode-windows", ConfigPath: "/mnt/c/Users/u/AppData/Roaming/vinhnx/vtcode/config/vtcode.toml",
		Registered: true, Shell: "sh", Warning: warning,
	}
	cases := []struct {
		name       string
		mutate     func(*hook.WindowsShellReport)
		wantRow    bool
		wantStatus Status
		wantInMsg  string
	}{
		{"registered, sh not found warns", func(r *hook.WindowsShellReport) { r.Status = winshell.NotFound }, true, StatusWarn, `C:\Program Files\Git\bin`},
		{"registered, sh found is ok", func(r *hook.WindowsShellReport) {
			r.Status, r.ShellPath = winshell.Found, "/mnt/c/Program Files/Git/bin/sh.exe"
		}, true, StatusOK, "Git/bin/sh.exe"},
		{"registered, unknown PATH has no row", func(r *hook.WindowsShellReport) { r.Status = winshell.Unknown }, false, StatusOK, ""},
		{"not registered has no row", func(r *hook.WindowsShellReport) { r.Registered, r.Status = false, winshell.NotFound }, false, StatusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := base
			tc.mutate(&rep)
			got := windowsHookShellChecks([]hook.WindowsShellReport{rep})
			if !tc.wantRow {
				if len(got) != 0 {
					t.Fatalf("want no row, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want one row, got %+v", got)
			}
			c := got[0]
			if c.Status != tc.wantStatus || !strings.Contains(c.Message, tc.wantInMsg) {
				t.Fatalf("check = %+v, want %s containing %q", c, tc.wantStatus, tc.wantInMsg)
			}
			if c.Name != "vtcode-windows.hooks.windows_shell" {
				t.Errorf("name = %q", c.Name)
			}
			// `observer doctor vtcode` and `observer doctor hooks` both scope to it.
			r := Report{Checks: got}
			if len(r.Filter("vtcode").Checks) != 1 || len(r.Filter("hooks").Checks) != 1 {
				t.Errorf("filter did not keep %q", c.Name)
			}
			if tc.wantStatus == StatusWarn && c.Message != warning {
				t.Errorf("doctor message %q differs from the registration warning %q", c.Message, warning)
			}
		})
	}
}

// TestCheckWindowsHookShellsSandboxed: a sandboxed doctor run (pinned home)
// reads no environment and no foreign-OS home, so it reports nothing.
func TestCheckWindowsHookShellsSandboxed(t *testing.T) {
	if got := checkWindowsHookShells(t.TempDir(), "/opt/observer/bin/observer", nil); len(got) != 0 {
		t.Fatalf("sandboxed run reported %+v", got)
	}
}
