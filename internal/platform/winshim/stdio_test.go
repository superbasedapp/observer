package winshim

import (
	"reflect"
	"testing"
)

// TestStdioLaunch pins the per-launch rewrite: only a bare npm or npx
// command changes, only on Windows, and only for a grounded launch form.
func TestStdioLaunch(t *testing.T) {
	args := []string{"-y", "@superbased/observer", "serve"}
	cases := []struct {
		name     string
		command  string
		goos     string
		how      Launch
		wantCmd  string
		wantArgs []string
	}{
		{"linux shell form unchanged", "npx", "linux", LaunchCmdShell, "npx", args},
		{"darwin extension form unchanged", "npx", "darwin", LaunchCmdExtension, "npx", args},
		{"windows as-is unchanged", "npx", "windows", LaunchAsIs, "npx", args},
		{"windows extension", "npx", "windows", LaunchCmdExtension, "npx.cmd", args},
		{"windows shell", "npx", "windows", LaunchCmdShell, "cmd", []string{"/c", "npx", "-y", "@superbased/observer", "serve"}},
		{"windows npm shell", "npm", "windows", LaunchCmdShell, "cmd", []string{"/c", "npm", "-y", "@superbased/observer", "serve"}},
		{"windows exe untouched", `C:\Users\u\observer.exe`, "windows", LaunchCmdShell, `C:\Users\u\observer.exe`, args},
		{"windows already cmd untouched", "npx.cmd", "windows", LaunchCmdShell, "npx.cmd", args},
		{"windows other tool untouched", "uvx", "windows", LaunchCmdExtension, "uvx", args},
		{"empty os unchanged", "npx", "", LaunchCmdShell, "npx", args},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCmd, gotArgs := StdioLaunch(tc.command, args, tc.goos, tc.how)
			if gotCmd != tc.wantCmd || !reflect.DeepEqual(gotArgs, tc.wantArgs) {
				t.Errorf("StdioLaunch(%q, %q, %v) = %q %q, want %q %q", tc.command, tc.goos, tc.how, gotCmd, gotArgs, tc.wantCmd, tc.wantArgs)
			}
		})
	}
}

// TestStdioLaunch_CopiesArgs pins that the caller's slice is never aliased.
func TestStdioLaunch_CopiesArgs(t *testing.T) {
	in := []string{"-y", "pkg"}
	_, out := StdioLaunch("npx", in, "linux", LaunchAsIs)
	out[0] = "changed"
	if in[0] != "-y" {
		t.Fatalf("input args were aliased: %q", in)
	}
}
