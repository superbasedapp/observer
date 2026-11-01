package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/winshell"
)

// winShellFS is an injected, case-insensitive file probe (NTFS and DrvFs are)
// over a fixed set of paths.
func winShellFS(paths ...string) func(string) bool {
	set := map[string]bool{}
	for _, p := range paths {
		set[strings.ToLower(p)] = true
	}
	return func(p string) bool { return set[strings.ToLower(p)] }
}

const (
	wslGitCmd = "/mnt/c/Program Files/Git/cmd"
	wslGitBin = "/mnt/c/Program Files/Git/bin"
	winGitCmd = `C:\Program Files\Git\cmd`
	winGitBin = `C:\Program Files\Git\bin`
)

var shellFS = winShellFS(
	wslGitCmd+"/git.exe", wslGitBin+"/sh.exe",
	winGitCmd+`\git.exe`, winGitBin+`\sh.exe`,
)

// vtCodeBridgeRegistry is a WSL-daemon registry for the vtcode-windows bridge
// under a temp HOME and a temp Windows user home, with pathEnv as the WSL
// PATH and dryRun as given.
func vtCodeBridgeRegistry(t *testing.T, pathEnv string, dryRun bool) (*Registry, string) {
	t.Helper()
	home := t.TempDir()
	win := filepath.Join(home, "win")
	sub, _ := waveCrossOSFor("vtcode")
	if err := os.MkdirAll(filepath.Join(win, sub.winSubdir), 0o755); err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry(Options{
		BinaryPath: "/opt/observer/bin/observer", HomeDir: home, WindowsUserHome: win, WSLDistro: "Ubuntu-T",
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		Getenv:        func(k string) string { return map[string]string{"PATH": pathEnv}[k] },
		GOOS:          "linux",
		DryRun:        dryRun,
		fileExists:    shellFS,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg, filepath.Join(win, sub.winSubdir, "vtcode.toml")
}

// TestVTCodeWindowsBridgeShellWarning: the vtcode-windows bridge result warns
// exactly when Windows PATH dirs are visible and none holds sh.exe, on a
// first write, on a dry run and on an already-set pass.
func TestVTCodeWindowsBridgeShellWarning(t *testing.T) {
	cases := []struct {
		name     string
		pathEnv  string
		dryRun   bool
		wantWarn bool
	}{
		{"only Git cmd on the Windows PATH", "/usr/bin:/bin:" + wslGitCmd + ":/mnt/c/WINDOWS", false, true},
		{"only Git cmd, dry run", "/usr/bin:" + wslGitCmd, true, true},
		{"Git bin on the Windows PATH", "/usr/bin:" + wslGitCmd + ":" + wslGitBin, false, false},
		{"no Windows dirs visible (appendWindowsPath=false)", "/usr/local/bin:/usr/bin:/bin", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, _ := vtCodeBridgeRegistry(t, tc.pathEnv, tc.dryRun)
			res := reg.Register("vtcode-windows")
			if res.Error != nil || len(res.HooksAdded) == 0 {
				t.Fatalf("register: %+v", res)
			}
			assertShellWarning(t, res, tc.wantWarn)
			if tc.dryRun {
				return
			}
			again := reg.Register("vtcode-windows")
			if again.Error != nil || len(again.AlreadySet) == 0 {
				t.Fatalf("second register: %+v", again)
			}
			assertShellWarning(t, again, tc.wantWarn)
		})
	}
}

// TestPersistentWindowsPATHWins: the persistent Windows PATH (Options.WindowsPATH)
// decides over the process PATH, which a WSL session started from Git Bash
// inherits with Git's own bin dirs (2026-10-24); a failed read falls back.
func TestPersistentWindowsPATHWins(t *testing.T) {
	gitBashView := "/usr/bin:" + wslGitCmd + ":" + wslGitBin // what Git Bash hands WSL
	cases := []struct {
		name       string
		persistent func() (string, bool)
		wantWarn   bool
	}{
		{"persistent PATH lacks Git bin", func() (string, bool) { return winshell.WSLPathList(winGitCmd), true }, true},
		{"persistent PATH has Git bin", func() (string, bool) { return winshell.WSLPathList(winGitCmd + ";" + winGitBin), true }, false},
		{"persistent read failed: process PATH", func() (string, bool) { return "", false }, false},
		{"no persistent source", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, _ := vtCodeBridgeRegistry(t, gitBashView, true)
			reg.opts.WindowsPATH = tc.persistent
			assertShellWarning(t, reg.Register("vtcode-windows"), tc.wantWarn)
		})
	}
}

func assertShellWarning(t *testing.T, res RegistrationResult, want bool) {
	t.Helper()
	if !want {
		if len(res.Warnings) != 0 {
			t.Fatalf("unexpected warnings: %v", res.Warnings)
		}
		return
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("warnings = %v, want one", res.Warnings)
	}
	for _, s := range []string{"VT Code runs hooks with `sh`", "sh.exe is not on the Windows PATH", "outside Git Bash", `C:\Program Files\Git\bin`} {
		if !strings.Contains(res.Warnings[0], s) {
			t.Errorf("warning %q missing %q", res.Warnings[0], s)
		}
	}
}

// TestVTCodeNativeShellWarning: a Windows observer's native vtcode target
// reads its own ';'-separated PATH; a Linux or macOS native target never
// warns (sh is part of the OS there).
func TestVTCodeNativeShellWarning(t *testing.T) {
	cases := []struct {
		name     string
		goos     string
		path     string
		wantWarn bool
	}{
		{"windows, only Git cmd", "windows", `C:\Windows\system32;` + winGitCmd, true},
		{"windows, Git bin (upper case)", "windows", `C:\WINDOWS\system32;C:\PROGRAM FILES\GIT\BIN`, false},
		{"windows, empty PATH is unknown", "windows", "", false},
		{"linux native never warns", "linux", "/usr/bin:" + wslGitCmd, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			env := map[string]string{"PATH": tc.path}
			reg, err := NewRegistry(Options{
				BinaryPath: "/opt/observer/bin/observer", HomeDir: home,
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
				Getenv:        func(k string) string { return env[k] },
				GOOS:          tc.goos,
				fileExists:    shellFS,
			})
			if err != nil {
				t.Fatal(err)
			}
			res := reg.Register("vtcode")
			if res.Error != nil || len(res.HooksAdded) == 0 {
				t.Fatalf("register: %+v", res)
			}
			assertShellWarning(t, res, tc.wantWarn)
		})
	}
}

// TestWindowsShellWarningOnlyForRequiringRows: a Windows target of a row
// without the capability (CodeBuddy's bridge) never warns, whatever the PATH.
func TestWindowsShellWarningOnlyForRequiringRows(t *testing.T) {
	home := t.TempDir()
	win := filepath.Join(home, "win")
	if err := os.MkdirAll(filepath.Join(win, ".codebuddy"), 0o755); err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry(Options{
		BinaryPath: "/opt/observer/bin/observer", HomeDir: home, WindowsUserHome: win, WSLDistro: "Ubuntu-T",
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		Getenv:        func(k string) string { return map[string]string{"PATH": "/usr/bin:" + wslGitCmd}[k] },
		GOOS:          "linux",
		fileExists:    shellFS,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := reg.Register("codebuddy-windows")
	if res.Error != nil {
		t.Fatalf("register: %+v", res)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("codebuddy-windows warned: %v", res.Warnings)
	}
}

// TestWindowsHookShellReports: the doctor's view of the vtcode-windows
// bridge, before and after registration.
func TestWindowsHookShellReports(t *testing.T) {
	reg, path := vtCodeBridgeRegistry(t, "/usr/bin:"+wslGitCmd, false)
	reps := reg.WindowsHookShellReports()
	if len(reps) != 1 || reps[0].Target != "vtcode-windows" {
		t.Fatalf("reports = %+v, want one vtcode-windows", reps)
	}
	if reps[0].Registered {
		t.Fatalf("registered before any write: %+v", reps[0])
	}
	if reps[0].Status != winshell.NotFound || reps[0].Warning == "" || reps[0].Shell != "sh" {
		t.Fatalf("report = %+v", reps[0])
	}
	if res := reg.Register("vtcode-windows"); res.Error != nil {
		t.Fatal(res.Error)
	}
	reps = reg.WindowsHookShellReports()
	if !reps[0].Registered || reps[0].ConfigPath != path {
		t.Fatalf("after register: %+v (want registered at %s)", reps[0], path)
	}

	// An entry written for another binary is no longer "already set" for this
	// one, but hook_checksums.json still records Observer's install.
	other, err := NewRegistry(Options{
		BinaryPath: "/opt/other/observer", HomeDir: reg.opts.HomeDir, WindowsUserHome: reg.opts.WindowsUserHome, WSLDistro: "Ubuntu-T",
		ChecksumsPath: reg.opts.ChecksumsPath, Getenv: reg.opts.Getenv, GOOS: "linux", fileExists: shellFS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reps := other.WindowsHookShellReports(); !reps[0].Registered {
		t.Fatalf("stale-binary entry not counted as registered: %+v", reps[0])
	}

	// A pinned home with no Windows user home suppresses crossmount, so the
	// bridge probe skips: listed, never Registered, and Unknown with no PATH.
	for _, r := range waveRegistry(t, t.TempDir(), "linux", nil, false).WindowsHookShellReports() {
		if r.Registered || r.Status != winshell.Unknown {
			t.Fatalf("sandboxed registry report: %+v", r)
		}
	}
}
