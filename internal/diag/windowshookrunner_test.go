package diag

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeRunnerProbe builds a windowsRunnerProbe from plain maps, so every case
// is GOOS-independent and nothing shells out.
type fakeRunnerProbe struct {
	goos     string
	env      map[string]string // nil: no Windows environment
	path     string            // "" with pathOK false: no Windows PATH visible
	pathOK   bool
	onPath   map[string]string // bare name -> resolved path
	files    map[string]bool
	policies map[string]string // exe -> ListScript output
	readErr  map[string]error
	present  map[string]string // target -> config path
	reads    []string
}

func (f *fakeRunnerProbe) probe() windowsRunnerProbe {
	p := windowsRunnerProbe{
		goos:        f.goos,
		windowsPATH: func() (string, bool) { return f.path, f.pathOK },
		lookPath: func(name string) (string, error) {
			if v, ok := f.onPath[name]; ok {
				return v, nil
			}
			return "", errors.New("not found")
		},
		exists: func(p string) bool { return f.files[p] },
		readPolicy: func(_ context.Context, exe string) (string, error) {
			f.reads = append(f.reads, exe)
			if err := f.readErr[exe]; err != nil {
				return "", err
			}
			if out, ok := f.policies[exe]; ok {
				return out, nil
			}
			return "", errors.New("no such PowerShell")
		},
		present: func(target string) (string, bool) {
			cfg, ok := f.present[target]
			return cfg, ok
		},
	}
	if f.env != nil {
		p.getenv = func(k string) string { return f.env[k] }
	}
	return p
}

const (
	winPowerShell = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	winPwsh7      = `C:\Program Files\PowerShell\7\pwsh.exe`
	wslPowerShell = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
)

func policyOut(machine, current string) string {
	return "MachinePolicy=" + machine + "\r\nUserPolicy=Undefined\r\nProcess=Undefined\r\nCurrentUser=" + current + "\r\nLocalMachine=Undefined\r\n"
}

// findCheck returns the check named name, or nil.
func findCheck(checks []Check, name string) *Check {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}

// TestExecutionPolicyChecks covers the PowerShell-script runner (gap review
// W-8): the old doctor had no such row at all, so every WARN case here is red
// on it.
func TestExecutionPolicyChecks(t *testing.T) {
	diracCfg := `C:\Users\u\.dirac\Hooks\PreToolUse.ps1`
	winBase := func() *fakeRunnerProbe {
		return &fakeRunnerProbe{
			goos:     "windows",
			env:      map[string]string{"ProgramFiles": `C:\Program Files`},
			onPath:   map[string]string{"powershell.exe": winPowerShell},
			files:    map[string]bool{},
			policies: map[string]string{},
			present:  map[string]string{"dirac": diracCfg},
		}
	}
	cases := []struct {
		name       string
		build      func() *fakeRunnerProbe
		check      string
		wantRow    bool
		wantStatus Status
		wantIn     []string
		wantFirst  string // first PowerShell read
	}{
		{
			name: "Group Policy AllSigned overrides the host's Bypass and Dirac fails open",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.policies[winPowerShell] = policyOut("AllSigned", "Undefined")
				return f
			},
			check: "dirac.hooks.execution_policy", wantRow: true, wantStatus: StatusWarn,
			wantIn: []string{"AllSigned", "MachinePolicy scope (Group Policy)", "overrides the host's -ExecutionPolicy Bypass", "fails open", "RemoteSigned"},
		},
		{
			name: "Group Policy Restricted at UserPolicy warns",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.policies[winPowerShell] = "MachinePolicy=Undefined\nUserPolicy=Restricted\n"
				return f
			},
			check: "dirac.hooks.execution_policy", wantRow: true, wantStatus: StatusWarn,
			wantIn: []string{"Restricted", "UserPolicy scope (Group Policy)", "sign Observer's hook scripts"},
		},
		{
			name: "a local AllSigned does not block a host that passes Bypass",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.policies[winPowerShell] = policyOut("Undefined", "AllSigned")
				return f
			},
			check: "dirac.hooks.execution_policy", wantRow: true, wantStatus: StatusOK,
			wantIn: []string{"Bypass", "Process scope"},
		},
		{
			name: "Group Policy RemoteSigned runs a locally written script",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.policies[winPowerShell] = policyOut("RemoteSigned", "Undefined")
				return f
			},
			check: "dirac.hooks.execution_policy", wantRow: true, wantStatus: StatusOK,
			wantIn: []string{"RemoteSigned", "Group Policy"},
		},
		{
			name: "PowerShell 7 is what the host picks, so its policy store decides",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.files[winPwsh7] = true
				f.policies[winPwsh7] = policyOut("RemoteSigned", "Undefined")
				f.policies[winPowerShell] = policyOut("AllSigned", "Undefined")
				return f
			},
			check: "dirac.hooks.execution_policy", wantRow: true, wantStatus: StatusOK,
			wantIn: []string{"RemoteSigned"}, wantFirst: winPwsh7,
		},
		{
			name: "a PowerShell that cannot answer is skipped like the host skips it",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.files[winPwsh7] = true
				f.readErr = map[string]error{winPwsh7: errors.New("exit status 1")}
				f.policies[winPowerShell] = policyOut("AllSigned", "Undefined")
				return f
			},
			check: "dirac.hooks.execution_policy", wantRow: true, wantStatus: StatusWarn,
			wantIn: []string{"AllSigned"}, wantFirst: winPwsh7,
		},
		{
			name: "no PowerShell answers: say so",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.readErr = map[string]error{winPowerShell: errors.New("timeout")}
				return f
			},
			check: "dirac.hooks.execution_policy", wantRow: true, wantStatus: StatusWarn,
			wantIn: []string{"could not read the PowerShell execution policy", "timeout"},
		},
		{
			name: "an unknown value is not classified",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.policies[winPowerShell] = policyOut("Shiny", "Undefined")
				return f
			},
			check: "dirac.hooks.execution_policy", wantRow: true, wantStatus: StatusWarn,
			wantIn: []string{"Shiny", "not a value Observer classifies"},
		},
		{
			name: "Observer's hook scripts are not there: no row",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.present = map[string]string{}
				f.policies[winPowerShell] = policyOut("AllSigned", "Undefined")
				return f
			},
			check: "dirac.hooks.execution_policy",
		},
		{
			name: "no PowerShell visible: no row",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.onPath = map[string]string{}
				return f
			},
			check: "dirac.hooks.execution_policy",
		},
		{
			name: "from WSL the -windows bridge is checked through interop",
			build: func() *fakeRunnerProbe {
				return &fakeRunnerProbe{
					goos:     "linux",
					onPath:   map[string]string{"powershell.exe": wslPowerShell},
					files:    map[string]bool{},
					policies: map[string]string{wslPowerShell: policyOut("AllSigned", "Undefined")},
					present:  map[string]string{"dirac-windows": "/mnt/c/Users/u/.dirac/Hooks/PreToolUse.ps1"},
				}
			},
			check: "dirac-windows.hooks.execution_policy", wantRow: true, wantStatus: StatusWarn,
			wantIn: []string{"AllSigned", "fails open"}, wantFirst: wslPowerShell,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.build()
			got := windowsHookRunnerChecks(context.Background(), f.probe())
			c := findCheck(got, tc.check)
			if !tc.wantRow {
				if c != nil {
					t.Fatalf("want no %s row, got %+v", tc.check, *c)
				}
				return
			}
			if c == nil {
				t.Fatalf("no %s row in %+v", tc.check, got)
			}
			if c.Status != tc.wantStatus {
				t.Errorf("status = %s, want %s (%s)", c.Status, tc.wantStatus, c.Message)
			}
			text := c.Message + "\n" + strings.Join(c.Details, "\n")
			for _, w := range tc.wantIn {
				if !strings.Contains(text, w) {
					t.Errorf("row text missing %q:\n%s", w, text)
				}
			}
			if tc.wantFirst != "" && (len(f.reads) == 0 || f.reads[0] != tc.wantFirst) {
				t.Errorf("first PowerShell read = %v, want %s", f.reads, tc.wantFirst)
			}
			if !strings.Contains(text, "never changes") {
				t.Errorf("row does not say Observer never changes the policy:\n%s", text)
			}
			r := Report{Checks: []Check{*c}}
			if len(r.Filter("dirac").Checks) != 1 || len(r.Filter("hooks").Checks) != 1 {
				t.Errorf("filter did not keep %q", c.Name)
			}
		})
	}
}

// TestGitBashChecks covers the Git Bash runner (gap review S-19): the old
// doctor had no CodeBuddy row, so every row here is red on it.
func TestGitBashChecks(t *testing.T) {
	winCfg := `C:\Users\u\.codebuddy\settings.json`
	winBash := `C:\Program Files\Git\bin\bash.exe`
	winBase := func() *fakeRunnerProbe {
		return &fakeRunnerProbe{
			goos:    "windows",
			env:     map[string]string{"ProgramFiles": `C:\Program Files`},
			path:    `C:\Windows\System32;C:\Windows`,
			pathOK:  true,
			files:   map[string]bool{},
			present: map[string]string{"codebuddy": winCfg},
		}
	}
	cases := []struct {
		name       string
		build      func() *fakeRunnerProbe
		check      string
		wantRow    bool
		wantStatus Status
		wantIn     []string
	}{
		{
			name: "the override names an existing bash.exe",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.env["CODEBUDDY_CODE_GIT_BASH_PATH"] = `D:\tools\git\bin\bash.exe`
				f.files[`D:\tools\git\bin\bash.exe`] = true
				return f
			},
			check: "codebuddy.hooks.git_bash", wantRow: true, wantStatus: StatusOK,
			wantIn: []string{`D:\tools\git\bin\bash.exe`, "CODEBUDDY_CODE_GIT_BASH_PATH"},
		},
		{
			name: "the override names a missing file",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.env["CODEBUDDY_CODE_GIT_BASH_PATH"] = `D:\gone\bash.exe`
				f.files[winBash] = true
				return f
			},
			check: "codebuddy.hooks.git_bash", wantRow: true, wantStatus: StatusWarn,
			wantIn: []string{`D:\gone\bash.exe`, "does not exist", "not verified"},
		},
		{
			name: "bash.exe beside the git.exe on the Windows PATH",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.path = `C:\Windows\System32;C:\Program Files\Git\cmd`
				f.files[`C:\Program Files\Git\cmd\git.exe`] = true
				f.files[winBash] = true
				f.env["ProgramFiles"] = `C:\Elsewhere`
				return f
			},
			check: "codebuddy.hooks.git_bash", wantRow: true, wantStatus: StatusOK,
			wantIn: []string{winBash, `Git\cmd\git.exe`},
		},
		{
			name: "the default Git for Windows directory",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.files[winBash] = true
				return f
			},
			check: "codebuddy.hooks.git_bash", wantRow: true, wantStatus: StatusOK,
			wantIn: []string{winBash, "default"},
		},
		{
			name: "no Git for Windows anywhere warns with the fix",
			build: func() *fakeRunnerProbe {
				return winBase()
			},
			check: "codebuddy.hooks.git_bash", wantRow: true, wantStatus: StatusWarn,
			wantIn: []string{"Git Bash", "found no bash.exe", "install Git for Windows", "CODEBUDDY_CODE_GIT_BASH_PATH", "not documented"},
		},
		{
			name: "from WSL: bash.exe beside git.exe on the interop PATH",
			build: func() *fakeRunnerProbe {
				return &fakeRunnerProbe{
					goos:   "linux",
					path:   "/usr/bin:/mnt/c/Program Files/Git/cmd",
					pathOK: true,
					files: map[string]bool{
						"/mnt/c/Program Files/Git/cmd/git.exe":  true,
						"/mnt/c/Program Files/Git/bin/bash.exe": true,
					},
					present: map[string]string{"codebuddy-windows": "/mnt/c/Users/u/.codebuddy/settings.json"},
				}
			},
			check: "codebuddy-windows.hooks.git_bash", wantRow: true, wantStatus: StatusOK,
			wantIn: []string{"/mnt/c/Program Files/Git/bin/bash.exe", "not visible from WSL"},
		},
		{
			name: "from WSL with no Windows PATH and no default: no row",
			build: func() *fakeRunnerProbe {
				return &fakeRunnerProbe{
					goos:    "linux",
					files:   map[string]bool{},
					present: map[string]string{"codebuddy-windows": "/mnt/c/Users/u/.codebuddy/settings.json"},
				}
			},
			check: "codebuddy-windows.hooks.git_bash",
		},
		{
			name: "Observer's hooks are not there: no row",
			build: func() *fakeRunnerProbe {
				f := winBase()
				f.present = map[string]string{}
				return f
			},
			check: "codebuddy.hooks.git_bash",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := windowsHookRunnerChecks(context.Background(), tc.build().probe())
			c := findCheck(got, tc.check)
			if !tc.wantRow {
				if c != nil {
					t.Fatalf("want no %s row, got %+v", tc.check, *c)
				}
				return
			}
			if c == nil {
				t.Fatalf("no %s row in %+v", tc.check, got)
			}
			if c.Status != tc.wantStatus {
				t.Errorf("status = %s, want %s (%s)", c.Status, tc.wantStatus, c.Message)
			}
			text := c.Message + "\n" + strings.Join(c.Details, "\n")
			for _, w := range tc.wantIn {
				if !strings.Contains(text, w) {
					t.Errorf("row text missing %q:\n%s", w, text)
				}
			}
			r := Report{Checks: []Check{*c}}
			if len(r.Filter("codebuddy").Checks) != 1 || len(r.Filter("hooks").Checks) != 1 {
				t.Errorf("filter did not keep %q", c.Name)
			}
		})
	}
}

// TestCheckWindowsHookRunnersSandboxed: a sandboxed doctor run (pinned home)
// reads no environment, no foreign home and runs no PowerShell.
func TestCheckWindowsHookRunnersSandboxed(t *testing.T) {
	if got := checkWindowsHookRunners(context.Background(), t.TempDir(), "/opt/observer/bin/observer", nil); len(got) != 0 {
		t.Fatalf("sandboxed run reported %+v", got)
	}
}

// TestWindowsHookRunnerNoToolLiteral: the doctor dispatches on the row's
// Kind, never on a tool name.
func TestWindowsHookRunnerNoToolLiteral(t *testing.T) {
	src, err := os.ReadFile("windowshookrunner.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, lit := range []string{`"dirac"`, `"codebuddy"`, `"vtcode"`} {
		if strings.Contains(string(src), lit) {
			t.Errorf("windowshookrunner.go names the tool literal %s", lit)
		}
	}
}

func TestExpandWindowsVars(t *testing.T) {
	env := map[string]string{"ProgramFiles": `C:\Program Files`}
	get := func(k string) string { return env[k] }
	cases := []struct {
		in, want string
		ok       bool
	}{
		{`%ProgramFiles%\Git\bin\bash.exe`, `C:\Program Files\Git\bin\bash.exe`, true},
		{`plain`, `plain`, true},
		{`%Missing%\x`, "", false},
		{`%Unclosed`, "", false},
	}
	for _, tc := range cases {
		got, ok := expandWindowsVars(tc.in, get)
		if got != tc.want || ok != tc.ok {
			t.Errorf("expandWindowsVars(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
