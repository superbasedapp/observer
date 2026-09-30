package shellwrap

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// shimFixture is a throwaway PATH world: a shim dir, a dir holding the
// "real" vendor binary, and a fake observer that records its argv.
type shimFixture struct {
	root, shimDir, realDir, obsPath, log string
}

func writeExec(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatal(err)
	}
}

func newShimFixture(t *testing.T) shimFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shim execution test")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	root := t.TempDir()
	f := shimFixture{
		root:    root,
		shimDir: filepath.Join(root, "shims"),
		realDir: filepath.Join(root, "real"),
		obsPath: filepath.Join(root, "obs", "observer"),
		log:     filepath.Join(root, "log"),
	}
	// The real vendor binary: records that IT ran, with its argv.
	writeExec(t, filepath.Join(f.realDir, "claude"), "#!/bin/sh\nprintf 'real %s\\n' \"$*\" >> '"+f.log+"'\n")
	// The fake observer: records its argv.
	writeExec(t, f.obsPath, "#!/bin/sh\nprintf 'observer %s|guard=%s\\n' \"$*\" \"$SBO_SHIM_GUARD\" >> '"+f.log+"'\n")
	return f
}

func (f shimFixture) install(t *testing.T, s ShimSpec) {
	t.Helper()
	s.ShimDir, s.ObserverPath = f.shimDir, f.obsPath
	body, err := RenderPOSIXShim(s)
	if err != nil {
		t.Fatalf("RenderPOSIXShim: %v", err)
	}
	writeExec(t, filepath.Join(f.shimDir, s.Name), body)
}

// run executes the command through PATH (shim dir first) and returns the log.
func (f shimFixture) run(t *testing.T, env []string, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(filepath.Join(f.shimDir, name), args...) //nolint:gosec // test
	cmd.Env = append([]string{"PATH=" + f.shimDir + ":" + f.realDir + ":/usr/bin:/bin"}, env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v (stderr %s)", err, stderr.String())
	}
	b, _ := os.ReadFile(f.log)
	_ = os.Remove(f.log)
	return string(b), code
}

var cliSpec = ShimSpec{Name: "claude", ToolID: "claude-code", Kind: integration.LaunchKindTerminal, Args: []string{"claude"}}

func TestPOSIXShimRunsObserverWithPassthroughArgs(t *testing.T) {
	f := newShimFixture(t)
	f.install(t, cliSpec)
	got, code := f.run(t, nil, "claude", "--model", "a b", "-p")
	if code != 0 || got != "observer claude -- --model a b -p|guard=claude\n" {
		t.Fatalf("code=%d log=%q", code, got)
	}
}

func TestPOSIXShimFallsBackToRealWhenObserverMissing(t *testing.T) {
	f := newShimFixture(t)
	f.install(t, cliSpec)
	if err := os.Remove(f.obsPath); err != nil {
		t.Fatal(err)
	}
	got, code := f.run(t, nil, "claude", "x")
	if code != 0 || got != "real x\n" {
		t.Fatalf("never locked out: code=%d log=%q", code, got)
	}
}

func TestPOSIXShimBypass(t *testing.T) {
	f := newShimFixture(t)
	f.install(t, cliSpec)
	got, _ := f.run(t, []string{BypassEnv + "=1"}, "claude", "y")
	if got != "real y\n" {
		t.Fatalf("log=%q", got)
	}
}

// TestPOSIXShimRecursionGuard: an observer that resolves back into the shim
// (the failure the resolver's exclusion prevents) must terminate at the real
// binary, not loop.
func TestPOSIXShimRecursionGuard(t *testing.T) {
	f := newShimFixture(t)
	f.install(t, cliSpec)
	writeExec(t, f.obsPath, "#!/bin/sh\nprintf 'observer %s\\n' \"$*\" >> '"+f.log+"'\nshift; shift\nexec claude \"$@\"\n")
	got, code := f.run(t, nil, "claude", "z")
	if code != 0 || got != "observer claude -- z\nreal z\n" {
		t.Fatalf("code=%d log=%q", code, got)
	}
}

func TestPOSIXShimSkipsOtherShimsWhenResolvingReal(t *testing.T) {
	f := newShimFixture(t)
	f.install(t, cliSpec)
	// A second, stale shim dir between ours and the real one.
	other := filepath.Join(f.root, "stale-shims")
	body, _ := RenderPOSIXShim(ShimSpec{
		Name: "claude", ToolID: "claude-code", Kind: integration.LaunchKindTerminal,
		Args: []string{"claude"}, ShimDir: other, ObserverPath: "/nonexistent/observer",
	})
	writeExec(t, filepath.Join(other, "claude"), body)
	cmd := exec.Command(filepath.Join(f.shimDir, "claude"), "q") //nolint:gosec // test
	cmd.Env = []string{"PATH=" + f.shimDir + ":" + other + ":" + f.realDir + ":/usr/bin:/bin", BypassEnv + "=1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	b, _ := os.ReadFile(f.log)
	if string(b) != "real q\n" {
		t.Fatalf("log=%q", b)
	}
}

func TestPOSIXShimRealMissingIs127(t *testing.T) {
	f := newShimFixture(t)
	f.install(t, cliSpec)
	_ = os.Remove(filepath.Join(f.realDir, "claude"))
	_, code := f.run(t, []string{BypassEnv + "=1"}, "claude")
	if code != 127 {
		t.Fatalf("code=%d", code)
	}
}

func TestPOSIXGUIShimArgumentMapping(t *testing.T) {
	gui := ShimSpec{
		Name: "claude", ToolID: "vscode", Kind: integration.LaunchKindGUI,
		Args: []string{"ide", "vscode"}, ProjectDirArgv: true, HandoffSegments: []string{"remote-cli"},
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bare launch is wrapped", nil, "observer ide vscode|guard=claude\n"},
		{"a directory is the project dir", []string{"DIR"}, "observer ide vscode DIR|guard=claude\n"},
		{"a file is a CLI use - real", []string{"file.txt"}, "real file.txt\n"},
		{"flags are a CLI use - real", []string{"--version"}, "real --version\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newShimFixture(t)
			f.install(t, gui)
			args := tc.args
			want := tc.want
			if len(args) == 1 && args[0] == "DIR" {
				args = []string{f.root}
				want = strings.Replace(want, "DIR", f.root, 1)
			}
			got, _ := f.run(t, nil, "claude", args...)
			if got != want {
				t.Fatalf("log=%q want %q", got, want)
			}
		})
	}
}

func TestPOSIXGUIShimHandoffClientRunsReal(t *testing.T) {
	f := newShimFixture(t)
	f.install(t, ShimSpec{
		Name: "claude", ToolID: "vscode", Kind: integration.LaunchKindGUI,
		Args: []string{"ide", "vscode"}, ProjectDirArgv: true, HandoffSegments: []string{"remote-cli"},
	})
	handoff := filepath.Join(f.root, "server", "remote-cli")
	writeExec(t, filepath.Join(handoff, "claude"), "#!/bin/sh\nprintf 'handoff %s\\n' \"$*\" >> '"+f.log+"'\n")
	cmd := exec.Command(filepath.Join(f.shimDir, "claude")) //nolint:gosec // test
	cmd.Env = []string{"PATH=" + f.shimDir + ":" + handoff + ":/usr/bin:/bin"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	b, _ := os.ReadFile(f.log)
	if string(b) != "handoff \n" {
		t.Fatalf("a hand-off client must run unchanged: %q", b)
	}
}

func TestShimSpecValidation(t *testing.T) {
	base := ShimSpec{
		Name: "claude", ToolID: "claude-code", Kind: integration.LaunchKindTerminal,
		Args: []string{"claude"}, ObserverPath: "/o/observer", ShimDir: "/h/shims",
	}
	bad := map[string]func(s *ShimSpec){
		"name with slash":     func(s *ShimSpec) { s.Name = "a/b" },
		"name with space":     func(s *ShimSpec) { s.Name = "a b" },
		"name is observer":    func(s *ShimSpec) { s.Name = "observer" },
		"quote in args":       func(s *ShimSpec) { s.Args = []string{"cl'aude"} },
		"no args":             func(s *ShimSpec) { s.Args = nil },
		"newline in path":     func(s *ShimSpec) { s.ObserverPath = "/o/\nrm" },
		"double quote in dir": func(s *ShimSpec) { s.ShimDir = `/h/"x` },
		"bad segment":         func(s *ShimSpec) { s.HandoffSegments = []string{"a/b"} },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			s := base
			mut(&s)
			if _, err := RenderPOSIXShim(s); err == nil {
				t.Fatal("RenderPOSIXShim accepted an unsafe spec")
			}
			if _, err := RenderCmdShim(s); err == nil {
				t.Fatal("RenderCmdShim accepted an unsafe spec")
			}
		})
	}
	// A path with a single quote and spaces is quoted, not refused.
	s := base
	s.ObserverPath = "/Users/o'brien/my apps/observer"
	out, err := RenderPOSIXShim(s)
	if err != nil || !strings.Contains(out, `sbo_observer='/Users/o'\''brien/my apps/observer'`) {
		t.Fatalf("quoting: err=%v\n%s", err, out)
	}
}

func TestShimMarkerParses(t *testing.T) {
	s := ShimSpec{
		Name: "codex", ToolID: "codex", Kind: integration.LaunchKindTerminal, Args: []string{"codex"},
		ObserverPath: `C:\obs\observer.exe`, ShimDir: `C:\u\.observer\shims`,
	}
	for name, render := range map[string]func(ShimSpec) (string, error){"posix": RenderPOSIXShim, "cmd": RenderCmdShim} {
		out, err := render(s)
		if err != nil {
			t.Fatal(err)
		}
		if !IsShim([]byte(out[:min(len(out), 512)])) {
			t.Fatalf("%s: marker not within the first 512 bytes", name)
		}
		tool, cmd, ver, ok := ParseMarkerLine(out)
		if !ok || tool != "codex" || cmd != "codex" || ver != ShimVersion {
			t.Fatalf("%s: parsed %q %q %q %v", name, tool, cmd, ver, ok)
		}
	}
}

func TestCmdShimShape(t *testing.T) {
	s := ShimSpec{
		Name: "claude", ToolID: "claude-code", Kind: integration.LaunchKindTerminal, Args: []string{"claude"},
		ObserverPath: `C:\Program Files (x86)\100%\observer.exe`, ShimDir: `C:\u\.observer\shims`,
	}
	out, err := RenderCmdShim(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"@echo off\r\n",
		"setlocal\r\n",
		`"C:\Program Files (x86)\100%%\observer.exe" claude -- %*`, // % doubled, args passthrough
		`if defined SBO_SHIM_BYPASS goto sbo_real`,
		`if /i "%SBO_SHIM_GUARD%"=="claude" goto sbo_real`,
		`if not exist "C:\Program Files (x86)\100%%\observer.exe" (`,
		`where "$PATH:claude"`,
		`"%%~dpB"=="%~dp0"`, // skip the shim's own dir
		`findstr /m /c:"SBO-SHELLWRAP-SHIM"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cmd shim missing %q\n%s", want, out)
		}
	}
	if strings.Contains(strings.ReplaceAll(out, "\r\n", ""), "\n") {
		t.Error("cmd shim must use CRLF line endings")
	}
	gui := ShimSpec{
		Name: "Code", ToolID: "vscode", Kind: integration.LaunchKindGUI, Args: []string{"ide", "vscode"},
		ProjectDirArgv: true, HandoffSegments: []string{"remote-cli"}, ObserverPath: `C:\o\observer.exe`, ShimDir: `C:\s`,
	}
	out, err = RenderCmdShim(gui)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`if not "%SBO_REAL:\remote-cli\=%"=="%SBO_REAL%" goto sbo_real`,
		`"C:\o\observer.exe" ide vscode "%~1"`,
		`if "%~2"=="" if exist "%~1\" (`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("gui cmd shim missing %q\n%s", want, out)
		}
	}
}
