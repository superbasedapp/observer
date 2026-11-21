//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/termoob"
)

// sandbox_windows_run4_fix_test.go pins the fixes of the Windows 11 Pro run
// 4 of 2026-10-23 (mxc-process, MXC 1.0.1): the box could start observer.exe
// from its read-only bundle but cmd.exe could not run the read-only
// claude.cmd ("Access is denied."), because the policy granted none of the
// parents of the tool's directory; the in-box launcher logged no tool path
// or error; the attach decision took the daemon-spawned row inside the box;
// and the daemon warned once per launch about the CLI's relay readiness
// check.

// TestMXCRunDocumentEnumeratesTheToolsParents: with the host's support the
// run's document lists the parents of the tool's directory, the observer
// bundle, the workspace and the box directory enumerate-only, and never a
// grant; without it the document is unchanged.
func TestMXCRunDocumentEnumeratesTheToolsParents(t *testing.T) {
	iso := `C:\Users\w\AppData\Local\Temp\sbo-p6-iso-1`
	plan := mxcPlanFile{
		RunID: "r4", Workspace: iso + `\work`, Tier: "internet",
		ReadWrite: []string{iso + `\work`},
		ReadOnly:  []string{iso + `\bin`, `C:\p6live\p6live (3)`, iso + `\.observer\config.toml`},
		Denied:    []string{iso + `\.observer`},
	}
	box := `C:\Users\w\AppData\Local\Temp\observer-sbx-r4`
	inner := []string{`C:\p6live\p6live (3)\observer.exe`, "claude"}
	plain, err := mxcRunDocument(plan, box, box+`\tmp`, inner, []string{"A=1"}, 4321, false)
	if err != nil {
		t.Fatal(err)
	}
	if plain.ProcessContainer == nil || plain.ProcessContainer.Filesystem != nil {
		t.Fatalf("enumerate paths without the host's support: %+v", plain.ProcessContainer)
	}
	doc, err := mxcRunDocument(plan, box, box+`\tmp`, inner, []string{"A=1"}, 4321, true)
	if err != nil {
		t.Fatal(err)
	}
	if doc.ProcessContainer == nil || doc.ProcessContainer.Filesystem == nil {
		t.Fatal("no enumerate paths")
	}
	got := doc.ProcessContainer.Filesystem.EnumeratePaths
	for _, want := range []string{iso, `C:\Users\w\AppData\Local\Temp`, `C:\Users\w`, `C:\Users`, `C:\`, `C:\p6live`} {
		if !slices.Contains(got, want) {
			t.Errorf("%s is not enumerable: %q", want, got)
		}
	}
	for _, p := range got {
		for _, g := range append(append(append([]string(nil), doc.Filesystem.ReadwritePaths...), doc.Filesystem.ReadonlyPaths...), doc.Filesystem.DeniedPaths...) {
			if strings.EqualFold(p, g) || strings.HasPrefix(strings.ToLower(p), strings.ToLower(g)+`\`) {
				t.Errorf("enumerate path %s narrows the grant %s", p, g)
			}
		}
	}
	if !slices.Equal(doc.Filesystem.ReadonlyPaths, plain.Filesystem.ReadonlyPaths) || !slices.Equal(doc.Filesystem.ReadwritePaths, plain.Filesystem.ReadwritePaths) {
		t.Fatal("the grants changed")
	}
	if _, err := doc.Encode(); err != nil {
		t.Fatal(err)
	}
}

// TestSandboxCLIToolPath: the launcher's own binary-path flag, read from the
// command tree, names the tool a sandboxed CLI launch runs, and the plan
// grants that binary's directory like a pinned [launch.tools] path. The host
// env capture is stubbed (tracker F-031): toolBinDirs resolves through
// dashResolveEnv, and the real one started the developer's login shell.
func TestSandboxCLIToolPath(t *testing.T) {
	stubDashResolveEnv(t)
	if f := sandboxCLIBinaryPathFlag("claude"); f != "claude-path" {
		t.Fatalf("claude's binary-path flag: %q", f)
	}
	if f := sandboxCLIBinaryPathFlag("no-such-verb"); f != "" {
		t.Fatalf("an unknown verb: %q", f)
	}
	// A rooted path on the temp directory's volume: "\iso" alone is not
	// absolute on Windows (no drive), so it was joined to the cwd.
	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	cwd := filepath.Join(root+"w", "work")
	abs := filepath.Join(root+"iso", "bin", "claude.cmd")
	for name, c := range map[string]struct {
		rest []string
		want string
	}{
		"spaced":                 {[]string{"--model", "m", "--claude-path", abs}, abs},
		"joined":                 {[]string{"--claude-path=" + abs}, abs},
		"relative":               {[]string{"--claude-path", filepath.Join("bin", "claude.cmd")}, filepath.Join(cwd, "bin", "claude.cmd")},
		"after -- is the tool's": {[]string{"--", "--claude-path", abs}, ""},
		"absent":                 {[]string{"--model", "m"}, ""},
	} {
		if got := sandboxCLIToolPath("claude", c.rest, cwd); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	cfg := map[string]config.LaunchToolConfig{"codex": {Path: "/x/codex"}}
	tools := withLaunchToolPath(cfg, "claude-code", abs)
	if _, written := cfg["claude-code"]; written || tools["codex"].Path != "/x/codex" || tools["claude-code"].Path != abs {
		t.Fatalf("tools %+v, config %+v", tools, cfg)
	}
	r := &sandboxRuntime{launchTools: tools}
	if dirs := r.toolBinDirs("claude-code"); !slices.Contains(dirs, filepath.Dir(abs)) {
		t.Fatalf("the --claude-path directory is not granted: %v", dirs)
	}
}

// TestBoxToolLaunchLine: a failed tool launch names the resolved tool, its
// argv with secret values removed, and the Win32 code and message; the
// tool's own plain exit code is logged without a decoded error.
func TestBoxToolLaunchLine(t *testing.T) {
	msgs := map[uint32]string{5: "Access is denied.", 1114: "A dynamic link library (DLL) initialization routine failed."}
	msg := func(c uint32) string { return msgs[c] }
	bin := `C:\iso\bin\claude.cmd`
	args := []string{"--session-id", "s1", "--api-key", "sk-not-real", "--token=abc", "--model", "m"}
	for name, c := range map[string]struct {
		o     boxToolOutcome
		msg   func(uint32) string
		want  []string
		loud  bool
		never []string
	}{
		"did not start": {
			boxToolOutcome{StartErr: &os.PathError{Op: "fork/exec", Path: bin, Err: syscall.Errno(5)}},
			msg,
			[]string{`the tool C:\iso\bin\claude.cmd (argv ["--session-id" "s1" "--api-key" "[REDACTED]" "--token=[REDACTED]" "--model" "m"]) did not start`, "(Win32 error 5: Access is denied.)"},
			true, nil,
		},
		"no system text": {
			boxToolOutcome{StartErr: &os.PathError{Op: "fork/exec", Path: bin, Err: syscall.Errno(5)}},
			nil,
			[]string{"(Win32 error 5)"},
			true, nil,
		},
		"cmd.exe's own exit (run 4)": {boxToolOutcome{Exit: 1}, msg, []string{"exited with code 1"}, false, []string{"Win32", "0x"}},
		"the stand-in's answer":      {boxToolOutcome{Exit: 7}, msg, []string{"exited with code 7"}, false, []string{"Win32"}},
		"the .NET stand-in (run 4)": {
			boxToolOutcome{Exit: 2147943514},
			msg,
			[]string{"exited with code 2147943514 (0x8007045A: the HRESULT of Win32 error 1114: A dynamic link library (DLL) initialization routine failed.)"},
			true, nil,
		},
		"a loader failure": {boxToolOutcome{Exit: 3221225794}, msg, []string{"0xC0000142: an NTSTATUS error"}, true, nil},
		"no exit status":   {boxToolOutcome{Exit: -1}, msg, []string{"no exit status"}, true, nil},
		// Windows 11 Pro rerun 2026-10-25, D4: a forced stop is not a crash.
		"a forced stop": {boxToolOutcome{Exit: 4294967295}, msg, []string{"exited with code 4294967295 (0xFFFFFFFF: the process was stopped from outside"}, true, []string{"NTSTATUS", "crashed"}},
	} {
		line, loud := boxToolLaunchLine(bin, args, c.o, c.msg)
		for _, w := range c.want {
			if !strings.Contains(line, w) {
				t.Errorf("%s: %q lacks %q", name, line, w)
			}
		}
		for _, w := range append(c.never, "sk-not-real", "abc\"") {
			if strings.Contains(line, w) {
				t.Errorf("%s: %q carries %q", name, line, w)
			}
		}
		if loud != c.loud {
			t.Errorf("%s: loud %v", name, loud)
		}
	}
}

// TestNoteBoxToolLaunch: inside a box the line reaches the inner log and,
// for a failure the tool could not report, the terminal; outside a box,
// nothing.
func TestNoteBoxToolLaunch(t *testing.T) {
	start := &os.PathError{Op: "fork/exec", Path: `C:\iso\bin\claude.exe`, Err: syscall.Errno(5)}
	t.Setenv(sandboxInnerLogEnv, "")
	var out bytes.Buffer
	noteBoxToolLaunch(&out, "claude", `C:\iso\bin\claude.exe`, nil, start)
	if out.Len() != 0 {
		t.Fatalf("outside a box: %q", out.String())
	}
	logp := filepath.Join(t.TempDir(), mxcInnerLogName)
	t.Setenv(sandboxInnerLogEnv, logp)
	noteBoxToolLaunch(&out, "claude", `C:\iso\bin\claude.exe`, []string{"--session-id", "s1"}, nil)
	if out.Len() != 0 {
		t.Fatalf("a nil error printed: %q", out.String())
	}
	noteBoxToolLaunch(&out, "claude", `C:\iso\bin\claude.exe`, []string{"--session-id", "s1"}, start)
	b, err := os.ReadFile(logp)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{string(b), out.String()} {
		if !strings.Contains(s, `observer claude: the tool C:\iso\bin\claude.exe (argv ["--session-id" "s1"]) did not start`) || !strings.Contains(s, "Win32 error 5") {
			t.Errorf("line %q", s)
		}
	}
}

// TestAttachInsideTheBox: the box's own OOB stream to its host helper is not
// the daemon's spawn channel, so an in-box launcher with two terminals
// takes the sandbox row and prints the notice (run 4 took the daemon-spawned
// row and stayed silent); a dashboard sandbox terminal (the daemon-child
// marker in the box) stays silent; the inner log names the row.
func TestAttachInsideTheBox(t *testing.T) {
	oobChanMu.Lock()
	prevEnc, prevBox := oobEncoder, oobBoxClaims
	oobEncoder, oobBoxClaims = termoob.NewEncoder(io.Discard), true
	oobChanMu.Unlock()
	t.Cleanup(func() {
		oobChanMu.Lock()
		oobEncoder, oobBoxClaims = prevEnc, prevBox
		oobChanMu.Unlock()
	})
	if !oobChannelActive() || oobChannelSpawnedByDaemon() {
		t.Fatal("a box's OOB stream counted as the daemon's spawn channel")
	}
	oobChanMu.Lock()
	oobBoxClaims = false
	oobChanMu.Unlock()
	if !oobChannelSpawnedByDaemon() {
		t.Fatal("the daemon's own channel is not recognised")
	}

	run4 := attachDecisionInputs{
		enabled: true, defaultOn: true, grounded: true, stdinTTY: true, stdoutTTY: true,
		inSandbox: true, daemonSpawned: false, reachable: func() bool { return false },
	}
	d := decideAttach(run4)
	if d.attach() || d.notice != attachInSandboxNotice || d.row != attachRowSandbox {
		t.Fatalf("the run 4 box: %+v", d)
	}
	if got := attachDecisionNote(run4, d); got != "attach: launches without attach, notice printed (row: attach is not available inside the sandbox; stdin is a terminal: true, stdout is a terminal: true)" {
		t.Fatalf("note %q", got)
	}
	dash := run4
	dash.daemonChild = true
	if d := decideAttach(dash); d.attach() || d.notice != "" || d.row != attachRowDaemonSandbox {
		t.Fatalf("a dashboard sandbox terminal: %+v", d)
	}
	host := run4
	host.inSandbox, host.daemonChild = false, true
	if d := decideAttach(host); d.notice != attachDaemonChildNotice {
		t.Fatalf("a shell inside a daemon PTY on the host keeps its notice: %+v", d)
	}
	spawned := run4
	spawned.daemonSpawned = true
	if d := decideAttach(spawned); d.notice != "" || d.row != attachRowDaemonSpawned {
		t.Fatalf("the daemon's own inner launcher: %+v", d)
	}
	if got := attachDecisionNote(spawned, decideAttach(spawned)); !strings.Contains(got, "row: the daemon's own inner launcher;") {
		t.Fatalf("note %q", got)
	}
}
