package cloudsession

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestClaudeSetupScriptLinesRunFromAnyDirectory runs the lines `init` prints
// for the Claude Code environment's setup script with a real sh, from a
// directory outside the repository (the live 2026-11-03 failure: the setup
// script does not run in the clone). They must find the committed installer,
// run it from its repository, pick the first match in sorted order when two
// clones carry one, skip a copy under a pruned system tree, and only warn
// when none exists.
func TestClaudeSetupScriptLinesRunFromAnyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX sh and find")
	}
	for _, tool := range []string{"sh", "find", "sort", "head"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}
	// The installer stand-in records the directory it ran from.
	const installer = "#!/bin/sh\npwd > \"$SBO_MARK\"\n"
	cases := []struct {
		name     string
		repos    []string // directories (below the root) holding the installer
		want     string   // the repository it must run from, "" for none
		wantWarn bool
	}{
		{name: "clone under a home", repos: []string{"home/user/probe"}, want: "home/user/probe"},
		{name: "clone under root's home", repos: []string{"root/work/probe"}, want: "root/work/probe"},
		{name: "two clones, first sorted", repos: []string{"home/user/zeta", "home/user/alpha"}, want: "home/user/alpha"},
		{name: "pruned system tree ignored", repos: []string{"usr/share/probe"}, wantWarn: true},
		{name: "none found", wantWarn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, r := range tc.repos {
				p := filepath.Join(root, filepath.FromSlash(r), filepath.FromSlash(SetupScriptPath))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(installer), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			mark := filepath.Join(t.TempDir(), "ran-from")
			cmd := exec.Command("sh", "-c", claudeSetupScriptLines(root+"/"))
			cmd.Dir = t.TempDir() // not the repository
			cmd.Env = append(os.Environ(), "SBO_MARK="+mark)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("lines failed: %v\n%s", err, out)
			}
			if tc.wantWarn != strings.Contains(string(out), "no "+SetupScriptPath+" found") {
				t.Errorf("warning = %q, want warn %v", out, tc.wantWarn)
			}
			got, err := os.ReadFile(mark)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("an installer ran from %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("installer did not run: %v\n%s", err, out)
			}
			want, _ := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(tc.want)))
			gotDir, _ := filepath.EvalSymlinks(strings.TrimSpace(string(got)))
			if gotDir != want {
				t.Fatalf("ran from %q, want %q", gotDir, want)
			}
		})
	}
}

// TestClaudeSetupScriptLinesSearchTheWholeFilesystem pins the printed form:
// it searches from / (no assumed clone path) and calls the shared installer
// path, and init prints it as the Claude Code manual step.
func TestClaudeSetupScriptLinesSearchTheWholeFilesystem(t *testing.T) {
	if !strings.Contains(ClaudeSetupScriptLines, "find / -maxdepth 8") {
		t.Fatalf("lines do not search from /: %s", ClaudeSetupScriptLines)
	}
	if strings.Contains(ClaudeSetupScriptLines, "/home/user") {
		t.Fatalf("lines assume an undocumented clone path: %s", ClaudeSetupScriptLines)
	}
	a, err := AgentByID("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(a.ManualSteps, "\n"), ClaudeSetupScriptLines) {
		t.Fatalf("claude-code manual steps do not carry the lines: %v", a.ManualSteps)
	}
}
