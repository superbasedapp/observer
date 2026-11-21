package gitview

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestInteropEnvNamesOnlyTheEnvelope (R3-86): a Windows git started through
// WSL interop gets exactly the envelope's variables and the caller's extra
// ones in WSLENV; this process's WSLENV (which could forward GIT_DIR or a
// credential) and GIT_ASKPASS's Linux path never reach it.
func TestInteropEnvNamesOnlyTheEnvelope(t *testing.T) {
	base := []string{"PATH=/usr/bin", "WSLENV=GIT_DIR/p:SECRET_TOKEN", "GIT_DIR=/mnt/d/elsewhere/.git", "HOME=/home/dev"}
	set := append(interopEnvOverrides(), noLazyFetchEnv, "bad:name=x", "=nameless")
	got := interopEnv(base, set)
	var wslenv []string
	for _, kv := range got {
		if v, ok := strings.CutPrefix(kv, "WSLENV="); ok {
			wslenv = append(wslenv, v)
		}
	}
	if len(wslenv) != 1 {
		t.Fatalf("WSLENV entries = %q, want exactly one", wslenv)
	}
	want := "LC_ALL:GIT_OPTIONAL_LOCKS:GIT_TERMINAL_PROMPT:GIT_NO_LAZY_FETCH:" + strings.Join(interopClearedVars, ":")
	if wslenv[0] != want {
		t.Fatalf("WSLENV = %q, want %q", wslenv[0], want)
	}
	// Every cleared git variable crosses EMPTY, so a value the Windows user
	// set (or the daemon's own GIT_DIR from base) is unset for git.exe: Go's
	// exec keeps the last duplicate, which is the envelope's.
	for _, name := range interopClearedVars {
		if last := lastValue(got, name); last != "" {
			t.Fatalf("%s crosses as %q, want empty", name, last)
		}
	}
	for _, kv := range got {
		if strings.HasPrefix(kv, "GIT_ASKPASS=") || strings.HasPrefix(kv, "bad:name") {
			t.Fatalf("env carries %q", kv)
		}
	}
	if !slices.Contains(got, "PATH=/usr/bin") {
		t.Fatal("the Linux environment the interop launcher needs was dropped")
	}
}

func TestProgramBinary(t *testing.T) {
	if bin, dir := (Program{}).binary("/r"); bin != "git" || dir != "/r" {
		t.Fatalf("zero Program = %q -C %q", bin, dir)
	}
	p := Program{Path: "/mnt/c/Program Files/Git/cmd/git.exe", Dir: `D:\r`, Interop: true}
	if bin, dir := p.binary("/mnt/d/r"); bin != p.Path || dir != `D:\r` {
		t.Fatalf("Program = %q -C %q", bin, dir)
	}
}

// TestProgramThatCannotStartIsUnavailable: a named program that does not
// exist is ErrGitUnavailable (what the quick scan falls back on), from both
// the run and the version probe.
func TestProgramThatCannotStartIsUnavailable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-git.exe")
	_, _, err := RunReadOnlyNoLazyFetchProgram(context.Background(), t.TempDir(), Program{Path: missing}, 0, time.Second, nil, "status")
	if !errors.Is(err, ErrGitUnavailable) {
		t.Fatalf("run err = %v, want ErrGitUnavailable", err)
	}
	if _, err := ProgramVersion(context.Background(), Program{Path: missing}, time.Second); !errors.Is(err, ErrGitUnavailable) {
		t.Fatalf("version err = %v, want ErrGitUnavailable", err)
	}
	if _, err := ProgramVersion(context.Background(), Program{}, time.Second); err == nil {
		t.Fatal("ProgramVersion without a program succeeded")
	}
}

// lastValue is the value exec would use for name: the last duplicate wins.
func lastValue(env []string, name string) string {
	v := ""
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, name+"="); ok {
			v = rest
		}
	}
	return v
}

// TestInteropEnvKeepsACallersGitVariable: a git variable the caller sets on
// purpose is passed with its value, named once, not cleared.
func TestInteropEnvKeepsACallersGitVariable(t *testing.T) {
	got := interopEnv([]string{"PATH=/usr/bin"}, []string{"GIT_INDEX_FILE=D:/x/index"})
	if v := lastValue(got, "GIT_INDEX_FILE"); v != "D:/x/index" {
		t.Fatalf("GIT_INDEX_FILE = %q, want the caller's value", v)
	}
	var wslenv string
	for _, kv := range got {
		if v, ok := strings.CutPrefix(kv, "WSLENV="); ok {
			wslenv = v
		}
	}
	if n := strings.Count(":"+wslenv+":", ":GIT_INDEX_FILE:"); n != 1 {
		t.Fatalf("WSLENV %q names GIT_INDEX_FILE %d times, want once", wslenv, n)
	}
}
