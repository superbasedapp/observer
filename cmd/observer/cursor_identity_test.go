//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termoob"
)

const cursorIdentityTestID = "42ec2be8-346b-4a72-8253-63f57e0ebf7f"

func activateCursorTestOOB(t *testing.T, dst io.Writer) {
	t.Helper()
	oobChanMu.Lock()
	previous := oobEncoder
	oobEncoder = termoob.NewEncoder(dst)
	oobChanMu.Unlock()
	t.Cleanup(func() {
		oobChanMu.Lock()
		oobEncoder = previous
		oobChanMu.Unlock()
	})
}

func writeCursorIdentityTestBin(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cursor-agent")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write fake cursor-agent: %v", err)
	}
	return path
}

func writeCursorIdentityTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.Join(dir, "observer.db") + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func readCursorIdentityLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	trimmed := strings.TrimSuffix(string(raw), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func TestCursorFreshLaunchEligible(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "bare interactive", want: true},
		{name: "prompt", args: []string{"implement the task exactly"}, want: true},
		{name: "known valued options", args: []string{
			"--model", "composer-1", "--workspace=/repo", "--sandbox", "enabled",
			"-H", "X-Test: value", "--mode", "agent", "initial prompt",
		}, want: true},
		{name: "safe booleans", args: []string{"--plan", "--force", "--trust", "prompt"}, want: true},
		{name: "cursor separator", args: []string{"--model", "composer-1", "--", "--resume", "literal prompt"}, want: true},
		{name: "wrapper resume translation", args: []string{"--resume=" + cursorIdentityTestID}, want: false},
		{name: "forwarded native resume joined", args: []string{"--resume=" + cursorIdentityTestID, "prompt"}, want: false},
		{name: "forwarded native resume separate", args: []string{"--resume", cursorIdentityTestID}, want: false},
		{name: "continue", args: []string{"--continue"}, want: false},
		{name: "short print", args: []string{"-p", "prompt"}, want: false},
		{name: "long print", args: []string{"--print", "prompt"}, want: false},
		{name: "help", args: []string{"--help"}, want: false},
		{name: "version", args: []string{"--version"}, want: false},
		{name: "list models", args: []string{"--list-models"}, want: false},
		{name: "optional worktree", args: []string{"--worktree"}, want: false},
		{name: "optional short worktree joined", args: []string{"-w=feature"}, want: false},
		{name: "unknown long option", args: []string{"--future-option", "value"}, want: false},
		{name: "unknown short option", args: []string{"-x", "value"}, want: false},
		{name: "grouped short options", args: []string{"-pf", "prompt"}, want: false},
		{name: "boolean joined value", args: []string{"--plan=true", "prompt"}, want: false},
		{name: "missing valued option", args: []string{"--model"}, want: false},
		{name: "ambiguous valued option", args: []string{"--model", "--sandbox", "enabled"}, want: false},
		{name: "empty joined value", args: []string{"--model="}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cursorFreshLaunchEligible(tc.args); got != tc.want {
				t.Fatalf("cursorFreshLaunchEligible(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}

	commands := make([]string, 0, len(cursorSubcommands))
	for subcommand := range cursorSubcommands {
		commands = append(commands, subcommand)
	}
	sort.Strings(commands)
	for _, subcommand := range commands {
		t.Run("subcommand "+subcommand, func(t *testing.T) {
			args := []string{"--model", "composer-1", subcommand}
			if cursorFreshLaunchEligible(args) {
				t.Fatalf("leading Cursor subcommand %q must skip fresh allocation", subcommand)
			}
		})
	}
}

func TestCursorFreshAllocationDir(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		childDir string
		want     string
		ok       bool
	}{
		{name: "inherits child directory", childDir: "/repo", want: "/repo", ok: true},
		{name: "absolute workspace", args: []string{"--model", "m", "--workspace", "/other/repo"}, childDir: "/repo", want: "/other/repo", ok: true},
		{name: "joined absolute workspace", args: []string{"--workspace=/other/repo"}, childDir: "/repo", want: "/other/repo", ok: true},
		{name: "saved workspace name is ambiguous", args: []string{"--workspace", "saved-name"}, childDir: "/repo", ok: false},
		{name: "relative workspace is ambiguous", args: []string{"--workspace=./other"}, childDir: "/repo", ok: false},
		{name: "duplicate workspace is ambiguous", args: []string{"--workspace=/one", "--workspace", "/two"}, childDir: "/repo", ok: false},
		{name: "prompt workspace after separator", args: []string{"--", "--workspace", "/prompt"}, childDir: "/repo", want: "/repo", ok: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := cursorFreshAllocationDir(tc.args, tc.childDir)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("cursorFreshAllocationDir(%q, %q) = (%q, %v), want (%q, %v)", tc.args, tc.childDir, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestAllocateCursorFreshSessionPreservesArgumentsAndDirectory(t *testing.T) {
	activateCursorTestOOB(t, io.Discard)
	workDir := t.TempDir()
	cwdPath := filepath.Join(t.TempDir(), "create-chat.cwd")
	callPath := filepath.Join(t.TempDir(), "create-chat.argv")
	bin := writeCursorIdentityTestBin(t,
		"printf '%s\\n' \"$PWD\" > "+cwdPath+"\n"+
			"printf '%s\\n' \"$@\" > "+callPath+"\n"+
			"printf '%s\\n' "+cursorIdentityTestID)
	original := []string{
		"--model", "composer-1", "--workspace", workDir, "--sandbox", "enabled",
		"--header", "X-Test: value", "initial prompt remains byte exact",
	}

	got, id, err := allocateCursorFreshSession(context.Background(), bin, workDir, original)
	if err != nil {
		t.Fatalf("allocateCursorFreshSession: %v", err)
	}
	if id != cursorIdentityTestID {
		t.Fatalf("session id = %q, want %q", id, cursorIdentityTestID)
	}
	want := append([]string{"--resume=" + cursorIdentityTestID}, original...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allocated argv = %#v, want %#v", got, want)
	}
	if calls := readCursorIdentityLines(t, callPath); !reflect.DeepEqual(calls, []string{"create-chat"}) {
		t.Fatalf("allocator argv = %#v, want create-chat only", calls)
	}
	if cwd := readCursorIdentityLines(t, cwdPath); !reflect.DeepEqual(cwd, []string{workDir}) {
		t.Fatalf("allocator cwd = %#v, want %q", cwd, workDir)
	}
}

func TestAllocateCursorFreshSessionRejectsUntrustedOutput(t *testing.T) {
	activateCursorTestOOB(t, io.Discard)
	bin := writeCursorIdentityTestBin(t, `
case "${CURSOR_TEST_MODE:-}" in
  empty) exit 0 ;;
  malformed) printf '%s\n' 'not-a-uuid' ;;
  uppercase) printf '%s\n' '42EC2BE8-346B-4A72-8253-63F57E0EBF7F' ;;
  extra) printf '%s\n%s\n' '`+cursorIdentityTestID+`' 'extra-line' ;;
  no-newline) printf '%s' '`+cursorIdentityTestID+`' ;;
  stderr) printf '%s\n' '`+cursorIdentityTestID+`'; printf '%s' 'vendor-private-detail' >&2 ;;
  nonzero) printf '%s' 'vendor-private-detail' >&2; exit 7 ;;
  oversized-stdout) printf '%0300d\n' 0 ;;
  oversized-stderr) printf '%s\n' '`+cursorIdentityTestID+`'; printf '%0300d' 0 >&2 ;;
  timeout) exec sleep 5 ;;
esac`)
	tests := []struct {
		mode string
		want string
	}{
		{mode: "empty", want: "empty output"},
		{mode: "malformed", want: "invalid id"},
		{mode: "uppercase", want: "invalid id"},
		{mode: "extra", want: "unexpected output"},
		{mode: "no-newline", want: "unexpected output"},
		{mode: "nonzero", want: "allocation failed"},
		{mode: "oversized-stdout", want: "oversized output"},
		{mode: "oversized-stderr", want: "oversized output"},
		{mode: "timeout", want: "timed out"},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("CURSOR_TEST_MODE", tc.mode)
			args := []string{"--model", "composer-1", "prompt"}
			got, id, err := allocateCursorFreshSessionWithConfig(
				context.Background(), bin, "", args,
				cursorCreateChatConfig{timeout: 60 * time.Millisecond, outputLimit: 256, waitDelay: 20 * time.Millisecond},
			)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want category %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "vendor-private-detail") {
				t.Fatalf("error leaked captured vendor output: %v", err)
			}
			if id != "" || !reflect.DeepEqual(got, args) {
				t.Fatalf("failed allocation returned id=%q argv=%#v, want empty id and original argv", id, got)
			}
		})
	}
}

func TestAllocateCursorFreshSessionAllowsBoundedStderrWarning(t *testing.T) {
	activateCursorTestOOB(t, io.Discard)
	bin := writeCursorIdentityTestBin(t,
		"printf '%s\\n' "+cursorIdentityTestID+"\n"+
			"printf '%s\\n' 'benign runtime warning' >&2")
	args := []string{"prompt"}
	got, id, err := allocateCursorFreshSession(context.Background(), bin, "", args)
	if err != nil {
		t.Fatalf("bounded stderr warning rejected: %v", err)
	}
	if id != cursorIdentityTestID {
		t.Fatalf("session id = %q, want %q", id, cursorIdentityTestID)
	}
	want := []string{"--resume=" + cursorIdentityTestID, "prompt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %#v, want %#v", got, want)
	}
}

func TestAllocateCursorFreshSessionRequiresOOB(t *testing.T) {
	args := []string{"prompt"}
	got, id, err := allocateCursorFreshSession(context.Background(), filepath.Join(t.TempDir(), "missing"), "", args)
	if err != nil || id != "" || !reflect.DeepEqual(got, args) {
		t.Fatalf("no-OOB allocation = argv %#v id %q err %v, want untouched no-op", got, id, err)
	}
}

func TestCursorFreshAllocationLaunchesAndAnnouncesAfterStart(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	nextOOB := oobCapture(t)
	dir := t.TempDir()
	callsPath := filepath.Join(dir, "calls")
	argvPath := filepath.Join(dir, "interactive.argv")
	bin := writeCursorIdentityTestBin(t, `
printf '%s\n' "$1" >> `+callsPath+`
if [ "$1" = create-chat ]; then
  printf '%s\n' '`+cursorIdentityTestID+`'
  exit 0
fi
: > `+argvPath+`
for arg in "$@"; do printf '%s\n' "$arg" >> `+argvPath+`; done`)
	cfgPath := writeCursorIdentityTestConfig(t)
	original := []string{
		"--model", "composer-1", "--workspace", dir, "--sandbox", "enabled",
		"--header", "X-Test: value", "initial prompt remains byte exact",
	}

	cmd := newCursorCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs(append([]string{
		"--config", cfgPath, "--cursor-agent-path", bin, "--no-attach",
	}, original...))
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cursor command: %v (output %q)", err, output.String())
	}
	if announced := nextOOB(); announced != cursorIdentityTestID {
		t.Fatalf("announced id = %q, want %q", announced, cursorIdentityTestID)
	}
	wantArgv := append([]string{"--resume=" + cursorIdentityTestID}, original...)
	if got := readCursorIdentityLines(t, argvPath); !reflect.DeepEqual(got, wantArgv) {
		t.Fatalf("interactive argv = %#v, want %#v", got, wantArgv)
	}
	if calls := readCursorIdentityLines(t, callsPath); !reflect.DeepEqual(calls, []string{"create-chat", "--resume=" + cursorIdentityTestID}) {
		t.Fatalf("process calls = %#v, want allocator then interactive", calls)
	}
}

func TestCursorWrapperResumeUsesExistingPathWithoutAllocation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	nextOOB := oobCapture(t)
	dir := t.TempDir()
	callsPath := filepath.Join(dir, "calls")
	bin := writeCursorIdentityTestBin(t, `
printf '%s\n' "$@" > `+callsPath)
	cfgPath := writeCursorIdentityTestConfig(t)

	cmd := newCursorCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{
		"--config", cfgPath, "--cursor-agent-path", bin, "--no-attach",
		"--resume", cursorIdentityTestID, "--model", "composer-1",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cursor resume command: %v (output %q)", err, output.String())
	}
	if announced := nextOOB(); announced != cursorIdentityTestID {
		t.Fatalf("announced resume id = %q, want %q", announced, cursorIdentityTestID)
	}
	want := []string{"--resume=" + cursorIdentityTestID, "--model", "composer-1"}
	if got := readCursorIdentityLines(t, callsPath); !reflect.DeepEqual(got, want) {
		t.Fatalf("resume argv = %#v, want one native process with %#v", got, want)
	}
}

func TestCursorUserCreateChatRunsExactlyOnce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	activateCursorTestOOB(t, io.Discard)
	dir := t.TempDir()
	callsPath := filepath.Join(dir, "calls")
	bin := writeCursorIdentityTestBin(t, `printf '%s\n' "$@" >> `+callsPath)
	cfgPath := writeCursorIdentityTestConfig(t)

	cmd := newCursorCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"--config", cfgPath, "--cursor-agent-path", bin, "--no-attach", "create-chat"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("user create-chat: %v (output %q)", err, output.String())
	}
	if got := readCursorIdentityLines(t, callsPath); !reflect.DeepEqual(got, []string{"create-chat"}) {
		t.Fatalf("user create-chat invocations = %#v, want exactly one", got)
	}
}

func TestCursorAllocationFailurePreventsInteractiveStartAndHidesOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var oob bytes.Buffer
	activateCursorTestOOB(t, &oob)
	dir := t.TempDir()
	callsPath := filepath.Join(dir, "calls")
	bin := writeCursorIdentityTestBin(t, `
printf '%s\n' "$1" >> `+callsPath+`
if [ "$1" = create-chat ]; then
  printf '%s' 'vendor-private-detail' >&2
  exit 9
fi`)
	cfgPath := writeCursorIdentityTestConfig(t)

	cmd := newCursorCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"--config", cfgPath, "--cursor-agent-path", bin, "--no-attach", "prompt"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "fresh chat allocation failed") {
		t.Fatalf("allocation error = %v, want honest allocation failure", err)
	}
	if strings.Contains(err.Error(), "vendor-private-detail") || strings.Contains(output.String(), "vendor-private-detail") {
		t.Fatalf("captured vendor output leaked: err=%v output=%q", err, output.String())
	}
	if got := readCursorIdentityLines(t, callsPath); !reflect.DeepEqual(got, []string{"create-chat"}) {
		t.Fatalf("calls after failed allocation = %#v, want no interactive spawn", got)
	}
	if oob.Len() != 0 {
		t.Fatalf("failed allocation emitted an OOB frame")
	}
}

func TestCursorInteractiveStartFailureDoesNotAnnounce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var oob bytes.Buffer
	activateCursorTestOOB(t, &oob)
	dir := t.TempDir()
	callsPath := filepath.Join(dir, "calls")
	bin := writeCursorIdentityTestBin(t, `
printf '%s\n' "$1" >> `+callsPath+`
if [ "$1" = create-chat ]; then
  printf '%s\n' '`+cursorIdentityTestID+`'
  rm -- "$0"
  exit 0
fi`)
	cfgPath := writeCursorIdentityTestConfig(t)

	cmd := newCursorCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"--config", cfgPath, "--cursor-agent-path", bin, "--no-attach", "prompt"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "exec cursor-agent") {
		t.Fatalf("interactive start error = %v, want start failure", err)
	}
	if got := readCursorIdentityLines(t, callsPath); !reflect.DeepEqual(got, []string{"create-chat"}) {
		t.Fatalf("calls = %#v, want only successful allocation", got)
	}
	if oob.Len() != 0 {
		t.Fatalf("interactive Start failure emitted an OOB frame")
	}
}

func TestCursorBudgetAdmissionPrecedesFreshAllocation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	activateCursorTestOOB(t, io.Discard)
	cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
	dir := t.TempDir()
	callsPath := filepath.Join(dir, "calls")
	bin := writeCursorIdentityTestBin(t, `printf '%s\n' "$@" >> `+callsPath)

	cmd := newCursorCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"--config", cfgPath, "--cursor-agent-path", bin, "--no-attach", "prompt"})
	err := cmd.Execute()
	if !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("budget admission error = %v, want %v", err, errBudgetLaunchUncontrolled)
	}
	if _, statErr := os.Stat(callsPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("cursor process ran before budget refusal: %v", statErr)
	}
}
