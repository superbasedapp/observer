//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestSandboxCLIEndReason pins N3 (Windows 11 Pro run 4) for a sandboxed
// CLI launch: one row per way it ends.
func TestSandboxCLIEndReason(t *testing.T) {
	for _, c := range []struct {
		name      string
		goos      string
		requested string
		sig       os.Signal
		code      int
		want      string
	}{
		{"Windows: the console window's X (CTRL_CLOSE_EVENT is SIGTERM)", "windows", "", syscall.SIGTERM, 1, termrun.EndConsoleClosed},
		{"POSIX: the terminal closed", "linux", "", syscall.SIGHUP, -1, termrun.EndConsoleClosed},
		{"POSIX: a SIGTERM from outside", "linux", "", syscall.SIGTERM, -1, termrun.EndStoppedOutside},
		{"Windows: Stop-Process on the tool", "windows", "", nil, 4294967295, termrun.EndStoppedOutside},
		{"Windows: the tool's own STATUS_CONTROL_C_EXIT", "windows", "", nil, 3221225786, termrun.EndConsoleClosed},
		{"the tool exited", "windows", "", nil, 7, termrun.EndChildExit},
		{"a daemon end request wins over its SIGHUP", "linux", termrun.EndOrgFloorHooksDrifted, syscall.SIGHUP, 1, termrun.EndOrgFloorHooksDrifted},
	} {
		if got := sandboxCLIEndReason(c.goos, c.requested, c.sig, c.code); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSandboxCLISignalsKeepsTheFirst: every signal is passed on, the first
// one is kept for the end reason.
func TestSandboxCLISignalsKeepsTheFirst(t *testing.T) {
	in := make(chan os.Signal, 2)
	s := recordSandboxCLISignals(in)
	defer s.stop()
	in <- syscall.SIGTERM
	in <- syscall.SIGHUP
	for _, want := range []os.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		select {
		case got := <-s.ch:
			if got != want {
				t.Fatalf("passed on %v, want %v", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a signal was not passed on")
		}
	}
	if s.first() != syscall.SIGTERM {
		t.Fatalf("first %v", s.first())
	}
	s.stop()
	s.stop()
}

// TestSandboxCLIEndedGivesOneDaemonLine: the CLI's end note becomes exactly
// one daemon log line naming the run, the reason and the exit code, and is
// removed; a reason outside the vocabulary is logged as unknown.
func TestSandboxCLIEndedGivesOneDaemonLine(t *testing.T) {
	dir := t.TempDir()
	writeSandboxCLIEnded(dir, "run-console-1", termrun.EndConsoleClosed, 1)
	writeSandboxCLIEnded(dir, "run-odd-2", "made-up", 5)
	writeSandboxCLIEnded(dir, "../bad", termrun.EndChildExit, 0) // refused: not a run id
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	if n := logSandboxCLIEnded(dir, logger); n != 2 {
		t.Fatalf("logged %d, want 2: %s", n, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		`msg="terminal: ended a sandboxed CLI run" run=run-console-1 end_reason=console_closed exit_code=1`,
		`run=run-odd-2 end_reason=unknown exit_code=5`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	left, _ := filepath.Glob(filepath.Join(sandboxCLIEndDir(dir), "*"+sandboxCLIEndedSuffix))
	if len(left) != 0 {
		t.Fatalf("notes left: %v", left)
	}
	buf.Reset()
	if n := logSandboxCLIEnded(dir, logger); n != 0 || buf.Len() != 0 {
		t.Fatalf("a second pass logged again: %s", buf.String())
	}
}

// TestEndReasonVocabularyMatchesStore pins the store's end-reason constants
// (the one writer of terminal_run.end_reason) to termrun's vocabulary.
func TestEndReasonVocabularyMatchesStore(t *testing.T) {
	for got, want := range map[string]string{
		store.EndReasonChildExit:            termrun.EndChildExit,
		store.EndReasonConsoleClosed:        termrun.EndConsoleClosed,
		store.EndReasonDashboardStop:        termrun.EndDashboardStop,
		store.EndReasonStoppedOutside:       termrun.EndStoppedOutside,
		store.EndReasonProcessGone:          termrun.EndProcessGone,
		store.EndReasonDaemonShutdown:       termrun.EndDaemonShutdown,
		store.EndReasonResumed:              termrun.EndResumed,
		store.EndReasonOrgFloorHooksDrifted: termrun.EndOrgFloorHooksDrifted,
	} {
		if got != want || !termrun.KnownEndReason(got) {
			t.Errorf("store %q, termrun %q", got, want)
		}
	}
}
