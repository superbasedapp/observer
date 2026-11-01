//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestSandboxCLIForwardsHangupAndTermAndRecordsTheEnd (audit finding F4 of
// lane sbx-p2d): a sandboxed CLI launch that gets SIGHUP (its terminal
// closed) or SIGTERM passes the signal on to its child and records the
// run's end once the child is gone, so the row never stays "running".
func TestSandboxCLIForwardsHangupAndTermAndRecordsTheEnd(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{}
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	iso := termrun.Isolation{
		Class: "process", Stack: []string{"bwrap"}, EgressTier: "internet", CaptureLevel: "full",
		CaptureRule: "C6", CaptureOrigin: "sandboxed", Verification: "live", KeyCustody: "host_bound",
	}
	// A test binary started with SIGHUP ignored (under nohup, setsid nohup
	// or a job runner that ignores it) passes that on to every child it
	// execs, and an ignored signal stays ignored across exec, so the child
	// would drop the forwarded hangup and the test would fail for its
	// environment, not the product (RB1 gate). Subscribing for the test's
	// duration makes the disposition Go's handler, which exec resets to the
	// default in the child. Unconditional: once any earlier test in the
	// package subscribed to SIGHUP and stopped, signal.Ignored reports false
	// while the process is back to ignoring it (seen in the full package
	// run), and without the ignore the subscription only catches a stray
	// hangup for the test's duration.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(hup) })
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			runID, err := recordSandboxCLIRun(ctx, cfg, "claude-code", t.TempDir(), iso)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sleep", "30")
			sigs := make(chan os.Signal, 1)
			// Read only after the child started: the supervisor forwards it.
			sigs <- sig
			type result struct {
				code int
				err  error
			}
			done := make(chan result, 1)
			go func() {
				code, err := superviseSandboxCLIChild(cmd, sigs, func(exit int) { endSandboxCLIRun(ctx, cfg, runID, exit, "") })
				done <- result{code, err}
			}()
			// Wait for the supervisor's own result, not a fixed short time:
			// under load the child's end plus the database write of the
			// run's end can take longer than any short bound. The wait is
			// bounded (hangupWaitBound) so a signal that is not passed on
			// fails with its cause, never hangs under -timeout 0.
			remaining, hasDeadline := time.Duration(0), false
			if dl, ok := t.Deadline(); ok {
				remaining, hasDeadline = time.Until(dl), true
			}
			timer := time.NewTimer(hangupWaitBound(remaining, hasDeadline))
			defer timer.Stop()
			var res result
			select {
			case res = <-done:
			case <-timer.C:
				// cmd belongs to the supervising goroutine; the child is a
				// sleep that ends on its own.
				t.Fatal("the signal was not passed on: the child is still running")
			}
			if res.err != nil {
				t.Fatalf("supervise: %v", res.err)
			}
			ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !ws.Signaled() || ws.Signal() != sig {
				t.Fatalf("the child did not end by %v: %v", sig, cmd.ProcessState)
			}
			database, closeDB, err := openDBForConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer closeDB()
			got, ok, err := store.New(database).LoadTerminalRun(ctx, runID)
			if err != nil || !ok || got.EndedAt == nil || got.ExitCode == nil || *got.ExitCode != res.code || got.EndReason != store.EndReasonChildExit {
				t.Fatalf("the run's end is not recorded: %+v %v %v (code %d)", got, ok, err, res.code)
			}
		})
	}
}

// hangupWaitMax bounds the hangup test's wait when the test binary has no
// deadline (go test -timeout 0) or a later one.
const hangupWaitMax = 2 * time.Minute

// hangupWaitBound is how long the hangup test waits for the supervisor:
// the smaller of hangupWaitMax and the time left before the test binary's
// deadline less a margin (a tenth of it, at most 10 s) so the failure names
// the cause instead of a timeout panic. It is never negative, so a test
// started close to its deadline does not fail at once.
func hangupWaitBound(remaining time.Duration, hasDeadline bool) time.Duration {
	if !hasDeadline {
		return hangupWaitMax
	}
	margin := min(remaining/10, 10*time.Second)
	return max(min(remaining-margin, hangupWaitMax), 0)
}

// TestHangupWaitBound (audit F5 of the RBFIX lane): the hangup test's wait
// is bounded under -timeout 0 and positive with under 10 s left.
func TestHangupWaitBound(t *testing.T) {
	for _, tc := range []struct {
		name        string
		remaining   time.Duration
		hasDeadline bool
		want        time.Duration
	}{
		{"no deadline (-timeout 0): two minutes", 0, false, 2 * time.Minute},
		{"a far deadline: two minutes", time.Hour, true, 2 * time.Minute},
		{"ten minutes left: two minutes", 10 * time.Minute, true, 2 * time.Minute},
		{"a minute left: less a 6 s margin", time.Minute, true, 54 * time.Second},
		{"5 s left: still waits, less a tenth", 5 * time.Second, true, 4500 * time.Millisecond},
		{"no time left: never negative", 0, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hangupWaitBound(tc.remaining, tc.hasDeadline); got != tc.want {
				t.Fatalf("hangupWaitBound(%s, %v) = %s, want %s", tc.remaining, tc.hasDeadline, got, tc.want)
			}
		})
	}
}

// TestSandboxCLIChildThatCannotStartIsEnded: a child that cannot be run
// still records the run's end.
func TestSandboxCLIChildThatCannotStartIsEnded(t *testing.T) {
	ended := 0
	code := 7
	_, err := superviseSandboxCLIChild(exec.Command(filepath.Join(t.TempDir(), "missing")), nil, func(exit int) { ended++; code = exit })
	if err == nil || ended != 1 || code != -1 {
		t.Fatalf("err %v, ended %d, code %d", err, ended, code)
	}
}
