//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSandboxCLIRunEndsUnderTheFloor (the SBX-P2E audit item routed to the
// SBX-P3A merge): a drifted sandboxed CLI launch is ended under the org's
// require_full_capture floor the way a dashboard run is. The daemon holds no
// terminal for it (its dashboard ender answers false), so the CLI ender
// stamps the end reason on the row and leaves an end request; the CLI
// process shows the floor's final line, hangs up its child, then kills it
// after the grace, and records the run's end with that reason. A run no CLI
// process watches gets no request.
func TestSandboxCLIRunEndsUnderTheFloor(t *testing.T) {
	prevFull, prevPoll, prevGrace := relayRequireFullCapture, sandboxCLIEndPoll, sandboxCLIEndGrace
	relayRequireFullCapture = func() bool { return true }
	sandboxCLIEndPoll, sandboxCLIEndGrace = 10*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { relayRequireFullCapture, sandboxCLIEndPoll, sandboxCLIEndGrace = prevFull, prevPoll, prevGrace })

	obs := t.TempDir()
	var mu sync.Mutex
	var stamped []string
	stamp := func(_ context.Context, runID, reason string) error {
		mu.Lock()
		defer mu.Unlock()
		stamped = append(stamped, runID+"="+reason)
		return nil
	}
	dashboard := func(string, string, string) bool { return false } // no live terminal here
	endRun := relayFirstEnder(dashboard, relayCLIRunEnder(obs, stamp, nil))
	drift := sandboxrelayd.Health{Causes: []sandboxrelayd.DegradedCause{sandboxrelayd.CauseHooksDrifted}}

	// No CLI process watches the run: nothing is written and the run stays
	// to be retried.
	unwatched := sandboxrelayd.RunRecord{RunID: "relay-cli-0", TerminalRunID: "termcli0000000000"}
	relayEndForFloor(unwatched, drift, endRun, nil)
	if _, end := sandboxCLIEndPaths(obs, unwatched.TerminalRunID); sandboxCLIFileExists(end) {
		t.Fatal("an end request was left for a run no CLI process watches")
	}
	if _, ok := relayEndedByFloor.Load(unwatched.RunID); ok {
		t.Fatal("an unended run was marked ended")
	}

	// A watched CLI launch.
	sigs := make(chan os.Signal, 4)
	out := &cliEndBuf{}
	runID := "termcli0000000001"
	reason, stop := watchSandboxCLIEnd(obs, runID, sigs, out)
	defer stop()
	run := sandboxrelayd.RunRecord{RunID: "relay-cli-1", TerminalRunID: runID}
	relayEndForFloor(run, drift, endRun, nil)
	if _, ok := relayEndedByFloor.Load(run.RunID); !ok {
		t.Fatal("the CLI run was not ended")
	}
	defer relayOnRunEnd(run)
	select {
	case s := <-sigs:
		if s != syscall.SIGHUP {
			t.Fatalf("first signal %v, want SIGHUP", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the CLI process never hung up its child")
	}
	select {
	case s := <-sigs:
		if s != syscall.SIGKILL {
			t.Fatalf("second signal %v, want SIGKILL after the grace", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the child was not killed after the grace")
	}
	if !strings.Contains(out.String(), `"Require full capture"`) || !strings.Contains(out.String(), "drifted") {
		t.Fatalf("the terminal's last line does not name the floor and the drift: %q", out.String())
	}
	if reason() != store.EndReasonOrgFloorHooksDrifted {
		t.Fatalf("end reason %q", reason())
	}
	mu.Lock()
	if len(stamped) != 1 || stamped[0] != runID+"="+store.EndReasonOrgFloorHooksDrifted {
		t.Errorf("stamped %v", stamped)
	}
	mu.Unlock()
	stop()
	watch, end := sandboxCLIEndPaths(obs, runID)
	if sandboxCLIFileExists(watch) || sandboxCLIFileExists(end) {
		t.Fatal("the marker or the request outlived the launch")
	}
}

func sandboxCLIFileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// cliEndBuf is a terminal stand-in safe for the watcher's goroutine.
type cliEndBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (c *cliEndBuf) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.Write(p)
}

func (c *cliEndBuf) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.String()
}
