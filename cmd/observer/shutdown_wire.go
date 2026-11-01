package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/marmutapp/superbased-observer/internal/shutdown"
)

// daemonShutdownBound is how long `observer start` may take to stop once a
// stop is requested (SIGTERM, ctrl-c, a dashboard restart, or a component
// failing) before the watchdog names what blocked and forces the exit
// (T-553). It covers the component drain, the WAL checkpoint and the deferred
// cleanups. The HTTP listeners drain for at most 5s inside it, so 20s leaves
// every loop room to finish its current unit of work. A var for tests.
var daemonShutdownBound = 20 * time.Second

// shutdownCheckpointTimeout bounds the final PASSIVE WAL checkpoint.
const shutdownCheckpointTimeout = 3 * time.Second

// namedGroup is the daemon's errgroup with every goroutine registered by
// name in the shutdown tracker, so an overrun can say which component is
// still running instead of leaving the operator to guess among forty loops.
type namedGroup struct {
	g *errgroup.Group
	t *shutdown.Tracker
}

// Go runs fn on the group, tracked as name for as long as it runs.
func (n namedGroup) Go(name string, fn func() error) {
	n.g.Go(func() error {
		done := n.t.Start(name)
		defer done()
		return fn()
	})
}

// daemonShutdownWatchdog builds the stop watchdog for one `observer start`
// run. Progress logs the stragglers part-way through the bound; Overrun logs
// them, writes every goroutine's stack beside the DB (the evidence an
// operator needs to file the bug), and ends the process: re-exec when a
// dashboard restart asked for one, else exit 1. SQLite's WAL keeps the
// database consistent across that forced exit, exactly as it does across the
// SIGKILL the operator would otherwise have to send.
func daemonShutdownWatchdog(tracker *shutdown.Tracker, stderr io.Writer, stackDir string) *shutdown.Watchdog {
	return shutdown.NewWatchdog(tracker, shutdown.Options{
		Bound: daemonShutdownBound,
		Progress: func(r shutdown.Report) {
			fmt.Fprintf(stderr, "shutdown: still stopping after %s (bound %s); waiting for: %s\n",
				r.Elapsed.Round(time.Millisecond), r.Bound, r.Blocking())
		},
		Overrun: func(r shutdown.Report) {
			fmt.Fprintf(stderr, "shutdown: did not finish within %s; blocked by: %s (stage %s). Forcing exit; SQLite WAL keeps the DB consistent.\n",
				r.Bound, r.Blocking(), r.Stage)
			if path, err := writeShutdownStacks(stackDir, os.Getpid()); err == nil {
				fmt.Fprintf(stderr, "shutdown: goroutine stacks written to %s\n", path)
			} else {
				fmt.Fprintf(stderr, "shutdown: could not write goroutine stacks: %v\n", err)
			}
			if restartRequested.Load() {
				if err := execSelf(); err != nil {
					fmt.Fprintf(stderr, "shutdown: dashboard restart re-exec failed, exiting instead: %v\n", err)
				}
			}
			daemonHardExit(1)
		},
	})
}

// shutdownStackDir is where an overrun writes its goroutine dump: the DB
// directory when the config loaded, else the OS temp dir.
func shutdownStackDir(dbPath string) string {
	if strings.TrimSpace(dbPath) != "" {
		return filepath.Dir(dbPath)
	}
	return os.TempDir()
}

// writeShutdownStacks writes a full goroutine dump (pprof debug=2, the same
// text a SIGQUIT prints) to observer-shutdown-<pid>.stacks in dir, 0600.
func writeShutdownStacks(dir string, pid int) (string, error) {
	path := filepath.Join(dir, fmt.Sprintf("observer-shutdown-%d.stacks", pid))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("writeShutdownStacks: %w", err)
	}
	defer f.Close()
	if prof := pprof.Lookup("goroutine"); prof != nil {
		if err := prof.WriteTo(f, 2); err != nil {
			return "", fmt.Errorf("writeShutdownStacks: %w", err)
		}
	}
	return path, nil
}

// checkpointOnShutdown runs one bounded PASSIVE WAL checkpoint on the
// daemon's long-lived handle after every component has returned. PASSIVE
// never waits on readers or writers (a hook process may still be writing),
// so it cannot stall the stop; the bound covers a slow disk. Best effort: the
// next open replays whatever is left.
func checkpointOnShutdown(database *sql.DB) {
	if database == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownCheckpointTimeout)
	defer cancel()
	_, _ = database.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)")
}

// startupStopBound is how long a stop requested during the earliest part of
// startup (before the stop watchdog below exists) may take before the
// process exits anyway (D-MU2). A var for tests.
var startupStopBound = daemonShutdownBound

// startupStopGuard covers the window between the signal context and the
// daemon's stop watchdog: a SIGTERM that arrives while startup is still in
// a step that does not watch ctx (a config migration, a governance load)
// used to be swallowed by the signal context, so `observer service stop`
// left the process running (D-MU2). Once ctx is done, the guard waits bound
// and then calls exit, unless handoff was called first (the stop watchdog
// is armed from then on and owns the bound). handoff is idempotent.
func startupStopGuard(ctx context.Context, bound time.Duration, stderr io.Writer, exit func(int)) (handoff func()) {
	handed := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-handed:
			return
		case <-ctx.Done():
		}
		t := time.NewTimer(bound)
		defer t.Stop()
		select {
		case <-handed:
		case <-t.C:
			fmt.Fprintf(stderr, "shutdown: stop requested during startup did not finish within %s; exiting.\n", bound)
			exit(1)
		}
	}()
	return func() { once.Do(func() { close(handed) }) }
}
