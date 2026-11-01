package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/shutdown"
)

// TestDaemonShutdownWatchdogNamesBlockerAndForcesExit pins the overrun half
// of T-553's bounded stop: when a component ignores the stop, the watchdog
// names it, writes every goroutine's stack beside the DB, and ends the
// process (through main.go's daemonHardExit) at the bound instead of leaving
// the operator to find the pid and SIGKILL it.
func TestDaemonShutdownWatchdogNamesBlockerAndForcesExit(t *testing.T) {
	prevBound, prevExit := daemonShutdownBound, daemonHardExit
	t.Cleanup(func() { daemonShutdownBound, daemonHardExit = prevBound, prevExit })
	daemonShutdownBound = 300 * time.Millisecond
	exited := make(chan int, 1)
	daemonHardExit = func(code int) { exited <- code }

	tr := shutdown.NewTracker()
	stuck := tr.Start("watcher") // ignores the stop
	defer stuck()
	tr.Start("proxy")() // stopped promptly
	tr.AdvanceStage(shutdown.StageRunning, shutdown.StageComponents)

	dir := t.TempDir()
	var stderr syncBuffer
	wd := daemonShutdownWatchdog(tr, &stderr, dir)
	defer wd.Disarm()
	wd.Arm()

	select {
	case code := <-exited:
		if code != 1 {
			t.Fatalf("forced exit code = %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("watchdog never forced the exit; stderr:\n%s", stderr.String())
	}
	out := stderr.String()
	for _, want := range []string{
		"shutdown: still stopping after",
		"waiting for: watcher",
		"did not finish within 300ms; blocked by: watcher (stage components)",
		"goroutine stacks written to",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q:\n%s", want, out)
		}
	}
	stacks, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("observer-shutdown-%d.stacks", os.Getpid())))
	if err != nil {
		t.Fatalf("stack dump: %v", err)
	}
	if !bytes.Contains(stacks, []byte("goroutine ")) {
		t.Fatalf("stack dump has no goroutines:\n%.400s", stacks)
	}
	if fi, err := os.Stat(filepath.Join(dir, fmt.Sprintf("observer-shutdown-%d.stacks", os.Getpid()))); err == nil && (posixModes && fi.Mode().Perm() != 0o600) {
		t.Fatalf("stack dump mode = %v, want 0600", fi.Mode().Perm())
	}
}

// TestStartStopsWithinBoundWhileWatcherIsMidScan drives the REAL `observer
// start` wiring (the same harness as the org startup tests) with the
// watcher busy on a transcript backlog and a directory tree to register,
// then stops it and asserts the whole stop, every component plus the
// deferred cleanups, finishes inside daemonShutdownBound without the
// watchdog having to force anything, and that the stop reports itself.
func TestStartStopsWithinBoundWhileWatcherIsMidScan(t *testing.T) {
	requireActiveAdapters(t, "claude-code")
	requireAdapter(t, "claude-code")
	prevExit := daemonHardExit
	t.Cleanup(func() { daemonHardExit = prevExit })
	forced := make(chan int, 1)
	daemonHardExit = func(code int) { forced <- code }

	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	writeTranscriptBacklog(t, filepath.Join(dir, ".claude", "projects"), 120, 2000)

	dbPath := filepath.Join(dir, ".observer", "observer.db")
	cfgPath := filepath.Join(dir, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("freeTCPPort: %v", err)
	}
	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.Observer.LogLevel = "error"
	cfg.Observer.Watch.EnabledAdapters = []string{"claude-code"}
	cfg.Observer.Hooks.AutoRegister = false
	cfg.Proxy.Port = port
	cfg.Terminal.Attach.Enabled = false
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		t.Fatalf("WriteToml: %v", err)
	}
	pre, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("preseed: %v", err)
	}
	_ = pre.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCmd := newStartCmd()
	t.Cleanup(func() { setDaemonConfigPath("") })
	startCmd.SetArgs([]string{"--no-dashboard", "--no-open", "--config", cfgPath})
	out := &syncBuffer{}
	startCmd.SetOut(out)
	startCmd.SetErr(out)
	done := make(chan error, 1)
	go func() { done <- startCmd.ExecuteContext(ctx) }()

	// Stop once the watcher is ingesting the backlog: mid-work, not idle.
	deadline := time.Now().Add(60 * time.Second)
	for !watcherHasIngested(dbPath) {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("watcher never started ingesting; output:\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopped := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("observer start returned %v on a requested stop; output:\n%s", err, out.String())
		}
	case code := <-forced:
		t.Fatalf("the watchdog had to force the exit (code %d); output:\n%s", code, out.String())
	case <-time.After(daemonShutdownBound):
		t.Fatalf("observer start still running %v after the stop; output:\n%s", daemonShutdownBound, out.String())
	}
	took := time.Since(stopped)
	if !strings.Contains(out.String(), "shutdown: components stopped in") {
		t.Errorf("the stop did not report itself; output:\n%s", out.String())
	}
	t.Logf("observer start stopped %v after the stop request", took.Round(time.Millisecond))
}

// writeTranscriptBacklog writes n Claude Code transcripts (copies of the
// gen-timing-real fixture with fresh ids) under root, plus dirs empty
// directories for the watcher's recursive registration to walk.
func writeTranscriptBacklog(t *testing.T, root string, n, dirs int) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "gen-timing-real.jsonl"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	idRE := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	for i := 0; i < n; i++ {
		proj := filepath.Join(root, fmt.Sprintf("-tmp-stopproj%02d", i%10))
		if err := os.MkdirAll(proj, 0o755); err != nil {
			t.Fatal(err)
		}
		seen := map[string]string{}
		body := idRE.ReplaceAllFunc(src, func(id []byte) []byte {
			k := string(id)
			if v, ok := seen[k]; ok {
				return []byte(v)
			}
			v := fmt.Sprintf("%08x-0000-4000-8000-%012x", i, len(seen))
			seen[k] = v
			return []byte(v)
		})
		name := fmt.Sprintf("%08x-1111-4000-8000-000000000000.jsonl", i)
		if err := os.WriteFile(filepath.Join(proj, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < dirs; i++ {
		if err := os.MkdirAll(filepath.Join(root, "deep", fmt.Sprintf("a%03d", i/100), fmt.Sprintf("b%03d", i%100)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// watcherHasIngested reports whether the watcher has advanced at least one
// parse cursor in the DB at dbPath.
func watcherHasIngested(dbPath string) bool {
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		return false
	}
	defer d.Close()
	var n int
	if err := d.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM parse_cursors`).Scan(&n); err != nil {
		return false
	}
	return n > 0
}
