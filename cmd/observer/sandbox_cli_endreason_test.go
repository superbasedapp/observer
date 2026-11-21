//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
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
		store.EndReasonCLIStop:              termrun.EndCLIStop,
		store.EndReasonLaunchRefused:        termrun.EndLaunchRefused,
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

// TestCLIMarkerRules is the marker sweep's table, one case per row. A live
// box or a live CLI keeps the marker before any end its row records is
// read (fixes-4 N1: a graceful daemon stop stamps daemon_shutdown on a live
// CLI launch's row), an end other than daemon_shutdown drops it, and so do
// a missing row and a CLI and box both gone; an unknown CLI keeps it.
func TestCLIMarkerRules(t *testing.T) {
	cases := []struct {
		name string
		f    cliMarkerFacts
		keep bool
		rule string
	}{
		{"K1 no sandboxed row", cliMarkerFacts{BoxLive: true, PIDKnown: true, CLIAlive: true}, false, "K1-no-sandboxed-row"},
		{"K2 ended by a daemon shutdown, box live", cliMarkerFacts{RowKnown: true, BoxLive: true, PIDKnown: true}, true, "K2-box-live"},
		{"K2 ended for good but the box still runs", cliMarkerFacts{RowKnown: true, RowEndedForGood: true, BoxLive: true}, true, "K2-box-live"},
		{"K3 ended by a daemon shutdown, CLI alive", cliMarkerFacts{RowKnown: true, PIDKnown: true, CLIAlive: true}, true, "K3-cli-alive"},
		{"K4 ended normally, box gone", cliMarkerFacts{RowKnown: true, RowEndedForGood: true, PIDKnown: true}, false, "K4-row-ended"},
		{"K4 ended normally, CLI unknown", cliMarkerFacts{RowKnown: true, RowEndedForGood: true}, false, "K4-row-ended"},
		{"K5 CLI and box gone", cliMarkerFacts{RowKnown: true, PIDKnown: true}, false, "K5-cli-and-box-gone"},
		{"K6 an older empty marker, row ended by a daemon shutdown, box gone", cliMarkerFacts{RowKnown: true, RowEnded: true}, false, "K6-unknown-cli-row-ended"},
		{"K2 an older empty marker, row ended by a daemon shutdown, box live", cliMarkerFacts{RowKnown: true, RowEnded: true, BoxLive: true}, true, "K2-box-live"},
		{"K7 unknown CLI on an unended row", cliMarkerFacts{RowKnown: true}, true, "K7-unknown-cli"},
	}
	for _, tc := range cases {
		keep, rule := cliMarkerKeep(tc.f)
		if keep != tc.keep || rule != tc.rule {
			t.Errorf("%s: keep %v by %s, want %v by %s", tc.name, keep, rule, tc.keep, tc.rule)
		}
	}
}

// TestGateCountsABoxAcrossADaemonRestart (fixes-4 N1): a graceful daemon
// stop stamps a sandboxed CLI launch's row daemon_shutdown while the CLI and
// its host-tier box keep running. After the restart the real sweep keeps
// its marker and the gate still refuses; a run that ended normally with
// its box gone loses its marker and gates nothing.
func TestGateCountsABoxAcrossADaemonRestart(t *testing.T) {
	obs := t.TempDir()
	write := func(runID string, pid int) {
		watch, _ := sandboxCLIEndPaths(obs, runID)
		if err := os.MkdirAll(filepath.Dir(watch), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(watch, []byte(`{"pid":`+strconv.Itoa(pid)+`}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ended := time.Now()
	rows := map[string]store.TerminalRunSummary{
		"run-shutdown": {RunID: "run-shutdown", IsolationClass: "process", Stack: "bwrap", EgressTier: "host", EndedAt: &ended, EndReason: store.EndReasonDaemonShutdown},
		"run-done":     {RunID: "run-done", IsolationClass: "process", Stack: "bwrap", EgressTier: "host", EndedAt: &ended, EndReason: store.EndReasonChildExit},
	}
	src := loopbackExposureSources{
		markers: func() []sandboxCLIMarker { return sandboxCLIMarkers(obs) },
		runRows: func(_ context.Context, ids []string) ([]store.TerminalRunSummary, error) {
			var out []store.TerminalRunSummary
			for _, id := range ids {
				if r, ok := rows[id]; ok {
					out = append(out, r)
				}
			}
			return out, nil
		},
		sweep: func(ms []sandboxCLIMarker, st map[string]cliRunState) []sandboxCLIMarker {
			return sweepSandboxCLIMarkers(obs, ms, st,
				func(pid int, _ string) bool { return pid == 501 },         // run-shutdown's CLI lives on
				func(runID string) bool { return runID == "run-shutdown" }) // and so does its box
		},
	}
	write("run-shutdown", 501)
	src.sweepStale(context.Background()) // the restarted daemon's start sweep
	reason, exposed := src.check(context.Background())
	if !exposed || !strings.Contains(reason, "run-shutdown") {
		t.Fatalf("a live host-tier box ended only by the daemon's stop is not gated: %q %v", reason, exposed)
	}
	write("run-done", 502)
	delete(rows, "run-shutdown")
	if reason, exposed := src.check(context.Background()); exposed {
		t.Fatalf("a run that ended with its box gone still gates: %s", reason)
	}
	if watch, _ := sandboxCLIEndPaths(obs, "run-done"); fileExists(watch) {
		t.Fatal("the over run's marker was not dropped")
	}
}

// TestSweepSandboxCLIMarkers (fixes-3 B): the sweep lists the markers with
// the PID their CLI wrote, removes the stale ones (and their end request)
// and keeps the rest.
func TestSweepSandboxCLIMarkers(t *testing.T) {
	obs := t.TempDir()
	write := func(runID, body string) string {
		watch, end := sandboxCLIEndPaths(obs, runID)
		if err := os.MkdirAll(filepath.Dir(watch), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(watch, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(end, []byte("{}"), 0o600)
		return watch
	}
	ended := write("run-ended", `{"pid":101}`)
	gone := write("run-gone", `{"pid":102}`)
	alive := write("run-alive", `{"pid":103}`)
	boxed := write("run-boxed", `{"pid":104}`)
	old := write("run-old", ``)
	markers := sandboxCLIMarkers(obs)
	if len(markers) != 5 {
		t.Fatalf("listed %+v, want 5 markers", markers)
	}
	for _, m := range markers {
		if m.RunID == "run-old" && m.PID != 0 {
			t.Fatalf("an empty marker read pid %d", m.PID)
		}
		if m.RunID == "run-alive" && m.PID != 103 {
			t.Fatalf("pid not read: %+v", m)
		}
	}
	rows := map[string]cliRunState{"run-gone": {}, "run-alive": {}, "run-boxed": {}, "run-old": {}, "run-ended": {Ended: true, EndReason: "child_exit"}}
	kept := sweepSandboxCLIMarkers(obs, markers, rows,
		func(pid int, _ string) bool { return pid == 103 },
		func(runID string) bool { return runID == "run-boxed" })
	got := map[string]bool{}
	for _, m := range kept {
		got[m.RunID] = true
	}
	if len(got) != 3 || !got["run-alive"] || !got["run-boxed"] || !got["run-old"] {
		t.Fatalf("kept %v, want run-alive, run-boxed and run-old", got)
	}
	for path, want := range map[string]bool{ended: false, gone: false, alive: true, boxed: true, old: true} {
		_, err := os.Stat(path)
		if (err == nil) != want {
			t.Errorf("%s present = %v, want %v", filepath.Base(path), err == nil, want)
		}
	}
	if _, end := sandboxCLIEndPaths(obs, "run-gone"); fileExists(end) {
		t.Error("a stale marker's end request was left")
	}
}

// TestWatchSandboxCLIEndRecordsThePID: the marker a CLI writes names its
// own process, which the sweep reads; stop removes it.
func TestWatchSandboxCLIEndRecordsThePID(t *testing.T) {
	obs := t.TempDir()
	sigs := make(chan os.Signal, 1)
	_, stop, err := watchSandboxCLIEnd(obs, "run-pid-1", sigs, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	markers := sandboxCLIMarkers(obs)
	if len(markers) != 1 || markers[0].PID != os.Getpid() {
		stop()
		t.Fatalf("markers %+v, want this process's pid %d", markers, os.Getpid())
	}
	stop()
	if len(sandboxCLIMarkers(obs)) != 0 {
		t.Fatal("stop left the marker")
	}
}

// TestSandboxRowHostLoopbackRelay: the MXC rows' relay rides host loopback
// (exposure rule X3); bwrap's does not.
func TestSandboxRowHostLoopbackRelay(t *testing.T) {
	for id, want := range map[string]bool{
		sandboxbackend.BackendMXCProcess:      true,
		sandboxbackend.BackendMXCAppContainer: true,
		sandboxbackend.BackendBwrap:           false,
		"no-such-backend":                     false,
	} {
		if got := sandboxRowHostLoopbackRelay(id); got != want {
			t.Errorf("%s: %v, want %v", id, got, want)
		}
	}
}

// TestSandboxRowTreeContained (callerid fixes-1, H3): bwrap runs its box
// in a PID namespace of its own, so the caller check may clear a caller by
// ancestry; the MXC rows do not, so an exposed MXC box refuses every
// caller (rule C5).
func TestSandboxRowTreeContained(t *testing.T) {
	for id, want := range map[string]bool{
		sandboxbackend.BackendBwrap:           true,
		sandboxbackend.BackendMXCProcess:      false,
		sandboxbackend.BackendMXCAppContainer: false,
		sandboxbackend.BackendProcessLite:     false,
		sandboxbackend.BackendOCIRunc:         false,
		sandboxbackend.BackendOCIRunsc:        false,
		"no-such-backend":                     false,
	} {
		if got := sandboxRowTreeContained(id); got != want {
			t.Errorf("%s: %v, want %v", id, got, want)
		}
	}
	// Only the bwrap row declares it, so a new row is false until it is
	// grounded (callerid fixes-2, N3).
	for _, id := range sandboxbackend.IDs() {
		if got, want := sandboxRowTreeContained(id), id == sandboxbackend.BackendBwrap; got != want {
			t.Errorf("registry row %s: TreeContained %v, want %v", id, got, want)
		}
	}
}

// TestSandboxRowDeniesObserverPorts: only the Landlock row claims its own
// enforcement refuses every Observer listener (exposure rule X2).
func TestSandboxRowDeniesObserverPorts(t *testing.T) {
	for _, id := range sandboxbackend.IDs() {
		want := id == sandboxbackend.BackendProcessLite
		if got := sandboxRowDeniesObserverPorts(id); got != want {
			t.Errorf("%s: %v, want %v", id, got, want)
		}
	}
}

// TestLoopbackExposurePerRegistryRow walks every registry row on every
// tier it offers through the real capability lookups and the exposure
// rule: only a row that reaches the host's loopback gates the dashboard
// (bwrap's host tier, the MXC rows); the Landlock row, whose rules deny
// Observer's ports, and every row with its own network do not.
func TestLoopbackExposurePerRegistryRow(t *testing.T) {
	exposedRows := map[string]bool{sandboxbackend.BackendMXCProcess: true, sandboxbackend.BackendMXCAppContainer: true}
	for _, id := range sandboxbackend.IDs() {
		row, _ := sandboxbackend.Get(id)
		for _, tier := range row.Net.Egress {
			want := exposedRows[id] || (string(tier) == "host" && id != sandboxbackend.BackendProcessLite)
			_, got := agentlaunch.LoopbackExposure([]agentlaunch.BoxRun{boxRun("r", "process", id, string(tier))})
			if got != want {
				t.Errorf("%s on tier %s: exposed %v, want %v", id, tier, got, want)
			}
		}
	}
}

// TestWatchSandboxCLIEndRefusesWithoutAMarker (fixes-4 N2): the daemon's
// gate finds a CLI box only through its marker, so a marker that cannot be
// written is an error (the launch is refused), never a silent watch of
// nothing.
func TestWatchSandboxCLIEndRefusesWithoutAMarker(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	if _, _, err := watchSandboxCLIEnd("", "run-pid-1", sigs, io.Discard); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("no observer dir: err = %v", err)
	}
	if _, _, err := watchSandboxCLIEnd(t.TempDir(), "../bad", sigs, io.Discard); err == nil {
		t.Fatal("a bad run id was watched")
	}
	// The marker directory's parent is a file, so the marker cannot be made.
	obs := t.TempDir()
	if err := os.WriteFile(filepath.Join(obs, sandboxrelayd.RelayDirName), []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := watchSandboxCLIEnd(obs, "run-pid-2", sigs, io.Discard); err == nil {
		t.Fatal("an unwritable marker was not refused")
	}
}

// TestSandboxCLIProcessAlive (lane callerid, L1): a marker's CLI counts as
// alive only while the process at its pid is the start the marker
// recorded, so a pid reused after a reboot or by a later process does not
// keep a stale marker (and so the gate) alive.
func TestSandboxCLIProcessAlive(t *testing.T) {
	self, ok := peerproc.StartToken(os.Getpid())
	if !ok {
		t.Skip("no start token on this platform")
	}
	if !sandboxCLIProcessAlive(os.Getpid(), self) {
		t.Fatal("this process with its own start is not alive")
	}
	if sandboxCLIProcessAlive(os.Getpid(), "another-boot:1") {
		t.Fatal("a reused pid (another start) counts as the CLI")
	}
	if !sandboxCLIProcessAlive(os.Getpid(), "") {
		t.Fatal("an older marker with no start: the live pid decides")
	}
	if sandboxCLIProcessAlive(0, "") || sandboxCLIProcessAlive(1<<30, "") {
		t.Fatal("no pid, or a pid that cannot exist, is alive")
	}
}

// TestWatchSandboxCLIEndRecordsTheStart: the marker a CLI writes carries
// its start token, which the listing reads back.
func TestWatchSandboxCLIEndRecordsTheStart(t *testing.T) {
	want, ok := peerproc.StartToken(os.Getpid())
	if !ok {
		t.Skip("no start token on this platform")
	}
	obs := t.TempDir()
	_, stop, err := watchSandboxCLIEnd(obs, "run-start-1", make(chan os.Signal, 1), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ms := sandboxCLIMarkers(obs)
	if len(ms) != 1 || ms[0].Start != want || ms[0].PID != os.Getpid() {
		t.Fatalf("markers %+v, want pid %d start %q", ms, os.Getpid(), want)
	}
}
