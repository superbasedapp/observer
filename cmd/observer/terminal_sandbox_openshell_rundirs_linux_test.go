//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestOpenShellRunScanIsQuietOutsideTheReaper (fix round 1 of lane FU1): a
// run dir whose plan names another run is logged by the reaper's scan only;
// the probe's note and the lifecycle's counts scan quietly, so the warning
// is not repeated on every call. Linux only: the plan reader's owner check
// is the Linux one, where the row runs.
func TestOpenShellRunScanIsQuietOutsideTheReaper(t *testing.T) {
	stateDir := t.TempDir()
	writeRunDir(t, stateDir, "run-mismatch-001", []byte(`{"version":`+strconv.Itoa(openShellPlanVersion)+`,"run_id":"run-other-000002"}`), time.Hour)
	var buf syncBuffer // the default logger is process-wide: a relay goroutine from another test may write it (L-4)
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_ = openShellReadRuns(stateDir)
	_ = openShellUnreadableRunNotes(stateDir, time.Now())
	_ = openShellRunDirsHint(stateDir, time.Now())
	_ = openShellRunsOn(stateDir, "sbo-anything")
	if strings.Contains(buf.String(), "names another run") {
		t.Fatalf("a scan outside the reaper logged: %q", buf.String())
	}
	_ = openShellReadRunsReaping(stateDir)
	if !strings.Contains(buf.String(), "names another run") {
		t.Fatalf("the reaper's scan did not log the mismatch: %q", buf.String())
	}
}
