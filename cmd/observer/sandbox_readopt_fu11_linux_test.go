//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestReadoptCLIRunBoundAfterKeep (audit FU11-A1): in a real launch the
// compose keeps the run's facts before the launcher binds the terminal
// run, so the kept facts name none. readoptCLIRun resolves the terminal
// run through readoptTerminalRun at each of its three callers, so a CLI
// run is told apart again. One case per caller.
func TestReadoptCLIRunBoundAfterKeep(t *testing.T) {
	const term = "cli-run-fu11"
	// setup is the real order: keep (inside raSetup), then the bind, then
	// the CLI's watch file.
	setup := func(t *testing.T, f *raFake, runID string, watch bool) raRun {
		t.Helper()
		raSettings(t, true, 0)
		ra := raSetup(t, f, runID)
		if e := readoptRead(ra.obs, ra.runID); !e.keptOK || e.kept.Facts.TerminalRunID != "" {
			t.Fatalf("the kept facts already name a terminal run: %+v", e.kept.Facts)
		}
		if err := sandboxrelayd.BindTerminalRun(ra.obs, ra.runID, term); err != nil {
			t.Fatal(err)
		}
		if watch {
			raCLIWatch(t, ra.obs, term)
		}
		return ra
	}
	t.Run("the live helper: the daemon-exit mark skips the CLI run", func(t *testing.T) {
		f := newRAFake(t)
		ra := setup(t, f, "run000000000000fu1", true)
		release := holdAlive(t, ra.obs, ra.runID)
		defer release()
		if marked := readoptMarkDaemonExitIn(ra.obs, readoptNow()); len(marked) != 0 {
			t.Fatalf("the daemon's exit marked a CLI run: %v", marked)
		}
	})
	t.Run("the dead-run hold before the prune lets the CLI run go (row cli-run)", func(t *testing.T) {
		var logBuf bytes.Buffer
		prev := processOCIReaper.logger.Load()
		processOCIReaper.logger.Store(slog.New(slog.NewJSONHandler(&logBuf, nil)))
		t.Cleanup(func() { processOCIReaper.logger.Store(prev) })
		f := newRAFake(t)
		ra := setup(t, f, "run000000000000fu2", true)
		raEnder(t)
		if _, err := sandboxrelayd.PruneDeadRunRecords(ra.obs); err != nil {
			t.Fatal(err)
		}
		if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err == nil {
			t.Fatal("the hold kept a CLI run's record")
		}
		if lines := raDecisionLines(t, &logBuf); len(lines) != 1 || lines[0]["row"] != "cli-run" {
			t.Fatalf("decision lines %v, want one with row cli-run", lines)
		}
	})
	t.Run("the sweep after the hold kept the record reaps the CLI run", func(t *testing.T) {
		f := newRAFake(t)
		ra := setup(t, f, "run000000000000fu3", false)
		raEnder(t)
		// No watch file yet: the hold keeps the record, as for any run.
		if _, err := sandboxrelayd.PruneDeadRunRecords(ra.obs); err != nil {
			t.Fatal(err)
		}
		if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err != nil {
			t.Fatalf("the hold did not keep the record: %v", err)
		}
		raCLIWatch(t, ra.obs, term)
		(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
		if e := readoptRead(ra.obs, ra.runID); e.hasOffer {
			t.Fatal("a CLI run was offered for dashboard re-adoption")
		}
		if len(f.removed) != 1 {
			t.Fatalf("the CLI run's container was not reaped: %v", f.removed)
		}
	})
}

// raCLIWatch writes the CLI's watch file for terminal run term.
func raCLIWatch(t *testing.T, obs, term string) {
	t.Helper()
	watch, _ := sandboxCLIEndPaths(obs, term)
	if err := os.MkdirAll(filepath.Dir(watch), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watch, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}
