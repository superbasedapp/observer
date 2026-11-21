//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestSandboxCLIRunIsRecorded (P-040, milestone 2b): a sandboxed CLI
// launch writes its terminal_run row through the dashboard launch's
// recorder (sealed isolation evidence), so the relay's lowering lands on
// it durably (capture_degraded, the causes, the resealed digest), and its
// exit is recorded.
func TestSandboxCLIRunIsRecorded(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{}
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	iso := termrun.Isolation{
		Class: "process", Stack: []string{"bwrap"}, EgressTier: "internet", CaptureLevel: "full",
		CaptureRule: "C6", CaptureOrigin: "sandboxed", Verification: "live", KeyCustody: "host_bound",
	}
	runID, err := recordSandboxCLIRun(ctx, cfg, "claude-code", t.TempDir(), iso)
	if err != nil || runID == "" {
		t.Fatalf("record: %q %v", runID, err)
	}
	database, closeDB, err := openDBForConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	st := store.New(database)
	got, ok, err := st.LoadTerminalRun(ctx, runID)
	if err != nil || !ok || got.Tool != "claude-code" || got.Kind != string(termrun.KindFresh) || got.EndedAt != nil {
		t.Fatalf("the run row %+v %v %v", got, ok, err)
	}
	wire := func() orgcontract.TerminalRunRow {
		t.Helper()
		rows, err := st.SelectTerminalRunRows(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.RunID == runID {
				return r
			}
		}
		t.Fatal("the CLI run is not on the org wire rows")
		return orgcontract.TerminalRunRow{}
	}
	row := wire()
	if row.EvidenceDigest == "" || row.CaptureOrigin != "sandboxed" || row.CaptureDegraded {
		t.Fatalf("the row carries no sealed evidence: %+v", row)
	}
	before := row.EvidenceDigest

	lower := func(ctx context.Context, id string, h store.TerminalRunCaptureHealth) error {
		_, err := st.LowerTerminalRunCapture(ctx, id, h, resealRunEvidence)
		return err
	}
	relayOnHealth(lower, nil)(sandboxrelayd.RunRecord{RunID: "relay-cli", TerminalRunID: runID},
		sandboxrelayd.Health{Causes: []sandboxrelayd.DegradedCause{sandboxrelayd.CauseHooksDrifted}})
	relayOnRunEnd(sandboxrelayd.RunRecord{TerminalRunID: runID})
	h, ok, err := st.LoadTerminalRunCaptureHealth(ctx, runID)
	if err != nil || !ok || h.Causes != "hooks_drifted" {
		t.Fatalf("the lowering did not land on the CLI run: %+v %v %v", h, ok, err)
	}
	if row = wire(); !row.CaptureDegraded || row.EvidenceDigest == before || row.EvidenceDigest == "" {
		t.Fatalf("not lowered or not resealed: %+v", row)
	}

	endSandboxCLIRun(ctx, cfg, runID, 3, "")
	got, _, _ = st.LoadTerminalRun(ctx, runID)
	if got.EndedAt == nil || got.ExitCode == nil || *got.ExitCode != 3 || got.EndReason != store.EndReasonChildExit {
		t.Fatalf("the exit is not recorded: %+v", got)
	}
	endSandboxCLIRun(ctx, cfg, "", 0, "") // nothing recorded: nothing to end
}

// TestRecordOrRefuseSandboxCLIRun (cli-1b fixes-3, D): a CLI launch whose
// run row cannot be written refuses, so no box runs that the daemon's
// loopback exposure gate could never see; a recorded run passes its id on.
func TestRecordOrRefuseSandboxCLIRun(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	failing := func(context.Context, config.Config, string, string, termrun.Isolation) (string, error) {
		return "", errors.New("database is locked")
	}
	if id, err := recordOrRefuseSandboxCLIRun(ctx, cfg, "claude-code", "/r", termrun.Isolation{}, failing); err == nil || id != "" || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("a failed record: id %q err %v, want the launch refused", id, err)
	}
	empty := func(context.Context, config.Config, string, string, termrun.Isolation) (string, error) {
		return "", nil
	}
	if _, err := recordOrRefuseSandboxCLIRun(ctx, cfg, "claude-code", "/r", termrun.Isolation{}, empty); err == nil {
		t.Fatal("an empty run id was accepted")
	}
	ok := func(context.Context, config.Config, string, string, termrun.Isolation) (string, error) {
		return "run-ok-1", nil
	}
	if id, err := recordOrRefuseSandboxCLIRun(ctx, cfg, "claude-code", "/r", termrun.Isolation{}, ok); err != nil || id != "run-ok-1" {
		t.Fatalf("a recorded run: id %q err %v", id, err)
	}
}

// TestEndRefusedSandboxCLIRun (lane callerid, L3): a launch refused after
// its row was written (the marker step, the native switch) ends that row
// with launch_refused, so it never reads as running.
func TestEndRefusedSandboxCLIRun(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{}
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	runID, err := recordSandboxCLIRun(ctx, cfg, "claude-code", t.TempDir(), termrun.Isolation{Class: "process", Stack: []string{"bwrap"}, EgressTier: "host"})
	if err != nil {
		t.Fatal(err)
	}
	endRefusedSandboxCLIRun(ctx, cfg, runID)
	database, closeDB, err := openDBForConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	got, ok, err := store.New(database).LoadTerminalRun(ctx, runID)
	if err != nil || !ok || got.EndedAt == nil || got.EndReason != store.EndReasonLaunchRefused {
		t.Fatalf("row %+v %v %v, want ended launch_refused", got, ok, err)
	}
}
