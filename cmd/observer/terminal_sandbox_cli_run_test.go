//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"path/filepath"
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
