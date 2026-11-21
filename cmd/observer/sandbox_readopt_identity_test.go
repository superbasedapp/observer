//go:build !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// The container's run id (the relay run) and the dashboard's terminal run
// id, the two shapes of the F-053 receipt.
const (
	f053ContainerRun = "2BaShegSENTINEL0000000"
	f053TerminalRun  = "PZRxkSENTINEL000000000000000000000000000000"
)

// TestReadoptTerminalRunRows is one case per rule of readoptTerminalRun
// (tracker F-053): the kept id, else the current record's bound id, else
// none.
func TestReadoptTerminalRunRows(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kept     string
		recBound string // "" with rec true: a record bound to nothing
		rec      bool
		want     string
	}{
		{"kept id wins", "keptSENTINEL", f053TerminalRun, true, "keptSENTINEL"},
		{"kept empty: the record's bound id (the compose ran before the bind)", "", f053TerminalRun, true, f053TerminalRun},
		{"kept empty, record never bound: none", "", "", true, ""},
		{"kept empty, no record: none", "", "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := t.TempDir()
			if tc.rec {
				rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: f053ContainerRun, Tool: "claude-code", ProjectRoot: obs, WorkspaceDir: obs, Roots: []string{obs}})
				if err != nil {
					t.Fatal(err)
				}
				if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
					t.Fatal(err)
				}
				if tc.recBound != "" {
					if err := sandboxrelayd.BindTerminalRun(obs, f053ContainerRun, tc.recBound); err != nil {
						t.Fatal(err)
					}
				}
			}
			if got := readoptTerminalRun(obs, f053ContainerRun, tc.kept); got != tc.want {
				t.Fatalf("readoptTerminalRun = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReadoptTerminalRunKeysRefusalRows pins the F-053 join: a refusal on
// a record re-keyed with the resolved terminal run is keyed by the terminal
// run (the id the store stamps backend and tier from), the same as before
// the re-adoption; on a record re-keyed from the compose's facts alone it
// was keyed by the container's run id.
func TestReadoptTerminalRunKeysRefusalRows(t *testing.T) {
	obs := t.TempDir()
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: f053ContainerRun, Tool: "claude-code", ProjectRoot: obs, WorkspaceDir: obs, Roots: []string{obs}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.BindTerminalRun(obs, f053ContainerRun, f053TerminalRun); err != nil {
		t.Fatal(err)
	}
	before, err := sandboxrelayd.ReadRun(obs, f053ContainerRun)
	if err != nil {
		t.Fatal(err)
	}
	// The re-key as readoptRekey builds it: the compose's facts name no
	// terminal run.
	after := sandboxrelayd.RunRecord{RunID: f053ContainerRun, ProjectRoot: obs, TerminalRunID: readoptTerminalRun(obs, f053ContainerRun, "")}
	now := time.Now()
	r := &egressRefusalReceiver{lim: sandboxnet.NewRefusalLimiter(0), now: func() time.Time { return now }}
	rep := sandboxrelay.EgressRefusalReport{Host: "refused.invalid", Port: 80, Rule: string(sandboxnet.RefusalAllowListMiss), AtMS: now.UnixMilli()}
	rowBefore, ok1 := r.row(before, rep)
	rowAfter, ok2 := r.row(after, rep)
	if !ok1 || !ok2 {
		t.Fatalf("rows rejected: %v %v", ok1, ok2)
	}
	if rowBefore.RunID != f053TerminalRun || rowAfter.RunID != rowBefore.RunID {
		t.Fatalf("run ids before %q after %q, want both %q", rowBefore.RunID, rowAfter.RunID, f053TerminalRun)
	}
}
