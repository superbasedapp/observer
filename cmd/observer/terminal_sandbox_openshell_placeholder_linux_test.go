//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// TestOpenShellReaperClearsAKilledHelpersPlaceholder (build tracker
// F-052): O1B-L1 SIGKILLs run 2's host helper, which had created the
// read-only placeholder `{}` at ~/.claude/settings.json (claude-code's
// ProtectRO path, missing on the host), so the file stayed on the host
// until the next daemon start. The reaper now clears the ledger of each
// run it judges abandoned. One row per case: a killed helper's untouched
// placeholder goes; a live helper's (its ledger still locked) stays; a
// placeholder the user has since written to stays; a run with no ledger
// and an invalid run id clear nothing.
func TestOpenShellReaperClearsAKilledHelpersPlaceholder(t *testing.T) {
	cases := []struct {
		name     string
		run      string
		ledger   bool // the helper recorded a ledger
		killed   bool // the helper is gone (its lock dropped)
		userEdit bool // the user wrote to the file after the helper died
		cleared  int  // ledgers the reaper reports cleared
		fileGone bool
	}{
		{name: "killed helper", run: "run-f052-0001", ledger: true, killed: true, cleared: 1, fileGone: true},
		{name: "live helper", run: "run-f052-0002", ledger: true},
		{name: "user wrote to it since", run: "run-f052-0003", ledger: true, killed: true, userEdit: true, cleared: 1},
		{name: "no ledger", run: "run-f052-0004", killed: true},
		{name: "invalid run id", run: "../escape", killed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := relayShortDir(t)
			claudeDir := filepath.Join(t.TempDir(), ".claude")
			if err := os.Mkdir(claudeDir, 0o700); err != nil {
				t.Fatal(err)
			}
			settings := filepath.Join(claudeDir, "settings.json")
			created, err := createPlaceholders([]string{settings}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(settings); string(b) != "{}\n" {
				t.Fatalf("placeholder body %q, want the 3-byte {} the live run found", b)
			}
			if tc.ledger {
				l, err := openPlaceholderLedger(obs, tc.run)
				if err != nil || l == nil {
					t.Fatalf("open ledger: %v", err)
				}
				if err := l.record(created); err != nil {
					t.Fatal(err)
				}
				if tc.killed {
					_ = l.f.Close() // SIGKILL: the lock goes, the ledger stays
				} else {
					t.Cleanup(l.close)
				}
			}
			if tc.userEdit {
				f, err := os.OpenFile(settings, os.O_WRONLY|os.O_TRUNC, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = f.WriteString("{\"theme\":\"dark\"}\n")
				_ = f.Close()
			}
			if got := openShellClearAbandonedPlaceholders(obs, []string{tc.run}); got != tc.cleared {
				t.Fatalf("cleared %d ledgers, want %d", got, tc.cleared)
			}
			if gone := !phExists(settings); gone != tc.fileGone {
				t.Fatalf("placeholder gone %v, want %v", gone, tc.fileGone)
			}
			if tc.ledger && tc.killed && phExists(placeholderLedgerPath(obs, tc.run)) {
				t.Fatal("a killed helper's ledger survived the reaper")
			}
		})
	}
}

// TestOpenShellReapPassClearsAbandonedPlaceholders (audit FU12-A8): the
// reaper loop's one pass function, driven with a fake CLI, clears the
// placeholder ledger of a run it judges abandoned under the observer dir
// it is given, and leaves a held run's and a young run's alone. One row
// per case.
func TestOpenShellReapPassClearsAbandonedPlaceholders(t *testing.T) {
	const run = "run-f052-pass1"
	for _, tc := range []struct {
		name    string
		held    bool
		young   bool // the plan is inside the reaper's grace
		cleared int
	}{
		{name: "abandoned", cleared: 1},
		{name: "held by its helper", held: true},
		{name: "inside the grace", young: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			prevRoot := openShellSockRoot
			t.Cleanup(func() { openShellSockRoot = prevRoot })
			openShellSockRoot = func() string { return root }
			obs := relayShortDir(t)
			stateDir := t.TempDir()
			dir := openShellRunDir(stateDir, run)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			pf := openShellPlanFile{
				Version: openShellPlanVersion, RunID: run, Target: sandboxopenshell.Target{Gateway: "openshell"}, Server: openShellTestServer,
				GatewayVersion: "0.1.6", Name: sandboxopenshell.SandboxName(run), SockDir: filepath.Join(root, "observer-sbx-"+run),
			}
			plan := filepath.Join(dir, "plan.json")
			if err := openShellWriteExcl(plan, openShellJSON(t, pf)); err != nil {
				t.Fatal(err)
			}
			if !tc.young {
				old := time.Now().Add(-time.Hour)
				if err := os.Chtimes(plan, old, old); err != nil {
					t.Fatal(err)
				}
			}
			claudeDir := filepath.Join(t.TempDir(), ".claude")
			if err := os.Mkdir(claudeDir, 0o700); err != nil {
				t.Fatal(err)
			}
			settings := filepath.Join(claudeDir, "settings.json")
			created, err := createPlaceholders([]string{settings}, nil)
			if err != nil {
				t.Fatal(err)
			}
			l, err := openPlaceholderLedger(obs, run)
			if err != nil || l == nil {
				t.Fatalf("open ledger: %v", err)
			}
			if err := l.record(created); err != nil {
				t.Fatal(err)
			}
			if tc.held {
				t.Cleanup(l.close)
			} else {
				_ = l.f.Close() // SIGKILL
			}
			f := healthyOpenShell()
			f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
				if slices.Contains(args, "status") {
					return extrun.ExecFacts{Stdout: []byte(f.status), PeakChildren: -1}, true
				}
				return extrun.ExecFacts{ExitCode: 1, Stderr: []byte("unavailable"), PeakChildren: -1}, true
			}
			r, _ := f.runner()
			res := openShellReapPass(context.Background(), r, stateDir, obs, "", func(d string) bool { return tc.held && filepath.Base(d) == run }, time.Now)
			if res.Cleared != tc.cleared {
				t.Fatalf("cleared %d ledgers, want %d (pass %+v)", res.Cleared, tc.cleared, res)
			}
			if gone := !phExists(settings); gone != (tc.cleared == 1) {
				t.Fatalf("placeholder gone %v, want %v", gone, tc.cleared == 1)
			}
		})
	}
}
