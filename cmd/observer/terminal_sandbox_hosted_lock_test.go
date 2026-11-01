//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// hostedLockChildEnv names the state directory and the child id of
// TestHostedStateLockChild.
const hostedLockChildEnv = "OBSERVER_HOSTED_LOCK_CHILD"

// hostedLockRounds is how many reserve, record and settle rounds each child
// runs.
const hostedLockRounds = 25

// TestHostedStateLockChild is the child half of
// TestHostedStateLockAcrossProcesses: it plays one run's sandbox-hosted-host
// helper, reserving, recording and settling its own runs, with the
// read-modify-write window widened so an unlocked ledger loses entries.
func TestHostedStateLockChild(t *testing.T) {
	spec := os.Getenv(hostedLockChildEnv)
	if spec == "" {
		t.Skip("run only as TestHostedStateLockAcrossProcesses's child process")
	}
	dir, id, _ := strings.Cut(spec, "|")
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for i := 0; i < hostedLockRounds; i++ {
		run := fmt.Sprintf("%s-%d", id, i)
		if err := hostedUpdateLedger(dir, now, func(l *sandboxremote.Ledger) error {
			time.Sleep(2 * time.Millisecond)
			l.Reserve(sandboxremote.VendorE2B, sandboxremote.DayOf(now), run, 30)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		rec := sandboxremote.NewIntent(run, sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", run, now, time.Hour)
		if err := hostedSaveRecord(dir, rec); err != nil {
			t.Fatal(err)
		}
		if err := hostedUpdateLedger(dir, now, func(l *sandboxremote.Ledger) error {
			time.Sleep(time.Millisecond)
			l.Settle(run, 10*time.Minute)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestHostedStateLockAcrossProcesses (the SBX-P7 merge's audit finding 3):
// two processes reserving and settling against one spend ledger at once
// never lose a reservation, and a settle never overwrites another run's.
func TestHostedStateLockAcrossProcesses(t *testing.T) {
	if os.Getenv(hostedLockChildEnv) != "" {
		t.Skip("the parent half")
	}
	dir := t.TempDir()
	type child struct {
		cmd *exec.Cmd
		out *bytes.Buffer
	}
	var kids []child
	for _, id := range []string{"a", "b"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHostedStateLockChild$", "-test.count=1") //nolint:gosec // G204: the test binary itself
		cmd.Env = append(os.Environ(), hostedLockChildEnv+"="+dir+"|"+id)
		out := &bytes.Buffer{}
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		kids = append(kids, child{cmd, out})
	}
	for _, k := range kids {
		if err := k.cmd.Wait(); err != nil {
			t.Fatalf("child: %v\n%s", err, k.out.String())
		}
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	var entries []sandboxremote.LedgerEntry
	_ = hostedUpdateLedger(dir, now, func(l *sandboxremote.Ledger) error {
		entries = append(entries, l.Entries...)
		return errors.New("read only")
	})
	if len(entries) != 2*hostedLockRounds {
		t.Fatalf("the ledger holds %d entries, want %d: a reservation was lost", len(entries), 2*hostedLockRounds)
	}
	for _, e := range entries {
		if !e.Settled || e.Minutes != 10 {
			t.Errorf("run %s: settled %v minutes %d, want settled at 10", e.RunID, e.Settled, e.Minutes)
		}
	}
	if recs := hostedLoadRecords(dir); len(recs) != 2*hostedLockRounds {
		t.Errorf("%d run records, want %d", len(recs), 2*hostedLockRounds)
	}
}
