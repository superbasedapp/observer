package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestNodeInterventionWorkloadSessionID pins P1-7's fix at the seam
// reconcileNodeIntervention actually calls: a matched process whose pid is
// already bridged to a real session (the SessionStart hook / watcher-path
// seed path both write session_pid_bridge for exactly this reason) gets
// that real session id, a pid the bridge has never heard of gets "" (never
// a guess), and a bridge row for a DIFFERENT tool is refused rather than
// misattributed to this one.
//
// The "bridged" case uses os.Getpid() (this test binary's own, genuinely
// live pid): store.LookupSessionPID's pid-reuse fence (P2-2) requires
// pidbridge.ProcessStartTime to independently confirm a real process is
// live at pid before trusting any row for it, so an arbitrary made-up pid
// can no longer hit.
func TestNodeInterventionWorkloadSessionID(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "store.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	pid := os.Getpid()

	if err := pidbridge.New(database).Write(ctx, pidbridge.Entry{
		PID: pid, SessionID: "sess-bridged", Tool: "muse",
	}); err != nil {
		t.Fatalf("seed bridge row: %v", err)
	}

	if got := nodeInterventionWorkloadSessionID(ctx, st, pid, "muse"); got != "sess-bridged" {
		t.Fatalf("bridged pid: got %q, want sess-bridged", got)
	}
	if got := nodeInterventionWorkloadSessionID(ctx, st, pid, "codex"); got != "" {
		t.Fatalf("tool mismatch must never misattribute: got %q, want \"\"", got)
	}
	if got := nodeInterventionWorkloadSessionID(ctx, st, 999999, "muse"); got != "" {
		t.Fatalf("unbridged pid must stay honestly unknown: got %q, want \"\"", got)
	}
	if got := nodeInterventionWorkloadSessionID(ctx, st, 0, "muse"); got != "" {
		t.Fatalf("non-positive pid must never look up: got %q, want \"\"", got)
	}
	if got := nodeInterventionWorkloadSessionID(ctx, nil, pid, "muse"); got != "" {
		t.Fatalf("nil store must degrade to empty, not panic: got %q", got)
	}
}
