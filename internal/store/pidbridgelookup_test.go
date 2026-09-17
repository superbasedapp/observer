package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/pidbridge"
)

// TestLookupSessionPID pins the honest-miss and real-hit shapes P1-7's
// node-intervention wiring depends on: a bridge row for the exact pid names
// a real session, a tool mismatch or missing row is a clean miss, and it
// never fabricates an id.
//
// The "hit" cases use os.Getpid() (this test binary's own, genuinely live
// pid) rather than an arbitrary number: LookupSessionPID's pid-reuse fence
// (P2-2) requires pidbridge.ProcessStartTime to independently confirm a
// real process is live at pid before trusting any row for it, so a made-up
// pid can never hit any more — that would defeat the fence's whole point.
func TestLookupSessionPID(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	pid := os.Getpid()

	if err := pidbridge.New(database).Write(ctx, pidbridge.Entry{
		PID: pid, SessionID: "sess-real", Tool: "muse",
	}); err != nil {
		t.Fatalf("seed bridge row: %v", err)
	}

	t.Run("hit, tool matches", func(t *testing.T) {
		id, ok, err := s.LookupSessionPID(ctx, pid, "muse")
		if err != nil || !ok || id != "sess-real" {
			t.Fatalf("LookupSessionPID(pid, muse) = %q, %v, %v; want sess-real, true, nil", id, ok, err)
		}
	})

	t.Run("hit, tool check skipped when empty", func(t *testing.T) {
		id, ok, err := s.LookupSessionPID(ctx, pid, "")
		if err != nil || !ok || id != "sess-real" {
			t.Fatalf("LookupSessionPID(pid, \"\") = %q, %v, %v; want sess-real, true, nil", id, ok, err)
		}
	})

	t.Run("tool mismatch is a clean miss, never a guess", func(t *testing.T) {
		id, ok, err := s.LookupSessionPID(ctx, pid, "codex")
		if err != nil || ok || id != "" {
			t.Fatalf("LookupSessionPID(pid, codex) = %q, %v, %v; want \"\", false, nil", id, ok, err)
		}
	})

	t.Run("no bridge row is a clean miss", func(t *testing.T) {
		id, ok, err := s.LookupSessionPID(ctx, 99999, "muse")
		if err != nil || ok || id != "" {
			t.Fatalf("LookupSessionPID(99999, muse) = %q, %v, %v; want \"\", false, nil", id, ok, err)
		}
	})

	t.Run("non-positive pid is a clean miss", func(t *testing.T) {
		id, ok, err := s.LookupSessionPID(ctx, 0, "muse")
		if err != nil || ok || id != "" {
			t.Fatalf("LookupSessionPID(0, muse) = %q, %v, %v; want \"\", false, nil", id, ok, err)
		}
	})

	t.Run("nil store never panics", func(t *testing.T) {
		var nilStore *Store
		if _, _, err := nilStore.LookupSessionPID(ctx, pid, "muse"); err == nil {
			t.Fatal("LookupSessionPID on nil store: want error, got nil")
		}
	})
}

// TestLookupSessionPID_PidReuseFence pins P2-2: a bridge row that was last
// written BEFORE the process currently living at that pid ever started
// cannot possibly be an attribution of that process — it is a leftover
// from whatever pid-reuse-vulnerable earlier occupant wrote it (a
// kill -9'd process's row, never cooperatively retracted, then the OS
// handed the same pid to something unrelated) — and must be refused, not
// handed to an ENFORCEMENT audit trail as if it were current.
func TestLookupSessionPID_PidReuseFence(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	pid := os.Getpid() // a real, currently-live process: this test binary.

	t.Run("row updated at or after the live process's start time is trusted", func(t *testing.T) {
		bridge := pidbridge.New(database)
		// Default clock (time.Now) - this write happens well after the test
		// process itself started, so UpdatedAt >= the process's real start.
		if err := bridge.Write(ctx, pidbridge.Entry{PID: pid, SessionID: "sess-live-fresh", Tool: "muse"}); err != nil {
			t.Fatalf("seed fresh bridge row: %v", err)
		}
		id, ok, err := s.LookupSessionPID(ctx, pid, "muse")
		if err != nil || !ok || id != "sess-live-fresh" {
			t.Fatalf("LookupSessionPID(pid, muse) = %q, %v, %v; want sess-live-fresh, true, nil", id, ok, err)
		}
	})

	t.Run("row updated before the live process started is refused as a reused pid", func(t *testing.T) {
		bridge := pidbridge.New(database)
		// A clock stuck in 1970 - long before this test binary's own,
		// genuinely-live process started - simulates an orphaned row from
		// whatever OLD process this pid belonged to before it was recycled.
		bridge.SetClock(func() time.Time { return time.Unix(0, 0) })
		if err := bridge.Write(ctx, pidbridge.Entry{PID: pid, SessionID: "sess-stale-orphan", Tool: "muse"}); err != nil {
			t.Fatalf("seed stale bridge row: %v", err)
		}
		id, ok, err := s.LookupSessionPID(ctx, pid, "muse")
		if err != nil || ok || id != "" {
			t.Fatalf("LookupSessionPID(pid, muse) over a stale row = %q, %v, %v; want \"\", false, nil (fenced as reused)", id, ok, err)
		}
	})
}
