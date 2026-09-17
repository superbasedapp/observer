package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/pidbridge"
)

// LookupSessionPID resolves the session a specific OS pid is already known
// to belong to, via the session_pid_bridge table (migration 004) — the SAME
// direct-attribution bridge the SessionStart-hook writers and the
// SessionProcessSeeds ingest path (see the "Session-process attribution
// seeds" block above in this package) populate. It is a plain, honest
// lookup: ok=false on a clean miss (no bridge row, an empty session id, a
// tool mismatch, or an unfenced/stale row — see below) — never a guess or a
// fabricated id (the same rule NodeProcessControlAudit's own doc comment
// states: "this helper never invents one").
//
// tool, when non-empty, additionally requires the bridge row to name the
// SAME tool (case-insensitively), so a caller cannot pick up an unrelated
// session merely because the OS recycled this pid to a different process
// of the caller's own tool before the row was pruned; passing "" skips
// that check.
//
// PID-REUSE FENCE. A bridge row is retracted only cooperatively (a writer
// that knows its process exited calls Delete) plus a 6h prune at daemon
// start — an orphaned row from a kill -9'd process can outlive it
// indefinitely in between. If the OS later hands that exact pid to an
// unrelated process (very plausible for a short-lived-pid-heavy tool), a
// tool-matching row alone would hand this caller the OLD session for a
// process that never had anything to do with it — dangerous specifically
// because a caller here feeds an ENFORCEMENT/audit trail, not a soft UI
// hint. So a hit is trusted only when the row's own UpdatedAt is AT OR
// AFTER the pid's CURRENT occupant's actual start time
// (pidbridge.ProcessStartTime, read fresh from /proc on every call): a row
// last written before this process existed could not possibly be an
// attribution of it. When ProcessStartTime itself cannot be established
// (non-Linux, an unreadable /proc, a raced-exited pid), that is "cannot
// verify," and the safest available fence is to refuse the row rather than
// trust it unchecked — this makes the fence Linux-effective-only by
// construction, which is fine: LookupSessionPID's only caller
// (node-intervention) is itself Linux-only.
//
// pidbridge types never leak past this seam (module boundary rule #1/#2 —
// same discipline as the existing session_pid_bridge writer in Ingest).
func (s *Store) LookupSessionPID(ctx context.Context, pid int, tool string) (sessionID string, ok bool, err error) {
	if s == nil || s.db == nil {
		return "", false, errors.New("store.LookupSessionPID: store unavailable")
	}
	if ctx == nil {
		return "", false, errors.New("store.LookupSessionPID: nil context")
	}
	if pid <= 0 {
		return "", false, nil
	}
	entry, found, lookupErr := pidbridge.New(s.db).Lookup(ctx, pid)
	if lookupErr != nil {
		return "", false, fmt.Errorf("store.LookupSessionPID: %w", lookupErr)
	}
	if !found || entry.SessionID == "" {
		return "", false, nil
	}
	if tool != "" && !strings.EqualFold(entry.Tool, tool) {
		return "", false, nil
	}
	startedAt, startOK := pidbridge.ProcessStartTime(pid)
	if !startOK || entry.UpdatedAt.Before(startedAt) {
		// Either the live process's start time couldn't be verified, or the
		// bridge row demonstrably predates it (pid reuse). Both are a clean
		// miss, never a guess.
		return "", false, nil
	}
	return entry.SessionID, true, nil
}
