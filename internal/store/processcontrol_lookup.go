package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// processcontrol_lookup.go is the READ seam over the guard_events
// process_control audit rows internal/store/nodeinterventionaudit.go writes
// (InsertNodeProcessControlAudit). It exists so a dashboard terminal surface
// (LaunchTerminal modal + the minimized pill) can explain a terminal exit the
// daemon itself caused — an org-managed node's node-intervention loop
// stopping a vendor process the operator launched from "New Terminal" — with
// the SAME audit row the daemon already wrote, rather than guessing at a bare
// exit code. This file only reads; InsertNodeProcessControlAudit remains the
// one writer (CLAUDE.md module-boundary rule #4).

// ProcessControlStop is one guard_events process_control audit row, decoded
// down to what a UI surface may show: the rule that fired, the outcome
// decision, the bounded human-readable reason, and when it happened. It
// deliberately excludes the audit row's process-identity fields
// (pid/uid/boot_id/executable device+inode) and policy/pricing fingerprints —
// those are attribution/forensics metadata, not something to echo to an
// operator explaining why their terminal closed.
type ProcessControlStop struct {
	// RuleID is the policy rule that fired (e.g. "B-602").
	RuleID string
	// Decision is the outcome status nodeProcessControlStatus normalized
	// (e.g. "terminated", "killed", "policy_unavailable").
	Decision string
	// Reason is the bounded human-readable explanation the intervention
	// outcome carried (nodeProcessControlReasonMetadata.Reason).
	Reason string
	// At is the audit row's timestamp (guard_events.ts).
	At time.Time
}

// processControlStopLookupLimit bounds the guard_events scan to the newest N
// process_control rows within the window: a terminal run is stopped by the
// node-intervention loop at most once, so the newest match in the window is
// authoritative, and this keeps the read a single bounded query rather than an
// unbounded table scan on a busy managed node.
const processControlStopLookupLimit = 50

// nodeProcessControlReasonView is the subset of the writer-side
// nodeProcessControlReasonMetadata (nodeinterventionaudit.go) this read seam
// needs to decode from guard_events.reason. Declared separately from the
// writer's type — even though both live in this package — so this seam only
// ever depends on the two JSON keys it actually reads and stays correct even
// if the writer's metadata struct grows unrelated fields.
type nodeProcessControlReasonView struct {
	PID    int    `json:"pid"`
	Reason string `json:"reason"`
}

// LookupProcessControlStop returns the newest guard_events process_control
// audit row (category=process_control, event_kind=NodeProcessControlEventKind)
// whose reason metadata names pid, among rows with ts >= since. found is false
// when no such row exists in the window — the honest "no policy stop on
// record", never a guess. since is normally the terminal run's launch time, so
// a stale audit row from an earlier, unrelated process that happened to reuse
// the same OS pid is never matched.
func (s *Store) LookupProcessControlStop(ctx context.Context, pid int, since time.Time) (stop ProcessControlStop, found bool, err error) {
	if s == nil || s.db == nil {
		return ProcessControlStop{}, false, errors.New("store.LookupProcessControlStop: store unavailable")
	}
	if ctx == nil {
		return ProcessControlStop{}, false, errors.New("store.LookupProcessControlStop: nil context")
	}
	if pid <= 0 {
		return ProcessControlStop{}, false, nil
	}
	rows, qerr := s.db.QueryContext(ctx, `
		SELECT ts, rule_id, decision, reason
		  FROM guard_events
		 WHERE category = ? AND event_kind = ? AND ts >= ?
		 ORDER BY ts DESC, id DESC
		 LIMIT ?`,
		nodeProcessControlCategory, NodeProcessControlEventKind, timestamp(since), processControlStopLookupLimit)
	if qerr != nil {
		return ProcessControlStop{}, false, fmt.Errorf("store.LookupProcessControlStop: query: %w", qerr)
	}
	defer rows.Close()

	for rows.Next() {
		var tsStr, ruleID, decision string
		var reason sql.NullString
		if serr := rows.Scan(&tsStr, &ruleID, &decision, &reason); serr != nil {
			return ProcessControlStop{}, false, fmt.Errorf("store.LookupProcessControlStop: scan: %w", serr)
		}
		if !reason.Valid || reason.String == "" {
			continue
		}
		var view nodeProcessControlReasonView
		if jerr := json.Unmarshal([]byte(reason.String), &view); jerr != nil {
			continue // a malformed/foreign reason payload is skipped, never fatal
		}
		if view.PID != pid {
			continue
		}
		at, perr := time.Parse(time.RFC3339Nano, tsStr)
		if perr != nil {
			at = time.Time{}
		}
		return ProcessControlStop{
			RuleID:   ruleID,
			Decision: decision,
			Reason:   view.Reason,
			At:       at,
		}, true, nil
	}
	if rerr := rows.Err(); rerr != nil {
		return ProcessControlStop{}, false, fmt.Errorf("store.LookupProcessControlStop: rows: %w", rerr)
	}
	return ProcessControlStop{}, false, nil
}
