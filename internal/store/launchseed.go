package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// launchseed.go — SQL seams for the launch_seeds table (migration 086).
//
// Ownership (CLAUDE.md rule 4): a pending row is written by the launcher at
// spawn and consumed (deleted) by the daemon sweep's atomic claim;
// unconsumed rows past the match window are expired by the sweep. The
// matching rule itself is pure — processobs.MatchLaunchSeeds — this file is
// I/O only.

// InsertLaunchSeed records a launched child pid so the daemon sweep can bind
// it to the session the watcher will ingest. Upsert on pid: a recycled pid
// from an earlier, already-retracted launch must not collide.
func (s *Store) InsertLaunchSeed(ctx context.Context, seed processobs.LaunchSeed) error {
	if seed.PID <= 0 {
		return errors.New("store.InsertLaunchSeed: PID must be > 0")
	}
	if seed.Tool == "" {
		return errors.New("store.InsertLaunchSeed: Tool required")
	}
	now := timestamp(time.Now().UTC())
	started := timestamp(seed.StartedAt)
	if seed.StartedAt.IsZero() {
		started = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO launch_seeds (pid, tool, cwd, started_at, updated_at, run_id)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(pid) DO UPDATE SET
		  tool       = excluded.tool,
		  cwd        = excluded.cwd,
		  started_at = excluded.started_at,
		  updated_at = excluded.updated_at,
		  run_id     = excluded.run_id`,
		seed.PID, seed.Tool, seed.CWD, started, now, seed.RunID)
	if err != nil {
		return fmt.Errorf("store.InsertLaunchSeed: %w", err)
	}
	return nil
}

// PendingLaunchSeeds returns unconsumed seeds whose started_at falls inside
// the match window (younger than maxAge). Older unconsumed seeds are the
// expiry pass's job, never this query's concern.
func (s *Store) PendingLaunchSeeds(ctx context.Context, maxAge time.Duration) ([]processobs.LaunchSeed, error) {
	since := timestamp(time.Now().UTC().Add(-maxAge))
	rows, err := s.db.QueryContext(ctx, `
		SELECT pid, tool, cwd, started_at, run_id
		  FROM launch_seeds
		 WHERE started_at >= ?`,
		since)
	if err != nil {
		return nil, fmt.Errorf("store.PendingLaunchSeeds: %w", err)
	}
	defer rows.Close()
	var out []processobs.LaunchSeed
	for rows.Next() {
		var seed processobs.LaunchSeed
		var started string
		if err := rows.Scan(&seed.PID, &seed.Tool, &seed.CWD, &started, &seed.RunID); err != nil {
			return nil, fmt.Errorf("store.PendingLaunchSeeds: scan: %w", err)
		}
		seed.StartedAt = parseStamp(started)
		out = append(out, seed)
	}
	return out, rows.Err()
}

// ClaimLaunchSeed atomically consumes a pending seed: the row is deleted and
// true reports that THIS caller won the claim (a row already retracted by the
// launcher's exit path reports false). The winner writes the
// session_pid_bridge row; the bridge row's later lifecycle is the standard
// pidbridge prune (same retention posture as hook-written rows), so no
// consumed-row bookkeeping survives here.
func (s *Store) ClaimLaunchSeed(ctx context.Context, pid int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM launch_seeds WHERE pid = ?`, pid)
	if err != nil {
		return false, fmt.Errorf("store.ClaimLaunchSeed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store.ClaimLaunchSeed: rows: %w", err)
	}
	return n > 0, nil
}

// ExpireStaleLaunchSeeds deletes unconsumed seeds older than olderThan —
// launches that died with their launcher (SIGKILL) or never produced a
// session inside the match window. Returns the number removed.
func (s *Store) ExpireStaleLaunchSeeds(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := timestamp(time.Now().UTC().Add(-olderThan))
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM launch_seeds WHERE started_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store.ExpireStaleLaunchSeeds: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.ExpireStaleLaunchSeeds: rows: %w", err)
	}
	return int(n), nil
}

// LaunchSeedRunSessions resolves {run_id → session_id} for the pending seeds
// that carry a run id (migration 091). It is the deterministic half of
// processobs.MatchLaunchSeeds: the daemon minted the run id before spawning
// the launcher, so this join REPLACES the cwd/tool/time inference for every
// dashboard-launched child.
//
// Two rules are applied here, at the boundary, so the pure matcher can trust
// what it is handed rather than re-judge it:
//
//   - CONFIDENCE GATE. Only correlations at or above minConfidence are
//     admitted. Callers pass termrun.MinLinkConfidence — the same bar every
//     other link attachment clears — which excludes the heuristic-sourced
//     correlations. Admitting those would promote one guess over another
//     while producing a session_pid_bridge row that every reader treats as
//     HIGH-confidence identity.
//   - ONE SESSION PER RUN. A run may accumulate several correlations; the
//     STRONGEST wins, ties broken by the earliest observation so the result
//     is stable across sweeps. A run whose best correlation is below the gate
//     contributes nothing and its seed falls back to the heuristic — absence,
//     never a weak answer dressed up as a strong one.
//
// An empty runIDs slice returns nil without touching the DB.
func (s *Store) LaunchSeedRunSessions(ctx context.Context, runIDs []string, minConfidence float64) (map[string]string, error) {
	ids := make([]any, 0, len(runIDs))
	seen := make(map[string]bool, len(runIDs))
	for _, id := range runIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	// The ORDER BY + first-wins scan is what implements "strongest per run";
	// doing it in SQL with a window function would cost a correlated subquery
	// on a table this small for no benefit.
	//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value is bound.
	query := `
		SELECT run_id, session_id
		  FROM terminal_run_session
		 WHERE confidence >= ?
		   AND run_id IN (` + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + `)
		 ORDER BY run_id, confidence DESC, observed_at ASC, session_id ASC`
	args := append([]any{minConfidence}, ids...)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.LaunchSeedRunSessions: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string, len(ids))
	for rows.Next() {
		var runID, sessionID string
		if err := rows.Scan(&runID, &sessionID); err != nil {
			return nil, fmt.Errorf("store.LaunchSeedRunSessions: scan: %w", err)
		}
		if runID == "" || sessionID == "" {
			continue
		}
		if _, ok := out[runID]; ok {
			continue // a weaker correlation for a run already resolved
		}
		out[runID] = sessionID
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LaunchSeedRunSessions: rows: %w", err)
	}
	return out, nil
}

// RecentSessionRefsForLaunchMatch loads the session candidates the launch-seed
// matcher may pair against: sessions started within windowMinutes, projected
// onto the same shape the cross-OS correlator uses.
func (s *Store) RecentSessionRefsForLaunchMatch(ctx context.Context, windowMinutes int) ([]processobs.CrossOSSessionRef, error) {
	if windowMinutes <= 0 {
		windowMinutes = 60
	}
	since := timestamp(time.Now().UTC().Add(-time.Duration(windowMinutes) * time.Minute))
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.tool, COALESCE(p.root_path, ''), s.started_at
		  FROM sessions s JOIN projects p ON s.project_id = p.id
		 WHERE s.started_at >= ?`,
		since)
	if err != nil {
		return nil, fmt.Errorf("store.RecentSessionRefsForLaunchMatch: %w", err)
	}
	defer rows.Close()
	var out []processobs.CrossOSSessionRef
	for rows.Next() {
		var ref processobs.CrossOSSessionRef
		var started string
		if err := rows.Scan(&ref.SessionID, &ref.Tool, &ref.ProjectRoot, &started); err != nil {
			return nil, fmt.Errorf("store.RecentSessionRefsForLaunchMatch: scan: %w", err)
		}
		ref.StartedAt = parseStamp(started)
		out = append(out, ref)
	}
	return out, rows.Err()
}
