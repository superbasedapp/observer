package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// HOOK LIVENESS (surface-gap review 2026-10-25, OBS-7 / CC-2; agent
// migration 198). The table name never enters orgpush.go (privacy
// sentinel, tests/invariant/privacy_test.go); its rows reach the org only
// as the HookActivitySessionRow wire composed by hookactivitysummary.go
// under [org_client.share].hook_activity (decision DEC-5). This file is its
// ONE owner: UpsertHookActivity is the only writer (called by the
// daemon's hook spool drainer, never by a hook process), PruneHookActivity
// its retention delete, and the loaders below the only reads. A component
// purge (componentpurge.go, purgeSessionDecisions) also deletes a purged
// session's rows, as it does for every session-keyed table.

// hookActivityTimeLayout is fixed width, so the first_at / last_at MIN / MAX
// in the upsert compare correctly as strings.
const hookActivityTimeLayout = "2006-01-02T15:04:05.000000000Z"

// HookActivityRetention is how long a hook_activity row is kept after its
// last invocation.
const HookActivityRetention = 30 * 24 * time.Hour

// HookActivityRow is one drained hook invocation (Count 1) or an aggregate
// of several. SessionID "" is the unattributed bucket. EnvClasses maps env
// variable NAMES to coarse classes (internal/hookliveness.EnvClasses); a
// value is never stored.
type HookActivityRow struct {
	Tool       string
	Event      string
	SessionID  string
	Count      int64
	FirstAt    time.Time
	LastAt     time.Time
	EnvClasses map[string]string
}

type hookActivityKey struct{ tool, event, session string }

// UpsertHookActivity folds rows into hook_activity in one transaction:
// counts add, first_at keeps the earliest, last_at the latest, and the env
// classes of the latest invocation that carried any replace the stored
// ones. Rows sharing a key are aggregated first. A row with no tool or event
// is skipped. A zero Count counts as one invocation.
func (s *Store) UpsertHookActivity(ctx context.Context, rows []HookActivityRow) error {
	agg := map[hookActivityKey]*HookActivityRow{}
	var order []hookActivityKey
	for _, r := range rows {
		if r.Tool == "" || r.Event == "" {
			continue
		}
		if r.Count <= 0 {
			r.Count = 1
		}
		if r.FirstAt.IsZero() {
			r.FirstAt = r.LastAt
		}
		if r.LastAt.IsZero() {
			r.LastAt = r.FirstAt
		}
		k := hookActivityKey{r.Tool, r.Event, r.SessionID}
		a := agg[k]
		if a == nil {
			c := r
			agg[k] = &c
			order = append(order, k)
			continue
		}
		a.Count += r.Count
		if r.FirstAt.Before(a.FirstAt) {
			a.FirstAt = r.FirstAt
		}
		if !r.LastAt.Before(a.LastAt) {
			a.LastAt = r.LastAt
			if len(r.EnvClasses) > 0 {
				a.EnvClasses = r.EnvClasses
			}
		} else if len(a.EnvClasses) == 0 {
			a.EnvClasses = r.EnvClasses
		}
	}
	if len(order) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertHookActivity: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO hook_activity (tool, event, session_id, count, first_at, last_at, env_classes)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tool, event, session_id) DO UPDATE SET
			count = hook_activity.count + excluded.count,
			first_at = MIN(hook_activity.first_at, excluded.first_at),
			env_classes = CASE
				WHEN excluded.env_classes != '' AND excluded.last_at >= hook_activity.last_at THEN excluded.env_classes
				WHEN hook_activity.env_classes = '' THEN excluded.env_classes
				ELSE hook_activity.env_classes END,
			last_at = MAX(hook_activity.last_at, excluded.last_at)`)
	if err != nil {
		return fmt.Errorf("store.UpsertHookActivity: prepare: %w", err)
	}
	defer stmt.Close()
	for _, k := range order {
		r := agg[k]
		env := ""
		if len(r.EnvClasses) > 0 {
			b, err := json.Marshal(r.EnvClasses)
			if err != nil {
				return fmt.Errorf("store.UpsertHookActivity: env: %w", err)
			}
			env = string(b)
		}
		if _, err := stmt.ExecContext(ctx, r.Tool, r.Event, r.SessionID, r.Count,
			r.FirstAt.UTC().Format(hookActivityTimeLayout), r.LastAt.UTC().Format(hookActivityTimeLayout), env); err != nil {
			return fmt.Errorf("store.UpsertHookActivity: exec: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.UpsertHookActivity: commit: %w", err)
	}
	return nil
}

// PruneHookActivity deletes rows whose last invocation is before cutoff and
// returns how many it removed.
func (s *Store) PruneHookActivity(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM hook_activity WHERE last_at < ?`, cutoff.UTC().Format(hookActivityTimeLayout))
	if err != nil {
		return 0, fmt.Errorf("store.PruneHookActivity: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// LoadHookActivity returns the rows whose last invocation is at or after
// since, ordered by tool, event, session id.
func (s *Store) LoadHookActivity(ctx context.Context, since time.Time) ([]HookActivityRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT tool, event, session_id, count, first_at, last_at, env_classes
		FROM hook_activity WHERE last_at >= ?
		ORDER BY tool, event, session_id`, since.UTC().Format(hookActivityTimeLayout))
	if err != nil {
		return nil, fmt.Errorf("store.LoadHookActivity: %w", err)
	}
	defer rows.Close()
	var out []HookActivityRow
	for rows.Next() {
		var r HookActivityRow
		var first, last, env string
		if err := rows.Scan(&r.Tool, &r.Event, &r.SessionID, &r.Count, &first, &last, &env); err != nil {
			return nil, fmt.Errorf("store.LoadHookActivity: scan: %w", err)
		}
		r.FirstAt, _ = time.Parse(hookActivityTimeLayout, first)
		r.LastAt, _ = time.Parse(hookActivityTimeLayout, last)
		if env != "" {
			_ = json.Unmarshal([]byte(env), &r.EnvClasses)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadHookActivity: rows: %w", err)
	}
	return out, nil
}

// HookActivityEpoch is the earliest first_at the table holds (zero when it
// is empty): the moment this node started recording hook liveness, as far
// as retention still shows.
func (s *Store) HookActivityEpoch(ctx context.Context) (time.Time, error) {
	var first *string
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(first_at) FROM hook_activity`).Scan(&first); err != nil {
		return time.Time{}, fmt.Errorf("store.HookActivityEpoch: %w", err)
	}
	if first == nil {
		return time.Time{}, nil
	}
	t, _ := time.Parse(hookActivityTimeLayout, *first)
	return t, nil
}

// HookLivenessSession is one captured session the liveness classifier
// judges.
type HookLivenessSession struct {
	ID        string
	Tool      string
	Surface   string
	StartedAt time.Time
}

// HookLivenessSessions returns, per tool, the sessions started at or after
// since, newest first, at most perTool each.
func (s *Store) HookLivenessSessions(ctx context.Context, since time.Time, perTool int) (map[string][]HookLivenessSession, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tool, COALESCE(surface, ''), started_at FROM sessions
		WHERE started_at >= ?
		ORDER BY started_at DESC`, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("store.HookLivenessSessions: %w", err)
	}
	defer rows.Close()
	out := map[string][]HookLivenessSession{}
	for rows.Next() {
		var r HookLivenessSession
		var started string
		if err := rows.Scan(&r.ID, &r.Tool, &r.Surface, &started); err != nil {
			return nil, fmt.Errorf("store.HookLivenessSessions: scan: %w", err)
		}
		if perTool > 0 && len(out[r.Tool]) >= perTool {
			continue
		}
		r.StartedAt = parseLivenessTime(started)
		out[r.Tool] = append(out[r.Tool], r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.HookLivenessSessions: rows: %w", err)
	}
	return out, nil
}

// parseLivenessTime reads a sessions.started_at stamp (RFC 3339, with or
// without fractional seconds). Zero when unparseable.
func parseLivenessTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Time{}
}
