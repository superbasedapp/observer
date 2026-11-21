package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Process capture READ seams for the summary, windowed tree, stats and
// compaction surfaces (docs/plans/process-capture-budget-plan-2026-11-04.md
// §9.3 and §9.4). Read-only: process_runs is written by processobs.go and
// process_rollups / process_capture_stats by processrollups.go. Every query
// here is bounded by an index (idx_process_runs_session (session_id,
// started_at), the partial idx_process_runs_session_service, the rollup
// session index) or by an explicit row cap, so none of them loads a 92k-row
// session whole.
//
// PRIVACY INVARIANT: node-local tables only; nothing here is on the org wire.

// Window caps for the session process tree (plan §9.3).
const (
	// ProcessWindowDefaultLimit is the rows a window returns when the caller
	// names no limit.
	ProcessWindowDefaultLimit = 2000
	// ProcessWindowMaxLimit is the hard cap; a larger limit is clamped.
	ProcessWindowMaxLimit = 10000
)

// ProcessRunWindow bounds a windowed read of one session's process rows.
// From / To bound started_at (a zero bound is open); Since keeps only rows
// seen alive (last_seen_at) at or after it, the polling form. Bounds are
// compared at ONE-SECOND resolution and To is inclusive of its second: the
// stored stamps mix RFC3339 and RFC3339Nano spellings, and the window the
// dashboard echoes back is whole seconds, so a sub-second bound would split
// rows the client cannot tell apart.
type ProcessRunWindow struct {
	From  time.Time
	To    time.Time
	Since time.Time
	Limit int
}

// Normalized returns w with Limit defaulted (<= 0) and capped.
func (w ProcessRunWindow) Normalized() ProcessRunWindow {
	switch {
	case w.Limit <= 0:
		w.Limit = ProcessWindowDefaultLimit
	case w.Limit > ProcessWindowMaxLimit:
		w.Limit = ProcessWindowMaxLimit
	}
	return w
}

// secondFloor is the lexicographic lower bound of t's second: the stamp's
// "YYYY-MM-DDTHH:MM:SS" prefix sorts before every spelling of any instant in
// that second ("…:05Z", "…:05.123Z") and after every earlier second.
func secondFloor(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05")
}

// where builds the window's predicate over process_runs (unaliased columns,
// so it composes with or without the pr alias).
func (w ProcessRunWindow) where(sessionID string) (string, []any) {
	var b strings.Builder
	b.WriteString("session_id = ?")
	args := []any{sessionID}
	if !w.From.IsZero() {
		b.WriteString(" AND started_at >= ?")
		args = append(args, secondFloor(w.From))
	}
	if !w.To.IsZero() {
		b.WriteString(" AND started_at < ?")
		args = append(args, secondFloor(w.To.Add(time.Second)))
	}
	if !w.Since.IsZero() {
		b.WriteString(" AND last_seen_at >= ?")
		args = append(args, secondFloor(w.Since))
	}
	return b.String(), args
}

// ProcessRunWindowResult is one window of a session's process rows, oldest
// first. Truncated reports that the session has rows OLDER than the oldest
// one returned that the window left out (the limit cut them, or From
// excluded them): the dashboard's "Load earlier" pages them with To.
type ProcessRunWindowResult struct {
	Rows      []ProcessRunRow
	Truncated bool
}

// ProcessRunsWindowForSession returns the most recent w.Limit rows of a
// session inside the window, oldest first. With a zero window it is the
// session's newest rows, never its whole history.
func (s *Store) ProcessRunsWindowForSession(ctx context.Context, sessionID string, w ProcessRunWindow) (ProcessRunWindowResult, error) {
	w = w.Normalized()
	pred, args := w.where(sessionID)
	//nolint:gosec // pred is built from this file's literal fragments.
	rows, err := s.db.QueryContext(ctx, `SELECT `+selectProcessRunCols+`
		FROM process_runs pr WHERE `+pred+`
		ORDER BY started_at DESC, pid DESC LIMIT ?`, append(args, w.Limit+1)...)
	if err != nil {
		return ProcessRunWindowResult{}, fmt.Errorf("store.ProcessRunsWindowForSession: query: %w", err)
	}
	defer rows.Close()
	runs, err := scanProcessRunRows(rows, "ProcessRunsWindowForSession")
	if err != nil {
		return ProcessRunWindowResult{}, err
	}
	res := ProcessRunWindowResult{}
	if len(runs) > w.Limit {
		runs = runs[:w.Limit]
		res.Truncated = true
	}
	reverseRuns(runs)
	res.Rows = runs
	if !res.Truncated && !w.From.IsZero() && w.Since.IsZero() {
		var older int
		if err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM process_runs WHERE session_id = ? AND started_at < ?)`,
			sessionID, secondFloor(w.From)).Scan(&older); err != nil {
			return ProcessRunWindowResult{}, fmt.Errorf("store.ProcessRunsWindowForSession: older: %w", err)
		}
		res.Truncated = older != 0
	}
	return res, nil
}

func reverseRuns(runs []ProcessRunRow) {
	for i, j := 0, len(runs)-1; i < j; i, j = i+1, j-1 {
		runs[i], runs[j] = runs[j], runs[i]
	}
}

// ProcessFindingsForSessionWindow derives the observe-only findings (§14) for
// exactly the rows ProcessRunsWindowForSession returns for the same window,
// oldest first, loading only the finding columns (no metric rings).
func (s *Store) ProcessFindingsForSessionWindow(ctx context.Context, sessionID string, w ProcessRunWindow) ([]ProcessFindingRow, error) {
	if sessionID == "" {
		return nil, nil
	}
	w = w.Normalized()
	pred, args := w.where(sessionID)
	//nolint:gosec // pred is built from this file's literal fragments.
	rows, err := s.db.QueryContext(ctx, `SELECT `+findingFactsCols+` FROM process_runs
		WHERE `+pred+` ORDER BY started_at DESC, pid DESC LIMIT ?`, append(args, w.Limit)...)
	if err != nil {
		return nil, fmt.Errorf("store.ProcessFindingsForSessionWindow: query: %w", err)
	}
	defer rows.Close()
	facts, meta, err := scanFindingFacts(rows, "ProcessFindingsForSessionWindow")
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(facts)-1; i < j; i, j = i+1, j-1 {
		facts[i], facts[j] = facts[j], facts[i]
	}
	return buildFindingRows(facts, meta), nil
}

// ProcessSessionRowMark is a cheap change mark for a session's process rows:
// the row count and the highest row id, both answered from
// idx_process_runs_session without touching the rows. A new or deleted row
// moves it; an in-place rewrite (an exit, a metrics refresh) does not, which
// is what ProcessSessionRecentMark adds.
func (s *Store) ProcessSessionRowMark(ctx context.Context, sessionID string) (rows, maxID int64, err error) {
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(id), 0) FROM process_runs WHERE session_id = ?`, sessionID).
		Scan(&rows, &maxID); err != nil {
		return 0, 0, fmt.Errorf("store.ProcessSessionRowMark: %w", err)
	}
	return rows, maxID, nil
}

// ProcessRecentMark is the in-place-rewrite half of the change mark over a
// session's newest rows: the latest last_seen_at, how many exited and how
// many are linked to an action, so an exit, a metrics refresh or a new action
// link on a recent run moves it.
type ProcessRecentMark struct {
	LastSeen string
	Exited   int64
	Linked   int64
}

// ProcessSessionRecentMark computes the ProcessRecentMark over the session's
// newest n rows (the default tree window). Bounded by n; n <= 0 means
// ProcessWindowDefaultLimit.
func (s *Store) ProcessSessionRecentMark(ctx context.Context, sessionID string, n int) (ProcessRecentMark, error) {
	if n <= 0 {
		n = ProcessWindowDefaultLimit
	}
	var m ProcessRecentMark
	var ls sql.NullString
	if err := s.db.QueryRowContext(ctx, `
		SELECT MAX(last_seen_at), COALESCE(SUM(exited_at IS NOT NULL), 0), COALESCE(SUM(action_id IS NOT NULL), 0) FROM (
		    SELECT last_seen_at, exited_at, action_id FROM process_runs WHERE session_id = ?
		     ORDER BY started_at DESC LIMIT ?)`, sessionID, n).Scan(&ls, &m.Exited, &m.Linked); err != nil {
		return ProcessRecentMark{}, fmt.Errorf("store.ProcessSessionRecentMark: %w", err)
	}
	m.LastSeen = ls.String
	return m, nil
}

// ProcessServiceRootRow is one service root of a session for the summary
// endpoint (plan §9.3 services[]): the root row itself plus the totals of
// what ran under it, kept rows (capture_class 'service') and rollups alike.
type ProcessServiceRootRow struct {
	RootKey     string
	Exe         string
	ArgvPreview string
	StartedAt   time.Time
	// LastSeen is the latest sighting of the root, a kept row under it or a
	// rollup of it.
	LastSeen  time.Time
	ActionID  *int64
	TurnIndex *int
	MessageID string
	// Kept counts the rows kept under the root (the root itself excluded);
	// RolledUp the runs rolled up under it.
	Kept     int64
	RolledUp int64
	// CPUSumMs sums the root's, its kept rows' and its rollups' CPU;
	// PeakRSSBytes is the largest of them.
	CPUSumMs     int64
	PeakRSSBytes int64
}

// ProcessServiceRootsForSession returns a session's service roots, oldest
// first, at most limit (<= 0 means 200), with their kept and rolled-up
// totals. Three bounded reads: the roots and their kept rows through the
// partial service index, the rollups through the rollup session index.
func (s *Store) ProcessServiceRootsForSession(ctx context.Context, sessionID string, limit int) ([]ProcessServiceRootRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT pr.process_key, COALESCE(pr.exe_basename, ''), COALESCE(pr.argv_preview, ''),
		       pr.started_at, pr.last_seen_at, pr.action_id, pr.turn_index, COALESCE(a.message_id, ''),
		       COALESCE(pr.cpu_user_ms, 0) + COALESCE(pr.cpu_system_ms, 0), COALESCE(pr.max_rss_bytes, 0)
		  FROM process_runs pr
		  LEFT JOIN actions a ON a.id = pr.action_id
		 WHERE pr.session_id = ? AND pr.service_root_key IS NOT NULL AND pr.capture_class = 'service_root'
		 ORDER BY pr.started_at ASC, pr.id ASC
		 LIMIT ?`, sessionID, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ProcessServiceRootsForSession: roots: %w", err)
	}
	var out []ProcessServiceRootRow
	index := map[string]int{}
	for rows.Next() {
		var r ProcessServiceRootRow
		var started, last string
		var actionID, turn sql.NullInt64
		if err := rows.Scan(&r.RootKey, &r.Exe, &r.ArgvPreview, &started, &last, &actionID, &turn,
			&r.MessageID, &r.CPUSumMs, &r.PeakRSSBytes); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.ProcessServiceRootsForSession: scan root: %w", err)
		}
		r.StartedAt, r.LastSeen = parseStamp(started), parseStamp(last)
		if actionID.Valid {
			v := actionID.Int64
			r.ActionID = &v
		}
		if turn.Valid {
			v := int(turn.Int64)
			r.TurnIndex = &v
		}
		index[r.RootKey] = len(out)
		out = append(out, r)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store.ProcessServiceRootsForSession: roots: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	merge := func(q, who string, add func(r *ProcessServiceRootRow, n int64)) error {
		rows, err := s.db.QueryContext(ctx, q, sessionID)
		if err != nil {
			return fmt.Errorf("store.ProcessServiceRootsForSession: %s: %w", who, err)
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			var n, cpu, rss int64
			var last sql.NullString
			if err := rows.Scan(&key, &n, &cpu, &rss, &last); err != nil {
				return fmt.Errorf("store.ProcessServiceRootsForSession: scan %s: %w", who, err)
			}
			i, ok := index[key]
			if !ok {
				continue
			}
			r := &out[i]
			add(r, n)
			r.CPUSumMs += cpu
			r.PeakRSSBytes = max(r.PeakRSSBytes, rss)
			if last.Valid {
				if t := parseStamp(last.String); t.After(r.LastSeen) {
					r.LastSeen = t
				}
			}
		}
		return rows.Err()
	}
	if err := merge(`
		SELECT service_root_key, COUNT(*), COALESCE(SUM(COALESCE(cpu_user_ms, 0) + COALESCE(cpu_system_ms, 0)), 0),
		       COALESCE(MAX(max_rss_bytes), 0), MAX(last_seen_at)
		  FROM process_runs
		 WHERE session_id = ? AND service_root_key IS NOT NULL AND capture_class = 'service'
		 GROUP BY service_root_key`, "kept",
		func(r *ProcessServiceRootRow, n int64) { r.Kept += n }); err != nil {
		return nil, err
	}
	if err := merge(`
		SELECT service_root_key, COALESCE(SUM(count), 0), COALESCE(SUM(cpu_sum_ms), 0),
		       COALESCE(MAX(peak_rss_bytes), 0), MAX(last_seen)
		  FROM process_rollups
		 WHERE session_id = ? AND service_root_key != ''
		 GROUP BY service_root_key`, "rollups",
		func(r *ProcessServiceRootRow, n int64) { r.RolledUp += n }); err != nil {
		return nil, err
	}
	return out, nil
}

// processOwnRow is the SQL predicate for a process_runs row that belongs to
// the session itself rather than to a service subtree it started.
const processOwnRow = `service_root_key IS NULL`

// ProcessSessionActivity is one session's stored process footprint for
// `observer process stats` and `observer process compact`.
type ProcessSessionActivity struct {
	SessionID string
	// Rows is the session's process_runs row count.
	Rows int64
	// OwnRows / OwnMaxID are the row count and highest id of the rows outside
	// a service subtree (processOwnRow). A service the session started can
	// outlive it by days and is re-sighted on every poll, so its rows say
	// nothing about the session being live, the same exclusion the capture
	// path's own last-activity clock makes. Compaction never changes a
	// classified row, so they are no reason to cancel one either.
	OwnRows  int64
	OwnMaxID int64
	// LastSeen is the latest last_seen_at of those own rows (LastSeenRaw the
	// stored stamp, compared verbatim by the compaction's watermark);
	// LastAction the latest action timestamp of the session. The later of the
	// two is the session's last activity.
	LastSeen    time.Time
	LastSeenRaw string
	LastAction  time.Time
	// StoredBytes is the measured length of the rows' variable columns
	// (exe path, cwd, argv preview, metric ring); MetricBytes the ring share.
	StoredBytes int64
	MetricBytes int64
}

// LastActivity is the later of LastSeen and LastAction.
func (a ProcessSessionActivity) LastActivity() time.Time {
	if a.LastAction.After(a.LastSeen) {
		return a.LastAction
	}
	return a.LastSeen
}

// CompactionMark is the watermark a compaction planned from this activity
// passes to CompactProcessSession.
func (a ProcessSessionActivity) CompactionMark() ProcessCompactionMark {
	return ProcessCompactionMark{Rows: a.OwnRows, MaxID: a.OwnMaxID, LastSeen: a.LastSeenRaw}
}

// ProcessSessionActivities returns the stored footprint of every session with
// process rows (or of sessionID alone when set), largest first, at most limit
// (<= 0 = all). One grouped pass over process_runs plus one indexed action
// lookup per session returned: an operator-command read, not a hot path.
func (s *Store) ProcessSessionActivities(ctx context.Context, sessionID string, limit int) ([]ProcessSessionActivity, error) {
	q := `
		SELECT session_id, COUNT(*),
		       COALESCE(SUM(` + processOwnRow + `), 0),
		       COALESCE(MAX(CASE WHEN ` + processOwnRow + ` THEN id END), 0),
		       COALESCE(MAX(CASE WHEN ` + processOwnRow + ` THEN last_seen_at END), ''),
		       COALESCE(SUM(COALESCE(length(exe_path), 0) + COALESCE(length(cwd), 0) + COALESCE(length(argv_preview), 0)
		           + COALESCE(length(metric_samples_json), 0)), 0),
		       COALESCE(SUM(COALESCE(length(metric_samples_json), 0)), 0)
		  FROM process_runs
		 WHERE session_id IS NOT NULL`
	var args []any
	if sessionID != "" {
		q += ` AND session_id = ?`
		args = append(args, sessionID)
	}
	q += ` GROUP BY session_id ORDER BY COUNT(*) DESC, session_id ASC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ProcessSessionActivities: %w", err)
	}
	var out []ProcessSessionActivity
	for rows.Next() {
		var a ProcessSessionActivity
		if err := rows.Scan(&a.SessionID, &a.Rows, &a.OwnRows, &a.OwnMaxID, &a.LastSeenRaw, &a.StoredBytes, &a.MetricBytes); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.ProcessSessionActivities: scan: %w", err)
		}
		a.LastSeen = parseStamp(a.LastSeenRaw)
		out = append(out, a)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store.ProcessSessionActivities: rows: %w", err)
	}
	for i := range out {
		var last sql.NullString
		if err := s.db.QueryRowContext(ctx, `SELECT MAX(timestamp) FROM actions WHERE session_id = ?`, out[i].SessionID).
			Scan(&last); err != nil {
			return nil, fmt.Errorf("store.ProcessSessionActivities: last action: %w", err)
		}
		if last.Valid {
			out[i].LastAction = parseStamp(last.String)
		}
	}
	return out, nil
}

// ProcessCount is one value of a grouped process-row count.
type ProcessCount struct {
	Key   string
	Count int64
}

// ProcessSessionBreakdown returns a session's process rows counted by
// attribution source and by executable (top limit, <= 0 means 10), for
// `observer process stats --session`.
func (s *Store) ProcessSessionBreakdown(ctx context.Context, sessionID string, limit int) (bySource, byExe []ProcessCount, err error) {
	if limit <= 0 {
		limit = 10
	}
	read := func(q string, args ...any) ([]ProcessCount, error) {
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []ProcessCount
		for rows.Next() {
			var c ProcessCount
			if err := rows.Scan(&c.Key, &c.Count); err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, rows.Err()
	}
	bySource, err = read(`SELECT COALESCE(attribution_source, ''), COUNT(*) FROM process_runs
		WHERE session_id = ? GROUP BY 1 ORDER BY 2 DESC, 1 ASC`, sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("store.ProcessSessionBreakdown: by source: %w", err)
	}
	byExe, err = read(`SELECT COALESCE(exe_basename, ''), COUNT(*) FROM process_runs
		WHERE session_id = ? GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT ?`, sessionID, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("store.ProcessSessionBreakdown: by exe: %w", err)
	}
	return bySource, byExe, nil
}
