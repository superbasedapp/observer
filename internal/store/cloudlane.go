package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Read seams for the "where it ran" views (cloud-agents arc, lane CA-B5):
// the node Sessions list and the Projects page's cloud lane. Read-only; the
// one writer of the execution columns stays SetSessionExecution
// (cloudsessions.go) and the one writer of cloud_usage_ledger stays
// cloudagentstate.go.

// sessionExecutionChunk bounds one IN (...) list. SQLite's default host
// parameter limit is far above this; the bound keeps each statement small.
const sessionExecutionChunk = 500

// LoadSessionExecutions returns the stored execution attribution for each
// of ids that exists and carries at least one stamped column. A session
// whose two columns are both NULL is absent from the map (the honest
// unknown), so a caller never mistakes "nothing stamped" for "local".
func (s *Store) LoadSessionExecutions(ctx context.Context, ids []string) (map[string]models.SessionExecution, error) {
	out := map[string]models.SessionExecution{}
	for start := 0; start < len(ids); start += sessionExecutionChunk {
		end := start + sessionExecutionChunk
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		//nolint:gosec // G202: the IN list is placeholders only; every value is bound.
		rows, err := s.db.QueryContext(ctx,
			`SELECT id, COALESCE(execution_location, ''), COALESCE(vendor_session_ref, '')
			   FROM sessions
			  WHERE id IN (`+placeholders(len(chunk))+`)
			    AND (execution_location IS NOT NULL OR vendor_session_ref IS NOT NULL)`, args...)
		if err != nil {
			return nil, fmt.Errorf("store.LoadSessionExecutions: %w", err)
		}
		for rows.Next() {
			var ex models.SessionExecution
			if err := rows.Scan(&ex.SessionID, &ex.ExecutionLocation, &ex.VendorSessionRef); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("store.LoadSessionExecutions: scan: %w", err)
			}
			out[ex.SessionID] = ex
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.LoadSessionExecutions: rows: %w", err)
		}
		_ = rows.Close()
	}
	return out, nil
}

// ProjectExecutionMix is one project's all-time session count per execution
// location. Key "" is the unknown (NULL) bucket.
type ProjectExecutionMix map[string]int

// LoadProjectExecutionMix returns, for every project that holds at least one
// session with a stamped execution_location, its all-time session count per
// location (the same all-time grain as the Projects list's session_count).
// A project where nothing was ever stamped is absent, so a node that never
// captured a cloud session adds nothing to the Projects list payload.
func (s *Store) LoadProjectExecutionMix(ctx context.Context) (map[int64]ProjectExecutionMix, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT project_id, COALESCE(execution_location, ''), COUNT(*)
		   FROM sessions
		  WHERE project_id IN (SELECT DISTINCT project_id FROM sessions
		                        WHERE execution_location IS NOT NULL AND project_id IS NOT NULL)
		  GROUP BY project_id, COALESCE(execution_location, '')`)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectExecutionMix: %w", err)
	}
	defer rows.Close()
	out := map[int64]ProjectExecutionMix{}
	for rows.Next() {
		var pid int64
		var loc string
		var n int
		if err := rows.Scan(&pid, &loc, &n); err != nil {
			return nil, fmt.Errorf("store.LoadProjectExecutionMix: scan: %w", err)
		}
		if out[pid] == nil {
			out[pid] = ProjectExecutionMix{}
		}
		out[pid][loc] += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadProjectExecutionMix: rows: %w", err)
	}
	return out, nil
}

// ListCloudUsageForSessions returns the ledger entries scoped to any of
// sessionIDs, newest report first, capped at limit (0 = 5000). truncated is
// true when the cap cut the result, so a caller can say the figure is
// partial instead of presenting a capped sum as complete. Like
// ListCloudUsage it never sums.
func (s *Store) ListCloudUsageForSessions(ctx context.Context, sessionIDs []string, limit int) ([]CloudUsageEntry, bool, error) {
	if limit <= 0 {
		limit = 5000
	}
	var out []CloudUsageEntry
	for start := 0; start < len(sessionIDs); start += sessionExecutionChunk {
		end := start + sessionExecutionChunk
		if end > len(sessionIDs) {
			end = len(sessionIDs)
		}
		chunk := sessionIDs[start:end]
		args := make([]any, 0, len(chunk)+1)
		for _, id := range chunk {
			args = append(args, id)
		}
		args = append(args, limit+1-len(out))
		//nolint:gosec // G202: the IN list is placeholders only; every value is bound.
		rows, err := s.db.QueryContext(ctx,
			`SELECT id, connector, source_record_id, measurement_source, value_type, unit, value, monetary_status,
			        scope_run, scope_session, scope_user, scope_account, scope_org, scope_model,
			        interval_start, interval_end, includes_children, reported_at, observed_at, COALESCE(supersedes_id, 0)
			   FROM cloud_usage_ledger
			  WHERE scope_session IN (`+placeholders(len(chunk))+`)
			  ORDER BY reported_at DESC, id DESC
			  LIMIT ?`, args...)
		if err != nil {
			return nil, false, fmt.Errorf("store.ListCloudUsageForSessions: %w", err)
		}
		for rows.Next() {
			var e CloudUsageEntry
			var startAt, endAt, reported, observed string
			var children sql.NullInt64
			if err := rows.Scan(&e.ID, &e.Connector, &e.SourceRecordID, &e.MeasurementSource, &e.ValueType, &e.Unit,
				&e.Value, &e.MonetaryStatus, &e.ScopeRun, &e.ScopeSession, &e.ScopeUser, &e.ScopeAccount, &e.ScopeOrg,
				&e.ScopeModel, &startAt, &endAt, &children, &reported, &observed, &e.SupersedesID); err != nil {
				_ = rows.Close()
				return nil, false, fmt.Errorf("store.ListCloudUsageForSessions: scan: %w", err)
			}
			if children.Valid {
				b := children.Int64 != 0
				e.IncludesChildren = &b
			}
			e.IntervalStart, e.IntervalEnd = parseCloudTime(startAt), parseCloudTime(endAt)
			e.ReportedAt, e.ObservedAt = parseCloudTime(reported), parseCloudTime(observed)
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, false, fmt.Errorf("store.ListCloudUsageForSessions: rows: %w", err)
		}
		_ = rows.Close()
		if len(out) > limit {
			return out[:limit], true, nil
		}
	}
	return out, false, nil
}
