package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Model-routing persistence helpers (docs/model-routing-spec.md §R9.1 +
// §R20, migrations 040 + 041).
//
// PRIVACY INVARIANT — router_decisions and model_calibration are
// NODE-LOCAL: they MUST NOT appear in internal/store/orgpush.go::
// SelectUnpushedSince. The privacy sentinel in tests/invariant pins
// both names; any future wire addition fails loudly. The §R19.4 org
// rollup (P2) pushes a separate aggregate shape, never these rows.
//
// MODULE-BOUNDARY NOTE — the row types here are the store's own
// SQL-shaped types, NOT internal/routing domain types (§24.2: routing
// types do not leak past the seam). Boundary code (cmd, P1 proxy seam)
// converts a routing.Decision into a RouterDecisionRow before calling
// the helpers below. ONE OWNER (§24.4): these two tables are written
// exclusively through the methods in this file.

// RouterDecisionRow is one row of router_decisions. APITurnID and
// OutcomeBackref are pointers so Channel-A decisions (no proxied turn)
// and ungraded decisions land NULL.
type RouterDecisionRow struct {
	APITurnID       *int64
	SessionID       string
	Timestamp       time.Time
	Mode            string
	Channel         string
	OriginalModel   string
	SelectedModel   string
	TurnKind        string
	PolicyName      string
	PolicyHash      string
	ReasonCodes     []string
	EstSavingsUSD   float64
	CacheForfeitUSD float64
	EstimateVersion string
	Applied         bool
	OutcomeBackref  *int64
}

// ModelCalibrationRow is one row of model_calibration — the observed
// outcome aggregates for one (model, turn_kind, project, window) cell.
// ProjectID 0 means "all projects". Graded fields carry the denominators
// actually observed for each rate (§R7.2 sample-size honesty).
type ModelCalibrationRow struct {
	Model            string
	TurnKind         string
	ProjectID        int64
	WindowDays       int
	ComputedAt       time.Time
	N                int64
	CostUSDTotal     float64
	LatencyP50Ms     int64
	LatencyP95Ms     int64
	LatencyGraded    int64
	ErrorCount       int64
	ErrorGraded      int64
	ToolFailureCount int64
	ToolActionCount  int64
}

// RouterDecisionStats is the cheap status rollup for the CLI / MCP
// status surfaces: row count plus the most recent decision timestamp
// (zero when the table is empty).
type RouterDecisionStats struct {
	Count  int64
	LastTS time.Time
}

const insertRouterDecisionSQL = `
INSERT INTO router_decisions (
    api_turn_id, session_id, ts, mode, channel,
    original_model, selected_model, turn_kind, policy_name, policy_hash,
    reason_codes, est_savings_usd, cache_forfeit_usd, estimate_version,
    applied, outcome_backref
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// InsertRouterDecisions appends decision rows in one transaction.
// Decisions are append-only (§R9.1) — there is no upsert path.
func (s *Store) InsertRouterDecisions(ctx context.Context, rows []RouterDecisionRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.InsertRouterDecisions: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, insertRouterDecisionSQL)
	if err != nil {
		return fmt.Errorf("store.InsertRouterDecisions: prepare: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for _, r := range rows {
		codes, err := json.Marshal(r.ReasonCodes)
		if err != nil {
			return fmt.Errorf("store.InsertRouterDecisions: marshal reason codes: %w", err)
		}
		if _, err := stmt.ExecContext(
			ctx,
			r.APITurnID, r.SessionID, timestamp(r.Timestamp), r.Mode, r.Channel,
			r.OriginalModel, r.SelectedModel, r.TurnKind, r.PolicyName, r.PolicyHash,
			string(codes), r.EstSavingsUSD, r.CacheForfeitUSD, r.EstimateVersion,
			boolInt(r.Applied), r.OutcomeBackref,
		); err != nil {
			return fmt.Errorf("store.InsertRouterDecisions: insert: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.InsertRouterDecisions: commit: %w", err)
	}
	return nil
}

// SelectRouterDecisionStats returns the status rollup for the decision
// log. Empty table → zero stats, no error.
func (s *Store) SelectRouterDecisionStats(ctx context.Context) (RouterDecisionStats, error) {
	var (
		out  RouterDecisionStats
		last *string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), MAX(ts) FROM router_decisions`).Scan(&out.Count, &last)
	if err != nil {
		return RouterDecisionStats{}, fmt.Errorf("store.SelectRouterDecisionStats: %w", err)
	}
	if last != nil {
		out.LastTS = parseStamp(*last)
	}
	return out, nil
}

const upsertModelCalibrationSQL = `
INSERT INTO model_calibration (
    model, turn_kind, project_id, window_days, computed_at,
    n, cost_usd_total, latency_p50_ms, latency_p95_ms, latency_graded,
    error_count, error_graded, tool_failure_count, tool_action_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(model, turn_kind, project_id, window_days) DO UPDATE SET
    computed_at        = excluded.computed_at,
    n                  = excluded.n,
    cost_usd_total     = excluded.cost_usd_total,
    latency_p50_ms     = excluded.latency_p50_ms,
    latency_p95_ms     = excluded.latency_p95_ms,
    latency_graded     = excluded.latency_graded,
    error_count        = excluded.error_count,
    error_graded       = excluded.error_graded,
    tool_failure_count = excluded.tool_failure_count,
    tool_action_count  = excluded.tool_action_count`

// UpsertModelCalibrations writes calibration cells in one transaction.
// The (model, turn_kind, project_id, window_days) key drives the upsert:
// a recomputed cell replaces its aggregates, never duplicates.
func (s *Store) UpsertModelCalibrations(ctx context.Context, rows []ModelCalibrationRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertModelCalibrations: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, upsertModelCalibrationSQL)
	if err != nil {
		return fmt.Errorf("store.UpsertModelCalibrations: prepare: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for _, r := range rows {
		if _, err := stmt.ExecContext(
			ctx,
			r.Model, r.TurnKind, r.ProjectID, r.WindowDays, timestamp(r.ComputedAt),
			r.N, r.CostUSDTotal, r.LatencyP50Ms, r.LatencyP95Ms, r.LatencyGraded,
			r.ErrorCount, r.ErrorGraded, r.ToolFailureCount, r.ToolActionCount,
		); err != nil {
			return fmt.Errorf("store.UpsertModelCalibrations: upsert: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.UpsertModelCalibrations: commit: %w", err)
	}
	return nil
}

// CountModelCalibrations returns the calibration cell count for status
// surfaces.
func (s *Store) CountModelCalibrations(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM model_calibration`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store.CountModelCalibrations: %w", err)
	}
	return n, nil
}

// RouterDecisionDetail is one decision row read back for the
// transparency surfaces (§R17): savings, explain, advise feed,
// dashboard. ProjectRoot/Tool join in from the session.
type RouterDecisionDetail struct {
	ID              int64
	APITurnID       *int64
	SessionID       string
	Timestamp       time.Time
	Mode            string
	Channel         string
	OriginalModel   string
	SelectedModel   string
	TurnKind        string
	PolicyName      string
	PolicyHash      string
	ReasonCodes     []string
	EstSavingsUSD   float64
	CacheForfeitUSD float64
	EstimateVersion string
	Applied         bool
	OutcomeBackref  *int64
	ProjectRoot     string
	Tool            string
}

const selectRouterDecisionSQL = `
SELECT rd.id, rd.api_turn_id, rd.session_id, rd.ts, rd.mode, rd.channel,
       rd.original_model, rd.selected_model, rd.turn_kind,
       rd.policy_name, rd.policy_hash, rd.reason_codes,
       rd.est_savings_usd, rd.cache_forfeit_usd, rd.estimate_version,
       rd.applied, rd.outcome_backref,
       COALESCE(p.root_path, ''), COALESCE(se.tool, '')
FROM router_decisions rd
LEFT JOIN sessions se ON se.id = rd.session_id
LEFT JOIN projects p ON p.id = se.project_id`

// SelectRouterDecisions loads decision rows since the horizon, newest
// first, optionally limited (limit <= 0 = unlimited).
func (s *Store) SelectRouterDecisions(ctx context.Context, since time.Time, limit int) ([]RouterDecisionDetail, error) {
	q := selectRouterDecisionSQL + `
WHERE rd.ts >= ?
ORDER BY rd.ts DESC, rd.id DESC`
	args := []any{timestamp(since)}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SelectRouterDecisions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []RouterDecisionDetail
	for rows.Next() {
		d, err := scanRouterDecision(rows)
		if err != nil {
			return nil, fmt.Errorf("store.SelectRouterDecisions: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SelectRouterDecisionByID loads one decision for `observer routing
// explain` (§R17.6). ok=false when absent.
func (s *Store) SelectRouterDecisionByID(ctx context.Context, id int64) (RouterDecisionDetail, bool, error) {
	rows, err := s.db.QueryContext(ctx, selectRouterDecisionSQL+` WHERE rd.id = ?`, id)
	if err != nil {
		return RouterDecisionDetail{}, false, fmt.Errorf("store.SelectRouterDecisionByID: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return RouterDecisionDetail{}, false, rows.Err()
	}
	d, err := scanRouterDecision(rows)
	if err != nil {
		return RouterDecisionDetail{}, false, fmt.Errorf("store.SelectRouterDecisionByID: %w", err)
	}
	return d, true, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanRouterDecision(r rowScanner) (RouterDecisionDetail, error) {
	var (
		d     RouterDecisionDetail
		ts    string
		codes string
		appl  int64
	)
	if err := r.Scan(&d.ID, &d.APITurnID, &d.SessionID, &ts, &d.Mode, &d.Channel,
		&d.OriginalModel, &d.SelectedModel, &d.TurnKind,
		&d.PolicyName, &d.PolicyHash, &codes,
		&d.EstSavingsUSD, &d.CacheForfeitUSD, &d.EstimateVersion,
		&appl, &d.OutcomeBackref, &d.ProjectRoot, &d.Tool); err != nil {
		return RouterDecisionDetail{}, err
	}
	d.Timestamp = parseStamp(ts)
	d.Applied = appl != 0
	if codes != "" {
		if err := json.Unmarshal([]byte(codes), &d.ReasonCodes); err != nil {
			// A malformed legacy blob degrades to an empty list, never
			// a failed read.
			d.ReasonCodes = nil
		}
	}
	return d, nil
}

// PruneRouterDecisions deletes decision rows older than the retention
// horizon ([routing].decision_log_retention_days). retentionDays <= 0
// is a no-op. Idempotent.
func (s *Store) PruneRouterDecisions(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := timestamp(time.Now().AddDate(0, 0, -retentionDays))
	res, err := s.db.ExecContext(ctx, `DELETE FROM router_decisions WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store.PruneRouterDecisions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SelectModelCalibrations loads every calibration cell for the tier-map
// overlay (§R17.1) and the calibration surfaces.
func (s *Store) SelectModelCalibrations(ctx context.Context) ([]ModelCalibrationRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT model, turn_kind, project_id, window_days, computed_at,
		       n, cost_usd_total, latency_p50_ms, latency_p95_ms, latency_graded,
		       error_count, error_graded, tool_failure_count, tool_action_count
		FROM model_calibration
		ORDER BY model, turn_kind, project_id`)
	if err != nil {
		return nil, fmt.Errorf("store.SelectModelCalibrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ModelCalibrationRow
	for rows.Next() {
		var (
			r  ModelCalibrationRow
			ts string
		)
		if err := rows.Scan(&r.Model, &r.TurnKind, &r.ProjectID, &r.WindowDays, &ts,
			&r.N, &r.CostUSDTotal, &r.LatencyP50Ms, &r.LatencyP95Ms, &r.LatencyGraded,
			&r.ErrorCount, &r.ErrorGraded, &r.ToolFailureCount, &r.ToolActionCount); err != nil {
			return nil, fmt.Errorf("store.SelectModelCalibrations: scan: %w", err)
		}
		r.ComputedAt = parseStamp(ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountEscalationsByKind counts §R7.4 escalation decision rows per
// turn-kind since the horizon — the calibration job's negative
// evidence (§R18.3).
func (s *Store) CountEscalationsByKind(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT turn_kind, COUNT(*)
		FROM router_decisions
		WHERE ts >= ? AND reason_codes LIKE '%"escalation"%'
		GROUP BY turn_kind`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.CountEscalationsByKind: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var (
			kind string
			n    int
		)
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, fmt.Errorf("store.CountEscalationsByKind: scan: %w", err)
		}
		out[kind] = n
	}
	return out, rows.Err()
}
