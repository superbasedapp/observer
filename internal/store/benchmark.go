//go:build !sbo_omit_benchmark

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
)

// benchmark.go is the ONE SQL seam for the four node-local benchmark_* tables
// (migration 061). Per CLAUDE.md rule #4 (one owner per table) every read and
// write of benchmark_runs / benchmark_attempts / benchmark_session_members /
// benchmark_scores goes through here. The pure benchmark package supplies the
// row/fact types and the inferential math; this file never computes statistics.
//
// Cost/tokens/cache are DERIVED here at report time by joining a session member
// to api_turns (success turns only) — they are never denormalized onto the
// benchmark tables, so the cost engine stays the one owner of cost.

// InsertBenchmarkRun writes the run header. The only writer of benchmark_runs
// (subsequent mutations go through UpdateBenchmarkRun).
func (s *Store) InsertBenchmarkRun(ctx context.Context, r benchmark.RunRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO benchmark_runs
		  (run_id, spec_name, spec_hash, spec_json, manifest_json, pricing_snapshot_json,
		   started_at, finished_at, status, planned_cells, completed_cells,
		   spend_usd, judge_spend_usd, budget_json, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.RunID, r.SpecName, r.SpecHash, r.SpecJSON,
		nullableString(r.ManifestJSON), nullableString(r.PricingSnapshotJSON),
		timestamp(r.StartedAt), nullableTimestamp(r.FinishedAt), r.Status,
		r.PlannedCells, r.CompletedCells, r.SpendUSD, r.JudgeSpendUSD,
		nullableString(r.BudgetJSON), nullableString(r.Notes))
	if err != nil {
		return fmt.Errorf("store.InsertBenchmarkRun: %w", err)
	}
	return nil
}

// UpdateBenchmarkRun rewrites the mutable run fields (progress, spend, status,
// manifest, pricing snapshot). Called after each attempt and at finalization.
func (s *Store) UpdateBenchmarkRun(ctx context.Context, r benchmark.RunRecord) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE benchmark_runs
		   SET manifest_json = ?, pricing_snapshot_json = ?, finished_at = ?,
		       status = ?, planned_cells = ?, completed_cells = ?,
		       spend_usd = ?, judge_spend_usd = ?, notes = ?
		 WHERE run_id = ?`,
		nullableString(r.ManifestJSON), nullableString(r.PricingSnapshotJSON), nullableTimestamp(r.FinishedAt),
		r.Status, r.PlannedCells, r.CompletedCells,
		r.SpendUSD, r.JudgeSpendUSD, nullableString(r.Notes), r.RunID)
	if err != nil {
		return fmt.Errorf("store.UpdateBenchmarkRun: %w", err)
	}
	return nil
}

// InsertBenchmarkAttempt writes one attempt row and returns its autoincrement
// id (for the session-member + score foreign keys).
func (s *Store) InsertBenchmarkAttempt(ctx context.Context, a benchmark.AttemptRecord) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO benchmark_attempts
		  (run_id, task_id, config_id, harness, model_requested, repeat_idx, attempt_no,
		   workspace_path, wall_ms, exit_code, status, final_answer_excerpt,
		   spend_usd, turns, error_class, started_at, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.RunID, a.TaskID, a.ConfigID, a.Harness, a.ModelRequested, a.RepeatIdx, a.AttemptNo,
		nullableString(a.WorkspacePath), a.WallMS, nullableIntPtr(a.ExitCode), string(a.Status),
		nullableString(a.FinalAnswerExcerpt), a.SpendUSD, a.Turns, nullableString(a.ErrorClass),
		timestamp(a.StartedAt), nullableTimestamp(a.FinishedAt))
	if err != nil {
		return 0, fmt.Errorf("store.InsertBenchmarkAttempt: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store.InsertBenchmarkAttempt: last id: %w", err)
	}
	return id, nil
}

// InsertBenchmarkSessionMembers attaches sessions to attempts. Idempotent on
// the (attempt_id, session_id) UNIQUE — a re-resolve won't duplicate.
func (s *Store) InsertBenchmarkSessionMembers(ctx context.Context, members []benchmark.SessionMember) error {
	if len(members) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.InsertBenchmarkSessionMembers: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, m := range members {
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO benchmark_session_members
			  (attempt_id, run_id, session_id, role, model_returned)
			VALUES (?, ?, ?, ?, ?)`,
			m.AttemptID, m.RunID, m.SessionID, string(m.Role), nullableString(m.ModelReturned)); err != nil {
			return fmt.Errorf("store.InsertBenchmarkSessionMembers: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.InsertBenchmarkSessionMembers: commit: %w", err)
	}
	return nil
}

// InsertBenchmarkScores writes scorer verdicts for an attempt.
func (s *Store) InsertBenchmarkScores(ctx context.Context, scores []benchmark.ScoreRecord) error {
	if len(scores) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.InsertBenchmarkScores: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, sc := range scores {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO benchmark_scores
			  (attempt_id, run_id, scorer, score, passed, rationale, judge_model, rubric_hash, degraded)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sc.AttemptID, sc.RunID, sc.Scorer, sc.Score, boolInt(sc.Passed),
			nullableString(sc.Rationale), nullableString(sc.JudgeModel), nullableString(sc.RubricHash),
			boolInt(sc.Degraded)); err != nil {
			return fmt.Errorf("store.InsertBenchmarkScores: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.InsertBenchmarkScores: commit: %w", err)
	}
	return nil
}

// UpdateBenchmarkAttemptStatus rewrites an attempt's terminal status +
// error_class after the fact (e.g. scorer_unavailable once scoring reveals no
// verdict was recoverable). The only mutator of a persisted attempt's status.
func (s *Store) UpdateBenchmarkAttemptStatus(ctx context.Context, attemptID int64, status benchmark.Status, errorClass string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE benchmark_attempts SET status = ?, error_class = ? WHERE id = ?`,
		string(status), nullableString(errorClass), attemptID)
	if err != nil {
		return fmt.Errorf("store.UpdateBenchmarkAttemptStatus: %w", err)
	}
	return nil
}

// LoadBenchmarkRun returns the run header, ok=false when absent.
func (s *Store) LoadBenchmarkRun(ctx context.Context, runID string) (benchmark.RunRecord, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT run_id, spec_name, spec_hash, spec_json, manifest_json, pricing_snapshot_json,
		       started_at, finished_at, status, planned_cells, completed_cells,
		       spend_usd, judge_spend_usd, budget_json, notes
		  FROM benchmark_runs WHERE run_id = ?`, runID)
	r, err := scanBenchmarkRun(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return benchmark.RunRecord{}, false, nil
		}
		return benchmark.RunRecord{}, false, fmt.Errorf("store.LoadBenchmarkRun: %w", err)
	}
	return r, true, nil
}

// ListBenchmarkRuns returns run headers most-recent first (limit 0 = 100).
func (s *Store) ListBenchmarkRuns(ctx context.Context, limit int) ([]benchmark.RunRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT run_id, spec_name, spec_hash, spec_json, manifest_json, pricing_snapshot_json,
		       started_at, finished_at, status, planned_cells, completed_cells,
		       spend_usd, judge_spend_usd, budget_json, notes
		  FROM benchmark_runs ORDER BY started_at DESC, run_id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListBenchmarkRuns: %w", err)
	}
	defer rows.Close()
	var out []benchmark.RunRecord
	for rows.Next() {
		r, err := scanBenchmarkRun(rows)
		if err != nil {
			return nil, fmt.Errorf("store.ListBenchmarkRuns: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanBenchmarkRun(sc rowScanner) (benchmark.RunRecord, error) {
	var r benchmark.RunRecord
	var manifest, pricing, budget, notes sql.NullString
	var startedAt string
	var finishedAt sql.NullString
	if err := sc.Scan(&r.RunID, &r.SpecName, &r.SpecHash, &r.SpecJSON, &manifest, &pricing,
		&startedAt, &finishedAt, &r.Status, &r.PlannedCells, &r.CompletedCells,
		&r.SpendUSD, &r.JudgeSpendUSD, &budget, &notes); err != nil {
		return r, err
	}
	r.ManifestJSON, r.PricingSnapshotJSON = manifest.String, pricing.String
	r.BudgetJSON, r.Notes = budget.String, notes.String
	if t, ok := parseStoredTimeOK(startedAt); ok {
		r.StartedAt = t
	}
	if finishedAt.Valid {
		if t, ok := parseStoredTimeOK(finishedAt.String); ok {
			r.FinishedAt = t
		}
	}
	return r, nil
}

// LoadBenchmarkFacts assembles the report substrate for a run: ONE fact per
// logical cell (run_id, task_id, config_id, repeat_idx) — the TERMINAL attempt
// (highest attempt_no; retries only follow infra failures and the loop stops at
// the first non-infra outcome, so the max-attempt_no row is the cell's terminal
// decision) — joined to its derived billed tokens/cost (summed across NON-judge
// session members' api_turns, success turns only — http_status IS NULL OR
// < 400) and its primary-scorer verdict. Selecting the terminal attempt keeps
// each logical cell counted once even after a retry persisted an earlier
// physical attempt (migration 068). This is the ONE owner of the
// attempt→api_turns dedup/derivation shape; the pure benchmark.ComputeReport
// consumes the result.
func (s *Store) LoadBenchmarkFacts(ctx context.Context, runID string) ([]benchmark.AttemptFact, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.task_id, a.config_id, a.harness, a.model_requested, a.repeat_idx,
		       a.status, a.wall_ms, a.turns,
		       COUNT(DISTINCT m.session_id),
		       COALESCE(SUM(CASE WHEN (t.http_status IS NULL OR t.http_status < 400) THEN t.input_tokens ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN (t.http_status IS NULL OR t.http_status < 400) THEN t.output_tokens ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN (t.http_status IS NULL OR t.http_status < 400) THEN COALESCE(t.cache_read_tokens,0) ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN (t.http_status IS NULL OR t.http_status < 400) THEN COALESCE(t.cost_usd,0) ELSE 0 END), 0)
		  FROM benchmark_attempts a
		  JOIN (
		         SELECT task_id, config_id, repeat_idx, MAX(attempt_no) AS mx
		           FROM benchmark_attempts
		          WHERE run_id = ?
		          GROUP BY task_id, config_id, repeat_idx
		       ) latest
		    ON latest.task_id = a.task_id AND latest.config_id = a.config_id
		   AND latest.repeat_idx = a.repeat_idx AND latest.mx = a.attempt_no
		  LEFT JOIN benchmark_session_members m ON m.attempt_id = a.id AND m.role <> 'judge'
		  LEFT JOIN api_turns t ON t.session_id = m.session_id
		 WHERE a.run_id = ?
		 GROUP BY a.id
		 ORDER BY a.id`, runID, runID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadBenchmarkFacts: attempts: %w", err)
	}
	defer rows.Close()

	facts := make([]benchmark.AttemptFact, 0)
	idIndex := make(map[int64]int)
	for rows.Next() {
		var id int64
		var f benchmark.AttemptFact
		var status string
		if err := rows.Scan(&id, &f.TaskID, &f.ConfigID, &f.Harness, &f.Model, &f.RepeatIdx,
			&status, &f.WallMS, &f.Turns, &f.Sessions,
			&f.InputTokens, &f.OutputTokens, &f.CacheReadTokens, &f.CostUSD); err != nil {
			return nil, fmt.Errorf("store.LoadBenchmarkFacts: scan: %w", err)
		}
		f.Status = benchmark.Status(status)
		idIndex[id] = len(facts)
		facts = append(facts, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadBenchmarkFacts: rows: %w", err)
	}

	// Primary-scorer verdict per attempt: Scored = any score row exists;
	// Passed = any score row passed. v1 tasks declare a single scorer, so
	// this is the pre-registered primary outcome.
	srows, err := s.db.QueryContext(ctx, `
		SELECT attempt_id, MAX(passed), COUNT(*)
		  FROM benchmark_scores WHERE run_id = ? GROUP BY attempt_id`, runID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadBenchmarkFacts: scores: %w", err)
	}
	defer srows.Close()
	for srows.Next() {
		var attemptID int64
		var maxPassed, count int
		if err := srows.Scan(&attemptID, &maxPassed, &count); err != nil {
			return nil, fmt.Errorf("store.LoadBenchmarkFacts: score scan: %w", err)
		}
		if idx, ok := idIndex[attemptID]; ok {
			facts[idx].Scored = count > 0
			facts[idx].Passed = maxPassed == 1
		}
	}
	return facts, srows.Err()
}

// BenchmarkSessionFact is the correlation-resolver substrate: a session's
// tool, resolved workspace root, and best-known model — read by the runner to
// verify a minted/captured session id resolves to exactly one session under
// the expected per-attempt workspace (plan §3.3 fail-on-ambiguous).
type BenchmarkSessionFact struct {
	SessionID string
	Tool      string
	Model     string
	RootPath  string
}

// LoadSessionCorrelation returns the session's tool/model/root (via
// sessions.project_id → projects.root_path), ok=false when the id is unknown.
// api_turns.project_id is NULL for proxy turns, so the workspace root is
// reachable ONLY through the sessions row — never key correlation on the turn.
func (s *Store) LoadSessionCorrelation(ctx context.Context, sessionID string) (BenchmarkSessionFact, bool, error) {
	var f BenchmarkSessionFact
	f.SessionID = sessionID
	var model sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT s.tool, COALESCE(s.model, ''), COALESCE(p.root_path, '')
		  FROM sessions s LEFT JOIN projects p ON p.id = s.project_id
		 WHERE s.id = ?`, sessionID).Scan(&f.Tool, &model, &f.RootPath)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return f, false, nil
		}
		return f, false, fmt.Errorf("store.LoadSessionCorrelation: %w", err)
	}
	f.Model = model.String
	return f, true, nil
}

// BenchmarkBilling is a session's billed rollup over its SUCCESS turns
// (http_status IS NULL OR < 400) — the runner's per-attempt budget accounting
// source. Failed/partial turns (400/404 artifacts) cost $0 and are excluded.
type BenchmarkBilling struct {
	Turns           int
	InputTokens     int64
	OutputTokens    int64
	CacheReadTokens int64
	CostUSD         float64
}

// LoadSessionBilling sums a session's success-turn billing from api_turns.
func (s *Store) LoadSessionBilling(ctx context.Context, sessionID string) (BenchmarkBilling, error) {
	var b BenchmarkBilling
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(SUM(input_tokens), 0),
		       COALESCE(SUM(output_tokens), 0),
		       COALESCE(SUM(COALESCE(cache_read_tokens,0)), 0),
		       COALESCE(SUM(COALESCE(cost_usd,0)), 0)
		  FROM api_turns
		 WHERE session_id = ? AND (http_status IS NULL OR http_status < 400)`, sessionID).
		Scan(&b.Turns, &b.InputTokens, &b.OutputTokens, &b.CacheReadTokens, &b.CostUSD)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return b, fmt.Errorf("store.LoadSessionBilling: %w", err)
	}
	return b, nil
}

// AvgTurnCostUSD returns the mean billed cost per success turn for a model over
// the last windowDays (0 = all time), for the dry-run cost estimate. ok=false
// when the model has no billed history (the estimate then shows $0 for it).
func (s *Store) AvgTurnCostUSD(ctx context.Context, model string, windowDays int) (float64, bool) {
	q := `SELECT AVG(cost_usd) FROM api_turns
	       WHERE model = ? AND cost_usd IS NOT NULL AND (http_status IS NULL OR http_status < 400)`
	args := []any{model}
	if windowDays > 0 {
		q += ` AND timestamp >= datetime('now', ?)`
		args = append(args, fmt.Sprintf("-%d days", windowDays))
	}
	var avg sql.NullFloat64
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&avg); err != nil {
		return 0, false
	}
	if !avg.Valid {
		return 0, false
	}
	return avg.Float64, true
}
