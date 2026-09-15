package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/runstate"
)

// arena.go — SQL seams for the Agent Arena tables (migration 088). The
// runner/judge engine owns lifecycle transitions; this file is I/O only.
// Patch text and transcripts stay on disk — these rows carry paths, stats,
// scores and provenance exclusively.

// InsertArenaRun persists a new run row.
func (s *Store) InsertArenaRun(ctx context.Context, run *models.ArenaRun) error {
	if run.ID == "" {
		return errors.New("store.InsertArenaRun: id required")
	}
	if run.ProjectRoot == "" || run.Prompt == "" {
		return errors.New("store.InsertArenaRun: project_root and prompt required")
	}
	now := timestamp(time.Now().UTC())
	run.CreatedAt = now
	run.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO arena_runs (id, project_root, base_branch, base_sha, prompt,
		    judge_tool, judge_model, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID, run.ProjectRoot, run.BaseBranch, run.BaseSHA, run.Prompt,
		run.JudgeTool, run.JudgeModel, run.Status, run.CreatedAt, run.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store.InsertArenaRun: %w", err)
	}
	return nil
}

// UpdateArenaRunStatus moves a run's status and touches its updated_at.
func (s *Store) UpdateArenaRunStatus(ctx context.Context, id, status string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE arena_runs SET status = ?, updated_at = ? WHERE id = ?`,
		status, timestamp(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("store.UpdateArenaRunStatus: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store.UpdateArenaRunStatus: rows affected: %w", err)
	} else if n != 1 {
		return errors.New("store.UpdateArenaRunStatus: run not found")
	}
	return nil
}

const arenaRunColumns = `id, project_root, base_branch, base_sha, prompt,
	judge_tool, judge_model, status, created_at, updated_at`

func scanArenaRun(row interface{ Scan(...any) error }) (*models.ArenaRun, error) {
	var r models.ArenaRun
	if err := row.Scan(&r.ID, &r.ProjectRoot, &r.BaseBranch, &r.BaseSHA, &r.Prompt,
		&r.JudgeTool, &r.JudgeModel, &r.Status, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// ArenaRun loads one run by id; returns (nil, nil) when absent.
func (s *Store) ArenaRun(ctx context.Context, id string) (*models.ArenaRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+arenaRunColumns+` FROM arena_runs WHERE id = ?`, id)
	r, err := scanArenaRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.ArenaRun: %w", err)
	}
	return r, nil
}

// RecentArenaRuns returns up to limit runs, newest first.
func (s *Store) RecentArenaRuns(ctx context.Context, limit int) ([]models.ArenaRun, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+arenaRunColumns+` FROM arena_runs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.RecentArenaRuns: %w", err)
	}
	defer rows.Close()
	var out []models.ArenaRun
	for rows.Next() {
		r, err := scanArenaRun(rows)
		if err != nil {
			return nil, fmt.Errorf("store.RecentArenaRuns: scan: %w", err)
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// InsertArenaCandidate persists a new candidate slot.
func (s *Store) InsertArenaCandidate(ctx context.Context, c *models.ArenaCandidate) error {
	if c.ID == "" || c.RunID == "" || c.Tool == "" {
		return errors.New("store.InsertArenaCandidate: id, run_id and tool required")
	}
	c.UpdatedAt = timestamp(time.Now().UTC())
	sessionIDs, scores, err := candidateJSONCols(c)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO arena_candidates (id, run_id, tool, model, seq, status,
		    branch_name, worktree_path, patch_path, exit_code, wall_ms, timed_out,
		    final_answer_excerpt, diff_files, diff_added, diff_removed,
		    input_tokens, output_tokens, cost_usd, session_ids, scores, verdict,
		    kept_commit_sha, error, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.RunID, c.Tool, c.Model, c.Seq, c.Status,
		c.BranchName, c.WorktreePath, c.PatchPath, c.ExitCode, c.WallMS, boolInt(c.TimedOut),
		c.FinalAnswerExcerpt, c.DiffFiles, c.DiffAdded, c.DiffRemoved,
		c.InputTokens, c.OutputTokens, c.CostUSD, sessionIDs, scores, c.Verdict,
		c.KeptCommitSHA, c.Error, c.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store.InsertArenaCandidate: %w", err)
	}
	return nil
}

// UpdateArenaCandidate rewrites a candidate row in full by id.
func (s *Store) UpdateArenaCandidate(ctx context.Context, c *models.ArenaCandidate) error {
	if c.ID == "" {
		return errors.New("store.UpdateArenaCandidate: id required")
	}
	c.UpdatedAt = timestamp(time.Now().UTC())
	sessionIDs, scores, err := candidateJSONCols(c)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE arena_candidates SET tool = ?, model = ?, seq = ?, status = ?,
		    branch_name = ?, worktree_path = ?, patch_path = ?, exit_code = ?,
		    wall_ms = ?, timed_out = ?, final_answer_excerpt = ?,
		    diff_files = ?, diff_added = ?, diff_removed = ?,
		    input_tokens = ?, output_tokens = ?, cost_usd = ?,
		    session_ids = ?, scores = ?, verdict = ?, kept_commit_sha = ?,
		    error = ?, updated_at = ?
		WHERE id = ?`,
		c.Tool, c.Model, c.Seq, c.Status,
		c.BranchName, c.WorktreePath, c.PatchPath, c.ExitCode,
		c.WallMS, boolInt(c.TimedOut), c.FinalAnswerExcerpt,
		c.DiffFiles, c.DiffAdded, c.DiffRemoved,
		c.InputTokens, c.OutputTokens, c.CostUSD,
		sessionIDs, scores, c.Verdict, c.KeptCommitSHA,
		c.Error, c.UpdatedAt, c.ID)
	if err != nil {
		return fmt.Errorf("store.UpdateArenaCandidate: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store.UpdateArenaCandidate: rows affected: %w", err)
	} else if n != 1 {
		return errors.New("store.UpdateArenaCandidate: candidate not found")
	}
	return nil
}

// SetCandidateKept stamps the merge-back commit SHA onto a kept candidate.
func (s *Store) SetCandidateKept(ctx context.Context, id, keptCommitSHA string) error {
	if id == "" || keptCommitSHA == "" {
		return errors.New("store.SetCandidateKept: id and kept commit SHA required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE arena_candidates SET status = ?, kept_commit_sha = ?, updated_at = ?
		WHERE id = ? AND status = ?`,
		models.ArenaCandidateStatusKept, keptCommitSHA, timestamp(time.Now().UTC()), id,
		models.ArenaCandidateStatusJudged)
	if err != nil {
		return fmt.Errorf("store.SetCandidateKept: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store.SetCandidateKept: rows affected: %w", err)
	} else if n != 1 {
		return errors.New("store.SetCandidateKept: candidate is missing or no longer judged")
	}
	return nil
}

// SetCandidateDiscarded marks a candidate discarded.
func (s *Store) SetCandidateDiscarded(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("store.SetCandidateDiscarded: id required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE arena_candidates SET status = ?, updated_at = ?
		WHERE id = ? AND status IN (?, ?, ?, ?)`,
		models.ArenaCandidateStatusDiscarded, timestamp(time.Now().UTC()), id,
		models.ArenaCandidateStatusDone, models.ArenaCandidateStatusFailed,
		models.ArenaCandidateStatusTimeout, models.ArenaCandidateStatusJudged)
	if err != nil {
		return fmt.Errorf("store.SetCandidateDiscarded: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store.SetCandidateDiscarded: rows affected: %w", err)
	} else if n != 1 {
		return errors.New("store.SetCandidateDiscarded: candidate is missing or not discardable")
	}
	return nil
}

const arenaCandidateColumns = `id, run_id, tool, model, seq, status,
	branch_name, worktree_path, patch_path, COALESCE(exit_code, 0),
	COALESCE(wall_ms, 0), timed_out, final_answer_excerpt, diff_files,
	diff_added, diff_removed, input_tokens, output_tokens, cost_usd,
	session_ids, scores, verdict, kept_commit_sha, error, updated_at`

func scanArenaCandidate(row interface{ Scan(...any) error }) (*models.ArenaCandidate, error) {
	var c models.ArenaCandidate
	var timedOut int
	var sessionIDs, scores string
	if err := row.Scan(&c.ID, &c.RunID, &c.Tool, &c.Model, &c.Seq, &c.Status,
		&c.BranchName, &c.WorktreePath, &c.PatchPath, &c.ExitCode, &c.WallMS, &timedOut,
		&c.FinalAnswerExcerpt, &c.DiffFiles, &c.DiffAdded, &c.DiffRemoved,
		&c.InputTokens, &c.OutputTokens, &c.CostUSD, &sessionIDs, &scores, &c.Verdict,
		&c.KeptCommitSHA, &c.Error, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.TimedOut = timedOut != 0
	if err := json.Unmarshal([]byte(sessionIDs), &c.SessionIDs); err != nil {
		return nil, fmt.Errorf("session_ids %q: %w", sessionIDs, err)
	}
	parsed, err := models.UnmarshalScores(scores)
	if err != nil {
		return nil, fmt.Errorf("scores: %w", err)
	}
	c.Scores = parsed
	return &c, nil
}

// ArenaCandidate loads one canonical candidate by id; it returns (nil, nil)
// when absent.
func (s *Store) ArenaCandidate(ctx context.Context, id string) (*models.ArenaCandidate, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+arenaCandidateColumns+`
		FROM arena_candidates WHERE id = ?`, id)
	c, err := scanArenaCandidate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.ArenaCandidate: %w", err)
	}
	return c, nil
}

// ArenaCandidates returns a run's candidates ordered by their slot number.
func (s *Store) ArenaCandidates(ctx context.Context, runID string) ([]models.ArenaCandidate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+arenaCandidateColumns+`
		  FROM arena_candidates WHERE run_id = ? ORDER BY seq`, runID)
	if err != nil {
		return nil, fmt.Errorf("store.ArenaCandidates: %w", err)
	}
	defer rows.Close()
	var out []models.ArenaCandidate
	for rows.Next() {
		c, err := scanArenaCandidate(rows)
		if err != nil {
			return nil, fmt.Errorf("store.ArenaCandidates: scan: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func candidateJSONCols(c *models.ArenaCandidate) (sessionIDs, scores string, err error) {
	b, err := json.Marshal(c.SessionIDs)
	if err != nil {
		return "", "", fmt.Errorf("store.candidateJSONCols: session_ids: %w", err)
	}
	sessionIDs = string(b)
	scores, err = models.MarshalScores(c.Scores)
	if err != nil {
		return "", "", fmt.Errorf("store.candidateJSONCols: scores: %w", err)
	}
	return sessionIDs, scores, nil
}

// ArenaUsageBySessions sums api_turns usage (input/output tokens and cost)
// across the given session/thread ids — the arena candidate rollup seam.
// An empty id list returns honest zeros without touching the DB.
func (s *Store) ArenaUsageBySessions(ctx context.Context, sessionIDs []string) (inTok, outTok int64, costUSD float64, err error) {
	if len(sessionIDs) == 0 {
		return 0, 0, 0, nil
	}
	placeholders := make([]string, len(sessionIDs))
	args := make([]any, 0, len(sessionIDs))
	for i, id := range sessionIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	//nolint:gosec // G202: the concatenated fragment is only bound placeholders
	// ("?,?,?") sized to len(sessionIDs); the session id values are passed
	// separately as bound args, never interpolated into the SQL.
	row := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
		    COALESCE(SUM(cost_usd), 0)
		  FROM api_turns WHERE session_id IN (`+strings.Join(placeholders, ",")+`)`,
		args...)
	if err := row.Scan(&inTok, &outTok, &costUSD); err != nil {
		return 0, 0, 0, fmt.Errorf("store.ArenaUsageBySessions: %w", err)
	}
	return inTok, outTok, costUSD, nil
}

// BindArenaProcess installs an authoritative, short-lived pid bridge from a
// directly spawned Arena harness to its synthetic per-candidate session id.
// The runner removes the exact scoped row when the child exits; pid validation
// in the proxy still protects against a recycled process between those points.
func (s *Store) BindArenaProcess(ctx context.Context, pid int, sessionID, tool, cwd string) error {
	if !strings.HasPrefix(sessionID, models.ArenaSessionIDPrefix) {
		return errors.New("store.BindArenaProcess: synthetic arena session id required")
	}
	if err := pidbridge.New(s.db).Write(ctx, pidbridge.Entry{
		PID: pid, SessionID: sessionID, Tool: tool, CWD: cwd,
	}); err != nil {
		return fmt.Errorf("store.BindArenaProcess: %w", err)
	}
	return nil
}

// UnbindArenaProcess removes only the bridge row this Arena candidate wrote.
// A session-scoped delete cannot erase a newer writer's row after PID reuse.
func (s *Store) UnbindArenaProcess(ctx context.Context, pid int, sessionID string) error {
	if _, err := pidbridge.New(s.db).Delete(ctx, pid, sessionID); err != nil {
		return fmt.Errorf("store.UnbindArenaProcess: %w", err)
	}
	return nil
}

// ReconcileStaleArena moves stranded in-flight Arena rows to a terminal status
// so the run history stops lying about what is still live. It is the store seam
// for the runstate primitive (the pure decision authority): this method loads
// only the small in-flight set, asks runstate for a verdict per row, and
// persists the changed ones.
//
// Two strandings are closed: (a) a candidate left "pending"/"running" under a
// run that has itself reached complete/failed (its driver goroutine finished or
// died without finalizing the child), closed immediately; and (b) a run — and
// its candidates — left in-flight far past any real drive (a daemon crash
// mid-run leaves nothing to re-drive), closed by age. Runs whose id is in
// liveRunIDs are being driven by THIS process and are never reconciled. Returns
// the number of rows updated.
func (s *Store) ReconcileStaleArena(ctx context.Context, now time.Time, liveRunIDs map[string]bool) (int, error) {
	rules := runstate.DefaultRules()
	changed := 0

	// (1) Runs first, so a newly-failed run's candidates then close via the
	// parent-terminal rule in the same pass.
	runRows, err := s.db.QueryContext(ctx, `
		SELECT id, status, updated_at FROM arena_runs
		 WHERE status IN (?, ?, ?)`,
		models.ArenaRunStatusPending, models.ArenaRunStatusRunning, models.ArenaRunStatusJudging)
	if err != nil {
		return 0, fmt.Errorf("store.ReconcileStaleArena: runs: %w", err)
	}
	type runState struct{ id, status string }
	var staleRuns []runState
	terminalRun := map[string]bool{}
	func() {
		defer runRows.Close()
		for runRows.Next() {
			var id, status, updated string
			if scanErr := runRows.Scan(&id, &status, &updated); scanErr != nil {
				err = scanErr
				return
			}
			out := runstate.Reconcile(rules, runstate.Signal{
				Kind:      runstate.KindArenaRun,
				Status:    status,
				Age:       now.Sub(parseStamp(updated)),
				KnownLive: liveRunIDs[id],
			})
			if out.Changed {
				staleRuns = append(staleRuns, runState{id: id, status: out.To})
				terminalRun[id] = true
			}
		}
		err = runRows.Err()
	}()
	if err != nil {
		return 0, fmt.Errorf("store.ReconcileStaleArena: runs scan: %w", err)
	}
	for _, r := range staleRuns {
		if uErr := s.UpdateArenaRunStatus(ctx, r.id, r.status); uErr != nil {
			return changed, fmt.Errorf("store.ReconcileStaleArena: update run: %w", uErr)
		}
		changed++
	}

	// (2) Candidates. A candidate's parent is terminal if the run was just
	// reconciled OR was already complete/failed on disk.
	candRows, err := s.db.QueryContext(ctx, `
		SELECT c.id, c.status, c.updated_at, r.id, r.status
		  FROM arena_candidates c JOIN arena_runs r ON r.id = c.run_id
		 WHERE c.status IN (?, ?)`,
		models.ArenaCandidateStatusPending, models.ArenaCandidateStatusRunning)
	if err != nil {
		return changed, fmt.Errorf("store.ReconcileStaleArena: candidates: %w", err)
	}
	type candFix struct {
		id, status, reason string
	}
	var fixes []candFix
	func() {
		defer candRows.Close()
		for candRows.Next() {
			var id, status, updated, runID, runStatus string
			if scanErr := candRows.Scan(&id, &status, &updated, &runID, &runStatus); scanErr != nil {
				err = scanErr
				return
			}
			parentTerminal := terminalRun[runID] ||
				runStatus == models.ArenaRunStatusComplete || runStatus == models.ArenaRunStatusFailed
			out := runstate.Reconcile(rules, runstate.Signal{
				Kind:           runstate.KindArenaCandidate,
				Status:         status,
				Age:            now.Sub(parseStamp(updated)),
				KnownLive:      liveRunIDs[runID],
				ParentTerminal: parentTerminal,
			})
			if out.Changed {
				fixes = append(fixes, candFix{id: id, status: out.To, reason: out.Reason})
			}
		}
		err = candRows.Err()
	}()
	if err != nil {
		return changed, fmt.Errorf("store.ReconcileStaleArena: candidates scan: %w", err)
	}
	for _, f := range fixes {
		res, uErr := s.db.ExecContext(ctx, `
			UPDATE arena_candidates
			   SET status = ?, error = ?, updated_at = ?
			 WHERE id = ? AND status IN (?, ?)`,
			f.status, "reconciled: "+f.reason, timestamp(now.UTC()), f.id,
			models.ArenaCandidateStatusPending, models.ArenaCandidateStatusRunning)
		if uErr != nil {
			return changed, fmt.Errorf("store.ReconcileStaleArena: update candidate: %w", uErr)
		}
		if n, _ := res.RowsAffected(); n == 1 {
			changed++
		}
	}
	return changed, nil
}
