package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// THIS FILE IS THE ONE OWNER of project_head_moves, project_skill_trees,
// project_skill_tree_files, project_skill_worktree and project_skill_scan
// (agent migration 135, S10-SKILLS; CLAUDE.md module-boundary rule #4).
// The only writer is the commit scanner's after-scan step
// (internal/skillscan, wired in cmd/observer/commitscan_wire.go), which
// reaches these methods through injected funcs; skillscan never imports
// internal/store.
//
// NODE-LOCAL: none of these tables is ever named in
// internal/store/orgpush.go (forbidden-name sentinel +
// TestSkillHistoryTablesPinnedOutOfPush). No free text is stored: the
// reflog message is reduced to an allow-listed kind token before it gets
// here, and no commit subject is copied.

// SkillScanState is the git step's per-project state row.
type SkillScanState struct {
	ProjectID   int64
	LastScanAt  time.Time
	HeadSHA     string
	ReflogSince time.Time
	// ProbedAt is when the repository probes last ran (refreshed daily,
	// independently of LastScanAt).
	ProbedAt time.Time
	// IgnoreCase / Shallow are meaningful only when their *Known flag is
	// set: a failed probe with no earlier answer is unknown, never false.
	IgnoreCase          bool
	IgnoreCaseKnown     bool
	Shallow             bool
	ShallowKnown        bool
	ObjectFormat        string
	LastError           string
	ConsecutiveFailures int
}

// HeadMoveRow is one reflog entry to persist.
type HeadMoveRow struct {
	MovedAt time.Time
	SHA     string
	Kind    string
}

// SkillTreeFileRow is one skill path in a commit's tree.
type SkillTreeFileRow struct {
	RelPath string
	Mode    string
	BlobOID string
}

// SkillWorktreeRow is one non-clean skill path from the status porcelain.
type SkillWorktreeRow struct {
	RelPath string
	State   string
}

// SkillScanStateFor loads a project's git-step state; ok=false when the
// step has never run for it.
func (s *Store) SkillScanStateFor(ctx context.Context, projectID int64) (SkillScanState, bool, error) {
	st := SkillScanState{ProjectID: projectID}
	var lastScan, since, probed string
	var ignorecase, shallow int
	err := s.db.QueryRowContext(ctx, `
SELECT last_scan_at, head_sha, reflog_since, probed_at, ignorecase, shallow, object_format, last_error, consecutive_failures
  FROM project_skill_scan WHERE project_id = ?`, projectID).Scan(
		&lastScan, &st.HeadSHA, &since, &probed, &ignorecase, &shallow, &st.ObjectFormat, &st.LastError, &st.ConsecutiveFailures)
	if errors.Is(err, sql.ErrNoRows) {
		return st, false, nil
	}
	if err != nil {
		return st, false, fmt.Errorf("store.SkillScanStateFor: %w", err)
	}
	st.LastScanAt, st.ReflogSince, st.ProbedAt = parseSkillTime(lastScan), parseSkillTime(since), parseSkillTime(probed)
	st.IgnoreCase, st.IgnoreCaseKnown = ignorecase == 1, ignorecase >= 0
	st.Shallow, st.ShallowKnown = shallow == 1, shallow >= 0
	return st, true, nil
}

// SetSkillScanState upserts a project's git-step state row.
func (s *Store) SetSkillScanState(ctx context.Context, st SkillScanState) error {
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO project_skill_scan
    (project_id, last_scan_at, head_sha, reflog_since, probed_at, ignorecase, shallow, object_format, last_error, consecutive_failures)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (project_id) DO UPDATE SET
    last_scan_at = excluded.last_scan_at, head_sha = excluded.head_sha,
    reflog_since = excluded.reflog_since, probed_at = excluded.probed_at, ignorecase = excluded.ignorecase,
    shallow = excluded.shallow, object_format = excluded.object_format,
    last_error = excluded.last_error, consecutive_failures = excluded.consecutive_failures`,
		st.ProjectID, formatSkillTime(st.LastScanAt), st.HeadSHA, formatSkillTime(st.ReflogSince), formatSkillTime(st.ProbedAt),
		triState(st.IgnoreCase, st.IgnoreCaseKnown), triState(st.Shallow, st.ShallowKnown),
		st.ObjectFormat, st.LastError, st.ConsecutiveFailures); err != nil {
		return fmt.Errorf("store.SetSkillScanState: %w", err)
	}
	return nil
}

// triState encodes a probe answer: 1 true, 0 false, -1 unknown.
func triState(v, known bool) int {
	if !known {
		return -1
	}
	return boolToInt(v)
}

// NewestHeadMove returns the newest stored reflog entry's time (ok=false
// when none is stored). The incremental reflog walk stops paging once it
// reaches entries older than this.
func (s *Store) NewestHeadMove(ctx context.Context, projectID int64) (time.Time, bool, error) {
	var at string
	err := s.db.QueryRowContext(ctx, `
SELECT moved_at FROM project_head_moves WHERE project_id = ? ORDER BY moved_at DESC LIMIT 1`, projectID).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("store.NewestHeadMove: %w", err)
	}
	return parseSkillTime(at), true, nil
}

// InsertHeadMoves persists reflog entries, ignoring ones already stored.
// moves MUST be one capture in the reflog's own order, NEWEST FIRST: each
// new row's seq is assigned from its position, above every stored seq, so
// seq orders entries that share one reflog second (larger = newer). An
// entry already stored keeps its seq. It reports how many were new and
// whether any was already present.
func (s *Store) InsertHeadMoves(ctx context.Context, projectID int64, moves []HeadMoveRow) (inserted int, sawExisting bool, err error) {
	if len(moves) == 0 {
		return 0, false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("store.InsertHeadMoves: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var maxSeq int64
	if err := tx.QueryRowContext(ctx, `
SELECT COALESCE(MAX(seq), 0) FROM project_head_moves WHERE project_id = ?`, projectID).Scan(&maxSeq); err != nil {
		return 0, false, fmt.Errorf("store.InsertHeadMoves: max seq: %w", err)
	}
	base := maxSeq + int64(len(moves))
	for i, m := range moves {
		res, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO project_head_moves (project_id, moved_at, sha, kind, seq) VALUES (?, ?, ?, ?, ?)`,
			projectID, formatSkillTime(m.MovedAt), m.SHA, m.Kind, base-int64(i))
		if err != nil {
			return 0, false, fmt.Errorf("store.InsertHeadMoves: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		} else {
			sawExisting = true
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("store.InsertHeadMoves: commit: %w", err)
	}
	return inserted, sawExisting, nil
}

// likePrefixes turns literal path prefixes into escaped LIKE patterns.
func likePrefixes(prefixes []string) []string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		p = strings.TrimSuffix(p, "/")
		if p == "" {
			continue
		}
		out = append(out, r.Replace(p)+"/%")
	}
	return out
}

func likeClause(col string, n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = col + ` LIKE ? ESCAPE '\'`
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// SkillTreeCandidates lists commits whose skill tree has not been listed
// yet, newest first, capped at limit: every non-merge commit that touched a
// path under one of prefixes (the commit timeline), and every commit the
// reflog says HEAD pointed at (the HEAD-at-session-start column). SQLite's
// LIKE is ASCII case-insensitive, which is the right answer for a
// case-insensitive checkout and harmless otherwise (the pure derivation
// matches exactly).
func (s *Store) SkillTreeCandidates(ctx context.Context, projectID int64, prefixes []string, limit int) ([]string, error) {
	pats := likePrefixes(prefixes)
	if limit <= 0 {
		limit = 50
	}
	var args []any
	timeline := "SELECT NULL AS sha, NULL AS at WHERE 0"
	if len(pats) > 0 {
		timeline = `SELECT c.sha AS sha, c.committed_at AS at
  FROM project_commits c JOIN project_commit_files f ON f.commit_id = c.id
 WHERE c.project_id = ? AND c.is_merge = 0 AND ` + likeClause("f.rel_path", len(pats))
		args = append(args, projectID)
		for _, p := range pats {
			args = append(args, p)
		}
	}
	args = append(args, projectID, projectID, limit)
	//nolint:gosec // G202: timeline is an in-function literal or likeClause's "LIKE ?" placeholders; every value is bound.
	q := `
SELECT sha FROM (
  ` + timeline + `
  UNION ALL
  SELECT sha, moved_at AS at FROM project_head_moves WHERE project_id = ?
) cand
WHERE sha IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM project_skill_trees t WHERE t.project_id = ? AND t.sha = cand.sha)
GROUP BY sha
ORDER BY MAX(at) DESC
LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SkillTreeCandidates: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return nil, fmt.Errorf("store.SkillTreeCandidates: scan: %w", err)
		}
		out = append(out, sha)
	}
	return out, rows.Err()
}

// SkillTreeKnown reports whether a commit's skill tree is already memoised.
func (s *Store) SkillTreeKnown(ctx context.Context, projectID int64, sha string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM project_skill_trees WHERE project_id = ? AND sha = ?`, projectID, sha).Scan(&n); err != nil {
		return false, fmt.Errorf("store.SkillTreeKnown: %w", err)
	}
	return n > 0, nil
}

// SaveSkillTree memoises one commit's skill tree (state "ok" with its
// files, or "missing" when the object is gone). A commit's tree never
// changes, so a stored tree is never rewritten.
func (s *Store) SaveSkillTree(ctx context.Context, projectID int64, sha, state string, files []SkillTreeFileRow, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.SaveSkillTree: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO project_skill_trees (project_id, sha, state, resolved_at) VALUES (?, ?, ?, ?)`,
		projectID, sha, state, formatSkillTime(at))
	if err != nil {
		return fmt.Errorf("store.SaveSkillTree: tree: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil // already memoised; immutable
	}
	for _, f := range files {
		if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO project_skill_tree_files (project_id, sha, rel_path, mode, blob_oid) VALUES (?, ?, ?, ?, ?)`,
			projectID, sha, f.RelPath, f.Mode, f.BlobOID); err != nil {
			return fmt.Errorf("store.SaveSkillTree: file %s: %w", f.RelPath, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.SaveSkillTree: commit: %w", err)
	}
	return nil
}

// ReplaceSkillWorktree replaces a project's working-tree status rows
// whole: the porcelain is a point-in-time answer, so the previous one is
// simply superseded.
func (s *Store) ReplaceSkillWorktree(ctx context.Context, projectID int64, entries []SkillWorktreeRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.ReplaceSkillWorktree: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM project_skill_worktree WHERE project_id = ?`, projectID); err != nil {
		return fmt.Errorf("store.ReplaceSkillWorktree: clear: %w", err)
	}
	for _, e := range entries {
		if _, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO project_skill_worktree (project_id, rel_path, state) VALUES (?, ?, ?)`,
			projectID, e.RelPath, e.State); err != nil {
			return fmt.Errorf("store.ReplaceSkillWorktree: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.ReplaceSkillWorktree: commit: %w", err)
	}
	return nil
}

// ProjectHasSkillSignal is the git step's cheap gate: true when the
// project carries a skill-kind guidance row, a committed path under one of
// prefixes, or an existing skill-scan row. A project with none of those
// costs zero git invocations.
func (s *Store) ProjectHasSkillSignal(ctx context.Context, projectID int64, rootPath string, prefixes []string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM project_skill_scan WHERE project_id = ?`, projectID).Scan(&n); err != nil {
		return false, fmt.Errorf("store.ProjectHasSkillSignal: scan row: %w", err)
	}
	if n > 0 {
		return true, nil
	}
	root := normalizeGuidanceRoot(strings.TrimSpace(rootPath))
	if root != "" {
		if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM project_guidance_files WHERE project_root = ? AND kind = 'skill' AND scope = 'project'`,
			root).Scan(&n); err != nil {
			return false, fmt.Errorf("store.ProjectHasSkillSignal: guidance: %w", err)
		}
		if n > 0 {
			return true, nil
		}
	}
	pats := likePrefixes(prefixes)
	if len(pats) == 0 {
		return false, nil
	}
	args := []any{projectID}
	for _, p := range pats {
		args = append(args, p)
	}
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM (
  SELECT 1 FROM project_commits c JOIN project_commit_files f ON f.commit_id = c.id
   WHERE c.project_id = ? AND `+likeClause("f.rel_path", len(pats))+` LIMIT 1)`, args...).Scan(&n); err != nil {
		return false, fmt.Errorf("store.ProjectHasSkillSignal: commits: %w", err)
	}
	return n > 0, nil
}
