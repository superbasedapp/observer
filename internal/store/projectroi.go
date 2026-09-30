package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
)

// Store-side composition for the Projects page ROI + commit-alignment
// arc (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md
// §2 R4/R7/R10/R11, §3.3, wave W3).
//
// Every loader here does exactly one job: read plain rows out of
// existing, already-owned tables (actions/file_changes/api_turns/
// token_usage/sessions/task_items/project_commits/project_commit_files)
// and hand back the internal/projectroi plain-struct shapes that pure
// package computes over. No new table is created or owned here — see
// internal/store/commits.go (project_commits/…) and
// internal/store/loc.go (file_changes) for the actual table owners.
//
// Every windowed loader takes CONCRETE, non-zero [since, until) bounds
// (the existing internal/store/commits.go convention — see
// LoadProjectCommits) — callers (the dashboard handlers,
// LoadPromptChainInput below) resolve "no upper bound" to time.Now()
// before calling in here, never a zero time.Time.

// commitFileIDChunk bounds how many commit ids ride in one
// project_commit_files IN(...) query — the same conservative bind-count
// precedent internal/intelligence/cost.MaxSessionIDsPerScope documents
// (SQLite's variable-count ceiling), applied here so loadCommitFilesByIDs
// never risks "too many SQL variables" on a large commit window.
const commitFileIDChunk = 900

// loadCommitFilesByIDs returns project_commit_files rows for EXACTLY the
// given commit ids — no independent row cap (F9 of the 2026-09-22 arc
// review; see loadCommitsForLink's doc comment). Reads only from
// project_commit_files / project_commits, both owned by
// internal/store/commits.go's UpsertCommits seam; this is a read-only
// join alongside that file's own LoadCommitFiles, not a second writer.
// Chunked at commitFileIDChunk ids per query to stay well under
// SQLite's bound-parameter ceiling.
func (s *Store) loadCommitFilesByIDs(ctx context.Context, commitIDs []int64) ([]ProjectCommitFileRow, error) {
	if len(commitIDs) == 0 {
		return nil, nil
	}
	var out []ProjectCommitFileRow
	for start := 0; start < len(commitIDs); start += commitFileIDChunk {
		end := start + commitFileIDChunk
		if end > len(commitIDs) {
			end = len(commitIDs)
		}
		chunk := commitIDs[start:end]
		ph := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for i, id := range chunk {
			ph[i] = "?"
			args[i] = id
		}
		//nolint:gosec // G202: the concatenated fragments are compile-time constant SQL; ids bind via args.
		q := `
			SELECT cf.commit_id, c.sha, c.committed_at, cf.rel_path, cf.path_hash, cf.status, cf.added, cf.deleted, cf.binary
			  FROM project_commit_files cf
			  JOIN project_commits c ON c.id = cf.commit_id
			 WHERE cf.commit_id IN (` + strings.Join(ph, ",") + `)
			 ORDER BY c.committed_at DESC, cf.commit_id DESC`
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("store.loadCommitFilesByIDs: %w", err)
		}
		for rows.Next() {
			var (
				r           ProjectCommitFileRow
				committedAt string
				binary      int
			)
			if err := rows.Scan(&r.CommitID, &r.SHA, &committedAt, &r.RelPath, &r.PathHash, &r.Status, &r.Added, &r.Deleted, &binary); err != nil {
				rows.Close()
				return nil, fmt.Errorf("store.loadCommitFilesByIDs: scan: %w", err)
			}
			r.CommittedAt = parseCommitTime(committedAt)
			r.Binary = binary != 0
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store.loadCommitFilesByIDs: rows: %w", err)
		}
		rows.Close()
	}
	return out, nil
}

// LoadProjectPrompts returns one project's `user_prompt` actions in
// [since, until), most-recent first, capped at limit (R11 — a detail
// read is never unbounded; limit<=0 falls back to 500). truncated is
// true when the window held more prompts than limit — the caller
// should render "showing the last N".
func (s *Store) LoadProjectPrompts(ctx context.Context, projectID int64, since, until time.Time, limit int) ([]projectroi.Prompt, bool, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, session_id, timestamp, COALESCE(target, ''), tool
		  FROM actions
		 WHERE project_id = ? AND action_type = ? AND timestamp >= ? AND timestamp < ?
		 ORDER BY timestamp DESC
		 LIMIT ?`,
		projectID, models.ActionUserPrompt, timestamp(since), timestamp(until), limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("store.LoadProjectPrompts: %w", err)
	}
	defer rows.Close()

	var out []projectroi.Prompt
	for rows.Next() {
		var p projectroi.Prompt
		var ts string
		if err := rows.Scan(&p.ActionID, &p.SessionID, &ts, &p.Preview, &p.Tool); err != nil {
			return nil, false, fmt.Errorf("store.LoadProjectPrompts: scan: %w", err)
		}
		p.At = parseCommitTime(ts)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("store.LoadProjectPrompts: rows: %w", err)
	}
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated, nil
}

// LoadProjectAIEdits returns one project's AI-authored file_changes rows
// in [since, until), most-recent first, capped at limit (limit<=0 falls
// back to 20000 — plan R11's "20k edits" cap).
//
// The WHERE clause is the R4.1 structural filter, enforced here rather
// than trusted to a caller: only actor='ai' AND action_id IS NOT NULL
// rows are ever eligible for attribution — a human/system/editor row or
// an action-less row (there is none by schema, but the filter is
// explicit) never reaches internal/projectroi.
func (s *Store) LoadProjectAIEdits(ctx context.Context, projectID int64, since, until time.Time, limit int) ([]projectroi.Edit, bool, error) {
	if limit <= 0 {
		limit = 20000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT fc.action_id, COALESCE(fc.session_id, a.session_id) AS session_id, fc.saved_at,
		       fc.file_path_hash, fc.added_code, fc.modified_code, fc.deleted_code,
		       fc.added_comment, fc.category,
		       fc.sidechain, fc.overwrite
		  FROM file_changes fc
		  JOIN actions a ON a.id = fc.action_id
		 WHERE fc.project_id = ? AND fc.actor = ? AND fc.action_id IS NOT NULL
		   AND fc.saved_at >= ? AND fc.saved_at < ?
		 ORDER BY fc.saved_at DESC
		 LIMIT ?`,
		projectID, LOCActorAI, timestamp(since), timestamp(until), limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("store.LoadProjectAIEdits: %w", err)
	}
	defer rows.Close()

	var out []projectroi.Edit
	for rows.Next() {
		var e projectroi.Edit
		var savedAt string
		var sidechain, overwrite int
		if err := rows.Scan(&e.ActionID, &e.SessionID, &savedAt, &e.PathHash,
			&e.AddedCode, &e.ModifiedCode, &e.DeletedCode, &e.AddedComment, &e.Category, &sidechain, &overwrite); err != nil {
			return nil, false, fmt.Errorf("store.LoadProjectAIEdits: scan: %w", err)
		}
		e.At = parseLOCTime(savedAt)
		e.Sidechain = sidechain != 0
		e.Overwrite = overwrite != 0
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("store.LoadProjectAIEdits: rows: %w", err)
	}
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated, nil
}

// loadCommitsForLink is the shared implementation behind
// LoadProjectCommitsForLink and LoadPromptChainInput: it composes
// LoadProjectCommits + LoadCommitFiles (already owned by
// internal/store/commits.go) into internal/projectroi's plain Commit
// shape, and ALSO hands back the raw ProjectCommitFileRow list — needed
// by LoadPromptChainInput for the file's RelPath (display-only; never
// on the org wire), which projectroi.CommitFile deliberately does not
// carry.
func (s *Store) loadCommitsForLink(ctx context.Context, projectID int64, since, until time.Time, limit int) ([]projectroi.Commit, []ProjectCommitFileRow, bool, error) {
	commits, _, fileRows, truncated, err := s.loadCommitsForLinkFull(ctx, projectID, since, until, limit)
	return commits, fileRows, truncated, err
}

// loadCommitsAndRowsForLink is loadCommitsForLink that also hands back the
// selected ProjectCommitRow slice (subject, author hash, numstat totals) -
// the commit-ownership composer (commitowner.go) needs the rows beside the
// Link input without a second LoadProjectCommits round trip.
func (s *Store) loadCommitsAndRowsForLink(ctx context.Context, projectID int64, since, until time.Time, limit int) ([]projectroi.Commit, []ProjectCommitRow, bool, error) {
	commits, rows, _, truncated, err := s.loadCommitsForLinkFull(ctx, projectID, since, until, limit)
	return commits, rows, truncated, err
}

// loadCommitsForLinkFull is the one implementation behind both forms.
func (s *Store) loadCommitsForLinkFull(ctx context.Context, projectID int64, since, until time.Time, limit int) ([]projectroi.Commit, []ProjectCommitRow, []ProjectCommitFileRow, bool, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.LoadProjectCommits(ctx, projectID, since, until, limit+1)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("store.loadCommitsForLink: %w", err)
	}
	truncated := false
	if len(rows) > limit {
		truncated = true
		rows = rows[:limit] // newest-first (LoadProjectCommits' own order); drop the oldest excess.
	}

	// F9 of the 2026-09-22 arc review: fetch files BY the commit ids this
	// call actually selected (capped upstream at the commit-count cap,
	// never an independent global row cap on project_commit_files). The
	// prior fixed 20,000-row cap on LoadCommitFiles (a generous multiple
	// of the commit cap, not an exact per-commit count) silently dropped
	// the file lists of the OLDEST commits once a busy project's 5,000-
	// commit window produced more than 20,000 file rows in total —
	// breaking prompt-to-commit linkage and AI-line attribution for
	// those commits without ever setting `truncated`. Loading by the
	// selected ids instead scales with the commit cap this call already
	// enforced, so no commit's file list is ever partial.
	commitIDs := make([]int64, 0, len(rows))
	for _, r := range rows {
		commitIDs = append(commitIDs, r.ID)
	}
	fileRows, err := s.loadCommitFilesByIDs(ctx, commitIDs)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("store.loadCommitsForLink: %w", err)
	}
	filesByCommit := make(map[int64][]projectroi.CommitFile, len(rows))
	for _, fr := range fileRows {
		filesByCommit[fr.CommitID] = append(filesByCommit[fr.CommitID], projectroi.CommitFile{
			PathHash: fr.PathHash, Added: fr.Added, Deleted: fr.Deleted,
		})
	}

	localAuthor, err := s.commitLocalAuthorHash(ctx, projectID)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("store.loadCommitsForLink: %w", err)
	}
	commits := make([]projectroi.Commit, 0, len(rows))
	for _, r := range rows {
		commits = append(commits, projectroi.Commit{
			ID: r.ID, SHA: r.SHA, CommittedAt: r.CommittedAt,
			IsMerge: r.IsMerge, Reachable: r.Reachable,
			ForeignAuthor: foreignAuthor(localAuthor, r.AuthorHash),
			Files:         filesByCommit[r.ID],
		})
	}
	return commits, rows, fileRows, truncated, nil
}

// foreignAuthor reports whether a commit's author hash names someone OTHER
// than the repository's local identity (review 2026-09-29 finding 8). Either
// side unknown ("") is never foreign: the ownership rule then keeps its
// pre-author-check behaviour rather than guessing.
func foreignAuthor(localAuthorHash, commitAuthorHash string) bool {
	return localAuthorHash != "" && commitAuthorHash != "" && localAuthorHash != commitAuthorHash
}

// commitLocalAuthorHash reads project_commit_scan.local_author_hash for one
// project ("" when the project was never scanned or its identity is
// unknown). Declared here beside its one reader; the column's one writer is
// SetCommitScanState.
func (s *Store) commitLocalAuthorHash(ctx context.Context, projectID int64) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx, `SELECT local_author_hash FROM project_commit_scan WHERE project_id = ?`, projectID).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store.commitLocalAuthorHash: %w", err)
	}
	return h, nil
}

// LoadProjectCommitsForLink returns one project's commits in [since,
// until) as internal/projectroi.Link's plain Commit input (R11 cap,
// limit<=0 -> 500).
func (s *Store) LoadProjectCommitsForLink(ctx context.Context, projectID int64, since, until time.Time, limit int) ([]projectroi.Commit, bool, error) {
	commits, _, truncated, err := s.loadCommitsForLink(ctx, projectID, since, until, limit)
	return commits, truncated, err
}

// LoadProjectSpendTurns loads, de-duplicates AND PRICES one project's API
// turns in [since, until) through the process cost engine's canonical
// per-turn pipeline (internal/intelligence/cost.Engine.TurnRows) — the
// SAME loadRows union (proxy api_turns + watcher token_usage +
// summary_calls) + dedup (per-turn id / session-shape / minute-bucketed
// orphan-shape, session-aggregate reconciliation, Copilot shadow
// collapse) + pricing (recorded cost wins, else LookupAt + Compute) that
// /api/cost and `observer cost` use, scoped to this one project via
// cost.Options.ProjectID (which itself resolves proxy rows through
// COALESCE(at.project_id, s.project_id) — api_turns.project_id is NULL
// on every row of every grounded install).
//
// This REPLACES the pre-2026-09-22 loadProjectTurnSource /
// dedupProjectTurns / priceProjectTurn trio: the Projects page used to
// re-implement a parallel copy of the cost engine's normalization (its
// own dedup keys, its own pricing call), which drifted from the
// engine's own fixes (reasoning-aware shape keys, session-aggregate
// handling, the Copilot shadow drop) — see docs/plans/projects-page-roi
// -and-commit-alignment-plan-2026-09-21.md's 2026-09-22 rework log.
// There is now exactly one owner of "what does this turn cost."
//
// unpricedCount is the number of returned turns that are not FULLY priced
// (cost.TurnRow.FullyPriced): no recorded cost AND no pricing-table entry
// at all for their model, OR a table price whose cache-read rate the
// vendor never quoted, so the turn's cached tokens billed an unpriced $0
// (review finding F2, 2026-09-26 - the same verdict Summary's rollup
// reaches). A KNOWN-FREE model IS priced, at $0 — see cost.TurnRow.Priced's
// doc comment. Each returned Turn's Priced carries the same FullyPriced
// verdict, so every per-bucket / per-session / per-commit unpriced count
// downstream agrees with this total.
func (s *Store) LoadProjectSpendTurns(ctx context.Context, engine *cost.Engine, projectID int64, since, until time.Time) (turns []projectroi.Turn, unpricedCount int, err error) {
	rows, err := engine.TurnRows(ctx, s.db, cost.Options{ProjectID: projectID, Since: since, Until: until})
	if err != nil {
		return nil, 0, fmt.Errorf("store.LoadProjectSpendTurns: %w", err)
	}
	turns = make([]projectroi.Turn, 0, len(rows))
	for _, r := range rows {
		turns = append(turns, projectroi.Turn{
			SessionID: r.SessionID, At: r.At, CostUSD: r.CostUSD,
			Input: r.Tokens.Input, Output: r.Tokens.Output, CacheRead: r.Tokens.CacheRead,
			CacheCreation: r.Tokens.CacheCreation, CacheCreation1h: r.Tokens.CacheCreation1h,
			Reasoning: r.Tokens.Reasoning, WebSearchRequests: r.Tokens.WebSearchRequests,
			Model: r.Model, Tool: r.Tool, Source: r.Source, TurnID: r.TurnID, Priced: r.FullyPriced(),
		})
		if !r.FullyPriced() {
			unpricedCount++
		}
	}
	return turns, unpricedCount, nil
}

// loadProjectSessionsQuery is the query text loadProjectSessionsUnion
// binds — extracted to a const so TestLoadProjectSessionsUnionIndexPlan
// can EXPLAIN QUERY PLAN the EXACT text this function issues (the same
// discipline migration 129's own pin test uses).
//
// ONE UNION of distinct in-window activity session ids (F8/finding #4 of
// the 2026-09-22 rework) replaces the prior four correlated `EXISTS`
// probes. Each EXISTS forced SQLite to re-plan and re-execute a
// correlated subquery per candidate session row; on a large corpus the
// actions/file_changes probes could only lean on migration 129's
// idx_actions_project_type_ts by its LEADING project_id column (this
// query binds no action_type), effectively scanning every action for
// the project and filtering timestamp row-by-row. A single UNION lets
// each source table be scanned ONCE via its own dedicated index
// (migration 130) and produces a small distinct session-id set the
// outer sessions scan then probes by primary key — one shared query
// shape instead of four independent per-row subqueries.
//
// summary_calls (previously MISSED entirely — a pre-window session with
// only an in-window rolling-summary call was silently omitted even
// though that spend is already included in the window's headline
// total) is now a fifth UNION arm. api_turns/token_usage/summary_calls
// bind no project_id of their own (api_turns.project_id is NULL on
// every row of every grounded install — the same COALESCE(at.project_id,
// s.project_id) reality internal/intelligence/cost/summary.go's
// loadProxyRows documents); the outer `s.project_id = ?` filter on the
// joined sessions row is what actually scopes them to this project, so
// these three arms filter by timestamp only.
const loadProjectSessionsQuery = `
	SELECT id, tool, started_at, COALESCE(ended_at, '')
	  FROM sessions s
	 WHERE s.project_id = ?
	   AND (
	     (s.started_at >= ? AND s.started_at < ?)
	     OR s.id IN (
	       SELECT session_id FROM actions
	        WHERE project_id = ? AND timestamp >= ? AND timestamp < ?
	       UNION
	       SELECT session_id FROM file_changes
	        WHERE project_id = ? AND saved_at >= ? AND saved_at < ? AND session_id IS NOT NULL
	       UNION
	       SELECT session_id FROM api_turns
	        WHERE timestamp >= ? AND timestamp < ? AND session_id IS NOT NULL
	       UNION
	       SELECT session_id FROM token_usage
	        WHERE timestamp >= ? AND timestamp < ?
	       UNION
	       SELECT session_id FROM summary_calls
	        WHERE timestamp >= ? AND timestamp < ? AND session_id IS NOT NULL
	     )
	   )
	 ORDER BY s.started_at`

// loadProjectSessionsQueryNoSummaryCalls is loadProjectSessionsQuery with
// the summary_calls UNION arm removed, for a legacy DB predating
// migration 016 (mirrors loadSummaryCallRows' own "no such table"
// degrade in internal/intelligence/cost/summary.go).
const loadProjectSessionsQueryNoSummaryCalls = `
	SELECT id, tool, started_at, COALESCE(ended_at, '')
	  FROM sessions s
	 WHERE s.project_id = ?
	   AND (
	     (s.started_at >= ? AND s.started_at < ?)
	     OR s.id IN (
	       SELECT session_id FROM actions
	        WHERE project_id = ? AND timestamp >= ? AND timestamp < ?
	       UNION
	       SELECT session_id FROM file_changes
	        WHERE project_id = ? AND saved_at >= ? AND saved_at < ? AND session_id IS NOT NULL
	       UNION
	       SELECT session_id FROM api_turns
	        WHERE timestamp >= ? AND timestamp < ? AND session_id IS NOT NULL
	       UNION
	       SELECT session_id FROM token_usage
	        WHERE timestamp >= ? AND timestamp < ?
	     )
	   )
	 ORDER BY s.started_at`

// LoadProjectSessions returns one project's sessions with relevant
// activity in [since, until): started in the window, OR carrying a
// prompt (actions), an AI edit (file_changes), a turn (api_turns /
// token_usage) or a rolling-summary call (summary_calls) timestamped
// inside it. A session started BEFORE the window but still active
// during it (F8 of the 2026-09-22 arc review — e.g. a session started
// 31 days ago with turns today) used to be dropped entirely by a plain
// `started_at >= since` filter, silently omitting its spend and
// prompt/edit counts from the by-session table even though the SAME
// activity was already included in the window's headline totals.
// Metadata (tool, started_at, ended_at) is still hydrated from the
// sessions row itself, never fabricated.
//
// CostUSD is left 0 here: a session's cost is the sum of its PRICED
// turns, and pricing (the cost engine) lives one layer up in the
// dashboard composition (internal/intelligence/dashboard/projectdetail.go
// loadProjectSpend), which fills it from LoadProjectSpendTurns — one
// owner for a session's dollar figure, never a recorded-column sum that
// disagrees with the priced turns.
func (s *Store) LoadProjectSessions(ctx context.Context, projectID int64, since, until time.Time) ([]projectroi.Session, error) {
	sinceStr, untilStr := timestamp(since), timestamp(until)
	rows, err := s.db.QueryContext(ctx, loadProjectSessionsQuery,
		projectID,
		sinceStr, untilStr,
		projectID, sinceStr, untilStr,
		projectID, sinceStr, untilStr,
		sinceStr, untilStr,
		sinceStr, untilStr,
		sinceStr, untilStr)
	if err != nil {
		// Legacy DB predating migration 016 (summary_calls didn't exist
		// yet) — degrade gracefully, same convention
		// internal/intelligence/cost/summary.go's loadSummaryCallRows
		// uses, rather than failing the whole Projects-page read.
		if strings.Contains(err.Error(), "no such table") {
			rows, err = s.db.QueryContext(ctx, loadProjectSessionsQueryNoSummaryCalls,
				projectID,
				sinceStr, untilStr,
				projectID, sinceStr, untilStr,
				projectID, sinceStr, untilStr,
				sinceStr, untilStr,
				sinceStr, untilStr)
		}
		if err != nil {
			return nil, fmt.Errorf("store.LoadProjectSessions: %w", err)
		}
	}
	defer rows.Close()

	var out []projectroi.Session
	for rows.Next() {
		var sess projectroi.Session
		var startedAt, endedAt string
		if err := rows.Scan(&sess.ID, &sess.Tool, &startedAt, &endedAt); err != nil {
			return nil, fmt.Errorf("store.LoadProjectSessions: scan: %w", err)
		}
		sess.StartedAt = parseCommitTime(startedAt)
		if endedAt != "" {
			sess.EndedAt = parseCommitTime(endedAt)
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadProjectSessions: rows: %w", err)
	}
	return out, nil
}

// taskStatusDone is the projectroi.Task.Status value proxyUSDPerTaskDone
// (internal/projectroi/proxies.go) counts as "completed" — distinct from
// taskflow's own "completed" wire value, translated here at the loader
// boundary (CLAUDE.md module-boundary rule #3: resolve source
// differences into normalized data at the boundary).
const taskStatusDone = "done"

// LoadProjectTasks returns one project's task_items in sessions started
// in [since, until), Status-normalized (taskflow.StatusCompleted ->
// "done", every other status passed through as-is).
//
// CostUSD is always 0: taskreport.LoadTaskRollup (the existing per-task
// pricer) only exposes an AGGREGATE across every task in a window, never
// a per-task row a caller can attach to one projectroi.Task — and no
// proxy internal/projectroi.Proxies emits today reads Task.CostUSD (see
// its doc comment), so this is a documented no-op, not a missing
// feature. ProjectDetail's top-level tasks.cost_usd (§3.4) is filled
// separately, from taskreport.LoadTaskRollup's own aggregate, by the
// dashboard handler.
func (s *Store) LoadProjectTasks(ctx context.Context, projectID int64, since, until time.Time) ([]projectroi.Task, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ti.session_id, ti.key, ti.status
		  FROM task_items ti
		  JOIN sessions s ON s.id = ti.session_id
		 WHERE s.project_id = ? AND s.started_at >= ? AND s.started_at < ?`,
		projectID, timestamp(since), timestamp(until))
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectTasks: %w", err)
	}
	defer rows.Close()

	var out []projectroi.Task
	for rows.Next() {
		var t projectroi.Task
		if err := rows.Scan(&t.SessionID, &t.Key, &t.Status); err != nil {
			return nil, fmt.Errorf("store.LoadProjectTasks: scan: %w", err)
		}
		if t.Status == taskflow.StatusCompleted {
			t.Status = taskStatusDone
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadProjectTasks: rows: %w", err)
	}
	return out, nil
}

// LoadProjectLOCTotals returns one project's AI-authored added/modified
// code-line totals in the EXACT [since, until) window, plus the
// project's human-capture posture ("none"/"vscode" —
// docs/loc-tracking.md).
//
// 2026-09-22 rework finding #5: this used to convert [since,until) into
// an approximate day count and call LoadLOCSummary(ctx, days,
// projectID), which independently recomputed `since` as its OWN
// `time.Now()-days` — silently ignoring the caller's actual `until` and
// drifting onto today's window whenever `until` was not "now" (e.g. a
// past/explicit window). It now calls LoadProjectLOCWindowed with the
// EXACT bounds, which is also what internal/store/projectroi.go's list
// sibling (LoadProjectListExtras) now calls for its own 30-day window —
// one shared AI-line loader, so the list and the detail panel can never
// disagree about what counts as "AI" lines in a window.
func (s *Store) LoadProjectLOCTotals(ctx context.Context, projectID int64, since, until time.Time) (aiAdded, aiModified int, humanCapture string, err error) {
	t, err := s.LoadProjectLOCBreakdown(ctx, projectID, since, until)
	if err != nil {
		return 0, 0, "none", fmt.Errorf("store.LoadProjectLOCTotals: %w", err)
	}
	return t.AIAdded, t.AIModified, t.HumanCapture, nil
}

// ProjectLOCTotals is one project's AI-authored line totals in an exact
// [since, until) window. Every count is CODE-category only (a docs or
// config file's lines are never "code" - LoadProjectLOCWindowed's filter):
// AIAdded + AIModified are the authored code lines, AIComment the added
// comment lines, the pair internal/loc.SplitAuthored turns into the
// code-vs-comment share. HumanCapture is "none" (unmeasured, never zero)
// or "vscode" (docs/loc-tracking.md).
type ProjectLOCTotals struct {
	AIAdded      int
	AIModified   int
	AIComment    int
	HumanCapture string
}

// LoadProjectLOCBreakdown is LoadProjectLOCTotals plus the AI comment-line
// total - the detail panel's source for the code-vs-comment split.
// LoadProjectLOCTotals is a thin projection of it, so the two can never
// disagree about a window.
func (s *Store) LoadProjectLOCBreakdown(ctx context.Context, projectID int64, since, until time.Time) (ProjectLOCTotals, error) {
	out := ProjectLOCTotals{HumanCapture: "none"}
	windows, err := s.LoadProjectLOCWindowed(ctx, projectID, since, until)
	if err != nil {
		return out, fmt.Errorf("store.LoadProjectLOCBreakdown: %w", err)
	}
	w := windows[projectID]
	out.AIAdded, out.AIModified, out.AIComment = w.AIAdded, w.AIModified, w.AIComment

	// HUMAN CAPTURE ("is an editor reporting saves in this window") —
	// windowed to the SAME [since,until) bounds, mirroring the rule
	// LoadLOCSummary applied (just with exact bounds instead of an
	// approximate day count).
	var editorRows sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM file_changes
		WHERE source IN ('editor','editor-echo')
		  AND project_id = ? AND saved_at >= ? AND saved_at < ?`,
		projectID, timestamp(since), timestamp(until)).Scan(&editorRows); err != nil {
		return ProjectLOCTotals{HumanCapture: "none"}, fmt.Errorf("store.LoadProjectLOCBreakdown: human capture: %w", err)
	}
	if editorRows.Int64 > 0 {
		out.HumanCapture = "vscode"
	}
	return out, nil
}

// ProjectMeta is the ProjectDetail.project wire shape's source (plan
// §3.4): identity plus the light facts (tool roster, first/last seen)
// the detail page's header renders.
type ProjectMeta struct {
	ID        int64
	RootPath  string
	GitRemote string
	Name      string
	Tools     []string
	FirstSeen time.Time
	LastSeen  time.Time
}

// LoadProjectMeta resolves one project's identity + header facts.
// ok=false means the project id is unknown (the handler 404s).
func (s *Store) LoadProjectMeta(ctx context.Context, projectID int64) (ProjectMeta, bool, error) {
	var m ProjectMeta
	m.ID = projectID
	var gitRemote, name sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT root_path, git_remote, name FROM projects WHERE id = ?`, projectID).
		Scan(&m.RootPath, &gitRemote, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectMeta{}, false, nil
	}
	if err != nil {
		return ProjectMeta{}, false, fmt.Errorf("store.LoadProjectMeta: %w", err)
	}
	m.GitRemote = gitRemote.String
	m.Name = name.String

	toolRows, err := s.db.QueryContext(ctx, `SELECT DISTINCT tool FROM sessions WHERE project_id = ? ORDER BY tool`, projectID)
	if err != nil {
		return ProjectMeta{}, false, fmt.Errorf("store.LoadProjectMeta: tools: %w", err)
	}
	for toolRows.Next() {
		var tool string
		if err := toolRows.Scan(&tool); err != nil {
			toolRows.Close()
			return ProjectMeta{}, false, fmt.Errorf("store.LoadProjectMeta: tools scan: %w", err)
		}
		m.Tools = append(m.Tools, tool)
	}
	if err := toolRows.Err(); err != nil {
		toolRows.Close()
		return ProjectMeta{}, false, fmt.Errorf("store.LoadProjectMeta: tools rows: %w", err)
	}
	toolRows.Close()

	var first, last sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT MIN(timestamp), MAX(timestamp) FROM actions WHERE project_id = ?`, projectID,
	).Scan(&first, &last); err != nil {
		return ProjectMeta{}, false, fmt.Errorf("store.LoadProjectMeta: seen: %w", err)
	}
	if first.Valid {
		m.FirstSeen = parseCommitTime(first.String)
	}
	if last.Valid {
		m.LastSeen = parseCommitTime(last.String)
	}
	return m, true, nil
}

// ProjectIDForAction resolves the project a single action belongs to.
// Used by cmd/observer's grade-commit CLI loader, which is keyed by an
// action id alone (--prompt), not a project id.
func (s *Store) ProjectIDForAction(ctx context.Context, actionID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT project_id FROM actions WHERE id = ?`, actionID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("store.ProjectIDForAction: action %d not found", actionID)
	}
	if err != nil {
		return 0, fmt.Errorf("store.ProjectIDForAction: %w", err)
	}
	return id, nil
}

// ProjectListExtra is the /api/projects list row's additive per-project
// summary (plan §3.4/R7): a fixed 30-day spend/AI-lines/commits window,
// the project's all-time last commit, and — ONLY for a project the
// commit scanner has actually touched at least once — its capture
// posture. A project absent from LoadProjectListExtras' returned map
// has none of this data yet (handleProjects must treat that as "omit",
// never a fabricated zero — R7).
type ProjectListExtra struct {
	// AILines30d is AI-authored CODE lines (added + modified, code-category
	// files only - docs/config lines are excluded since 2026-09-28) and
	// AIComment30d the AI-added comment lines over the same rows: the pair
	// internal/loc.SplitAuthored turns into the list's comment share.
	AILines30d   int
	AIComment30d int
	Commits30d   int
	LastCommitAt time.Time
	// CommitsScanned is true once a project_commit_scan row exists for
	// this project at all (regardless of the 30-day window) — the gate
	// for whether CommitCapture/HumanLOC are meaningful.
	CommitsScanned bool
	CommitCapture  string // "ok" | "no_git" | "error" (commitCaptureStateFor) — meaningful only when CommitsScanned.
	HumanLOC       string // "vscode" | "none" — meaningful only when CommitsScanned.
}

// LoadProjectListExtras computes the /api/projects additive fields for
// every project with relevant activity, in a small fixed number of
// grouped queries rather than one query per project (R11).
//
// [since, until) is now a real HALF-OPEN window on both ends (2026-09-22
// rework finding #12 — the pre-rework signature took only `since`, so a
// future-dated or corrupted row's timestamp landed in the list's "last
// 30 days" total with no upper bound at all, and the list could
// disagree with the detail panel's own [since,until) window over the
// exact same corpus). Callers resolve "no upper bound" to time.Now()
// before calling in here, matching every other windowed loader in this
// file (see this file's own package doc comment).
func (s *Store) LoadProjectListExtras(ctx context.Context, since, until time.Time) (map[int64]*ProjectListExtra, error) {
	out := make(map[int64]*ProjectListExtra)
	get := func(id int64) *ProjectListExtra {
		e, ok := out[id]
		if !ok {
			e = &ProjectListExtra{}
			out[id] = e
		}
		return e
	}
	ts, untilTS := timestamp(since), timestamp(until)

	// Spend is NOT summed here: the recorded cost columns are 0 on many
	// corpora (priced on read), so the dashboard handler prices the list
	// through cost.Engine.Summary(GroupByProject) instead (F1/F6 of the
	// 2026-09-22 arc review) — the SAME per-turn dedup+pricing pipeline
	// the detail panel's LoadProjectSpendTurns uses, so the list and the
	// detail panel can never disagree about a project's spend.

	// AI lines: LoadProjectLOCWindowed (finding #5), NOT a raw SUM over
	// file_changes — the raw sum bypasses locDedupCTESQL's collapse rule
	// entirely, so a duplicate AI capture (the codex invocation/executor
	// pair migration 103's own doc comment describes) inflated the
	// list's AI-line count above what the detail panel's (already
	// deduplicated) figure showed for the identical window.
	locWindows, err := s.LoadProjectLOCWindowed(ctx, 0, since, until)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectListExtras: loc: %w", err)
	}
	for pid, w := range locWindows {
		if w.AIAdded == 0 && w.AIModified == 0 && w.AIComment == 0 {
			continue
		}
		e := get(pid)
		e.AILines30d = w.AIAdded + w.AIModified
		e.AIComment30d = w.AIComment
	}

	// reachable = 1 only — a merge counts toward Commits30d exactly like
	// every other proxy/detail-panel commit count (F17 of the 2026-09-22
	// arc review: this query used to also require is_merge = 0, which
	// disagreed with both projectroi.CountsAsCommit — the ROI proxies'
	// predicate, merges count when reachable — and the detail panel's
	// Commits.Count once that was fixed to use the same predicate).
	commitRows, err := s.db.QueryContext(ctx, `
		SELECT project_id, COUNT(*)
		  FROM project_commits
		 WHERE reachable = 1 AND committed_at >= ? AND committed_at < ?
		 GROUP BY project_id`, ts, untilTS)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectListExtras: commits: %w", err)
	}
	for commitRows.Next() {
		var pid int64
		var n int
		if err := commitRows.Scan(&pid, &n); err != nil {
			commitRows.Close()
			return nil, fmt.Errorf("store.LoadProjectListExtras: commits scan: %w", err)
		}
		get(pid).Commits30d = n
	}
	if err := commitRows.Err(); err != nil {
		commitRows.Close()
		return nil, fmt.Errorf("store.LoadProjectListExtras: commits rows: %w", err)
	}
	commitRows.Close()

	// last_commit_at is ALL-TIME (unwindowed) — the same convention
	// handleProjects' existing last_seen already uses for actions.
	lastRows, err := s.db.QueryContext(ctx, `
		SELECT project_id, MAX(committed_at) FROM project_commits WHERE reachable = 1 GROUP BY project_id`)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectListExtras: last commit: %w", err)
	}
	for lastRows.Next() {
		var pid int64
		var last string
		if err := lastRows.Scan(&pid, &last); err != nil {
			lastRows.Close()
			return nil, fmt.Errorf("store.LoadProjectListExtras: last commit scan: %w", err)
		}
		get(pid).LastCommitAt = parseCommitTime(last)
	}
	if err := lastRows.Err(); err != nil {
		lastRows.Close()
		return nil, fmt.Errorf("store.LoadProjectListExtras: last commit rows: %w", err)
	}
	lastRows.Close()

	// Capture posture: only for a project the scanner has actually
	// touched (a project_commit_scan row exists) — types.ts's
	// ProjectRow doc comment: "a project the commit scanner has never
	// touched simply omits" the whole capture struct on the list.
	scanRows, err := s.db.QueryContext(ctx, `SELECT project_id, last_error, consecutive_failures FROM project_commit_scan`)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectListExtras: scan state: %w", err)
	}
	for scanRows.Next() {
		var pid int64
		var lastErr string
		var failures int
		if err := scanRows.Scan(&pid, &lastErr, &failures); err != nil {
			scanRows.Close()
			return nil, fmt.Errorf("store.LoadProjectListExtras: scan state scan: %w", err)
		}
		e := get(pid)
		e.CommitsScanned = true
		e.CommitCapture = commitCaptureStateFor(lastErr, failures)
	}
	if err := scanRows.Err(); err != nil {
		scanRows.Close()
		return nil, fmt.Errorf("store.LoadProjectListExtras: scan state rows: %w", err)
	}
	scanRows.Close()

	// Human LOC capture is an ALL-TIME check ("is an editor reporting
	// saves", not "in this window") — the same rule LoadLOCSummary uses.
	humanRows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT project_id FROM file_changes WHERE source IN (?, ?)`, LOCSourceEditor, LOCSourceEditorEcho)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectListExtras: human loc: %w", err)
	}
	humanProjects := make(map[int64]bool)
	for humanRows.Next() {
		var pid int64
		if err := humanRows.Scan(&pid); err != nil {
			humanRows.Close()
			return nil, fmt.Errorf("store.LoadProjectListExtras: human loc scan: %w", err)
		}
		humanProjects[pid] = true
	}
	if err := humanRows.Err(); err != nil {
		humanRows.Close()
		return nil, fmt.Errorf("store.LoadProjectListExtras: human loc rows: %w", err)
	}
	humanRows.Close()
	for pid, e := range out {
		if !e.CommitsScanned {
			continue
		}
		if humanProjects[pid] {
			e.HumanLOC = "vscode"
		} else {
			e.HumanLOC = "none"
		}
	}

	return out, nil
}

// promptChainHunkCap/promptChainHunkExcerptBytes bound the AI-edited
// hunk excerpts LoadPromptChainInput attaches to a prompt's linked
// commit — the same 20-hunk / 2KiB-per-hunk bound
// cloudcontract.MaxCommitAlignmentHunks/MaxCommitAlignmentHunkExcerptBytes
// enforce for the cloud tier, applied here too so the judge tier never
// sends a materially larger payload than the cloud tier would.
const (
	promptChainHunkCap          = 20
	promptChainHunkExcerptBytes = 2048
)

// PromptChainCommitFile is one file the prompt's linked commit touched.
// RelPath is display-only (never on the org wire, same class as
// actions.target) — the cloud tier (cmd/observer's grade-commit loader)
// uses PathHash only; the judge tier's alignment.FileStat uses RelPath
// so the local LLM sees a real file name.
type PromptChainCommitFile struct {
	PathHash string
	RelPath  string
	Added    int
	Deleted  int
}

// PromptChainHunk is one bounded AI-edited hunk excerpt tied to a file
// the prompt's linked commit touched. Excerpt is the value already
// stored in actions.raw_tool_input — scrubbed at ingest time like every
// other stored action field, so a caller's OWN additional scrub pass
// over it (cloudevidence.BuildCommitAlignment's documented "raw,
// pre-scrub" contract) is idempotent, never a leak.
type PromptChainHunk struct {
	PathHash string
	Excerpt  string
}

// PromptChainFacts is the raw per-prompt attribution facts
// LoadPromptChainInput resolves alongside the already-scrubbed
// alignment.Input judge payload it builds from the SAME facts. It
// carries everything cmd/observer's grade-commit CLI loader needs to
// build a cloudevidence.CommitAlignmentInput (§3.6 tier C) without
// re-running the attribution pipeline itself.
type PromptChainFacts struct {
	ProjectID     int64
	ActionID      int64
	SessionID     string
	Tool          string
	PromptText    string
	LinkStatus    string
	WindowDays    int
	CommitID      int64
	CommitSHA     string
	CommitSubject string
	CommitFiles   []PromptChainCommitFile
	Hunks         []PromptChainHunk
}

// LoadPromptChainInput resolves one prompt's full attribution chain —
// which commit (if any) its AI edits reached, that commit's files, and
// up to 20 bounded hunk excerpts from the edits that reached it — and
// returns it as BOTH an alignment.Input (ready for the J-tier judge)
// and the raw PromptChainFacts a cloud-evidence caller composes into a
// cloudevidence.CommitAlignmentInput separately (that builder scrubs
// its own inputs; PromptChainFacts carries the same already-ingest-
// scrubbed text, so its own scrub pass is idempotent).
//
// It runs internal/projectroi.Link over a bounded FORWARD window
// [prompt.At, prompt.At+DefaultLinkWindow+1d] — the only span that can
// affect THIS prompt's own outcome, since R4.3's supersede rule only
// ever looks at a STRICTLY LATER prompt touching the same path — so it
// never needs to load the project's full history to grade one prompt.
func (s *Store) LoadPromptChainInput(ctx context.Context, projectID, actionID int64) (alignment.Input, PromptChainFacts, error) {
	var sessionID, tool, ts, target string
	var rawInput sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT session_id, tool, timestamp, COALESCE(target, ''), raw_tool_input
		  FROM actions WHERE id = ? AND project_id = ? AND action_type = ?`,
		actionID, projectID, models.ActionUserPrompt,
	).Scan(&sessionID, &tool, &ts, &target, &rawInput)
	if errors.Is(err, sql.ErrNoRows) {
		return alignment.Input{}, PromptChainFacts{}, fmt.Errorf("store.LoadPromptChainInput: prompt action %d not found in project %d", actionID, projectID)
	}
	if err != nil {
		return alignment.Input{}, PromptChainFacts{}, fmt.Errorf("store.LoadPromptChainInput: %w", err)
	}
	promptAt := parseCommitTime(ts)
	promptText := target
	if rawInput.Valid && rawInput.String != "" {
		promptText = rawInput.String
	}

	windowUntil := promptAt.Add(projectroi.DefaultLinkWindow + 24*time.Hour)

	prompts, _, err := s.LoadProjectPrompts(ctx, projectID, promptAt, windowUntil, 500)
	if err != nil {
		return alignment.Input{}, PromptChainFacts{}, err
	}
	edits, _, err := s.LoadProjectAIEdits(ctx, projectID, promptAt, windowUntil, 20000)
	if err != nil {
		return alignment.Input{}, PromptChainFacts{}, err
	}
	commits, fileRows, _, err := s.loadCommitsForLink(ctx, projectID, promptAt, windowUntil, 500)
	if err != nil {
		return alignment.Input{}, PromptChainFacts{}, err
	}

	linkage := projectroi.Link(prompts, edits, commits, projectroi.Options{})
	var chain projectroi.PromptChain
	found := false
	for _, c := range linkage.Chains {
		if c.Prompt.ActionID == actionID {
			chain, found = c, true
			break
		}
	}
	if !found {
		return alignment.Input{}, PromptChainFacts{}, fmt.Errorf("store.LoadPromptChainInput: prompt action %d produced no attribution chain", actionID)
	}

	facts := PromptChainFacts{
		ProjectID:  projectID,
		ActionID:   actionID,
		SessionID:  sessionID,
		Tool:       tool,
		PromptText: promptText,
		LinkStatus: string(chain.Status),
		WindowDays: int(projectroi.DefaultLinkWindow.Hours() / 24),
	}
	in := alignment.Input{
		PromptText: contentScrubber().String(promptText),
		LinkStatus: facts.LinkStatus,
		Tool:       tool,
	}
	// JUDGE-1: the session's data authority rides with the input so the
	// tier-J judge egress gate (alignment.EgressGate via
	// dataauthority.JudgeEgressAllowed) can refuse to ship org-owned
	// content to a judge endpoint the org never approved. in.Authority
	// stays "" whenever the classification could not be established —
	// SessionAuthority errored, the session row is missing, or the
	// session's authority column is legitimately NULL/unclassified — and
	// that is a deliberate FAIL-CLOSED choice, not a swallowed error: an
	// empty alignment.Input.Authority is dataauthority's own "unknown"
	// bucket, which JudgeEgressAllowed treats identically to AuthorityOrg
	// (allowed only over loopback or an org-pinned judge config, refused
	// otherwise — see alignmentJudgeAdapter.AllowInput in
	// cmd/observer/alignment_wire.go). A DB error here therefore never
	// widens what a remote judge may see; it can only ever narrow it to
	// the same restrictive default an unclassified session already gets.
	// The lookup error itself is intentionally not propagated as this
	// call's own error: LoadPromptChainInput's job is producing the
	// alignment.Input/PromptChainFacts pair, and a transient authority
	// read failure should not fail the whole grading call when the
	// egress gate already fails closed on its behalf.
	if c, found, aerr := s.SessionAuthority(ctx, sessionID); aerr == nil && found {
		in.Authority = string(c.Authority)
	}

	if len(chain.Commits) == 0 {
		return in, facts, nil
	}
	// "First commit in the chain" (§3.6): chain.Commits is already
	// ordered ascending by CommittedAt (internal/projectroi.Link).
	picked := chain.Commits[0]
	facts.CommitID, facts.CommitSHA = picked.ID, picked.SHA

	var subject string
	if serr := s.db.QueryRowContext(ctx, `SELECT subject FROM project_commits WHERE id = ?`, picked.ID).Scan(&subject); serr != nil && !errors.Is(serr, sql.ErrNoRows) {
		return alignment.Input{}, PromptChainFacts{}, fmt.Errorf("store.LoadPromptChainInput: commit subject: %w", serr)
	}
	facts.CommitSubject = subject
	in.CommitSubject = contentScrubber().String(subject)

	relByHash := make(map[string]string, len(fileRows))
	reachedPaths := make(map[string]bool)
	for _, f := range chain.Files {
		if !f.Superseded && f.CommitID == picked.ID {
			reachedPaths[f.PathHash] = true
		}
	}
	for _, fr := range fileRows {
		relByHash[fr.PathHash] = fr.RelPath
		if fr.CommitID != picked.ID || !reachedPaths[fr.PathHash] {
			continue
		}
		facts.CommitFiles = append(facts.CommitFiles, PromptChainCommitFile{
			PathHash: fr.PathHash, RelPath: fr.RelPath, Added: fr.Added, Deleted: fr.Deleted,
		})
		in.Files = append(in.Files, alignment.FileStat{Path: fr.RelPath, Added: fr.Added, Deleted: fr.Deleted})
	}

	// Up to promptChainHunkCap bounded hunk excerpts from THIS prompt's
	// own edits whose path reached the picked commit (§3.6: "the
	// AI-edited hunks already in actions.raw_tool_input for the linked
	// edits").
	for _, e := range chain.Edits {
		if len(facts.Hunks) >= promptChainHunkCap {
			break
		}
		if !reachedPaths[e.PathHash] {
			continue
		}
		var raw sql.NullString
		if serr := s.db.QueryRowContext(ctx, `SELECT raw_tool_input FROM actions WHERE id = ?`, e.ActionID).Scan(&raw); serr != nil {
			if errors.Is(serr, sql.ErrNoRows) {
				continue
			}
			return alignment.Input{}, PromptChainFacts{}, fmt.Errorf("store.LoadPromptChainInput: edit hunk: %w", serr)
		}
		if !raw.Valid || raw.String == "" {
			continue
		}
		excerpt := scrub.TruncateN(raw.String, promptChainHunkExcerptBytes)
		facts.Hunks = append(facts.Hunks, PromptChainHunk{PathHash: e.PathHash, Excerpt: excerpt})
		in.Hunks = append(in.Hunks, alignment.Hunk{Path: relByHash[e.PathHash], Excerpt: contentScrubber().String(excerpt)})
	}

	return in, facts, nil
}

// LoadProjectPromptCounts returns, per session, how many user_prompt
// actions the project recorded in [since, until) — UNCAPPED, unlike
// LoadProjectPrompts' newest-N slice, so a session older than the cap
// reports its real prompt count on the by-session table rather than a
// misleading 0 (F5 of the 2026-09-22 arc review).
func (s *Store) LoadProjectPromptCounts(ctx context.Context, projectID int64, since, until time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT session_id, COUNT(*)
		  FROM actions
		 WHERE project_id = ? AND action_type = ? AND timestamp >= ? AND timestamp < ?
		 GROUP BY session_id`,
		projectID, models.ActionUserPrompt, timestamp(since), timestamp(until))
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectPromptCounts: %w", err)
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var sid string
		var n int
		if err := rows.Scan(&sid, &n); err != nil {
			return nil, fmt.Errorf("store.LoadProjectPromptCounts: scan: %w", err)
		}
		out[sid] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadProjectPromptCounts: rows: %w", err)
	}
	return out, nil
}
