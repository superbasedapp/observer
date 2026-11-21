package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
)

// HandoffSubstrate is everything the store contributes to a session
// handoff (docs/plans/session-handoff-plan-2026-07-03.md §5): session
// metadata plus action-derived facts, all content-free. The transcript
// itself is NOT loaded here — it comes from the source tool's own files
// via the adapter's transcript reader (Phase 0 D-P0.1), and SourceFiles
// only carries path hints for that reader.
type HandoffSubstrate struct {
	Session     models.Session
	ProjectRoot string
	// SourceFiles are the distinct REAL source paths observed for the
	// session (hook-fed sessions carry a `<tool>:hook` sentinel instead,
	// which is filtered out here — readers derive paths in that case).
	SourceFiles []string
	Files       []handoff.FileFact
	Commands    []handoff.CommandFact
	Errors      []handoff.ErrorFact
}

// LoadHandoffSubstrate assembles the handoff facts for one session.
// Returns sql.ErrNoRows when the session doesn't exist.
func (s *Store) LoadHandoffSubstrate(ctx context.Context, sessionID string) (HandoffSubstrate, error) {
	var sub HandoffSubstrate

	var model, branch, started, ended sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT s.id, s.project_id, s.tool, s.model, s.git_branch, s.started_at, s.ended_at,
		        COALESCE(p.root_path, '')
		   FROM sessions s LEFT JOIN projects p ON p.id = s.project_id
		  WHERE s.id = ?`, sessionID).
		Scan(&sub.Session.ID, &sub.Session.ProjectID, &sub.Session.Tool, &model, &branch, &started, &ended, &sub.ProjectRoot)
	if err != nil {
		return sub, err
	}
	sub.Session.Model = model.String
	sub.Session.GitBranch = branch.String
	sub.Session.StartedAt = parseStamp(started.String)
	sub.Session.EndedAt = parseStamp(ended.String)

	// Model fallback: dominant token_usage.model (sessions.model is empty
	// for most claude-code sessions — same fallback LoadSessionShape uses).
	if sub.Session.Model == "" {
		var fb sql.NullString
		if err := s.db.QueryRowContext(ctx,
			`SELECT model FROM token_usage WHERE session_id = ? AND model != ''
			  GROUP BY model ORDER BY SUM(input_tokens + output_tokens) DESC LIMIT 1`,
			sessionID).Scan(&fb); err == nil {
			sub.Session.Model = fb.String
		}
	}

	if err := s.loadHandoffSourceFiles(ctx, sessionID, &sub); err != nil {
		return sub, err
	}
	if err := s.loadHandoffFiles(ctx, sessionID, &sub); err != nil {
		return sub, err
	}
	if err := s.loadHandoffCommands(ctx, sessionID, &sub); err != nil {
		return sub, err
	}
	if err := s.loadHandoffErrors(ctx, sessionID, &sub); err != nil {
		return sub, err
	}
	return sub, nil
}

func (s *Store) loadHandoffSourceFiles(ctx context.Context, sessionID string, sub *HandoffSubstrate) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT source_file FROM token_usage
		  WHERE session_id = ? AND source_file != ''
		 UNION
		 SELECT DISTINCT source_file FROM actions
		  WHERE session_id = ? AND source_file != ''`,
		sessionID, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadHandoffSubstrate: source files: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return err
		}
		// Only real transcript paths: a local absolute path on this OS. This
		// is pathnorm.IsLocalAbsPath rather than a SQL `LIKE '/%'`, which
		// also dropped every C:\ path on a Windows daemon; it is the one
		// stored-path open gate (ledger CLOUDSESS-12), so a UNC, device or
		// extended-length path never reaches a reader that opens it
		// (handoffsvc, the MCP get_session_message tool). A `<tool>:hook`
		// sentinel is not absolute on any OS, so it stays filtered (D-P0.1).
		if !pathnorm.IsLocalAbsPath(f) {
			continue
		}
		sub.SourceFiles = append(sub.SourceFiles, f)
	}
	return rows.Err()
}

func (s *Store) loadHandoffFiles(ctx context.Context, sessionID string, sub *HandoffSubstrate) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT target,
		        SUM(CASE WHEN action_type IN (?, ?) THEN 1 ELSE 0 END),
		        SUM(CASE WHEN action_type = ? THEN 1 ELSE 0 END),
		        MAX(timestamp)
		   FROM actions
		  WHERE session_id = ? AND action_type IN (?, ?, ?) AND target != ''
		  GROUP BY target
		  ORDER BY 2 DESC, 3 DESC
		  LIMIT 40`,
		models.ActionEditFile, models.ActionWriteFile, models.ActionReadFile,
		sessionID, models.ActionReadFile, models.ActionEditFile, models.ActionWriteFile)
	if err != nil {
		return fmt.Errorf("store.LoadHandoffSubstrate: files: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var f handoff.FileFact
		var last string
		if err := rows.Scan(&f.Path, &f.Edits, &f.Reads, &last); err != nil {
			return err
		}
		f.LastAt = parseStamp(last)
		sub.Files = append(sub.Files, f)
	}
	return rows.Err()
}

func (s *Store) loadHandoffCommands(ctx context.Context, sessionID string, sub *HandoffSubstrate) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT target, COUNT(*), MAX(timestamp),
		        (SELECT a2.success FROM actions a2
		          WHERE a2.session_id = a.session_id AND a2.target = a.target
		            AND a2.action_type = a.action_type
		          ORDER BY a2.timestamp DESC LIMIT 1),
		        COALESCE((SELECT a3.error_message FROM actions a3
		          WHERE a3.session_id = a.session_id AND a3.target = a.target
		            AND a3.action_type = a.action_type
		          ORDER BY a3.timestamp DESC LIMIT 1), '')
		   FROM actions a
		  WHERE session_id = ? AND action_type = ? AND target != ''
		  GROUP BY target
		  ORDER BY MAX(timestamp) DESC
		  LIMIT 40`,
		sessionID, models.ActionRunCommand)
	if err != nil {
		return fmt.Errorf("store.LoadHandoffSubstrate: commands: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c handoff.CommandFact
		var last string
		var ok sql.NullBool
		if err := rows.Scan(&c.Command, &c.Runs, &last, &ok, &c.LastError); err != nil {
			return err
		}
		c.LastAt = parseStamp(last)
		c.LastOK = !ok.Valid || ok.Bool
		if c.LastOK {
			c.LastError = ""
		}
		sub.Commands = append(sub.Commands, c)
	}
	return rows.Err()
}

func (s *Store) loadHandoffErrors(ctx context.Context, sessionID string, sub *HandoffSubstrate) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.target, COALESCE(a.error_message, ''), MAX(a.timestamp)
		   FROM actions a
		  WHERE a.session_id = ? AND a.success = 0 AND a.target != ''
		    AND NOT EXISTS (SELECT 1 FROM actions b
		                     WHERE b.session_id = a.session_id AND b.target = a.target
		                       AND b.success = 1 AND b.timestamp > a.timestamp)
		  GROUP BY a.target
		  ORDER BY 3 DESC
		  LIMIT 10`, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadHandoffSubstrate: errors: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e handoff.ErrorFact
		var at string
		if err := rows.Scan(&e.Target, &e.Message, &at); err != nil {
			return err
		}
		e.At = parseStamp(at)
		if strings.TrimSpace(e.Message) == "" {
			e.Message = "(no error message captured)"
		}
		sub.Errors = append(sub.Errors, e)
	}
	return rows.Err()
}

// HandoffRecord mirrors one handoffs row (migration 055, NODE-LOCAL).
// Counts, enums, hashes, and paths only — never the rendered doc.
type HandoffRecord struct {
	ID               int64
	SourceSessionID  string
	SourceTool       string
	TargetTool       string
	CarryMode        string
	ForkKind         string
	ForkMessageIndex int
	ForkMessageTime  time.Time
	ForkAnchorHash   string
	RequestedIndex   int
	DocTokenEstimate int64
	EstimateJSON     string
	Delivery         string
	DeliveryRef      string
	TargetSessionID  string
	CreatedAt        time.Time
	// ShortID is the handoff's random opaque short-id (the token the
	// rendered doc carries into the target session as
	// `<!-- superbased-handoff <shortid> -->`). Stored since migration 057
	// so the linker no longer has to recover it from delivery_ref's
	// HANDOFF-<shortid>.md basename — a custom --out handoff is now linkable.
	// A random token, not content (same privacy class as a hash).
	ShortID string
	// ProjectRoot is the source session's project root (a path, not
	// content) — the inject_hook claim matches on it so an armed handoff
	// fires only for the same project. Migration 056.
	ProjectRoot string
	// HookExpiresAt arms an inject_hook delivery: the row is deliverable
	// until this time, then expires. Zero for non-hook rows. Migration 056.
	HookExpiresAt time.Time
}

// InsertHandoff records one delivered handoff.
func (s *Store) InsertHandoff(ctx context.Context, r HandoffRecord) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO handoffs
		   (source_session_id, source_tool, target_tool, carry_mode, fork_kind,
		    fork_message_index, fork_message_time, fork_anchor_hash, requested_index,
		    doc_token_estimate, estimate_json, delivery, delivery_ref, target_session_id,
		    project_root, hook_expires_at, short_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.SourceSessionID, r.SourceTool, r.TargetTool, r.CarryMode, r.ForkKind,
		nullableInt(r.ForkMessageIndex), nullableStamp(r.ForkMessageTime), r.ForkAnchorHash,
		nullableInt(r.RequestedIndex), r.DocTokenEstimate, r.EstimateJSON,
		r.Delivery, r.DeliveryRef, r.TargetSessionID,
		nullableString(r.ProjectRoot), nullableStamp(r.HookExpiresAt),
		nullableString(r.ShortID), timestamp(time.Now()))
	if err != nil {
		return 0, fmt.Errorf("store.InsertHandoff: %w", err)
	}
	return res.LastInsertId()
}

// ListHandoffs returns the most recent handoffs, newest first.
func (s *Store) ListHandoffs(ctx context.Context, limit int) ([]HandoffRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, source_session_id, source_tool, target_tool, carry_mode, fork_kind,
		        COALESCE(fork_message_index, 0), COALESCE(fork_message_time, ''),
		        COALESCE(fork_anchor_hash, ''), COALESCE(requested_index, 0),
		        COALESCE(doc_token_estimate, 0), COALESCE(estimate_json, ''),
		        delivery, COALESCE(delivery_ref, ''), COALESCE(target_session_id, ''),
		        COALESCE(short_id, ''), created_at
		   FROM handoffs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListHandoffs: %w", err)
	}
	defer rows.Close()
	var out []HandoffRecord
	for rows.Next() {
		var r HandoffRecord
		var ft, created string
		if err := rows.Scan(&r.ID, &r.SourceSessionID, &r.SourceTool, &r.TargetTool, &r.CarryMode,
			&r.ForkKind, &r.ForkMessageIndex, &ft, &r.ForkAnchorHash, &r.RequestedIndex,
			&r.DocTokenEstimate, &r.EstimateJSON, &r.Delivery, &r.DeliveryRef, &r.TargetSessionID,
			&r.ShortID, &created); err != nil {
			return nil, err
		}
		r.ForkMessageTime = parseStamp(ft)
		r.CreatedAt = parseStamp(created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LinkTargetSession stamps a handoff's target_session_id — the
// best-effort P3 linker's write seam (plan §10 post-injection
// accounting). The UPDATE is GUARDED so a link is written at most once:
// once a row carries a non-empty target_session_id it is never
// overwritten (a later sweep that finds a different candidate leaves the
// first, earliest link intact). A no-op when the row is already linked or
// does not exist — best-effort, never an error for those cases.
func (s *Store) LinkTargetSession(ctx context.Context, handoffID int64, targetSessionID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE handoffs
		    SET target_session_id = ?
		  WHERE id = ?
		    AND (target_session_id IS NULL OR target_session_id = '')`,
		targetSessionID, handoffID)
	if err != nil {
		return fmt.Errorf("store.LinkTargetSession: %w", err)
	}
	return nil
}

// ListUnlinkedHandoffs returns delivered (non-dry-run) handoffs created
// within the window that still have no target_session_id — the work list
// for the best-effort linker. Rows are ordered newest-first. project_root
// falls back to the SOURCE session's project root for pre-migration-056
// rows whose own project_root column is NULL (so the candidate query can
// still scope by project). Only the columns the linker needs are selected
// (id, source/target tool, the stored short_id + delivery_ref for the
// short-id fallback, project_root, created_at); the rest of HandoffRecord
// is left zero. short_id is COALESCE'd to ” so pre-057 rows (which never
// stored it) fall back to the delivery_ref basename in the linker.
func (s *Store) ListUnlinkedHandoffs(ctx context.Context, since time.Time) ([]HandoffRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT h.id, h.source_session_id, h.source_tool, h.target_tool,
		        h.carry_mode, h.delivery, COALESCE(h.delivery_ref, ''),
		        COALESCE(h.short_id, ''),
		        COALESCE(NULLIF(h.project_root, ''),
		                 (SELECT COALESCE(p.root_path, '')
		                    FROM sessions s JOIN projects p ON p.id = s.project_id
		                   WHERE s.id = h.source_session_id)),
		        h.created_at
		   FROM handoffs h
		  WHERE (h.target_session_id IS NULL OR h.target_session_id = '')
		    AND h.delivery != 'dry_run'
		    AND datetime(h.created_at) >= datetime(?)
		  ORDER BY h.id DESC`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.ListUnlinkedHandoffs: %w", err)
	}
	defer rows.Close()
	var out []HandoffRecord
	for rows.Next() {
		var r HandoffRecord
		var projectRoot sql.NullString
		var created string
		if err := rows.Scan(&r.ID, &r.SourceSessionID, &r.SourceTool, &r.TargetTool,
			&r.CarryMode, &r.Delivery, &r.DeliveryRef, &r.ShortID, &projectRoot, &created); err != nil {
			return nil, err
		}
		r.ProjectRoot = projectRoot.String
		r.CreatedAt = parseStamp(created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// CandidateSession is one possible target session for the linker: enough
// metadata for the shared transcript-reader dispatch (id + tool) to
// re-read its content from the source tool's own files. Hints carries the
// distinct source_file paths recorded for the session so the reader opens
// the EXACT store it was captured from — load-bearing for foreign-mount
// installs where several stores of the same tool coexist (mirrors the
// doctor probe's recentSessionsToProbe hint routing).
type CandidateSession struct {
	SessionID string
	Tool      string
	Hints     []string
}

// CandidateTargetSessions lists sessions of tool that could be the target
// of a handoff: same project root (when known), started at or after the
// handoff's creation time, oldest-first (the first session to appear after
// a handoff is the most likely target), capped at limit. When projectRoot
// is empty the project filter is dropped (any project). datetime() bridges
// the RFC3339 / RFC3339Nano / SQLite-default stamp formats the corpus
// mixes.
func (s *Store) CandidateTargetSessions(ctx context.Context, tool, projectRoot string, after time.Time, limit int) ([]CandidateSession, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT s.id, s.tool
		   FROM sessions s
		   LEFT JOIN projects p ON p.id = s.project_id
		  WHERE s.tool = ?
		    AND (? = '' OR COALESCE(p.root_path, '') = ?)
		    AND datetime(s.started_at) >= datetime(?)
		  ORDER BY s.started_at ASC, s.id ASC
		  LIMIT ?`,
		tool, projectRoot, projectRoot, timestamp(after), limit)
	if err != nil {
		return nil, fmt.Errorf("store.CandidateTargetSessions: %w", err)
	}
	defer rows.Close()
	var out []CandidateSession
	for rows.Next() {
		var c CandidateSession
		if err := rows.Scan(&c.SessionID, &c.Tool); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Attach each candidate's recorded source_file hints so the linker's
	// reader opens the exact store the session was captured from (foreign-
	// mount installs coexist multiple stores of one tool). Same shape as
	// the doctor probe's recentSessionsToProbe → sessionSourceHints.
	for i := range out {
		out[i].Hints = s.candidateSourceHints(ctx, out[i].SessionID)
	}
	return out, nil
}

// candidateSourceHints returns the distinct non-empty source_file paths
// recorded in actions for a session — ReadTranscript hints. A query error
// yields no hints (the reader then falls back to its default roots); the
// linker must never fail on a missing hint. Query shape kept consistent
// with the doctor probe's sessionSourceHints (internal/diag/handoff.go).
func (s *Store) candidateSourceHints(ctx context.Context, sessionID string) []string {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT source_file FROM actions
		  WHERE session_id = ? AND source_file IS NOT NULL AND source_file <> ''`,
		sessionID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var hints []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return hints
		}
		hints = append(hints, s)
	}
	return hints
}

// LatestSessionID resolves the most recently started session, optionally
// filtered by tool name and/or project root — the MCP continue_session
// tool's "latest" addressing. sql.ErrNoRows (wrapped) when nothing matches.
func (s *Store) LatestSessionID(ctx context.Context, tool, projectRoot string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT s.id FROM sessions s
		   LEFT JOIN projects p ON p.id = s.project_id
		  WHERE (? = '' OR s.tool = ?)
		    AND (? = '' OR p.root_path = ?)
		  ORDER BY s.started_at DESC, s.id DESC LIMIT 1`,
		tool, tool, projectRoot, projectRoot).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("store.LatestSessionID: %w", err)
	}
	return id, nil
}

// ClaimArmedHandoffHook atomically claims the most recent live, undelivered
// inject_hook handoff armed for targetTool in projectRoot, marking it
// delivered (one-shot) and returning the written HANDOFF-*.md path so the
// SessionStart hook can read the doc from disk. ok=false with a nil error
// means nothing was armed (the overwhelmingly common case).
//
// One owner, race-safe: the delivery timestamp is set inside a single
// guarded UPDATE ... RETURNING, so two concurrent SessionStarts can never
// both claim the same row — exactly one sees the row, the other sees no
// undelivered match. Expired rows (hook_expires_at < now) and already
// delivered rows are excluded, so a stale armed handoff never fires days
// later. The delivery enum matched here is string(integration.InjectHook)
// ("hook") — kept as a literal to avoid importing integration into store.
func (s *Store) ClaimArmedHandoffHook(ctx context.Context, targetTool, projectRoot string, now time.Time) (docPath string, ok bool, err error) {
	nowStr := timestamp(now)
	var ref sql.NullString
	scanErr := s.db.QueryRowContext(ctx,
		`UPDATE handoffs
		    SET hook_delivered_at = ?
		  WHERE id = (
		        SELECT id FROM handoffs
		         WHERE target_tool = ?
		           AND delivery = 'hook'
		           AND hook_delivered_at IS NULL
		           AND hook_expires_at IS NOT NULL
		           AND hook_expires_at >= ?
		           AND (project_root = ? OR ? = '')
		         ORDER BY created_at DESC, id DESC
		         LIMIT 1)
		 RETURNING delivery_ref`,
		nowStr, targetTool, nowStr, projectRoot, projectRoot).Scan(&ref)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return "", false, nil
	}
	if scanErr != nil {
		return "", false, fmt.Errorf("store.ClaimArmedHandoffHook: %w", scanErr)
	}
	return ref.String, ref.Valid && ref.String != "", nil
}

// PruneHandoffRows deletes handoffs rows whose created_at is older than
// retentionDays days ago — the [handoff].retention_days sweep
// (plan §15 P4). Same orchestration contract as PruneCacheRows /
// PruneGuardRows / PruneProcessRows: retentionDays <= 0 is a clean no-op
// (keep-forever), and the store is the one owner of the table. The
// handoffs row is tiny content-free metadata (hashes/enums/paths), so
// there is no chain-checkpoint or child-table concern — a straight
// DELETE. datetime() bridges the RFC3339 / RFC3339Nano stamp formats the
// corpus mixes. Idempotent: a second run within the same horizon removes
// nothing.
func (s *Store) PruneHandoffRows(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM handoffs WHERE datetime(created_at) < datetime(?)`,
		timestamp(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store.PruneHandoffRows: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func nullableStamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}
