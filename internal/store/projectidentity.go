package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/freshness"
)

// projectidentity.go is the ONE OWNER of the migration-102 columns
// (CLAUDE.md module-boundary rule #4): projects.{git_upstream_remote,
// git_upstream_remote_hash, git_remote_owner_hash, git_upstream_owner_hash,
// root_commit_sha, root_commit_hash, root_commit_checked_at,
// content_fingerprint, content_fingerprint_hash} and sessions.{workspace,
// workspace_hash, is_worktree}. See internal/db/migrations/
// 102_project_identity_v2.sql for the full privacy rationale (hash-always,
// raw-gated-or-node-local) and
// docs/plans/project-identity-resolver-v2-plan-2026-09-06.md §3.1 for the
// design. Values themselves are produced by internal/git.ResolveIdentity;
// this file only persists and hashes them.

// RootCommitRecheckInterval is the retry fence for the lazy root-commit
// exec: a project whose root commit is still unknown (a huge repo whose
// `git rev-list` timed out, or a machine with no git binary) is retried
// at most this often — never on every process start. See
// RootCommitNeedsCheck.
const RootCommitRecheckInterval = 7 * 24 * time.Hour

// RootCommitResolverFunc runs the root-commit exec for one project root.
// See internal/git.DefaultRootCommit for the production implementation.
// Store.SetRootCommitResolver wires it; the New() default is nil, which
// disables the lazy exec entirely so internal/store's own tests never
// shell out to git.
type RootCommitResolverFunc func(ctx context.Context, repoRoot string) (string, error)

// SetRootCommitResolver wires the lazy root-commit exec Ingest uses to
// populate projects.root_commit_sha (gated by RootCommitNeedsCheck's
// 7-day retry fence, at most once per project root per Ingest batch).
// Idempotent; pass nil to disable it again. Production wiring calls
// SetRootCommitResolver(git.DefaultRootCommit) once when the daemon
// constructs its long-lived Store.
func (s *Store) SetRootCommitResolver(fn RootCommitResolverFunc) { s.rootCommitResolver = fn }

// ProjectIdentity is the additive identity bundle for one projects row
// (Project Identity Resolver v2, W1). Every field is optional — a caller
// (typically store.Ingest, from a ToolEvent/TokenEvent's matching
// fields) passes whatever internal/git.ResolveIdentity produced, honestly
// empty when the adapter has no git info to offer. UpstreamRemote is
// expected pre-normalized (internal/git.ResolveIdentity's job); this
// struct does not re-normalize it.
type ProjectIdentity struct {
	// UpstreamRemote is stored raw in git_upstream_remote (raw wire
	// disclosure gated by ShareOptions.shipsRawContent(), like
	// git_remote); git_upstream_remote_hash = sha256Hex(UpstreamRemote)
	// always.
	UpstreamRemote string
	// RemoteOwner / UpstreamOwner have NO raw column — only their
	// sha256 hash is ever persisted (git_remote_owner_hash /
	// git_upstream_owner_hash).
	RemoteOwner   string
	UpstreamOwner string
	// RootCommitSHA is the RAW pre-image, persisted node-locally in
	// root_commit_sha so the hash can be recomputed without re-running
	// git; only sha256Hex(RootCommitSHA) (root_commit_hash) ever ships.
	RootCommitSHA string
	// ContentFingerprint is likewise a node-local raw pre-image
	// (content_fingerprint); only its hash (content_fingerprint_hash)
	// ever ships.
	ContentFingerprint string
}

// isZero reports whether every field of id is empty — used to skip a
// no-op UPDATE when a caller (e.g. an adapter with no git info at all)
// has nothing to contribute.
func (id ProjectIdentity) isZero() bool {
	return id == ProjectIdentity{}
}

// UpsertProjectWithIdentity is UpsertProject plus the migration-102
// identity columns, using the same backfill-on-touch semantics as
// git_remote: a non-empty new value wins, an empty one never clobbers an
// existing value. remote and every ProjectIdentity field may be empty.
func (s *Store) UpsertProjectWithIdentity(ctx context.Context, rootPath, remote string, id ProjectIdentity) (int64, error) {
	pid, err := s.upsertProjectBase(ctx, rootPath, remote)
	if err != nil {
		return 0, err
	}
	if err := s.upsertProjectIdentity(ctx, pid, id); err != nil {
		return 0, err
	}
	return pid, nil
}

// upsertProjectIdentity writes id's columns onto the projects row
// identified by projectID, hashing each field with the shared sha256Hex
// helper (which itself maps "" -> "" — an empty input never becomes
// sha256("")). COALESCE(NULLIF(?, ”), col) is the same backfill-on-touch
// idiom UpsertProject already uses for git_remote: a non-empty new value
// wins, an empty one preserves whatever is already stored.
func (s *Store) upsertProjectIdentity(ctx context.Context, projectID int64, id ProjectIdentity) error {
	if id.isZero() {
		return nil
	}
	_, err := s.db.ExecContext(
		ctx,
		`UPDATE projects SET
		   git_upstream_remote      = COALESCE(NULLIF(?, ''), git_upstream_remote),
		   git_upstream_remote_hash = COALESCE(NULLIF(?, ''), git_upstream_remote_hash),
		   git_remote_owner_hash    = COALESCE(NULLIF(?, ''), git_remote_owner_hash),
		   git_upstream_owner_hash  = COALESCE(NULLIF(?, ''), git_upstream_owner_hash),
		   root_commit_sha          = COALESCE(NULLIF(?, ''), root_commit_sha),
		   root_commit_hash         = COALESCE(NULLIF(?, ''), root_commit_hash),
		   content_fingerprint      = COALESCE(NULLIF(?, ''), content_fingerprint),
		   content_fingerprint_hash = COALESCE(NULLIF(?, ''), content_fingerprint_hash)
		 WHERE id = ?`,
		id.UpstreamRemote, sha256Hex(id.UpstreamRemote),
		sha256Hex(id.RemoteOwner), sha256Hex(id.UpstreamOwner),
		id.RootCommitSHA, sha256Hex(id.RootCommitSHA),
		id.ContentFingerprint, sha256Hex(id.ContentFingerprint),
		projectID,
	)
	if err != nil {
		return fmt.Errorf("store.upsertProjectIdentity: %w", err)
	}
	return nil
}

// RootCommitNeedsCheck reports whether the lazy root-commit exec should
// run for rootPath's project: true when root_commit_sha is still empty
// AND (root_commit_checked_at is NULL, unparsable, or older than
// RootCommitRecheckInterval). A rootPath with no projects row yet (the
// common case on a session's very first event, before UpsertProject has
// run) reports false — there's nothing to attach a check to; the caller
// re-asks on the next batch once the row exists.
func (s *Store) RootCommitNeedsCheck(ctx context.Context, rootPath string) (bool, error) {
	rootPath = normalizeProjectRoot(rootPath)
	var sha sql.NullString
	var checkedAt sql.NullString
	err := s.db.QueryRowContext(
		ctx,
		`SELECT root_commit_sha, root_commit_checked_at FROM projects WHERE root_path = ?`,
		rootPath,
	).Scan(&sha, &checkedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store.RootCommitNeedsCheck: %w", err)
	}
	if sha.Valid && sha.String != "" {
		return false, nil
	}
	if !checkedAt.Valid || checkedAt.String == "" {
		return true, nil
	}
	last, perr := time.Parse(time.RFC3339Nano, checkedAt.String)
	if perr != nil {
		// Unparsable timestamp: fail open toward rechecking rather than
		// getting permanently stuck never retrying.
		return true, nil
	}
	return time.Since(last) >= RootCommitRecheckInterval, nil
}

// maybeRunLazyRootCommit runs the wired root-commit resolver for rootPath
// at most once per Ingest batch's first touch of that project, and only
// when RootCommitNeedsCheck's 7-day fence says it's due. Both the
// resolver call and RootCommitNeedsCheck's own error are swallowed
// (fail-open): a git failure, or a store read error on this
// supplementary check, must never fail the surrounding Ingest batch that
// is the whole reason the project row exists in the first place.
func (s *Store) maybeRunLazyRootCommit(ctx context.Context, rootPath string) {
	if s.rootCommitResolver == nil {
		return
	}
	needs, err := s.RootCommitNeedsCheck(ctx, rootPath)
	if err != nil || !needs {
		return
	}
	sha, _ := s.rootCommitResolver(ctx, normalizeProjectRoot(rootPath))
	_ = s.RecordRootCommitCheck(ctx, rootPath, sha)
}

// RecordRootCommitCheck stamps root_commit_checked_at to now and, when
// sha is non-empty, writes root_commit_sha/root_commit_hash
// (backfill-on-touch — an empty sha never clobbers a previously stored
// one). Called after every lazy root-commit exec attempt, including a
// failed one (empty sha), which is the entire point of the 7-day retry
// fence: a huge repo that times out is retried at most weekly, not on
// every process start.
func (s *Store) RecordRootCommitCheck(ctx context.Context, rootPath, sha string) error {
	rootPath = normalizeProjectRoot(rootPath)
	_, err := s.db.ExecContext(
		ctx,
		`UPDATE projects SET
		   root_commit_sha        = COALESCE(NULLIF(?, ''), root_commit_sha),
		   root_commit_hash       = COALESCE(NULLIF(?, ''), root_commit_hash),
		   root_commit_checked_at = ?
		 WHERE root_path = ?`,
		sha, sha256Hex(sha), timestamp(time.Now()), rootPath,
	)
	if err != nil {
		return fmt.Errorf("store.RecordRootCommitCheck: %w", err)
	}
	return nil
}

// ProjectRootRow is one projects row and how many sessions it holds.
type ProjectRootRow struct {
	ID       int64
	RootPath string
	Name     string
	Sessions int64
}

// ListProjectRoots returns every projects row with its session count, in
// id order (the `observer backfill --worktree-roots` candidate scan).
func (s *Store) ListProjectRoots(ctx context.Context) ([]ProjectRootRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT p.id, p.root_path, COALESCE(p.name, ''),
		        (SELECT COUNT(*) FROM sessions s WHERE s.project_id = p.id)
		   FROM projects p ORDER BY p.id`)
	if err != nil {
		return nil, fmt.Errorf("store.ListProjectRoots: %w", err)
	}
	defer rows.Close()
	var out []ProjectRootRow
	for rows.Next() {
		var r ProjectRootRow
		if err := rows.Scan(&r.ID, &r.RootPath, &r.Name, &r.Sessions); err != nil {
			return nil, fmt.Errorf("store.ListProjectRoots: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListProjectRoots: %w", err)
	}
	return out, nil
}

// ProjectMove counts what MoveProjectRows moved (or PlanProjectMove would
// move). Sessions, Actions and APITurns repeat their Tables rows.
type ProjectMove struct {
	Sessions int64 `json:"sessions"`
	Actions  int64 `json:"actions"`
	APITurns int64 `json:"api_turns"`
	// Tables is every project-keyed table the move covers, in move order
	// (lane shr-worktree2, PT-39).
	Tables []TableMove `json:"tables"`
}

// TableMove is what a move did (or would do) to one table.
type TableMove struct {
	Table string `json:"table"`
	// Moved is how many rows end on the target project.
	Moved int64 `json:"moved"`
	// KeptOnOld is how many rows stay on the old project: for a table
	// with a project-scoped unique key, the older row of each clashing
	// pair (the newer one always ends on the target).
	KeptOnOld int64 `json:"kept_on_old,omitempty"`
	// Swapped is how many clashes the old project's row won: it moved,
	// and the target's older row went to the old project.
	Swapped int64 `json:"swapped,omitempty"`
}

// projectRowMover moves one table's rows of project fromID onto toID
// inside tx; toID 0 only counts what would move. Each row of
// projectRowMovers calls the seam of the package that owns the table.
type projectRowMover struct {
	table string
	move  ProjectTableMoveFunc
}

// ProjectTableMoveFunc moves one table's rows of project fromID onto toID
// inside tx (toID 0: count only). A caller passes one to MoveProjectRows
// for a table whose owning package this one cannot import.
type ProjectTableMoveFunc func(ctx context.Context, tx *sql.Tx, fromID, toID int64) (TableMove, error)

// ProjectTableMover names a caller-supplied mover's table.
type ProjectTableMover struct {
	Table string
	Move  ProjectTableMoveFunc
}

// plainProjectMover moves every row of a table with no project-scoped
// unique key; countQ and moveQ are the table's two fixed statements.
func plainProjectMover(table, countQ, moveQ string) projectRowMover {
	return projectRowMover{table: table, move: func(ctx context.Context, tx *sql.Tx, fromID, toID int64) (TableMove, error) {
		m := TableMove{Table: table}
		if toID == 0 {
			if err := tx.QueryRowContext(ctx, countQ, fromID).Scan(&m.Moved); err != nil {
				return m, fmt.Errorf("%s: count: %w", table, err)
			}
			return m, nil
		}
		res, err := tx.ExecContext(ctx, moveQ, toID, fromID)
		if err != nil {
			return m, fmt.Errorf("%s: %w", table, err)
		}
		m.Moved, _ = res.RowsAffected()
		return m, nil
	}}
}

// projectRowMovers is every project-keyed table the worktree-roots
// backfill moves, in move order. sessions, actions, api_turns,
// failure_context, process_runs and process_events are this package's;
// file_changes is loc.go's, project_commits commits.go's (its files follow
// by commit id) and file_state internal/freshness's. compaction_events is
// moved by the mover its owner internal/intelligence/compaction gives the
// caller (that package's tests import this one). A process run takes its
// session's project when it is attributed, so a run attributed while its
// session sat on the old row moves with the session (live 2026-11-07: 85K
// runs were left on folded worktree rows). Tables not listed
// (project_patterns, project_commit_scan, the codeintel and guard tables)
// stay on the old row: they are per-root caches or keyed state the next
// scan rebuilds. Rows in the cold archive (archive.db) are not moved.
var projectRowMovers = []projectRowMover{
	plainProjectMover("sessions",
		`SELECT COUNT(*) FROM sessions WHERE project_id = ?`,
		`UPDATE sessions SET project_id = ? WHERE project_id = ?`),
	plainProjectMover("actions",
		`SELECT COUNT(*) FROM actions WHERE project_id = ?`,
		`UPDATE actions SET project_id = ? WHERE project_id = ?`),
	plainProjectMover("api_turns",
		`SELECT COUNT(*) FROM api_turns WHERE project_id = ?`,
		`UPDATE api_turns SET project_id = ? WHERE project_id = ?`),
	plainProjectMover("failure_context",
		`SELECT COUNT(*) FROM failure_context WHERE project_id = ?`,
		`UPDATE failure_context SET project_id = ? WHERE project_id = ?`),
	plainProjectMover("process_runs",
		`SELECT COUNT(*) FROM process_runs WHERE project_id = ?`,
		`UPDATE process_runs SET project_id = ? WHERE project_id = ?`),
	plainProjectMover("process_events",
		`SELECT COUNT(*) FROM process_events WHERE project_id = ?`,
		`UPDATE process_events SET project_id = ? WHERE project_id = ?`),
	{table: "file_state", move: func(ctx context.Context, tx *sql.Tx, fromID, toID int64) (TableMove, error) {
		fm, err := freshness.MoveProjectFileState(ctx, tx, fromID, toID)
		return TableMove{Table: "file_state", Moved: fm.Moved, KeptOnOld: fm.KeptOnOld, Swapped: fm.Swapped}, err
	}},
	{table: "file_changes", move: func(ctx context.Context, tx *sql.Tx, fromID, toID int64) (TableMove, error) {
		n, err := moveFileChangesTx(ctx, tx, fromID, toID)
		return TableMove{Table: "file_changes", Moved: n}, err
	}},
	{table: "project_commits", move: moveProjectCommitsTx},
}

// worktreeRootMovedPrefix begins the name WorktreeRootMovedMark gives a
// folded row; FoldedProjectSQL matches on it.
const worktreeRootMovedPrefix = "worktree root moved to project "

// WorktreeRootMovedMark is the name the worktree-roots backfill gives an
// old projects row once its rows moved onto project toID (the mark
// MoveProjectRows writes).
func WorktreeRootMovedMark(toID int64) string {
	return fmt.Sprintf("%s%d (observer backfill --worktree-roots)", worktreeRootMovedPrefix, toID)
}

// IsWorktreeRootMovedMark reports whether name is a WorktreeRootMovedMark:
// the row was already folded into another project.
func IsWorktreeRootMovedMark(name string) bool {
	return strings.HasPrefix(name, worktreeRootMovedPrefix)
}

// FoldedProjectSQL is an SQL predicate over the projects row aliased alias
// (a fixed identifier, never user input) that holds for a row the
// worktree-roots backfill folded into another project and that no session
// or action has been filed under since: a row with nothing of its own to
// show. The project list and the project count leave such rows out, so a
// folded worktree does not reappear as an empty project. It is never NULL
// (most rows have no name), so NOT (...) of it is safe in a WHERE.
func FoldedProjectSQL(alias string) string {
	return "COALESCE(" + alias + ".name, '') LIKE '" + worktreeRootMovedPrefix + "%'" +
		" AND NOT EXISTS (SELECT 1 FROM sessions fold_s WHERE fold_s.project_id = " + alias + ".id)" +
		" AND NOT EXISTS (SELECT 1 FROM actions fold_a WHERE fold_a.project_id = " + alias + ".id)"
}

// MoveProjectRows moves every row of project fromID in the tables of
// projectRowMovers, then of each extra mover, onto project toID in one
// transaction and sets the old
// row's name to mark, so it reads as moved. The old projects row is kept,
// never deleted, and so is every row a unique-key clash leaves on it. The
// sessions trigger of agent migration 140 queues each moved session (and
// its token rows) for the org push's re-send lane.
func (s *Store) MoveProjectRows(ctx context.Context, fromID, toID int64, mark string, extra ...ProjectTableMover) (ProjectMove, error) {
	if toID == 0 {
		return ProjectMove{}, fmt.Errorf("store.MoveProjectRows: no target project")
	}
	return s.moveProjectRows(ctx, fromID, toID, mark, true, extra)
}

// PlanProjectMove reports what MoveProjectRows would move and changes
// nothing: with toID 0 (a target row that does not exist yet) it counts
// fromID's rows; otherwise it runs the move in a transaction it rolls back,
// so the counts, clashes included, are exactly the apply's.
func (s *Store) PlanProjectMove(ctx context.Context, fromID, toID int64, extra ...ProjectTableMover) (ProjectMove, error) {
	return s.moveProjectRows(ctx, fromID, toID, "", false, extra)
}

func (s *Store) moveProjectRows(ctx context.Context, fromID, toID int64, mark string, apply bool, extra []ProjectTableMover) (ProjectMove, error) {
	var m ProjectMove
	if fromID == toID {
		return m, fmt.Errorf("store.MoveProjectRows: source and target are the same project %d", fromID)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return m, fmt.Errorf("store.MoveProjectRows: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	movers := append([]projectRowMover(nil), projectRowMovers...)
	for _, e := range extra {
		movers = append(movers, projectRowMover{table: e.Table, move: e.Move})
	}
	for _, mv := range movers {
		tm, err := mv.move(ctx, tx, fromID, toID)
		if err != nil {
			return ProjectMove{}, fmt.Errorf("store.MoveProjectRows: %w", err)
		}
		tm.Table = mv.table
		m.Tables = append(m.Tables, tm)
		switch tm.Table {
		case "sessions":
			m.Sessions = tm.Moved
		case "actions":
			m.Actions = tm.Moved
		case "api_turns":
			m.APITurns = tm.Moved
		}
	}
	if !apply {
		return m, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE projects SET name = ? WHERE id = ?`, mark, fromID); err != nil {
		return ProjectMove{}, fmt.Errorf("store.MoveProjectRows: mark: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ProjectMove{}, fmt.Errorf("store.MoveProjectRows: %w", err)
	}
	return m, nil
}
