package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/failure"
	"github.com/marmutapp/superbased-observer/internal/freshness"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/identity"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
)

// Store is the storage layer over an initialized SQLite database. All methods
// are safe for concurrent use.
//
// indexer, when non-nil, lets UpdateActionOutcome push the after-event's
// tool_output body into the FTS5 action_excerpts table. Wire it via
// WithIndexer from the caller that has an indexing.Indexer in scope
// (e.g. cmd/observer/hook.go::handleCursorHook). The Ingest path still
// prefers IngestOptions.Indexer over this fallback so the daemon's
// watcher-attached indexer keeps full control of its batch path.
type Store struct {
	db          *sql.DB
	indexer     *indexing.Indexer
	stamper     *identity.Stamper
	cacheEngine *cachetrack.Engine
	guard       *guard.Guard
	// pushPricer is the push-time token_usage pricer (orgpush_pricing.go,
	// G1-COST(b)). nil = ship the adapter-stored cost untouched.
	pushPricer OrgPushPricer
	// tasksEnabled gates the taskflow ingest seam (internal/store/taskflow.go,
	// [tasks].enabled). Set via SetTasksEnabled at daemon composition; the
	// zero value (false) is the pre-feature baseline — a Store built by a
	// struct literal decodes nothing.
	tasksEnabled bool
	// tasksMatchMode / tasksConcurrentAttribution / tasksIncludeSidechains
	// mirror [tasks].match_mode / .concurrent_attribution /
	// .include_sidechains (FIX-4). Set via SetTasksOptions at daemon
	// composition alongside SetTasksEnabled; the zero values ("", "",
	// false) are each their documented default (exact / shared /
	// false), so a Store built by a struct literal behaves identically
	// to a fully-defaulted [tasks] section.
	tasksMatchMode             string
	tasksConcurrentAttribution string
	tasksIncludeSidechains     bool
	obsOrg                     ObsOrgProviders
	advisorOrg                 AdvisorOrgProvider
	// snap is the org-push snapshot change-detection gate (Track R2 —
	// internal/store/orgsnapgate.go). In-memory and per-daemon; a nil gate
	// degrades to "recompute every family every tick", which is the
	// pre-R2 behaviour, so a Store built by a struct literal still works.
	snap *snapGate
	// contentCapture is the enterprise adapter-side message-content
	// producer's posture (internal/store/messagecontent.go). Its zero value
	// (nil ShipsRawContent) disables the producer, so a Store built by a
	// struct literal — and every non-enterprise node — writes no
	// otel_content rows and behaves exactly as before the producer existed.
	contentCapture ContentCapture
	// rootCommitResolver is the lazy root-commit exec used by Ingest
	// (Project Identity Resolver v2, W1 — internal/store/projectidentity.go).
	// nil (the New() default) disables it entirely, so internal/store's
	// own test suite never shells out to git. See SetRootCommitResolver.
	rootCommitResolver RootCommitResolverFunc
	// budgetPosture is the org BUDGET posture provider seam
	// (internal/store/budgetposture.go, wave W3b). nil (the New() default)
	// means "no posture reported", which is byte-identical to a build without
	// the budget rail. See SetBudgetPostureProvider.
	budgetPosture BudgetPostureProvider
}

// SetObsOrgProviders wires the org-tier observability provider seam
// (obs-org-tier plan §2). obs OWNS the obs_* reads (they live in
// internal/obs/store and return plain orgcontract rows); the host binds these
// funcs at the single obs wiring point (cmd/observer/obs_wire.go) so
// internal/store never imports internal/obs. orgpush.go composes the opt-in
// tiers via these funcs (composeObsTiers) and thus names no obs_* table — the
// privacy sentinel stays green. A zero value (no_obs build, or obs disabled)
// leaves every provider nil → every tier no-ops. Idempotent.
func (s *Store) SetObsOrgProviders(p ObsOrgProviders) { s.obsOrg = p }

// New wraps an already-opened *sql.DB (use internal/db.Open).
func New(db *sql.DB) *Store { return &Store{db: db, snap: newSnapGate()} }

// SetCacheEngine wires the same per-process cachetrack.Engine
// instance the proxy uses through to the watcher-side Ingest
// path, so Tier-2 (transcript) observations advance the SAME
// CacheModel state Tier-1 (proxy) advances. The cross-tier
// dedup gate (CacheEventExistsForMessage) prevents a proxy-
// observed message from getting re-observed by the watcher —
// the engine state stays consistent regardless of which side
// saw the turn first.
//
// Idempotent. Passing nil disables Tier-2 emission on the
// ingest path (the watcher then becomes a pure no-op for
// cache_*, which is the pre-wire baseline). Set on the proxy's
// store by cmd/observer/proxy.go::buildProxy after constructing
// the engine, and on the watcher's store by `observer start` via
// Watcher.SetCacheEngine(p.CacheEngine()) — the SAME engine
// instance feeds both Tier-1 (proxy) and Tier-2 (watcher).
func (s *Store) SetCacheEngine(e *cachetrack.Engine) {
	s.cacheEngine = e
}

// SetGuard wires the per-process guard composition layer into the
// watcher-side Ingest path (guard spec §3.2 seam 3): each ingested
// batch's ACTUALLY-INSERTED actions are evaluated post-hoc and
// record-worthy verdicts persist as guard_events linked to the
// action rows. Same wiring pattern as SetCacheEngine: idempotent,
// set once at daemon composition (cmd/observer/main.go::
// buildWatcherWithOverride); nil disables the seam (the pre-guard
// baseline — backfill/scan paths deliberately leave it unset so
// historical replays don't generate audit noise; `observer guard
// rescan` is the deliberate retroactive sweep, G8).
func (s *Store) SetGuard(g *guard.Guard) {
	s.guard = g
}

// ProjectRoots returns every observed project's root path — the
// cross-project-bleed rule R-151's reference set, snapshot at daemon
// composition into guard.Options.KnownProjectRoots.
func (s *Store) ProjectRoots(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT root_path FROM projects ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store.ProjectRoots: query: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var rp string
		if err := rows.Scan(&rp); err != nil {
			return nil, fmt.Errorf("store.ProjectRoots: scan: %w", err)
		}
		if rp != "" {
			out = append(out, rp)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ProjectRoots: rows: %w", err)
	}
	return out, nil
}

// WithStamper binds an org-attribution Stamper to this Store so the four
// row-insert paths (UpsertSession, InsertActions, InsertTokenEvents,
// InsertAPITurn) stamp org_id + user_email on each row when the agent is
// enrolled. Chainable, mirroring WithIndexer. A nil stamper (the
// solo-local default) is a no-op: rows are stamped with empty values and
// the org columns persist as NULL, so inserts behave identically to an
// agent that never enrolled.
func (s *Store) WithStamper(stmp *identity.Stamper) *Store {
	s.stamper = stmp
	return s
}

// WithIndexer binds an Indexer to this Store so single-row hook handlers
// (cursor postToolUse / beforeReadFile, future codex equivalents) can
// surface their tool_output bodies into action_excerpts without each
// having to wire an indexer through IngestOptions. Chainable. Pass nil
// to clear. Returns the same Store for `store.New(db).WithIndexer(idx)`
// composition.
func (s *Store) WithIndexer(idx *indexing.Indexer) *Store {
	s.indexer = idx
	return s
}

// normalizeProjectRoot folds paths that point inside a `.git` directory
// back to the working tree root. Pre-fix the live install accumulated a
// project row at `<repo>/.git/worktrees` because some
// session's cwd resolved into the worktree manager directory; that's an
// administrative path, not a project. Returns the input unchanged for
// any other shape.
func normalizeProjectRoot(rootPath string) string {
	const sep = "/.git/"
	if i := strings.Index(rootPath, sep); i > 0 {
		return rootPath[:i]
	}
	if strings.HasSuffix(rootPath, "/.git") {
		return strings.TrimSuffix(rootPath, "/.git")
	}
	return rootPath
}

// UpsertProject inserts or returns the id of the projects row for rootPath.
// remote may be empty. It is a thin wrapper over UpsertProjectWithIdentity
// with a zero ProjectIdentity, kept so the ~dozens of existing call sites
// that only ever had a root path and a remote need no change (CLAUDE.md
// module-boundary rule #6, additive not invasive).
func (s *Store) UpsertProject(ctx context.Context, rootPath, remote string) (int64, error) {
	return s.upsertProjectBase(ctx, rootPath, remote)
}

// upsertProjectBase is UpsertProject's original body, factored out so
// UpsertProjectWithIdentity (internal/store/projectidentity.go) can call it
// once and layer the migration-102 identity columns on top without a
// second INSERT/SELECT round-trip's worth of duplicated SQL.
func (s *Store) upsertProjectBase(ctx context.Context, rootPath, remote string) (int64, error) {
	if rootPath == "" {
		return 0, errors.New("store.UpsertProject: rootPath is required")
	}
	rootPath = normalizeProjectRoot(rootPath)
	now := timestamp(time.Now().UTC())
	rootPathHash := sha256Hex(rootPath)
	var remoteHash string
	if remote != "" {
		remoteHash = sha256Hex(remote)
	}
	// Try insert; on conflict, keep the existing row but update remote if
	// the caller supplied a non-empty value. Path hashes (M1.3 / v1.8.0)
	// are denormalized here so the org-push seam can ship them without
	// recomputing per row.
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO projects (root_path, git_remote, created_at, root_path_hash, git_remote_hash)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(root_path) DO UPDATE SET
		   git_remote      = COALESCE(NULLIF(excluded.git_remote, ''), projects.git_remote),
		   git_remote_hash = COALESCE(NULLIF(excluded.git_remote_hash, ''), projects.git_remote_hash)`,
		rootPath, remote, now, rootPathHash, remoteHash,
	)
	if err != nil {
		return 0, fmt.Errorf("store.UpsertProject: %w", err)
	}
	var id int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT id FROM projects WHERE root_path = ?`, rootPath,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("store.UpsertProject: select id: %w", err)
	}
	return id, nil
}

// UpsertSession inserts a new session row or updates its mutable fields
// (ended_at, total_actions, model). id and started_at are immutable after
// first insert.
func (s *Store) UpsertSession(ctx context.Context, sess models.Session) error {
	if sess.ID == "" || sess.ProjectID == 0 || sess.Tool == "" {
		return errors.New("store.UpsertSession: ID, ProjectID, Tool are required")
	}
	s.stamper.Stamp(sessionOrgRow{&sess})
	// Data-authority stamp (migration 096, CI-P1 Lane B). FD2: the enrolment
	// read and the session UPSERT run in ONE immediate transaction (the DSN's
	// _txlock=immediate makes BeginTx take the write lock at BEGIN), so a
	// concurrent WriteEnrolment cannot commit between the resolver read and the
	// write — closing the "capture lands personal AFTER enrolment" race. The
	// stamp is resolved LIVE per write (fail-closed: an undeterminable resolve
	// binds NULL == UNKNOWN, never personal). See internal/store/dataauthority.go.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertSession: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	authStamp, authVerStamp := s.resolveAuthorityStampFrom(ctx, tx)

	// upsertSessionMidTxHook fires here, between the in-tx enrolment read and
	// the session write, for the FD2 barrier regression test only (nil in
	// production). It proves the read+write are atomic: a concurrent
	// WriteEnrolment launched here cannot commit while this tx holds the
	// write lock.
	if upsertSessionMidTxHook != nil {
		upsertSessionMidTxHook()
	}

	workspaceHash := sha256Hex(sess.Workspace)

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO sessions (id, project_id, tool, model, git_branch, started_at, ended_at, total_actions, metadata, org_id, user_email, authority, authority_classifier_version, workspace, workspace_hash, is_worktree)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   project_id = excluded.project_id,
		   model = COALESCE(NULLIF(excluded.model, ''), sessions.model),
		   ended_at = COALESCE(excluded.ended_at, sessions.ended_at),
		   git_branch = COALESCE(NULLIF(excluded.git_branch, ''), sessions.git_branch),
		   total_actions = MAX(sessions.total_actions, excluded.total_actions),
		   -- Project Identity Resolver v2 (migration 102, W1). workspace/
		   -- workspace_hash follow git_branch's exact backfill-on-touch
		   -- idiom: a non-empty new value wins, an empty one never
		   -- clobbers. is_worktree is a plain bool derived deterministically
		   -- from the session's cwd (stable for the session's lifetime), so
		   -- once true it is never flipped back to false by a later write
		   -- that simply didn't carry the signal.
		   workspace = COALESCE(NULLIF(excluded.workspace, ''), sessions.workspace),
		   workspace_hash = COALESCE(NULLIF(excluded.workspace_hash, ''), sessions.workspace_hash),
		   is_worktree = CASE WHEN excluded.is_worktree = 1 THEN 1 ELSE sessions.is_worktree END,
		   -- Org attribution refreshes forward: a session first inserted
		   -- pre-enrolment upgrades once the agent enrols mid-stream
		   -- (M2). NULLIF keeps a no-op (NULL) stamp from clobbering an
		   -- existing value — so solo-local stays NULL, byte-identical.
		   org_id = COALESCE(NULLIF(excluded.org_id, ''), sessions.org_id),
		   user_email = COALESCE(NULLIF(excluded.user_email, ''), sessions.user_email),
		   -- Data-authority sticky/upgrade rule (dataauthority.Combine)
		   -- applied ATOMICALLY here so two concurrent ingests of the same
		   -- session can never read-modify-write a corrupt stamp.
		   -- excluded.authority is THIS write's at-capture classification:
		   -- 'org' iff currently enrolled, 'personal' iff definitively
		   -- unenrolled, NULL iff the live resolver could not determine
		   -- enrolment. Ordered rule (first match wins):
		   --   1. prior 'org'         -> 'org'  (sticky; even if now
		   --                                     unenrolled or the resolver
		   --                                     errored on this write)
		   --   2. currently enrolled  -> 'org'  (excluded.authority='org';
		   --                                     upgrades a prior personal or
		   --                                     unknown session)
		   --   3. else                -> keep prior. 'personal' is written
		   --                                     ONLY on first capture (the
		   --                                     INSERT above); a later write
		   --                                     while unenrolled leaves
		   --                                     personal as personal and
		   --                                     UNKNOWN (NULL) as UNKNOWN —
		   --                                     unknown never upgrades to
		   --                                     personal.
		   authority = CASE
		     WHEN sessions.authority = 'org' OR excluded.authority = 'org' THEN 'org'
		     ELSE sessions.authority
		   END,
		   -- Combine always carries the CURRENT contract Version. FD5: a
		   -- personal session rewritten while still unenrolled upgrades its
		   -- stored version to the current contract version too (dataauthority
		   -- .Combine returns the current Version for personal-then-unenrolled,
		   -- not the stale one). The ELSE preserves the prior version for the
		   -- undeterminable-resolver case and for a SQL NULL (unknown), which is
		   -- a distinct fail-closed legacy/indeterminate state, not personal.
		   authority_classifier_version = CASE
		     WHEN sessions.authority = 'org' OR excluded.authority = 'org' THEN ?
		     WHEN sessions.authority = 'personal' AND excluded.authority = 'personal' THEN ?
		     ELSE sessions.authority_classifier_version
		   END`,
		// project_id is always overwritten on conflict because the
		// caller's incoming value reflects the latest adapter parse
		// (which may correct an earlier mis-attribution). The
		// wrong-workspace-stub bug surfaced this 2026-05-19: the
		// initial buggy ingest pinned e371fdb1 to project 109
		// (/home/marmutapp/superbased), and even after the
		// adapter fix routed re-ingest through the correct server
		// (workspace=superbased-observer, project 307), the session
		// row's project_id stayed at 109 because the OLD upsert
		// preserved it. The dashboard then showed the session under
		// the wrong project. Always-overwrite is the principled
		// fix — adapters that derive project_root from per-file
		// metadata always have a "current" answer worth preferring.
		// Cross-project session resumes are not a thing observer
		// supports.
		sess.ID,
		sess.ProjectID,
		sess.Tool,
		sess.Model,
		sess.GitBranch,
		timestamp(sess.StartedAt),
		nullableTimestamp(sess.EndedAt),
		sess.TotalActions,
		sess.Metadata,
		nullableString(sess.OrgID),
		nullableString(sess.UserEmail),
		authStamp,    // INSERT: authority (at-capture stamp; nil == UNKNOWN)
		authVerStamp, // INSERT: authority_classifier_version (nil == UNKNOWN)
		sess.Workspace,
		workspaceHash,
		boolToInt(sess.IsWorktree),
		dataauthority.Version, // ON CONFLICT: version carried on an 'org' result
		dataauthority.Version, // ON CONFLICT: version carried on a personal upgrade (FD5)
	)
	if err != nil {
		return fmt.Errorf("store.UpsertSession: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.UpsertSession: %w", err)
	}
	return nil
}

// upsertSessionMidTxHook, when non-nil, is invoked inside UpsertSession's
// transaction after the enrolment read and before the session write. It is a
// test seam for the FD2 atomicity regression test and is nil in production.
var upsertSessionMidTxHook func()

// SetSessionLineage persists codex fork/subagent lineage markers onto
// an existing session row (migration 069). It is the SINGLE owner of
// the forked_from_id / parent_thread_id / thread_source columns —
// UpsertSession never writes them. NODE-LOCAL: these columns must never
// enter the org-push wire (pinned by tests/invariant/privacy_test.go).
//
// COALESCE(NULLIF(?, ”), col) is preserve-on-empty, so a re-parse that
// re-captures only some markers never clobbers a previously stored
// value. A missing session id is a silent no-op (the UPDATE matches
// zero rows) — lineage arrives after the session is upserted in the
// same Ingest batch.
//
// Returns changed=true only when the UPDATE actually altered a stored
// value; a re-run over an already-stamped (or missing) session returns
// false. The backfill uses this to keep its lineage-backfilled count
// honest across re-runs.
func (s *Store) SetSessionLineage(ctx context.Context, lin models.SessionLineage) (bool, error) {
	if lin.SessionID == "" {
		return false, errors.New("store.SetSessionLineage: SessionID is required")
	}
	// The WHERE guard requires at least one supplied (non-empty) marker
	// to differ from what's already stored, so a re-run over an
	// already-stamped session matches zero rows. RowsAffected then
	// honestly reports whether a value actually changed — the backfill
	// counts a lineage-backfilled session only when changed is true.
	res, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions SET
		   forked_from_id = COALESCE(NULLIF(?, ''), forked_from_id),
		   parent_thread_id = COALESCE(NULLIF(?, ''), parent_thread_id),
		   thread_source = COALESCE(NULLIF(?, ''), thread_source)
		 WHERE id = ?
		   AND ( (? != '' AND ? != IFNULL(forked_from_id, ''))
		      OR (? != '' AND ? != IFNULL(parent_thread_id, ''))
		      OR (? != '' AND ? != IFNULL(thread_source, '')) )`,
		lin.ForkedFromID, lin.ParentThreadID, lin.ThreadSource, lin.SessionID,
		lin.ForkedFromID, lin.ForkedFromID,
		lin.ParentThreadID, lin.ParentThreadID,
		lin.ThreadSource, lin.ThreadSource,
	)
	if err != nil {
		return false, fmt.Errorf("store.SetSessionLineage: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// sessionExists reports whether a session row with id is already
// persisted. Used by Ingest to stop a terminal lifecycle marker
// (session_end) from bootstrapping a phantom session that has no other
// record (the empty Windows-CC session case).
func (s *Store) sessionExists(ctx context.Context, id string) (bool, error) {
	var present int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE id = ? LIMIT 1`, id).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store.sessionExists: %w", err)
	}
	return true, nil
}

// SessionHasSourceFileRows reports whether at least one action row
// for sessionID has the given source_file. Used by the cursor watcher
// to decide whether the live hook has already captured this session
// (in which case the watcher's transcript replay would be a pure
// duplicate and is skipped). Indexed on session_id, so the lookup is
// cheap even on a large actions table.
func (s *Store) SessionHasSourceFileRows(ctx context.Context, sessionID, sourceFile string) (bool, error) {
	var present int
	err := s.db.QueryRowContext(
		ctx,
		`SELECT 1 FROM actions WHERE session_id = ? AND source_file = ? LIMIT 1`,
		sessionID, sourceFile,
	).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store.SessionHasSourceFileRows: %w", err)
	}
	return true, nil
}

// LoadActionTargets returns the distinct Target column values already
// persisted for sourceFile, split by ActionType into user_prompt
// targets and assistant targets. Used by the antigravity
// adapter's plaintext-transcript augmentation path to dedup
// synthesized entries against rows from prior parse cycles — see
// antigravity.TargetCoverageReader for the bug it closes.
//
// The assistant bucket matches BOTH 'assistant_message' and
// 'task_complete'. The WP-T6/B2 sweep re-typed the assistant-text emit
// sites to assistant_message while genuinely-terminal rows keep
// task_complete, and a database mid-upgrade (rows ingested before the
// sweep, or before migration 078 ran) carries both spellings for the
// same text. Matching one type only would return an empty coverage set
// and reopen the duplicate-assistant-row bug this query closes.
//
// Empty Target rows are skipped on the SQL side (DISTINCT collapses
// them but they'd be useless for text dedup anyway). Returning empty
// slices for an unknown source_file is not an error — the caller
// treats it as the baseline "no extra coverage" case.
func (s *Store) LoadActionTargets(ctx context.Context, sourceFile string) (userTargets, asstTargets []string, err error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT action_type, target FROM actions
		  WHERE source_file = ?
		    AND target <> ''
		    AND action_type IN ('user_prompt', 'task_complete', 'assistant_message')`,
		sourceFile)
	if err != nil {
		return nil, nil, fmt.Errorf("store.LoadActionTargets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var actionType, target string
		if scanErr := rows.Scan(&actionType, &target); scanErr != nil {
			return nil, nil, fmt.Errorf("store.LoadActionTargets: scan: %w", scanErr)
		}
		switch actionType {
		case "user_prompt":
			userTargets = append(userTargets, target)
		case "task_complete", "assistant_message":
			asstTargets = append(asstTargets, target)
		}
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, nil, fmt.Errorf("store.LoadActionTargets: rows: %w", rowsErr)
	}
	return userTargets, asstTargets, nil
}

// GetCursor returns the persisted byte offset for sourceFile, or 0 on first
// access. A missing row is not an error.
func (s *Store) GetCursor(ctx context.Context, sourceFile string) (int64, error) {
	var off int64
	err := s.db.QueryRowContext(
		ctx,
		`SELECT byte_offset FROM parse_cursors WHERE source_file = ?`, sourceFile,
	).Scan(&off)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store.GetCursor: %w", err)
	}
	return off, nil
}

// CursorEntry is one parse_cursors row exposed to callers that need to
// enumerate every known session file (e.g. the watcher's poll fallback).
type CursorEntry struct {
	SourceFile string
	ByteOffset int64
}

// ListCursors returns every parse_cursors row. Order is unspecified.
//
// Used by the watcher's poll fallback to re-stat known session files
// and recover from fsnotify Write events dropped on busy filesystems
// (notably WSL2/NTFS, where fsnotify is documented to be lossy).
func (s *Store) ListCursors(ctx context.Context) ([]CursorEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT source_file, byte_offset FROM parse_cursors`)
	if err != nil {
		return nil, fmt.Errorf("store.ListCursors: %w", err)
	}
	defer rows.Close()
	var out []CursorEntry
	for rows.Next() {
		var c CursorEntry
		if err := rows.Scan(&c.SourceFile, &c.ByteOffset); err != nil {
			return nil, fmt.Errorf("store.ListCursors: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListCursors: %w", err)
	}
	return out, nil
}

// SetCursor persists the byte offset for sourceFile. Monotonic — a lower
// offset than the existing one is rejected to protect against accidental
// rewinds.
func (s *Store) SetCursor(ctx context.Context, sourceFile string, offset int64) error {
	if sourceFile == "" {
		return errors.New("store.SetCursor: sourceFile is required")
	}
	now := timestamp(time.Now().UTC())
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO parse_cursors (source_file, byte_offset, last_parsed)
		 VALUES (?, ?, ?)
		 ON CONFLICT(source_file) DO UPDATE SET
		   byte_offset = MAX(parse_cursors.byte_offset, excluded.byte_offset),
		   last_parsed = excluded.last_parsed`,
		sourceFile, offset, now,
	)
	if err != nil {
		return fmt.Errorf("store.SetCursor: %w", err)
	}
	return nil
}

// DeleteCursor removes the parse_cursors row for sourceFile. Safe to
// call on a missing row (no-op). Used by the hook-spool drainer to drop
// the cursor when it deletes a fully-drained, aged-out spool file, so
// parse_cursors doesn't accumulate one stale row per spool-file-day.
func (s *Store) DeleteCursor(ctx context.Context, sourceFile string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM parse_cursors WHERE source_file = ?`, sourceFile); err != nil {
		return fmt.Errorf("store.DeleteCursor: %w", err)
	}
	return nil
}

// insertActionSQL upserts an action row keyed on
// (source_file, source_event_id). On conflict, a small set of columns
// are allowed to update: `duration_ms` (backfill when new value is
// non-zero AND existing is zero); `metadata` (backfill when existing
// is NULL, OR refresh when THIS upsert also enriches the row's content
// — see below); and the length-merged `raw_tool_input` /
// `raw_tool_output` / `content_bytes`. These rules let adapter
// improvements propagate to historical rows on re-scan without ever
// clobbering an already-populated value. All other columns stay
// frozen on re-insert. Pattern mirrors the v1.4.27 token_usage.model
// fix and v1.4.28 duration_ms backfill.
//
// The metadata refresh-on-enrichment is a coherence fix (browser
// full-detail wave): metadata describes the content it rides with (the
// browser rail's granularity label + token estimates), so when a turn
// first stored at usage_only (no content) is re-fired at full (content
// arrives), the metadata MUST advance alongside the newly-accepted body
// instead of staying frozen at the stale usage_only label. It is gated
// on the content actually growing — a capability, not a tool name — so
// every adapter's metadata stays coherent with its content and an
// idempotent re-fire (same content) never churns metadata.
const insertActionSQL = `INSERT INTO actions (
	session_id, project_id, timestamp, turn_index,
	action_type, is_native_tool,
	target, target_hash,
	success, error_message,
	duration_ms,
	content_hash, file_mtime, file_size_bytes, freshness, prior_action_id, change_detected,
	preceding_reasoning,
	raw_tool_name, raw_tool_input, raw_tool_output,
	tool,
	source_file, source_file_hash, source_event_id,
	is_sidechain,
	message_id,
	metadata,
	org_id, user_email,
	content_bytes,
	user_attachments
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(source_file, source_event_id) DO UPDATE SET
	duration_ms = CASE
		WHEN excluded.duration_ms > 0 AND (actions.duration_ms IS NULL OR actions.duration_ms = 0)
		THEN excluded.duration_ms
		ELSE actions.duration_ms
	END,
	metadata = CASE
		WHEN excluded.metadata IS NOT NULL
		 AND (
		   actions.metadata IS NULL
		   -- Refresh-on-enrichment: when THIS upsert also accepts a richer
		   -- raw_tool_output/input (the length-merge below), the metadata
		   -- describing that content must advance with it — otherwise a
		   -- browser turn stored at usage_only then re-fired at full keeps
		   -- content but a stale granularity label / token estimates.
		   -- Capability-gated (content grew), never tool-gated.
		   OR (excluded.raw_tool_output IS NOT NULL AND excluded.raw_tool_output != ''
		       AND (actions.raw_tool_output IS NULL OR actions.raw_tool_output = ''
		            OR LENGTH(excluded.raw_tool_output) > LENGTH(actions.raw_tool_output)))
		   OR (excluded.raw_tool_input IS NOT NULL AND excluded.raw_tool_input != ''
		       AND (actions.raw_tool_input IS NULL OR actions.raw_tool_input = ''
		            OR LENGTH(excluded.raw_tool_input) > LENGTH(actions.raw_tool_input)))
		 )
		THEN excluded.metadata
		ELSE actions.metadata
	END,
	-- Adapter-rescan can carry a richer raw_tool_input than the
	-- original emit captured (e.g. codex web_search's action.queries
	-- fan-out, which v1.4.53 surfaces as JSON; pre-fix rows only
	-- stored the top-level Query string). Refresh when (a) the
	-- existing value is empty OR (b) the new value is strictly
	-- longer. The length heuristic protects against accidental
	-- truncation by a future adapter regression overwriting good
	-- data with a shorter render.
	raw_tool_input = CASE
		WHEN excluded.raw_tool_input IS NOT NULL
		 AND excluded.raw_tool_input != ''
		 AND (
		   actions.raw_tool_input IS NULL
		   OR actions.raw_tool_input = ''
		   OR LENGTH(excluded.raw_tool_input) > LENGTH(actions.raw_tool_input)
		 )
		THEN excluded.raw_tool_input
		ELSE actions.raw_tool_input
	END,
	-- Mirror the raw_tool_input length-merge for raw_tool_output
	-- (v1.6.29 full-output capture). A re-emit can legitimately carry
	-- a richer body than the initial insert — e.g. a hook captures
	-- pre-completion output, then the JSONL adapter sees the final
	-- buffer. Length-merge keeps the better one without ever
	-- regressing to a shorter version. Note: bridges and other
	-- best-effort capture paths that return truncated-valid responses
	-- need their own quality metric (see antigravity snapshot.go
	-- reconciliation); the length heuristic here is the
	-- general-case defense at the store boundary.
	raw_tool_output = CASE
		WHEN excluded.raw_tool_output IS NOT NULL
		 AND excluded.raw_tool_output != ''
		 AND (
		   actions.raw_tool_output IS NULL
		   OR actions.raw_tool_output = ''
		   OR LENGTH(excluded.raw_tool_output) > LENGTH(actions.raw_tool_output)
		 )
		THEN excluded.raw_tool_output
		ELSE actions.raw_tool_output
	END,
	-- content_bytes (verbosity, migration 054): a re-emit can carry the
	-- real authored-byte length where the original insert had none (e.g.
	-- a hook emit lacking the full input, later refreshed by the JSONL
	-- adapter with the untruncated content). Keep the larger, never
	-- regress a real value back to NULL/0.
	content_bytes = CASE
		WHEN excluded.content_bytes IS NOT NULL
		 AND excluded.content_bytes > COALESCE(actions.content_bytes, 0)
		THEN excluded.content_bytes
		ELSE actions.content_bytes
	END,
	-- user_attachments (Issue 1, migration 126): a re-emit can carry the
	-- structured attachment metadata where the original insert had none
	-- (e.g. a hook emit lacking the user content, later refreshed by the
	-- JSONL adapter which does see the image/document blocks). Fill only
	-- when the existing value is NULL; never regress a captured value back
	-- to NULL. Metadata (kinds/counts/media-types) only — never content.
	user_attachments = CASE
		WHEN excluded.user_attachments IS NOT NULL
		 AND actions.user_attachments IS NULL
		THEN excluded.user_attachments
		ELSE actions.user_attachments
	END,
	-- success self-heal, ASYMMETRIC 1 → 0 ONLY (outcome seam).
	-- A tool_use and its tool_result are separate records: every call
	-- inserts optimistically successful and is corrected when the
	-- result is seen. When a parse window ends between the two, the
	-- row can be left permanently wrong; a force rescan (offset 0)
	-- pairs them in ONE window and re-emits the CORRECTED event, but
	-- with success frozen on conflict that repair could never land.
	--
	-- The reverse direction must stay frozen: an optimistic re-emit
	-- carries success=1 by construction, so allowing 0 → 1 would let
	-- an ordinary re-scan un-fix a row a real failure had already
	-- corrected. Same asymmetry as the action_type unknown → known
	-- rule below — a re-emit may only ever ADD information.
	--
	-- The flip is gated on EVIDENCE, not on tool identity: a measured
	-- failure carries its error text, while a PROVISIONAL false
	-- carries none. Snapshot adapters re-emit stable ids with such
	-- sentinels — antigravity's "no exit code yet" (success is derived
	-- from an unsigned exit value) and copilot's isComplete=false
	-- task_complete row — and a stale or truncated snapshot parse
	-- landing after a complete one would otherwise downgrade a real
	-- success. Requiring the error body makes that impossible without
	-- naming a single adapter.
	--
	-- Accepted miss: a genuine failure whose result body is empty
	-- won't self-heal on rescan. The cross-tick update path still
	-- fixes it — ActionOutcomeUpdate.SuccessKnown carries the verdict
	-- without needing a message.
	success = CASE
		WHEN actions.success = 1 AND excluded.success = 0
		 AND excluded.error_message IS NOT NULL AND excluded.error_message != ''
		THEN excluded.success
		ELSE actions.success
	END,
	-- error_message rides along on that same flip (and only then), so
	-- a healed row explains itself. Bound as a plain string by
	-- InsertActions, hence the '' guard rather than IS NULL alone.
	error_message = CASE
		WHEN actions.success = 1 AND excluded.success = 0
		 AND excluded.error_message IS NOT NULL AND excluded.error_message != ''
		THEN excluded.error_message
		ELSE actions.error_message
	END,
	-- action_type reclassification (rescan self-heal). An adapter
	-- mapping fix (e.g. grok's search_replace -> edit_file, 2026-07-09)
	-- lets a re-scan finally classify a tool the original emit stored
	-- as the 'unknown' sentinel. Upgrade ONLY unknown -> known: the
	-- existing value must be the 'unknown' sentinel AND the re-emitted
	-- value must be a real, non-empty, non-unknown type. This never
	-- rewrites one known type to another (a rescan must not fight a
	-- hook-vs-adapter disagreement) and never downgrades a known type
	-- back to unknown/empty.
	action_type = CASE
		WHEN actions.action_type = 'unknown'
		 AND excluded.action_type IS NOT NULL
		 AND excluded.action_type != ''
		 AND excluded.action_type != 'unknown'
		THEN excluded.action_type
		ELSE actions.action_type
	END`

// marshalActionMetadata returns the JSON-encoded metadata blob
// suitable for insertion into actions.metadata, or nil for the
// "no metadata" case (NULL on disk). A non-nil but zero-valued
// struct also returns nil — the IsZero() guard keeps the column
// dense rather than persisting a stream of "{}" placeholders.
// Errors marshaling the struct (shouldn't happen for the
// well-typed ActionMetadata) fall back to nil so a per-event
// metadata bug can't fail the whole batch.
func marshalActionMetadata(m *models.ActionMetadata) any {
	if m == nil || m.IsZero() {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return string(b)
}

// marshalUserAttachments returns the JSON-encoded attachment array
// suitable for insertion into actions.user_attachments, or nil for the
// "no attachments" case (NULL on disk). Metadata only by construction
// (kind + optional media_type) — the UserAttachment type carries no
// filename and no bytes. Marshal errors fall back to nil so a per-event
// bug can't fail the whole batch.
func marshalUserAttachments(atts []models.UserAttachment) any {
	if len(atts) == 0 {
		return nil
	}
	b, err := json.Marshal(atts)
	if err != nil {
		return nil
	}
	return string(b)
}

// InsertActions writes a batch of actions using INSERT OR IGNORE — duplicate
// (source_file, source_event_id) rows are silently skipped. Returns the
// count of newly inserted rows. Runs in a single transaction.
//
// For each successfully inserted row, the corresponding actions[i].ID is
// populated with the new rowid so callers can chain additional work
// (e.g. freshness.UpsertFileState). Rows skipped via INSERT OR IGNORE retain
// ID = 0.
func (s *Store) InsertActions(ctx context.Context, actions []models.Action) (int, error) {
	if len(actions) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.InsertActions: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, insertActionSQL)
	if err != nil {
		return 0, fmt.Errorf("store.InsertActions: prepare: %w", err)
	}
	defer stmt.Close()

	// Pre-check stmt for the upsert-vs-insert distinction. The
	// `INSERT ... ON CONFLICT DO UPDATE` SQL above takes the UPDATE
	// branch on conflict, which means RowsAffected() returns 1 even
	// for duplicates, AND LastInsertId() returns a stale value (the
	// connection's last successful true INSERT rowid — which can
	// point at a row long since pruned by retention). Pre-checking
	// existence is the only reliable way to tell INSERT from UPDATE
	// without bumping the SQL to use RETURNING (would also work but
	// needs every code path tested for the schema-shape change).
	preCheckStmt, err := tx.PrepareContext(ctx,
		`SELECT id FROM actions WHERE source_file = ? AND source_event_id = ?`)
	if err != nil {
		return 0, fmt.Errorf("store.InsertActions: prepare pre-check: %w", err)
	}
	defer preCheckStmt.Close()

	var inserted int
	for i := range actions {
		a := &actions[i]
		s.stamper.Stamp(actionOrgRow{a}) // no-op unless enrolled; covers both exec branches below

		// Fast path: SELECT to determine if this row already exists.
		// Indexed on (source_file, source_event_id) UNIQUE, so the
		// lookup is a single index probe.
		var existingID int64
		switch err := preCheckStmt.QueryRowContext(ctx, a.SourceFile, a.SourceEventID).Scan(&existingID); {
		case err == nil:
			// Row already exists — UPSERT will take the DO UPDATE
			// path. Run the upsert (so duration_ms backfill still
			// fires for legitimately-improved values), but leave
			// a.ID = 0 so the caller's `if a.ID == 0` skip stays
			// correct for failure_context / file_state side effects
			// that should only fire on TRUE inserts.
			if _, err := stmt.ExecContext(
				ctx,
				a.SessionID, a.ProjectID, timestamp(a.Timestamp), a.TurnIndex,
				a.ActionType, boolToInt(a.IsNativeTool),
				a.Target, a.TargetHash,
				boolToInt(a.Success), a.ErrorMessage, a.DurationMs,
				nullableString(a.ContentHash), nullableTimestamp(a.FileMtime),
				nullableInt64(a.FileSizeBytes), nullableString(a.Freshness),
				nullableInt64(a.PriorActionID), boolToInt(a.ChangeDetected),
				nullableString(a.PrecedingReasoning),
				nullableString(a.RawToolName), nullableString(a.RawToolInput),
				nullableString(a.RawToolOutput),
				a.Tool, a.SourceFile, sha256HexOrEmpty(a.SourceFile), a.SourceEventID,
				boolToInt(a.IsSidechain), nullableString(a.MessageID),
				marshalActionMetadata(a.Metadata),
				nullableString(a.OrgID), nullableString(a.UserEmail),
				nullableInt64(a.ContentBytes),
				marshalUserAttachments(a.UserAttachments),
			); err != nil {
				return inserted, fmt.Errorf("store.InsertActions: upsert dup: %w", err)
			}
			// a.ID stays 0 so caller skips side-effects.
			continue
		case errors.Is(err, sql.ErrNoRows):
			// New row — INSERT path will fire.
		default:
			return inserted, fmt.Errorf("store.InsertActions: pre-check: %w", err)
		}

		res, err := stmt.ExecContext(
			ctx,
			a.SessionID, a.ProjectID, timestamp(a.Timestamp), a.TurnIndex,
			a.ActionType, boolToInt(a.IsNativeTool),
			a.Target, a.TargetHash,
			boolToInt(a.Success), a.ErrorMessage, a.DurationMs,
			nullableString(a.ContentHash), nullableTimestamp(a.FileMtime),
			nullableInt64(a.FileSizeBytes), nullableString(a.Freshness),
			nullableInt64(a.PriorActionID), boolToInt(a.ChangeDetected),
			nullableString(a.PrecedingReasoning),
			nullableString(a.RawToolName), nullableString(a.RawToolInput),
			nullableString(a.RawToolOutput),
			a.Tool, a.SourceFile, sha256HexOrEmpty(a.SourceFile), a.SourceEventID,
			boolToInt(a.IsSidechain), nullableString(a.MessageID),
			marshalActionMetadata(a.Metadata),
			nullableString(a.OrgID), nullableString(a.UserEmail),
			nullableInt64(a.ContentBytes),
			marshalUserAttachments(a.UserAttachments),
		)
		if err != nil {
			return inserted, fmt.Errorf("store.InsertActions: exec: %w", err)
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			if id, err := res.LastInsertId(); err == nil {
				a.ID = id
			}
			inserted++
		}
	}
	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("store.InsertActions: commit: %w", err)
	}
	return inserted, nil
}

// UpdateActionOutcome enriches an existing actions row with the
// outcome fields from a paired after-event hook. Used by the Cursor
// dispatcher to apply afterShellExecution / afterMCPExecution /
// postToolUse data onto the matching beforeShellExecution /
// beforeMCPExecution / preToolUse row, eliminating the pre-fix
// "before-row stays Success=true forever" drift.
//
// Backfill semantics (each column independently):
//   - success: always overwritten — the after-event is the
//     authoritative outcome for the tool call.
//   - error_message: only overwritten when newValue is non-empty.
//     Protects an error message a postToolUseFailure row already
//     stored on this same row (rare; both events would target the
//     same source_event_id only if cursor coalesces them).
//   - duration_ms: only overwritten when newValue is non-zero AND
//     existing is zero. Mirrors the InsertActions backfill rule —
//     don't ever lower a populated duration.
//
// Returns rows updated (0 means the before-row didn't land yet —
// rare race against hook ordering — or the pairing key didn't
// match any row, which can happen for after-events fired against
// older payloads that don't share the same correlation key).
//
// v1.6.23: signature extended to carry the after-event's tool_output
// body (postToolUse.tool_output per cursor audit F3). A non-empty
// toolOutput plus a matched UPDATE row triggers an FTS5 insert into
// action_excerpts via the Store's bound Indexer (WithIndexer). The
// FTS5 insert is best-effort — indexer errors log to stderr but never
// fail the outcome write, because the row update is the
// load-bearing change.
func (s *Store) UpdateActionOutcome(
	ctx context.Context,
	sourceFile, sourceEventID string,
	success bool,
	errorMessage string,
	durationMs int64,
	toolOutput, toolName, target string,
) (int64, error) {
	// successKnown=true: an after-event hook always reports a verdict,
	// and this path is the authoritative one for it.
	return s.updateActionOutcome(ctx, sourceFile, sourceEventID, true, success,
		errorMessage, durationMs, toolOutput, toolName, target, s.indexer)
}

// updateActionOutcome is the implementation behind UpdateActionOutcome,
// with the FTS5 indexer supplied by the caller instead of read off the
// Store. The watcher's Store has no WithIndexer binding — its indexer
// arrives per-call through IngestOptions — so the Ingest path must be
// able to hand its own indexer in, or cross-tick tool output would
// silently skip the action_excerpts index.
//
// idx may be nil: the outcome columns still update, only the FTS insert
// is skipped.
//
// successKnown=false leaves the success column untouched — for a result
// record that carried no verdict, where writing anything would be an
// invention (see [models.ActionOutcomeUpdate.SuccessKnown]).
func (s *Store) updateActionOutcome(
	ctx context.Context,
	sourceFile, sourceEventID string,
	successKnown bool,
	success bool,
	errorMessage string,
	durationMs int64,
	toolOutput, toolName, target string,
	idx *indexing.Indexer,
) (int64, error) {
	if sourceFile == "" || sourceEventID == "" {
		return 0, errors.New("store.UpdateActionOutcome: sourceFile and sourceEventID are required")
	}
	res, err := s.db.ExecContext(
		ctx,
		`UPDATE actions SET
			success = CASE WHEN ? THEN ? ELSE success END,
			error_message = CASE WHEN ? <> '' THEN ? ELSE error_message END,
			duration_ms = CASE
				WHEN ? > 0 AND (duration_ms IS NULL OR duration_ms = 0)
				THEN ?
				ELSE duration_ms
			END,
			-- v1.6.29 full-output persistence: when a post-tool hook
			-- carries non-empty output AND the new payload is strictly
			-- longer than what's stored (or nothing is stored), upgrade
			-- the column. Length-merge mirrors the insertActionSQL
			-- ON CONFLICT rule so a hook captured pre-completion can
			-- still be replaced by a later, richer JSONL-derived body
			-- — and vice versa — without ever regressing.
			raw_tool_output = CASE
				WHEN ? <> ''
				 AND (raw_tool_output IS NULL
				      OR raw_tool_output = ''
				      OR LENGTH(?) > LENGTH(raw_tool_output))
				THEN ?
				ELSE raw_tool_output
			END
		 WHERE source_file = ? AND source_event_id = ?`,
		boolToInt(successKnown), boolToInt(success),
		errorMessage, errorMessage,
		durationMs, durationMs,
		toolOutput, toolOutput, toolOutput,
		sourceFile, sourceEventID,
	)
	if err != nil {
		return 0, fmt.Errorf("store.UpdateActionOutcome: %w", err)
	}
	n, _ := res.RowsAffected()
	// FTS5 index the tool output only when the column NOW holds exactly
	// this payload. Read the POST-update state and compare bytes: the
	// UPDATE's length-merge may have rejected this body (a shorter
	// duplicate), and indexing a rejected payload would leave
	// action_excerpts describing something raw_tool_output doesn't
	// hold. Asking the row what it ended up with — rather than
	// predicting the merge from a pre-read length — closes two holes at
	// once: a concurrent writer installing a longer body between the
	// two statements, and SQLite's LENGTH() stopping at the first
	// embedded U+0000 where a Go-side count would not. A later, longer
	// write by another path re-indexes with its own body, exactly as
	// the hook path already behaves.
	//
	// Index failures are swallowed: the outcome columns are the
	// load-bearing write. (The indexer's own DELETE+INSERT is not
	// atomic — a pre-existing property shared with the hook path, out
	// of scope here.)
	if n > 0 && toolOutput != "" && idx != nil {
		var (
			actionID  int64
			isCurrent int
		)
		err := s.db.QueryRowContext(
			ctx,
			`SELECT id, COALESCE(raw_tool_output, '') = ?
			   FROM actions WHERE source_file = ? AND source_event_id = ?`,
			toolOutput, sourceFile, sourceEventID,
		).Scan(&actionID, &isCurrent)
		if err == nil && actionID > 0 && isCurrent != 0 {
			_ = idx.Index(ctx, actionID, toolName, target, toolOutput, errorMessage)
		}
	}
	return n, nil
}

// InsertTokenEvents batches token_usage rows. Idempotent via
// UNIQUE(source_file, source_event_id).
func (s *Store) InsertTokenEvents(ctx context.Context, events []models.TokenEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.InsertTokenEvents: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// On conflict (same source_file + source_event_id), backfill any
	// column whose new value is strictly greater than the existing one.
	// Token counts are monotonically non-decreasing per logical event:
	// a re-parse for a finalized request produces identical numbers
	// (MAX returns same); a re-parse that captures REFINED state for
	// an in-flight request produces larger numbers (MAX upgrades).
	// A re-parse can never legitimately produce smaller numbers, so
	// the existing larger value is preserved when that does happen
	// (guards against an adapter regression overwriting good data).
	//
	// Pre-v1.6.23: counts were FROZEN on first insert. This was correct
	// for append-only JSONL adapters where source_event_id maps to a
	// final-on-write event, but caused Copilot's snapshot+patches
	// adapter to permanently persist partial state when the first
	// snapshot of a request landed before completionTokens was set.
	// See docs/audits/cursor-audit-2026-05-21.md / Copilot stale-cost report.
	//
	// model upgrade rule retained: empty new value is preserved as the
	// existing one via COALESCE+NULLIF (placeholder → resolved swap).
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO token_usage (
		session_id, timestamp, tool, model,
		input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
		cache_creation_1h_tokens, reasoning_tokens, web_search_requests,
		estimated_cost_usd, source, reliability,
		source_file, source_file_hash, source_event_id, message_id, turn_id,
		org_id, user_email, fast, is_sidechain
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(source_file, source_event_id) DO UPDATE SET
		model = COALESCE(NULLIF(excluded.model, ''), token_usage.model),
		-- Heal a placeholder message_id. Modern Copilot CLI process logs
		-- record a "Request-ID null" header, so a Tier-1 row first lands with
		-- the literal "null"; a later parse recovers the real id from the
		-- sibling events.jsonl (see copilotcli.recoverNullRequestIDs). Upgrade
		-- an existing NULL/empty/"null" message_id to a real (non-empty,
		-- non-"null") new value so observer backfill --copilot-cli-rescan
		-- restores the (session_id, message_id) sweep below for installs that
		-- already ingested the "null" row. A real existing id is never
		-- overwritten, and a stale emit can't re-introduce "null".
		message_id = CASE
			WHEN excluded.message_id IS NOT NULL
			 AND excluded.message_id != ''
			 AND excluded.message_id != 'null'
			 AND (token_usage.message_id IS NULL
			      OR token_usage.message_id = ''
			      OR token_usage.message_id = 'null')
			THEN excluded.message_id
			ELSE token_usage.message_id
		END,
		-- Allow a copilot rescan to correct input DOWN when it newly
		-- discovers cache-write tokens. Modern Copilot CLI lumps the
		-- cache-write portion into the gross prompt; a pre-fix row stored it
		-- as net input (too high). When a re-parse raises cache_creation
		-- above the stored value, its (lower) input is the authoritative
		-- decomposition — trust it. Scoped to the copilot tools + the
		-- cache_creation-grew condition, so every other adapter keeps the
		-- monotonic MAX (a partial re-parse can't lower a complete count).
		input_tokens = CASE
			WHEN excluded.tool IN ('copilot-cli', 'copilot')
			 AND COALESCE(excluded.cache_creation_tokens, 0) > COALESCE(token_usage.cache_creation_tokens, 0)
			THEN excluded.input_tokens
			ELSE MAX(COALESCE(token_usage.input_tokens, 0), COALESCE(excluded.input_tokens, 0))
		END,
		output_tokens         = MAX(COALESCE(token_usage.output_tokens, 0), COALESCE(excluded.output_tokens, 0)),
		cache_read_tokens     = MAX(COALESCE(token_usage.cache_read_tokens, 0), COALESCE(excluded.cache_read_tokens, 0)),
		cache_creation_tokens = MAX(COALESCE(token_usage.cache_creation_tokens, 0), COALESCE(excluded.cache_creation_tokens, 0)),
		cache_creation_1h_tokens = CASE
			-- NULL-safe MAX: the column is nullable (Anthropic-only),
			-- so coalesce both sides to 0 for comparison and preserve
			-- NULL only when both are NULL.
			WHEN excluded.cache_creation_1h_tokens IS NULL AND token_usage.cache_creation_1h_tokens IS NULL
			THEN NULL
			ELSE MAX(COALESCE(token_usage.cache_creation_1h_tokens, 0), COALESCE(excluded.cache_creation_1h_tokens, 0))
		END,
		reasoning_tokens      = MAX(COALESCE(token_usage.reasoning_tokens, 0), COALESCE(excluded.reasoning_tokens, 0)),
		-- turn_id backfill: existing row's NULL upgrades to a non-empty
		-- new value (older codex parses pre-migration 032 had no TurnID
		-- to set; re-parse with v1.7.24+ adapter fills it in). Keep an
		-- existing non-NULL value if the new emit is empty so a stale
		-- adapter can't clear it.
		turn_id = COALESCE(NULLIF(excluded.turn_id, ''), token_usage.turn_id),
		-- is_sidechain heals on re-parse (migration 087): the flag is a
		-- deterministic function of the source line — the adapter reads it
		-- straight off every transcript record — so the incoming value
		-- always wins. That is exactly what lets "observer scan --force"
		-- backfill the flag onto pre-087 rows with no dedicated surgical
		-- pass. Contrast the MAX-guarded counters above: those defend
		-- against a PARTIAL re-parse of an in-flight request; a boolean
		-- read whole off the line has no partial state to protect.
		is_sidechain = excluded.is_sidechain,
		-- Cost: upgrade when the new emit carries a non-zero cost and
		-- the existing one is zero (proxy-sourced rows are gold standard
		-- per the v1.4.12 cost-provenance rule). Two non-zero values
		-- shouldn't disagree, but if they do, keep the larger so an
		-- adapter regression can't silently lower a row's cost.
		estimated_cost_usd = CASE
			WHEN excluded.estimated_cost_usd > 0 AND COALESCE(token_usage.estimated_cost_usd, 0) = 0
			THEN excluded.estimated_cost_usd
			WHEN excluded.estimated_cost_usd > COALESCE(token_usage.estimated_cost_usd, 0)
			THEN excluded.estimated_cost_usd
			ELSE COALESCE(token_usage.estimated_cost_usd, 0)
		END,
		-- Backfill web_search_requests when a rescan re-emits the
		-- same token_count line but now carries the count from a
		-- newer adapter version. Existing zero/NULL gets the new
		-- count; a non-zero existing value is preserved so a later
		-- emission that doesn't count searches can't accidentally
		-- clear it.
		web_search_requests = CASE
			WHEN excluded.web_search_requests IS NOT NULL
			 AND excluded.web_search_requests > 0
			 AND COALESCE(token_usage.web_search_requests, 0) = 0
			THEN excluded.web_search_requests
			ELSE token_usage.web_search_requests
		END
	-- Never mutate another tool's row on a key collision. The conflict
	-- target (source_file, source_event_id) excludes tool, so a
	-- cross-tool collision is theoretically possible; it's impossible by
	-- construction today (per-adapter source_file namespaces are
	-- disjoint), but must never silently upgrade a claude-code/codex
	-- row's token dims from a different tool's emit. The dedup-sweep
	-- gates (hasClaudeCode/hasCodex, derived from the INCOMING batch)
	-- depend on this: a batch without those tools must not be able to
	-- modify their rows at all. On a cross-tool collision this predicate
	-- is false, so conflict resolution no-ops (RowsAffected 0, no error).
	WHERE token_usage.tool = excluded.tool`)
	if err != nil {
		return 0, fmt.Errorf("store.InsertTokenEvents: prepare: %w", err)
	}
	defer stmt.Close()

	var inserted int
	hasCopilotCLI := false
	cursorSessions := make(map[string]struct{})
	hasMsgIDBearing := false
	hasClaudeCode := false
	hasCodex := false
	for _, e := range events {
		if e.Tool == models.ToolCursor {
			cursorSessions[e.SessionID] = struct{}{}
			// Native request IDs survive copies and diagnostic-log relocation.
			// Reuse the first source path so the regular UPSERT also heals model
			// context without counting a recovered copy as another request.
			if e.Source == models.TokenSourceJSONL && e.MessageID != "" && e.SourceEventID == "cursor-cli-outcome:"+e.MessageID {
				var sourceFile string
				err := tx.QueryRowContext(ctx, `SELECT source_file FROM token_usage
					WHERE tool = 'cursor' AND session_id = ? AND source = 'jsonl'
					AND source_event_id = ? ORDER BY id LIMIT 1`, e.SessionID, e.SourceEventID).Scan(&sourceFile)
				if err == nil {
					e.SourceFile = sourceFile
				} else if !errors.Is(err, sql.ErrNoRows) {
					return inserted, fmt.Errorf("store.InsertTokenEvents: cursor source identity: %w", err)
				}
			}
		}
		if e.Tool == models.ToolCopilotCLI {
			hasCopilotCLI = true
		}
		if e.Tool == models.ToolClaudeCode {
			hasClaudeCode = true
		}
		if e.Tool == models.ToolCodex {
			hasCodex = true
		}
		if e.MessageID != "" {
			hasMsgIDBearing = true
		}
		s.stamper.Stamp(tokenOrgRow{&e}) // no-op unless enrolled
		res, err := stmt.ExecContext(
			ctx,
			e.SessionID,
			timestamp(e.Timestamp),
			e.Tool,
			e.Model,
			e.InputTokens,
			e.OutputTokens,
			e.CacheReadTokens,
			e.CacheCreationTokens,
			nullableInt64(e.CacheCreation1hTokens),
			e.ReasoningTokens,
			nullableInt64(e.WebSearchRequests),
			e.EstimatedCostUSD,
			e.Source,
			e.Reliability,
			nullableString(e.SourceFile),
			sha256HexOrEmpty(e.SourceFile),
			nullableString(e.SourceEventID),
			nullableString(e.MessageID),
			nullableString(e.TurnID),
			nullableString(e.OrgID),
			nullableString(e.UserEmail),
			boolToInt(e.Fast),
			boolToInt(e.IsSidechain),
		)
		if err != nil {
			return inserted, fmt.Errorf("store.InsertTokenEvents: exec: %w", err)
		}
		n, _ := res.RowsAffected()
		inserted += int(n)
	}

	// A headless CLI outcome is the complete reported request aggregate.
	// Some Cursor builds also emit hooks for its individual model generations
	// (<request UUID>-<step>-<suffix>). Prefer the aggregate for that request
	// only, in either arrival order; preserve hooks from other turns/attempts.
	for sessionID := range cursorSessions {
		if _, err := tx.ExecContext(ctx, `DELETE FROM token_usage
			WHERE tool = 'cursor' AND session_id = ? AND source = 'hook' AND EXISTS (
			 SELECT 1 FROM token_usage c WHERE c.tool = 'cursor'
			 AND c.source = 'jsonl' AND c.session_id = token_usage.session_id
			 AND c.source_event_id = 'cursor-cli-outcome:' || c.message_id
			 AND (token_usage.message_id = c.message_id
			 OR substr(token_usage.message_id, 1, length(c.message_id) + 1) = c.message_id || '-')
			)`, sessionID); err != nil {
			return inserted, fmt.Errorf("store.InsertTokenEvents: cursor usage dedup: %w", err)
		}
	}

	// copilot-cli emits a Tier-3 (events.jsonl, OutputTokens only) row
	// and a Tier-1 (debug-log, full usage) row for the same Request-ID
	// when --log-level debug is enabled. They land under different
	// (source_file, source_event_id) keys, so the ON CONFLICT clause
	// above can't dedup them — output_tokens would double-count in
	// rollups. Sweep here: when an OTel row exists for a given
	// (session_id, message_id), drop the matching JSONL row. Scoped to
	// copilot-cli so other adapters (e.g. Anthropic proxy + claudecode
	// JSONL overlap) aren't accidentally affected. Idempotent across
	// re-parses; arrival-order independent. Index
	// idx_token_usage_session_message keeps the EXISTS cheap.
	if hasCopilotCLI {
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM token_usage
			 WHERE tool = ?
			   AND source = ?
			   AND COALESCE(message_id, '') != ''
			   AND EXISTS (
			     SELECT 1 FROM token_usage h
			     WHERE h.tool = token_usage.tool
			       AND h.source = ?
			       AND h.session_id = token_usage.session_id
			       AND h.message_id = token_usage.message_id
			       AND h.id != token_usage.id
			   )`,
			models.ToolCopilotCLI, models.TokenSourceJSONL, models.TokenSourceOTel,
		); err != nil {
			return inserted, fmt.Errorf("store.InsertTokenEvents: dedup: %w", err)
		}

		// Tier 0 (`source='session_summary'`, derived from
		// session.shutdown.modelMetrics) is the v1.6.6 capture path
		// that fills the input/cache/reasoning gap when copilot-cli
		// runs without --log-level debug. When Tier 1 (`source='otel'`)
		// rows DO exist for the same session, Tier 1 has full
		// per-request breakdowns and Tier 0 would over-count the
		// session-aggregate input/cache columns (a session might emit
		// 50 Tier 1 rows totaling 5M input + one Tier 0 row also
		// totaling 5M input → naïve SUM = 10M, 2x reality).
		//
		// Sweep here: drop a session_summary row only when otel rows
		// exist in its OWN per-shutdown coverage window — the open-
		// closed interval (prior_session_summary_ts, this_ts] for the
		// same session. Each session.shutdown carries a delta covering
		// just the work span since the most recent session.resume; the
		// previous session_summary row's timestamp is a good proxy for
		// "start of this shutdown's window". When this row is the
		// FIRST session_summary in the session, the lower bound is ''
		// (empty string, which is lexicographically less than every
		// RFC3339 timestamp) — i.e. since session start.
		//
		// SCOPING — v1.6.8 B2 fix (docs/copilot-cli-audit-2026-05-18.md
		// §B2). The original v1.6.6 sweep dropped session-wide whenever
		// any otel row existed. That worked for "always-debug" sessions
		// (every shutdown's window has Tier-1 coverage → drop all) but
		// silently lost modelMetrics rows when debug was enabled
		// mid-session: the pre-debug shutdowns' session_summary entries
		// got dropped even though no otel rows covered their window. The
		// per-shutdown-range scope keeps pre-debug session_summary rows
		// (correct — Tier 0 is the only Tier with input/cache info for
		// that period) and still drops post-debug entries that overlap
		// otel coverage.
		//
		// Arrival-order independent: works whether the shutdown event
		// landed before or after the debug-log rows. Idempotent across
		// re-parses since each call DELETEs from a fresh starting set
		// (rows already dropped on a prior run simply aren't there).
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM token_usage
			 WHERE tool = ?
			   AND source = ?
			   AND EXISTS (
			     SELECT 1 FROM token_usage h
			     WHERE h.tool = ?
			       AND h.source = ?
			       AND h.session_id = token_usage.session_id
			       AND h.timestamp <= token_usage.timestamp
			       AND h.timestamp > COALESCE(
			         (SELECT MAX(p.timestamp) FROM token_usage p
			          WHERE p.tool = token_usage.tool
			            AND p.source = token_usage.source
			            AND p.session_id = token_usage.session_id
			            AND p.timestamp < token_usage.timestamp),
			         ''
			       )
			   )`,
			models.ToolCopilotCLI, models.TokenSourceSessionSummary,
			models.ToolCopilotCLI, models.TokenSourceOTel,
		); err != nil {
			return inserted, fmt.Errorf("store.InsertTokenEvents: session_summary dedup: %w", err)
		}
	}

	// Tuple-level dedup: per (tool, session_id, message_id), drop rows
	// that are byte-identical on every token-count dimension to a
	// higher-id sibling. Catches re-emissions the UNIQUE
	// (source_file, source_event_id) constraint can't, e.g.:
	//   - claudecode JSONL emits N content-block lines per assistant
	//     message all carrying the same cumulative usage snapshot, and
	//     pre-cb16006 the adapter used per-line UUID as source_event_id
	//     so re-parses inserted fresh rows. ~22k historical residue
	//     rows on the maintainer DB.
	//   - codex token_count events occasionally fire twice within
	//     ~2-3s with byte-identical last_token_usage AND
	//     total_token_usage; the in-call seenModernTotal map doesn't
	//     survive across parser invocations so cross-tick re-emissions
	//     slip through.
	// Rows with distinct token values (real progressions, real
	// per-emission deltas) are preserved — only byte-identical tuples
	// collapse.
	//
	// SCOPING — allowlist, not tool-agnostic. The v1.6.5 implementation
	// was tool-agnostic; the v1.6.8 copilot-cli audit (docs/copilot-cli-
	// audit-2026-05-18.md §B1) found that Copilot CLI emits per-block
	// outputTokens DELTAS sharing one requestId (= MessageID) — so two
	// distinct content blocks with byte-identical small output counts
	// were wrongly collapsed (6 rows / 1,440 output tokens lost on the
	// sample). The fix scopes the sweep to adapters whose MessageID
	// strategy guarantees "same MessageID implies same logical content":
	//   - claude-code: MessageID = msg.ID, one logical message per id;
	//     re-emissions carry identical cumulative usage. Safe.
	//   - codex: MessageID = turn_id, monotonic-total guard in adapter
	//     means byte-identical = re-emission. Safe.
	// New tools opt in by joining this list with a verified note that
	// their adapter never emits multiple legitimate rows under one
	// MessageID. Future adapters following Copilot CLI's per-block
	// pattern must stay out.
	//
	// Gated on the batch containing at least one msgid-bearing event so
	// empty-msgid-only inserts skip the EXISTS scan entirely, AND on the
	// batch actually containing claude-code or codex — the only two tools
	// this sweep can ever delete. A batch of neither tool provably can't
	// create a new duplicate in those partitions, so running the sweep is
	// pure cost: it full-scans token_usage (the outer DELETE has no index
	// leading with `tool`), and a browser-hook batch (claude-web/gemini-web,
	// always msgid-bearing, 500ms ctx deadline) was timing out on it.
	// idx_token_usage_tool_session_message (migration 070) turns the outer
	// filter into a SEARCH for the legit claude-code/codex sweeps.
	if hasMsgIDBearing && (hasClaudeCode || hasCodex) {
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM token_usage
			 WHERE tool IN (?, ?)
			   AND COALESCE(message_id, '') != ''
			   AND EXISTS (
			     SELECT 1 FROM token_usage h
			     WHERE h.tool = token_usage.tool
			       AND h.session_id = token_usage.session_id
			       AND h.message_id = token_usage.message_id
			       AND COALESCE(h.input_tokens, 0)             = COALESCE(token_usage.input_tokens, 0)
			       AND COALESCE(h.output_tokens, 0)            = COALESCE(token_usage.output_tokens, 0)
			       AND COALESCE(h.cache_read_tokens, 0)        = COALESCE(token_usage.cache_read_tokens, 0)
			       AND COALESCE(h.cache_creation_tokens, 0)    = COALESCE(token_usage.cache_creation_tokens, 0)
			       AND COALESCE(h.cache_creation_1h_tokens, 0) = COALESCE(token_usage.cache_creation_1h_tokens, 0)
			       AND COALESCE(h.reasoning_tokens, 0)         = COALESCE(token_usage.reasoning_tokens, 0)
			       AND h.id > token_usage.id
			   )`,
			models.ToolClaudeCode, models.ToolCodex,
		); err != nil {
			return inserted, fmt.Errorf("store.InsertTokenEvents: tuple dedup: %w", err)
		}
	}

	// Cross-source-file snapshot-drift dedup — claude-code ONLY, so gate
	// on the batch actually carrying claude-code. Like the tuple sweep it
	// full-scans and can only ever delete claude-code rows; a batch without
	// claude-code can't create new snapshot-drift duplicates, so skipping
	// it keeps non-claude-code batches (incl. the browser-hook lane under a
	// 500ms deadline) off the full scan.
	if hasMsgIDBearing && hasClaudeCode {
		// Cross-source-file snapshot-drift dedup (v1.6.10 / audit B2).
		//
		// Anthropic's JSONL emits N content-block records per assistant
		// API call, each carrying a progressing cumulative usage
		// snapshot. The adapter's per-file dedup at
		// claudecode/adapter.go:279 (msgIDToIdx) collapses those N rows
		// to one TokenEvent per msg.id within a single file, picking the
		// highest-output cumulative state. That's correct WITHIN a file.
		//
		// But Claude Code's auto-compaction (`agent-acompact-*.jsonl`
		// subagent files) snapshots in-flight API turns from the parent
		// file. The acompact snapshot captures a LATER cumulative state
		// than the parent file's earliest matching row. After both files
		// ingest, the same msg.id has TWO rows in DB — one from parent
		// (early, low output) and one from acompact (later, higher
		// output). Tuples differ on output_tokens so the byte-identical
		// dedup above doesn't catch them; the cost engine then sums
		// both, double-counting the API call.
		//
		// The maintainer corpus audit (2026-05-18) found 96 msgids
		// across 2 sessions inflated by 2,401 output tokens — small in
		// dollars (~$0.06 at Opus rates) but a real billing inflation.
		// Per the audit operator's "absolute accuracy" gate it fails.
		//
		// Fix: same (tool, session_id, message_id) allowlist as the
		// byte-identical pass; keep the row with highest output_tokens
		// (the canonical latest cumulative snapshot) and drop siblings.
		// Ties broken by highest id (matching the existing pass's
		// determinism). The two passes compose cleanly — byte-identical
		// collisions disappear in pass 1, snapshot-drift in pass 2.
		//
		// Scoping: claude-code ONLY (NOT codex) AND same `source` only.
		//
		// 1. Claude-code-only: codex emits LEGITIMATE multiple per-turn
		//    delta token_count rows under one TurnID with distinct
		//    cumulative values (see
		//    TestInsertTokenEvents_TupleDedupPreservesDistinctRows —
		//    three rows summing to 101720 input_tokens). If this pass
		//    ran on codex it would keep only the max-output row and
		//    lose the other two. Claude-code's per-file adapter dedup
		//    at claudecode/adapter.go:279 already collapses the
		//    N-content-block emissions to one row per msg.id per file,
		//    so cross-file collisions can only come from parent-vs-
		//    acompact snapshot drift — which IS the bug being fixed.
		//
		// 2. Same-source-only: a future Anthropic proxy capture
		//    overlapping with a JSONL row for the same msg.id is a
		//    LEGITIMATE complementary-data scenario — the proxy carries
		//    full input/cache breakdown the JSONL omits. They MUST
		//    both survive (see TestInsertTokenEvents_DedupScopedToCopilotCLI's
		//    claudecode-proxy + claudecode-jsonl assertion). Restricting
		//    `h.source = token_usage.source` lets the proxy+jsonl pair
		//    pass through while still catching the parent+acompact
		//    snapshot drift (both are Source=jsonl).
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM token_usage
			 WHERE tool = ?
			   AND COALESCE(message_id, '') != ''
			   AND EXISTS (
			     SELECT 1 FROM token_usage h
			     WHERE h.tool = token_usage.tool
			       AND h.session_id = token_usage.session_id
			       AND h.message_id = token_usage.message_id
			       AND h.source = token_usage.source
			       AND h.id != token_usage.id
			       AND (h.output_tokens > token_usage.output_tokens
			            OR (h.output_tokens = token_usage.output_tokens AND h.id > token_usage.id))
			   )`,
			models.ToolClaudeCode,
		); err != nil {
			return inserted, fmt.Errorf("store.InsertTokenEvents: snapshot-drift dedup: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("store.InsertTokenEvents: commit: %w", err)
	}
	return inserted, nil
}

// IngestOptions parameterizes Ingest.
type IngestOptions struct {
	// ToolAccounts is node-local login evidence; processed independently of action dedup.
	ToolAccounts []models.ToolAccountObservation
	// IsNativeTool decides whether a ToolEvent's raw tool name maps to a
	// native tool (drives actions.is_native_tool). Defaults to always false.
	IsNativeTool func(rawToolName string) bool
	// Classifier, when non-nil, computes freshness for file-typed actions
	// (read_file, write_file, edit_file) and maintains the file_state table.
	// Requires an initialized DB with the file_state schema.
	Classifier *freshness.Classifier
	// RecordFailures, when true, populates failure_context for every
	// failed run_command action and updates retry_count / eventually_succeeded
	// on matching prior failures.
	RecordFailures bool
	// Indexer, when non-nil, stores the event's ToolOutput excerpt in the
	// FTS5 action_excerpts table so the MCP search_past_outputs tool can
	// retrieve it.
	Indexer *indexing.Indexer
	// CacheObservations carries per-turn Tier-2 cache observations
	// emitted by adapters (claudecode in C7, codex / opencode /
	// kilo-cli / cline-cli per spec §14.3). C6 plumbs the slice
	// through; C7+ wires the internal/cachetrack engine to consume
	// it (write cache_segments + cache_entries + cache_events via
	// the seam in internal/store/cachetrack.go). An empty/nil
	// slice is a clean no-op at every stop on the path.
	CacheObservations []models.CacheTurnObservation
	// SessionProcessSeeds carries candidate (OS pid → session)
	// attribution links an adapter discovered in its own session data
	// (cline-cli's sessions.pid column, qwen-code's runtime.json
	// sidecar). Ingest validates each seed's liveness + identity
	// (pidbridge.ValidateLocalProcess) and writes the surviving ones
	// into session_pid_bridge — the direct, daemon-side counterpart of
	// the SessionStart hook's ancestor-walk. Empty/nil is a clean
	// no-op. Only the watcher path populates this; hook + scan callers
	// leave it nil, so no spurious /proc reads happen off the watcher.
	SessionProcessSeeds []models.SessionProcessSeed
	// SessionLineages carries codex fork/subagent lineage markers
	// (migration 069). Ingest persists each onto its session row via
	// SetSessionLineage after the sessions are upserted. NODE-LOCAL —
	// never on the org-push wire. Empty/nil is a clean no-op.
	SessionLineages []models.SessionLineage
	// SessionSurfaces carries capture-surface attribution (migration
	// 094). Ingest persists each onto its session row via
	// SetSessionSurface after the sessions are upserted, FIRST-WINS-
	// UNLESS-EMPTY per column (the first grounded stamp sticks; a later
	// parse only fills still-empty columns). Applied best-effort: a
	// rejected or failing stamp is counted in
	// IngestResult.SessionSurfacesSkipped, never returned as an error —
	// the actions and tokens have already landed by then. NODE-LOCAL —
	// never on the org-push wire. Empty/nil is a clean no-op.
	SessionSurfaces []models.SessionSurface
	// SessionToolVersions carries captured tool/CLI versions (migration
	// 125). Ingest persists each onto its session row via
	// SetSessionToolVersion after the sessions are upserted, FIRST-WINS-
	// UNLESS-EMPTY (the first grounded stamp sticks; a later parse only
	// fills a still-empty column). Applied best-effort: a rejected
	// (malformed) or failing stamp is counted in
	// IngestResult.SessionToolVersionsSkipped, never returned as an
	// error. NODE-LOCAL — never on the org-push wire. Empty/nil is a
	// clean no-op.
	SessionToolVersions []models.SessionToolVersion
	// OutcomeUpdates carries outcomes for actions inserted by an
	// EARLIER Ingest call: a tool_result an adapter parsed in a later
	// watcher tick than the tool_use that created the row (see
	// adapter.ParseResult.OutcomeUpdates). Applied after the batch
	// insert via UpdateActionOutcome's merge rules, using this options
	// struct's Indexer for the FTS excerpt. An entry matching no row is
	// silently tolerated, and a per-entry error is non-fatal — a late
	// outcome must never fail an ingest.
	OutcomeUpdates []models.ActionOutcomeUpdate
}

// fileActionTypes is the set of normalized actions whose target is a file
// path eligible for freshness classification.
var fileActionTypes = map[string]struct{}{
	models.ActionReadFile:  {},
	models.ActionWriteFile: {},
	models.ActionEditFile:  {},
}

// IngestResult is the summary returned by Ingest.
type IngestResult struct {
	ActionsInserted int
	TokensInserted  int
	ProjectsTouched int
	SessionsTouched int
	// CacheObservationsSeen is the count of cache observations the
	// caller supplied in IngestOptions.CacheObservations. C6 plumbs
	// the count through so the watcher → Ingest path is testable
	// end-to-end before C7 wires the engine. Replaced by an
	// engine-emitted result in C7 (event/segment/entry counts).
	CacheObservationsSeen int
	// GuardEventsRecorded is the count of guard_events rows the
	// post-hoc guard seam persisted for this batch (0 when no guard
	// is wired — see SetGuard).
	GuardEventsRecorded int
	// MessageContentRows is the count of otel_content rows the
	// adapter-side message-content producer inserted for this batch —
	// always 0 unless the node opted into content sharing (see
	// SetContentCapture / internal/store/messagecontent.go). Re-parsing an
	// already-captured window inserts nothing, so a steady 0 on a
	// content-capturing node means "nothing new", not "not wired".
	MessageContentRows int
	// SessionSurfacesSkipped counts the IngestOptions.SessionSurfaces
	// entries this batch did NOT persist: an out-of-vocabulary kind
	// (the emitting adapter leaked a raw vendor token instead of
	// resolving it through its table) or a write error. The stamp is
	// best-effort — it runs AFTER actions and tokens have landed, so
	// failing the whole ingest over it would discard real captured work
	// — but the store has no logger, so the count is how the failure
	// stays visible instead of vanishing. A steady non-zero here on a
	// given adapter is a bug in that adapter's surface table.
	SessionSurfacesSkipped int
	// SessionToolVersionsSkipped counts the
	// IngestOptions.SessionToolVersions entries this batch did NOT
	// persist because of a store WRITE ERROR. A malformed value returns
	// (false, nil) from SetSessionToolVersion and is silently skipped
	// (not counted here) — the version column is best-effort. Best-effort
	// like SessionSurfacesSkipped: it runs AFTER actions and tokens have
	// landed, so the count is how a write failure stays visible without a
	// logger the store does not have.
	SessionToolVersionsSkipped int
}

// Ingest is the high-level batch API used by the watcher and scan commands.
// It resolves projects from ToolEvent.ProjectRoot, upserts sessions, and
// inserts actions + token events in one go.
//
// Events with an empty SessionID or empty ProjectRoot are skipped and
// counted in warnings (callers should prefer to filter upstream).
func (s *Store) Ingest(
	ctx context.Context,
	events []models.ToolEvent,
	tokens []models.TokenEvent,
	opts IngestOptions,
) (IngestResult, error) {
	return s.ingest(ctx, events, tokens, opts, false)
}

func (s *Store) ingest(ctx context.Context, events []models.ToolEvent, tokens []models.TokenEvent, opts IngestOptions, usageOnly bool) (IngestResult, error) {
	if opts.IsNativeTool == nil {
		opts.IsNativeTool = func(string) bool { return false }
	}
	// Fall back to the Store-bound Indexer (WithIndexer) when the
	// caller didn't supply one in opts. Lets hook handlers wire the
	// indexer once at Store creation rather than threading IngestOptions
	// through every Ingest call site. Per-call opts.Indexer still wins
	// (the daemon watcher passes its long-lived indexer this way).
	if opts.Indexer == nil && s.indexer != nil {
		opts.Indexer = s.indexer
	}

	projectIDs := map[string]int64{}
	sessionsSeen := map[string]struct{}{}
	sessionExistsCache := map[string]bool{}
	var result IngestResult

	actionCapacity := len(events)
	if usageOnly {
		actionCapacity = 0
	}
	actions := make([]models.Action, 0, actionCapacity)

	// Guard post-hoc seam (guard spec §7): collect evaluation inputs
	// in EVENT ORDER as actions insert (order matters — taint marks
	// from an earlier action must be visible to a later sink in the
	// same batch). batchIdx >= 0 marks inputs whose action id is only
	// known after the batched InsertActions; -1 marks single-insert
	// (classifier-branch) inputs that already carry it. Collection is
	// skipped entirely when no guard is wired (zero overhead).
	type guardPending struct {
		input    guard.ActionInput
		batchIdx int
	}
	var pendingGuard []guardPending

	// Batch indices of actions whose tool call has no observed outcome
	// yet (models.ToolEvent.OutcomePending). Their success=true is an
	// optimistic placeholder, so failure-context bookkeeping is held
	// back until the matching ActionOutcomeUpdate arrives — see the
	// RecordFailures loops below.
	outcomePending := map[int]bool{}

	for _, e := range events {
		if e.SessionID == "" || e.ProjectRoot == "" {
			continue
		}
		// A terminal lifecycle marker (session_end) must not bootstrap a
		// session that has no other record. Windows Claude Code fires a
		// session_end hook for empty/probe sessions that never produced a
		// transcript; routed through Ingest, that conjured a phantom
		// session whose only row is the session_end itself (no actions,
		// api_turns, or token rows) — surfacing as a contentless session on
		// the dashboard. Skip the event when the session is unknown both in
		// this batch and in the DB. A real session — created by the
		// watcher's transcript parse, or by an earlier event in this batch —
		// already exists, so its session_end still attaches normally.
		if e.ActionType == models.ActionSessionEnd {
			if _, seen := sessionsSeen[e.SessionID]; !seen {
				exists, cached := sessionExistsCache[e.SessionID]
				if !cached {
					var err error
					exists, err = s.sessionExists(ctx, e.SessionID)
					if err != nil {
						return result, err
					}
					sessionExistsCache[e.SessionID] = exists
				}
				if !exists {
					continue
				}
			}
		}
		pid, ok := projectIDs[e.ProjectRoot]
		if !ok {
			var err error
			pid, err = s.UpsertProjectWithIdentity(ctx, e.ProjectRoot, e.GitRemote, ProjectIdentity{
				UpstreamRemote:     e.GitUpstreamRemote,
				RemoteOwner:        e.GitRemoteOwner,
				UpstreamOwner:      e.GitUpstreamOwner,
				RootCommitSHA:      e.RootCommitSHA,
				ContentFingerprint: e.ContentFingerprint,
			})
			if err != nil {
				return result, err
			}
			projectIDs[e.ProjectRoot] = pid
			result.ProjectsTouched++
			s.maybeRunLazyRootCommit(ctx, e.ProjectRoot)
		}
		if _, ok := sessionsSeen[e.SessionID]; !ok {
			err := s.UpsertSession(ctx, models.Session{
				ID:         e.SessionID,
				ProjectID:  pid,
				Tool:       e.Tool,
				Model:      e.Model,
				GitBranch:  e.GitBranch,
				StartedAt:  e.Timestamp,
				Workspace:  e.Workspace,
				IsWorktree: e.IsWorktree,
			})
			if err != nil {
				return result, err
			}
			sessionsSeen[e.SessionID] = struct{}{}
			result.SessionsTouched++
		}
		if usageOnly {
			continue
		}
		act := models.Action{
			SessionID:          e.SessionID,
			ProjectID:          pid,
			Timestamp:          e.Timestamp,
			TurnIndex:          e.TurnIndex,
			ActionType:         e.ActionType,
			IsNativeTool:       opts.IsNativeTool(e.RawToolName),
			Target:             e.Target,
			TargetHash:         sha256Hex(e.Target),
			Success:            e.Success,
			ErrorMessage:       e.ErrorMessage,
			DurationMs:         e.DurationMs,
			PrecedingReasoning: e.PrecedingReasoning,
			RawToolName:        e.RawToolName,
			RawToolInput:       e.RawToolInput,
			ContentBytes:       e.ContentBytes,
			RawToolOutput:      e.ToolOutput,
			Tool:               e.Tool,
			SourceFile:         e.SourceFile,
			SourceEventID:      e.SourceEventID,
			IsSidechain:        e.IsSidechain,
			MessageID:          e.MessageID,
			Metadata:           e.Metadata,
			UserAttachments:    e.UserAttachments,
		}

		// File-typed actions with a classifier go through a per-event
		// classify → insert → file_state upsert cycle, so that a second
		// file event in this same batch sees the first one's hash.
		// Non-file actions stay in the batched actions slice.
		if opts.Classifier != nil && isFileAction(e.ActionType) {
			abs := resolveAbs(e.ProjectRoot, e.Target)
			if abs != "" {
				obs, err := opts.Classifier.Classify(ctx, pid, e.SessionID, e.ActionType, abs)
				if err == nil {
					act.ContentHash = obs.ContentHash
					act.FileMtime = obs.FileMtime
					act.FileSizeBytes = obs.FileSizeBytes
					act.Freshness = obs.Freshness
					act.PriorActionID = obs.PriorActionID
					act.ChangeDetected = obs.ChangeDetected
				}
				inserted, err := s.insertSingleAction(ctx, &act)
				if err != nil {
					return result, err
				}
				if inserted && act.ContentHash != "" {
					if err := opts.Classifier.UpsertFileState(
						ctx, pid, abs,
						freshness.FileObservation{
							ContentHash:    act.ContentHash,
							FileMtime:      act.FileMtime,
							FileSizeBytes:  act.FileSizeBytes,
							Freshness:      act.Freshness,
							PriorActionID:  act.PriorActionID,
							ChangeDetected: act.ChangeDetected,
						},
						act.ID, act.ActionType, e.SessionID,
					); err != nil {
						return result, err
					}
				}
				if inserted {
					result.ActionsInserted++
					if s.guard != nil {
						pendingGuard = append(pendingGuard, guardPending{
							batchIdx: -1,
							input: guard.ActionInput{
								ActionID:       act.ID,
								SessionID:      e.SessionID,
								ProjectRoot:    e.ProjectRoot,
								Tool:           e.Tool,
								ActionType:     e.ActionType,
								Target:         e.Target,
								Timestamp:      e.Timestamp,
								TurnIndex:      e.TurnIndex,
								Success:        e.Success,
								ExternalChange: act.ChangeDetected,
							},
						})
					}
				}
				continue
			}
		}

		actions = append(actions, act)
		if e.OutcomePending {
			outcomePending[len(actions)-1] = true
		}
		if s.guard != nil {
			pendingGuard = append(pendingGuard, guardPending{
				batchIdx: len(actions) - 1,
				input: guard.ActionInput{
					SessionID:   e.SessionID,
					ProjectRoot: e.ProjectRoot,
					Tool:        e.Tool,
					ActionType:  e.ActionType,
					Target:      e.Target,
					Timestamp:   e.Timestamp,
					TurnIndex:   e.TurnIndex,
					Success:     e.Success,
				},
			})
		}
	}

	if usageOnly {
		// Session bootstrap above uses the original events. The remaining
		// action/content/LOC stages must not replay historical tool work during
		// a budget catchup; the ordinary watcher still owns those stages.
		events = nil
	}

	// Upsert sessions referenced only by TokenEvents (e.g. subagent
	// compaction turns that have usage but no tool_use blocks).
	validTokens := make([]models.TokenEvent, 0, len(tokens))
	for _, tk := range tokens {
		if tk.SessionID == "" {
			continue
		}
		if _, ok := sessionsSeen[tk.SessionID]; ok {
			validTokens = append(validTokens, tk)
			continue
		}
		if tk.ProjectRoot == "" {
			// No project root on the token event (e.g. Cursor's stop hook,
			// whose workspace_roots we can't always decode). token_usage
			// carries no project_id — it attaches by session_id — so a
			// project is only needed to BOOTSTRAP a missing session row.
			// When the session already exists in the DB the token attaches
			// cleanly; only skip when the session is truly unknown (nothing
			// to attach to and no project to conjure one). Reuses the
			// session-existence cache the session_end guard populates.
			exists, cached := sessionExistsCache[tk.SessionID]
			if !cached {
				var err error
				exists, err = s.sessionExists(ctx, tk.SessionID)
				if err != nil {
					return result, err
				}
				sessionExistsCache[tk.SessionID] = exists
			}
			if exists {
				validTokens = append(validTokens, tk)
			}
			continue
		}
		pid, ok := projectIDs[tk.ProjectRoot]
		if !ok {
			var err error
			pid, err = s.UpsertProjectWithIdentity(ctx, tk.ProjectRoot, tk.GitRemote, ProjectIdentity{
				UpstreamRemote:     tk.GitUpstreamRemote,
				RemoteOwner:        tk.GitRemoteOwner,
				UpstreamOwner:      tk.GitUpstreamOwner,
				RootCommitSHA:      tk.RootCommitSHA,
				ContentFingerprint: tk.ContentFingerprint,
			})
			if err != nil {
				return result, err
			}
			projectIDs[tk.ProjectRoot] = pid
			result.ProjectsTouched++
			s.maybeRunLazyRootCommit(ctx, tk.ProjectRoot)
		}
		err := s.UpsertSession(ctx, models.Session{
			ID:         tk.SessionID,
			ProjectID:  pid,
			Tool:       tk.Tool,
			Model:      tk.Model,
			GitBranch:  tk.GitBranch,
			StartedAt:  tk.Timestamp,
			Workspace:  tk.Workspace,
			IsWorktree: tk.IsWorktree,
		})
		if err != nil {
			return result, err
		}
		sessionsSeen[tk.SessionID] = struct{}{}
		result.SessionsTouched++
		validTokens = append(validTokens, tk)
	}

	// Transfer previously captured transcript rows before replay can collide
	// with their stable source keys. Sessions have been upserted above.
	for _, lin := range opts.SessionLineages {
		if err := s.reassignSessionSource(ctx, lin); err != nil {
			return result, err
		}
	}
	n, err := s.InsertActions(ctx, actions)
	if err != nil {
		return result, err
	}
	result.ActionsInserted += n

	if opts.RecordFailures {
		for i := range actions {
			a := &actions[i]
			if a.ID == 0 || a.ActionType != models.ActionRunCommand {
				continue
			}
			if outcomePending[i] {
				// Outcome not observed yet. Filing it now would record
				// an unobserved success and wrongly flip every prior
				// failure of the same command to eventually_succeeded.
				// The OutcomeUpdate loop below files it for real once
				// the tool_result lands.
				continue
			}
			if err := s.recordCommandOutcome(ctx, a); err != nil {
				// failure_context is a supplementary index for the
				// dashboard's "this command kept failing" view — not
				// the main action data path. A per-row insert error
				// (e.g. an FK violation if the action row's session
				// or project was elided by an earlier upsert race)
				// shouldn't fail the entire batch and rip down the
				// watcher. Log to stderr and keep going so the
				// actions/tokens that DID land stay landed.
				fmt.Fprintf(os.Stderr,
					"store.Ingest: recordCommandOutcome non-fatal err for action_id=%d session=%s tool=%s: %v\n",
					a.ID, a.SessionID, a.Tool, err)
			}
		}
	}

	if opts.Indexer != nil {
		if err := s.indexOutputs(ctx, events, actions, opts.Indexer); err != nil {
			return result, err
		}
	}

	// Cross-tick outcomes: a tool_result whose tool_use was inserted by
	// an earlier Ingest call, which the action upsert can only partly
	// express (its ON CONFLICT success rule is a one-way 1 → 0 repair
	// and needs the corrected event re-emitted in one window). Applied
	// AFTER the batch insert so an update targeting a row created in
	// THIS same batch still lands. Tool name / target are empty by
	// design — the adapter no longer knows them cross-tick — so the
	// FTS excerpt indexes on output alone.
	//
	// Errors are COLLECTED, not swallowed: this record is the only
	// carrier of the outcome, and the watcher advances its cursor past
	// it as soon as Ingest returns nil. The realistic error class is
	// transient (SQLITE_BUSY against a concurrent hook process), so
	// failing the tick — exactly as an InsertActions error would — is
	// what makes the watcher retry the window whole. Re-processing is
	// idempotent (upserts plus idempotent updates). A zero-row update
	// is NOT an error: the row may be unknown or pruned.
	var updateErrs []error
	for _, up := range opts.OutcomeUpdates {
		if up.SourceFile == "" || up.SourceEventID == "" {
			continue
		}
		n, err := s.updateActionOutcome(ctx, up.SourceFile, up.SourceEventID,
			up.SuccessKnown, up.Success, up.ErrorMessage, up.DurationMs, up.ToolOutput, "", "",
			opts.Indexer)
		if err != nil {
			updateErrs = append(updateErrs, fmt.Errorf("%s#%s: %w", up.SourceFile, up.SourceEventID, err))
			continue
		}
		if n > 0 && opts.RecordFailures && up.SuccessKnown {
			// The moment the outcome is actually known is the moment
			// failure_context may be written — the insert-time call
			// above deliberately skipped this row. Non-fatal, mirroring
			// that call site.
			if err := s.recordOutcomeUpdateFailureContext(ctx, up); err != nil {
				fmt.Fprintf(os.Stderr,
					"store.Ingest: outcome recordCommandOutcome non-fatal err for source_file=%s source_event_id=%s: %v\n",
					up.SourceFile, up.SourceEventID, err)
			}
		}
	}

	tn, err := s.InsertTokenEvents(ctx, validTokens)
	if err != nil {
		return result, err
	}
	result.TokensInserted = tn

	// sessions.model rollup (IDE-13 / plan C8): several adapters (codex,
	// cursor, cline, cowork, ...) emit ToolEvents with no Model, leaving
	// sessions.model permanently empty even though the same session's
	// token_usage rows carry it. Best-effort like the cache/pid seams
	// below — a rollup failure is a cosmetic gap in a summary column,
	// never a reason to fail the token insert that already landed.
	if len(validTokens) > 0 {
		rollupIDs := make([]string, 0, len(validTokens))
		for _, tk := range validTokens {
			rollupIDs = append(rollupIDs, tk.SessionID)
		}
		_ = s.rollupSessionModels(ctx, rollupIDs)
	}

	// Cache observations Tier-2 wiring. C6 plumbed the count;
	// C10 (this commit) feeds the slice into the engine. The
	// CacheEventExistsForMessage dedup gate is per-observation —
	// a Tier-1 event already persisted for this message_id (the
	// proxy saw the turn first) skips the engine + persist
	// pair, keeping CacheModel state consistent. Persistence
	// failures are WARN-only per spec §8 ("cache writes must
	// NOT fail the turn insert"); they're swallowed so a
	// transient DB error can't kill the user-visible ingest.
	result.CacheObservationsSeen = len(opts.CacheObservations)
	if s.cacheEngine != nil && len(opts.CacheObservations) > 0 {
		for _, obs := range opts.CacheObservations {
			if exists, derr := s.CacheEventExistsForMessage(ctx, obs.SessionID, obs.MessageID); derr == nil && exists {
				continue
			}
			in, persistResult := s.observationToObserveInput(obs)
			engineResult := s.cacheEngine.ObserveTurn(in)
			if !persistResult {
				continue
			}
			_ = s.PersistCacheObservation(ctx, in, engineResult, 0, 0)
		}
	}

	// Session-process attribution seeds. Adapters that read a live
	// local pid from their own session data (cline-cli sessions.pid,
	// qwen-code runtime.json) hand candidates up through
	// ParseResult → IngestOptions; here — on the daemon host that owns
	// the pid — we validate liveness + identity and write the surviving
	// links into session_pid_bridge. This is the watcher-path analogue
	// of the SessionStart hook's ancestor-walk; the store is the single
	// owner of the table write so pidbridge types never leak past this
	// seam. Best-effort per spec P1: a bad pid or a write error is
	// swallowed and can never fail the user-visible ingest.
	if len(opts.SessionProcessSeeds) > 0 {
		bridge := pidbridge.New(s.db)
		for _, seed := range opts.SessionProcessSeeds {
			if seed.PID <= 1 || seed.SessionID == "" || seed.Tool == "" {
				continue
			}
			if !pidbridge.ValidateLocalProcess(seed.PID, seed.ExecHint) {
				continue
			}
			_ = bridge.Write(ctx, pidbridge.Entry{
				PID:       seed.PID,
				SessionID: seed.SessionID,
				Tool:      seed.Tool,
				CWD:       seed.CWD,
			})
		}
	}

	// Session lineage (migration 069): stamp codex fork/subagent markers
	// onto the sessions upserted above. NODE-LOCAL; a missing session id
	// matches zero rows (silent no-op).
	for _, lin := range opts.SessionLineages {
		if lin.SessionID == "" {
			continue
		}
		if _, err := s.SetSessionLineage(ctx, lin); err != nil {
			return result, err
		}
		if err := s.reconcileSourceAPITurns(ctx, lin); err != nil {
			return result, err
		}
	}

	// Capture-surface attribution (migration 107): stamp the normalized
	// surface kind + host an adapter resolved at its boundary onto the
	// sessions upserted above. NODE-LOCAL; a missing session id matches
	// zero rows (silent no-op).
	//
	// BEST-EFFORT, like the pidbridge / cache-observation seams above.
	// SetSessionSurface stays strict for direct callers (an
	// out-of-vocabulary kind is a programming error in the emitting
	// adapter and is refused loudly), but this seam runs AFTER the
	// actions and token rows have already been written — propagating
	// the error here would report a failed ingest for work that
	// actually landed, and the watcher would then retry the whole file
	// forever on a stamp it can never satisfy. So a rejected or failing
	// stamp is counted, not returned: SessionSurfacesSkipped is how the
	// failure stays visible without a logger the store does not have.
	for _, sf := range opts.SessionSurfaces {
		if sf.SessionID == "" {
			continue
		}
		if _, err := s.SetSessionSurface(ctx, sf); err != nil {
			result.SessionSurfacesSkipped++
		}
	}

	// Captured tool/CLI version (migration 125): stamp the free-form
	// version an adapter resolved at its boundary onto the sessions
	// upserted above. NODE-LOCAL; FIRST-WINS-UNLESS-EMPTY. Same
	// best-effort posture as the surface seam above — it runs AFTER the
	// actions/tokens landed, so a write error is counted, not returned.
	// A malformed value returns (false, nil) and is skipped silently
	// inside SetSessionToolVersion.
	for _, tv := range opts.SessionToolVersions {
		if tv.SessionID == "" {
			continue
		}
		if _, err := s.SetSessionToolVersion(ctx, tv); err != nil {
			result.SessionToolVersionsSkipped++
		}
	}

	// Adapter-side message-content capture (enterprise ruling 2026-08-28):
	// feed the conversation text the adapters already parsed into
	// otel_content, so the org admin's Messages panel is populated for EVERY
	// tool, not only a native-OTel Claude Code. Gated at the producer on the
	// node's own content-sharing posture — see SetContentCapture — so a
	// metadata-only node writes nothing and stays byte-identical to the
	// pre-producer build. Best-effort like the cache/pid seams above: a
	// content-store failure is reported on stderr and never fails the
	// user-visible ingest.
	n, cerr := s.captureMessageContent(ctx, events)
	result.MessageContentRows = n
	if cerr != nil {
		fmt.Fprintf(os.Stderr, "store.Ingest: message-content capture non-fatal err (%d written): %v\n", n, cerr)
	}

	// Guard post-hoc evaluation (guard spec §7), last so the
	// user-visible ingest work always completes first. Only ACTUALLY
	// INSERTED actions evaluate (dedup-skipped rows keep ID 0 and are
	// dropped here — re-parsing a transcript never re-evaluates).
	// Failure-isolated end to end: evaluation faults surface as
	// guard_error verdicts inside EvaluateActions' Q2 wrapper, and a
	// persistence error is WARN-only — a guard problem never fails an
	// ingest (guard spec §17.4).
	if s.guard != nil && len(pendingGuard) > 0 {
		inputs := make([]guard.ActionInput, 0, len(pendingGuard))
		for _, p := range pendingGuard {
			if p.batchIdx >= 0 {
				id := actions[p.batchIdx].ID
				if id == 0 {
					continue // dedup-skipped: not inserted this batch
				}
				p.input.ActionID = id
			} else if p.input.ActionID == 0 {
				continue
			}
			inputs = append(inputs, p.input)
		}
		if verdicts := s.guard.EvaluateActions(inputs); len(verdicts) > 0 {
			n, gerr := s.PersistGuardVerdicts(ctx, verdicts)
			if gerr != nil {
				fmt.Fprintf(os.Stderr,
					"store.Ingest: guard verdict persist non-fatal err (%d/%d written): %v\n",
					n, len(verdicts), gerr)
			}
			result.GuardEventsRecorded = n
			// Desktop alerts ([guard.alerts]) fire after persistence —
			// MaybeAlert applies the min_severity threshold itself, so
			// flag-noise stays off the operator's screen.
			for i := range verdicts {
				s.guard.MaybeAlert(verdicts[i])
			}
		}
	}

	// Lines-of-code capture (docs/plans/lines-of-code-tracking-plan-2026-09-07.md
	// §3.2). ONE call, here, after every action row exists: the LOC seam
	// resolves each edit/write event back to its stored row and counts the
	// authored lines from the raw_tool_input the store already holds. It
	// owns its own table (internal/store/loc.go) and threads no type back
	// through Ingest. Failure-isolated like the guard stage above — a
	// counting problem must never cost the operator an ingest.
	if _, lerr := s.RecordFileChanges(ctx, events); lerr != nil {
		warnLOC("record", lerr)
	}

	// Task-tracking post-hoc decode (internal/store/taskflow.go, migration
	// 109): re-reads the todo_update / task_complete / post_tool_batch rows
	// ACTUALLY INSERTED above into per-item task_items/task_transitions.
	// Best-effort like the cache/guard seams above — a decode error is a
	// bug in one tool's payload shape, never a reason to fail the
	// user-visible ingest that already landed. No-ops entirely when
	// [tasks].enabled is false (SetTasksEnabled default).
	if _, terr := s.applyTaskEvents(ctx, actions); terr != nil {
		fmt.Fprintf(os.Stderr, "store.Ingest: task-tracking decode non-fatal err: %v\n", terr)
	}

	if err := s.RecordToolAccounts(ctx, opts.ToolAccounts); err != nil {
		updateErrs = append(updateErrs, err)
	}
	// Outcome-update failures are reported LAST, after every other
	// stage has run. Returning earlier would make a failed late outcome
	// cost the batch its guard evaluation and cache observations too:
	// the actions are already inserted by then, so the retry re-inserts
	// them as duplicates with ID == 0 and the guard stage drops them
	// (only genuinely-inserted rows evaluate). Retrying the updates
	// alone is idempotent, so this is the cheapest honest failure.
	if len(updateErrs) > 0 {
		return result, fmt.Errorf("store.Ingest: outcome update: %w", errors.Join(updateErrs...))
	}

	return result, nil
}

// observationToObserveInput translates a CacheTurnObservation
// (the cross-tier adapter→store seam type) into the engine's
// ObserveInput. Tier is hard-coded to TierTranscript here — the
// only callers today are Tier-2 (claudecode JSONL); future
// counts-only Tier-3 callers would route through a different
// adapter that builds its own ObserveInput. Returns a
// persistResult bool that's currently always true; reserved
// for future "engine-only observe, don't persist" diagnostics
// in case the backfill flag adds a dry-run mode.
func (s *Store) observationToObserveInput(obs models.CacheTurnObservation) (cachetrack.ObserveInput, bool) {
	blocks := make([]cachetrack.ObserveBlock, 0, len(obs.BlockHashes))
	// Session-handoff marker: for this Tier-2 lane the reconstructed
	// block bodies (CanonicalBytes) carry the turn's actual content,
	// so we can scan them here — no extra I/O. The marker rides into a
	// handoff TARGET session's early content (injected first prompt,
	// SessionStart context, or a HANDOFF-<id>.md file read landing as a
	// tool_result). cachetrack only consults the flag on the first
	// observed turn (Prior == nil), so scanning every turn is harmless.
	// Non-proxied lanes whose blocks don't reconstruct the marker (or
	// counts-only Tier-3) fall through to the advisor's retroactive
	// handoff-target exemption.
	var handoffMarker bool
	for _, bh := range obs.BlockHashes {
		if !handoffMarker && bytes.Contains(bh.CanonicalBytes, []byte(handoff.MarkerPrefix)) {
			handoffMarker = true
		}
		blocks = append(blocks, cachetrack.ObserveBlock{
			Level:          cachetrack.BlockLevelFromLabel(bh.LevelLabel),
			Kind:           bh.Kind,
			CanonicalBytes: bh.CanonicalBytes,
			Role:           bh.Role,
		})
	}
	in := cachetrack.ObserveInput{
		SessionID:      obs.SessionID,
		Model:          obs.Model,
		Scope:          "default",
		Tier:           cachetrack.TierTranscript,
		MessageID:      obs.MessageID,
		Now:            obs.Timestamp,
		Fast:           obs.Fast,
		CompactionSeen: obs.CompactionSeen,
		HandoffMarker:  handoffMarker,
		Blocks:         blocks,
		Usage: cachetrack.CacheUsageObserved{
			NetInputTokens:        obs.Usage.NetInputTokens,
			OutputTokens:          obs.Usage.OutputTokens,
			CacheReadTokens:       obs.Usage.CacheReadTokens,
			CacheCreationTokens:   obs.Usage.CacheCreationTokens,
			CacheCreation1hTokens: obs.Usage.CacheCreation1hTokens,
		},
	}
	// §15.3 boundary-overlay: when the adapter signals implicit
	// routing (codex Tier-2, cline-cli/opencode/kilo against an
	// implicit-cache provider), overlay Capabilities.ImplicitCache=
	// true so the engine dispatches to the reduced attribution
	// path. Same shape as the proxy boundary at internal/proxy/
	// proxy.go::buildCacheObserveInput. The engine never sees
	// the adapter name or the provider string — only the
	// capability.
	if obs.ImplicitCache {
		caps := cachetrack.CapabilitiesFor(cachetrack.TierTranscript)
		caps.ImplicitCache = true
		in.Caps = caps
	}
	return in, true
}

// indexOutputs records tool output excerpts in the FTS5 action_excerpts
// table. It matches inserted actions (ID != 0) back to their originating
// event by SourceEventID and skips events whose ToolOutput is empty.
func (s *Store) indexOutputs(
	ctx context.Context,
	events []models.ToolEvent,
	actions []models.Action,
	idx *indexing.Indexer,
) error {
	byID := make(map[string]*models.Action, len(actions))
	for i := range actions {
		a := &actions[i]
		if a.ID == 0 {
			continue
		}
		byID[a.SourceEventID] = a
	}
	for i := range events {
		e := &events[i]
		if e.ToolOutput == "" {
			continue
		}
		a, ok := byID[e.SourceEventID]
		if !ok {
			continue
		}
		// Skip indexing MCP tool outputs. Their bodies are derived
		// query data — JSON hit lists from search_past_outputs,
		// stashed-bytes echoes from retrieve_stashed, cost summaries,
		// etc. Indexing them creates a recursive self-reference loop:
		// a query for "app.set" matches every prior search whose
		// JSON hit-list mentioned "app.set", which match more priors,
		// degrading FTS5 quality session-over-session. Surfaced
		// 2026-05-08 dogfood — the model itself flagged "Many of the
		// hits are recursive — prior search_past_outputs calls for
		// the same/similar query that themselves got indexed." Same
		// `isMCPToolName` predicate as the per-type compression skip
		// in conversation/anthropic.go.
		if isMCPToolName(e.RawToolName) {
			continue
		}
		if err := idx.Index(ctx, a.ID, e.RawToolName, a.Target, e.ToolOutput, a.ErrorMessage); err != nil {
			return err
		}
	}
	return nil
}

// isMCPToolName reports whether a raw tool name is from an MCP server
// (Anthropic's MCP convention prefixes such names with
// `mcp__<server>__<tool>`). Duplicated from
// conversation/anthropic.go::isMCPToolName because the store package
// is downstream of conversation in the import graph and we keep the
// helper inline rather than introduce a tiny shared dependency.
func isMCPToolName(name string) bool {
	return strings.HasPrefix(name, "mcp__")
}

// recordCommandOutcome maintains failure_context for a single run_command
// action: failed commands get a new row with retry_count set to the number of
// prior failures of the same command_hash in this session, and succeeded
// commands flip eventually_succeeded on all prior matching failure rows.
func (s *Store) recordCommandOutcome(ctx context.Context, a *models.Action) error {
	// Defensive guard: failure_context has NOT NULL FKs on action_id,
	// session_id, project_id. If any of the referenced ids are zero/
	// empty, skip rather than provoke a FOREIGN KEY constraint failure
	// that the caller would have to swallow anyway.
	if a.ID == 0 || a.SessionID == "" || a.ProjectID == 0 {
		return nil
	}
	cmdHash := failure.CommandHash(a.Target)
	if cmdHash == "" {
		return nil
	}
	if a.Success {
		if _, err := s.db.ExecContext(
			ctx,
			`UPDATE failure_context SET eventually_succeeded = 1
			 WHERE session_id = ? AND command_hash = ? AND eventually_succeeded = 0`,
			a.SessionID, cmdHash,
		); err != nil {
			return fmt.Errorf("store.recordCommandOutcome: update succeeded: %w", err)
		}
		return nil
	}
	var retryCount int
	err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM failure_context
		 WHERE session_id = ? AND command_hash = ?`,
		a.SessionID, cmdHash,
	).Scan(&retryCount)
	if err != nil {
		return fmt.Errorf("store.recordCommandOutcome: count prior: %w", err)
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO failure_context (
			action_id, session_id, project_id, timestamp,
			command_hash, command_summary, error_category, error_message,
			retry_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.SessionID, a.ProjectID, timestamp(a.Timestamp),
		cmdHash, failure.CommandSummary(a.Target),
		failure.Categorize(a.ErrorMessage),
		failure.TruncateErrorMessage(a.ErrorMessage),
		retryCount,
	)
	if err != nil {
		return fmt.Errorf("store.recordCommandOutcome: insert: %w", err)
	}
	return nil
}

// recordOutcomeUpdateFailureContext files failure_context for a
// run_command row whose real outcome arrived cross-tick, after the
// insert-time pass deliberately skipped it (models.ToolEvent.
// OutcomePending). It reloads the identifying columns the bookkeeping
// needs — the update carries only the key plus the outcome — and hands
// recordCommandOutcome an Action bearing the NEW success/error, so a
// failure files with the right retry_count and a success flips prior
// failures of the same command at the moment it is actually observed.
//
// A non-run_command row, or a key that matches nothing, is a silent
// no-op.
//
// Unlike the insert-time call site, this one needs its own replay
// guard. There, a duplicate insert leaves Action.ID == 0 and the row is
// skipped; here the update MATCHES on every replay (RowsAffected counts
// matched rows, not changed ones), failure_context has no uniqueness on
// action_id, and recordCommandOutcome's failure branch is a plain
// INSERT — so a retried window (which an outcome-update error now
// deliberately causes) or a duplicate result record would re-file the
// same failure with an inflated retry_count. The success branch needs
// no guard: its UPDATE is already scoped WHERE eventually_succeeded = 0.
func (s *Store) recordOutcomeUpdateFailureContext(ctx context.Context, up models.ActionOutcomeUpdate) error {
	var (
		a  models.Action
		ts string
	)
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, session_id, project_id, timestamp, action_type, COALESCE(target, '')
		   FROM actions WHERE source_file = ? AND source_event_id = ?`,
		up.SourceFile, up.SourceEventID,
	).Scan(&a.ID, &a.SessionID, &a.ProjectID, &ts, &a.ActionType, &a.Target)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store.recordOutcomeUpdateFailureContext: load: %w", err)
	}
	if a.ActionType != models.ActionRunCommand {
		return nil
	}
	if !up.Success {
		var exists int
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT EXISTS(SELECT 1 FROM failure_context WHERE action_id = ?)`,
			a.ID,
		).Scan(&exists); err != nil {
			return fmt.Errorf("store.recordOutcomeUpdateFailureContext: replay check: %w", err)
		}
		if exists != 0 {
			return nil
		}
	}
	a.Timestamp = parseStamp(ts)
	a.Success = up.Success
	a.ErrorMessage = up.ErrorMessage
	return s.recordCommandOutcome(ctx, &a)
}

// insertSingleAction is the per-row path used for file-typed actions so the
// freshness pipeline can read and write file_state between adjacent events in
// the same batch. Returns (true, nil) when a new row was inserted;
// (false, nil) means a duplicate (source_file, source_event_id) was skipped
// via INSERT OR IGNORE.
func (s *Store) insertSingleAction(ctx context.Context, a *models.Action) (bool, error) {
	s.stamper.Stamp(actionOrgRow{a}) // no-op unless enrolled
	// Pre-check upsert-vs-insert: the `INSERT ... ON CONFLICT DO UPDATE`
	// SQL takes the UPDATE branch on conflict, which means RowsAffected()
	// returns 1 even for duplicates AND LastInsertId() returns the
	// connection's last successful true-INSERT rowid (per SQLite docs:
	// UPSERTs that turn into UPDATE do not change last_insert_rowid).
	// That stale rowid can point at a row long since pruned by retention
	// — file_state.last_action_id then FK-fails with SQLITE_CONSTRAINT_FOREIGNKEY
	// (787) when the caller chains UpsertFileState on a re-scanned action.
	//
	// Match the batch InsertActions path's pre-check pattern: SELECT first,
	// then either bind a.ID to the existing row (on UPDATE path) or take
	// LastInsertId only on the genuine-INSERT path. The lookup is a single
	// index probe on the UNIQUE (source_file, source_event_id) constraint.
	var existingID int64
	preCheckErr := s.db.QueryRowContext(
		ctx,
		`SELECT id FROM actions WHERE source_file = ? AND source_event_id = ?`,
		a.SourceFile, a.SourceEventID,
	).Scan(&existingID)
	if preCheckErr != nil && !errors.Is(preCheckErr, sql.ErrNoRows) {
		return false, fmt.Errorf("store.insertSingleAction: pre-check: %w", preCheckErr)
	}

	res, err := s.db.ExecContext(
		ctx, insertActionSQL,
		a.SessionID,
		a.ProjectID,
		timestamp(a.Timestamp),
		a.TurnIndex,
		a.ActionType,
		boolToInt(a.IsNativeTool),
		a.Target,
		a.TargetHash,
		boolToInt(a.Success),
		a.ErrorMessage,
		a.DurationMs,
		nullableString(a.ContentHash),
		nullableTimestamp(a.FileMtime),
		nullableInt64(a.FileSizeBytes),
		nullableString(a.Freshness),
		nullableInt64(a.PriorActionID),
		boolToInt(a.ChangeDetected),
		nullableString(a.PrecedingReasoning),
		nullableString(a.RawToolName),
		nullableString(a.RawToolInput),
		nullableString(a.RawToolOutput),
		a.Tool,
		a.SourceFile,
		sha256HexOrEmpty(a.SourceFile),
		a.SourceEventID,
		boolToInt(a.IsSidechain),
		nullableString(a.MessageID),
		marshalActionMetadata(a.Metadata),
		nullableString(a.OrgID),
		nullableString(a.UserEmail),
		nullableInt64(a.ContentBytes),
		marshalUserAttachments(a.UserAttachments),
	)
	if err != nil {
		return false, fmt.Errorf("store.insertSingleAction: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	if preCheckErr == nil {
		// UPSERT-UPDATE path: bind a.ID to the existing row. The caller's
		// downstream UpsertFileState then writes a valid last_action_id;
		// without this we'd use the stale LastInsertId.
		a.ID = existingID
	} else if id, err := res.LastInsertId(); err == nil {
		// Genuine INSERT path: LastInsertId is the freshly-assigned rowid.
		a.ID = id
	}
	return true, nil
}

// isFileAction reports whether actionType classifies a file target.
func isFileAction(actionType string) bool {
	_, ok := fileActionTypes[actionType]
	return ok
}

// resolveAbs resolves a possibly project-relative target into an absolute
// filesystem path suitable for freshness hashing. Returns "" for
// "[external]/..." pseudo-paths (handled as unknown).
func resolveAbs(projectRoot, target string) string {
	if target == "" {
		return ""
	}
	if strings.HasPrefix(target, "[external]/") {
		return ""
	}
	if filepath.IsAbs(target) {
		return target
	}
	if projectRoot == "" {
		return ""
	}
	return filepath.Join(projectRoot, target)
}

// CountActions returns the total number of rows in the actions table. Useful
// for tests and the status command.
func (s *Store) CountActions(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&n)
	return n, err
}

// InsertAPITurn records a single proxy-observed request/response pair. An
// empty SessionID becomes NULL; a zero ProjectID becomes NULL. Returns the
// new rowid.
//
// For successful turns Provider + Model are required. For error turns
// (HTTPStatus != 0) Model may be empty — the upstream sometimes
// rejects malformed requests before any model field is parsed, and
// a zero-token error row with empty model is still useful for
// surfacing the failure.
func (s *Store) InsertAPITurn(ctx context.Context, t models.APITurn) (int64, error) {
	var ownerErr error
	t.SessionID, ownerErr = s.transcriptChildForRequest(ctx, t.SessionID, t.RequestID)
	if ownerErr != nil {
		return 0, ownerErr
	}
	if t.Provider == "" {
		return 0, errors.New("store.InsertAPITurn: Provider is required")
	}
	if t.Model == "" && t.HTTPStatus == 0 {
		return 0, errors.New("store.InsertAPITurn: Model is required for non-error turns")
	}
	s.stamper.Stamp(apiTurnOrgRow{&t}) // no-op unless enrolled
	res, err := s.db.ExecContext(
		ctx,
		`INSERT INTO api_turns (
			session_id, project_id, timestamp,
			provider, model, request_id,
			input_tokens, output_tokens,
			cache_read_tokens, cache_creation_tokens, cache_creation_1h_tokens,
			web_search_requests,
			cost_usd, message_count, tool_use_count,
			system_prompt_hash, message_prefix_hash,
			time_to_first_token_ms, total_response_ms,
			stop_reason,
			compression_original_bytes, compression_compressed_bytes,
			compression_count, compression_dropped_count, compression_marker_count,
			http_status, error_class, error_message,
			org_id, user_email, fast, source,
			route, routing_generation, authority_source
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullableString(t.SessionID),
		nullableInt64(t.ProjectID),
		timestamp(t.Timestamp),
		t.Provider,
		t.Model,
		nullableString(t.RequestID),
		t.InputTokens,
		t.OutputTokens,
		nullableInt64(t.CacheReadTokens),
		nullableInt64(t.CacheCreationTokens),
		nullableInt64(t.CacheCreation1hTokens),
		nullableInt64(t.WebSearchRequests),
		nullableFloat64(t.CostUSD),
		nullableInt(t.MessageCount),
		nullableInt(t.ToolUseCount),
		nullableString(t.SystemPromptHash),
		nullableString(t.MessagePrefixHash),
		nullableInt64(t.TimeToFirstTokenMS),
		nullableInt64(t.TotalResponseMS),
		nullableString(t.StopReason),
		nullableInt64(t.CompressionOriginalBytes),
		nullableInt64(t.CompressionCompressedBytes),
		nullableInt64(t.CompressionCount),
		nullableInt64(t.CompressionDroppedCount),
		nullableInt64(t.CompressionMarkerCount),
		nullableInt(t.HTTPStatus),
		nullableString(t.ErrorClass),
		nullableString(t.ErrorMessage),
		nullableString(t.OrgID),
		nullableString(t.UserEmail),
		boolToInt(t.Fast),
		nullableString(t.Source),
		nullableString(t.Route),
		nullableInt64(t.RoutingGeneration),
		nullableString(t.AuthoritySource),
	)
	if err != nil {
		return 0, fmt.Errorf("store.InsertAPITurn: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store.InsertAPITurn: last insert id: %w", err)
	}
	// Per-event compression detail (migration 009). Best-effort: if the
	// table doesn't exist (pre-migration test DB) or insert fails for a
	// single event, we log and continue rather than abort the turn —
	// the aggregate columns above already captured what cost.Engine
	// needs. The dashboard's mechanism breakdown depends on these rows
	// landing, but the cost calc doesn't.
	if len(t.CompressionEvents) > 0 {
		for _, ev := range t.CompressionEvents {
			ts := ev.Timestamp
			if ts.IsZero() {
				ts = t.Timestamp
			}
			var importance any
			if ev.Mechanism == "drop" {
				importance = ev.ImportanceScore
			}
			// V7-9 (v1.7.12+): body_hash is sha256-hex of the
			// pre-compression body bytes, NULL for pre-v1.7.12
			// producers and 'drop' events. Migration 031 added
			// the column. nullableString writes NULL for empty
			// strings so the partial index stays small.
			if _, err := s.db.ExecContext(
				ctx,
				`INSERT INTO compression_events
					(api_turn_id, timestamp, mechanism, original_bytes,
					 compressed_bytes, msg_index, importance_score, body_hash)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				id, timestamp(ts), ev.Mechanism,
				ev.OriginalBytes, ev.CompressedBytes,
				nullableInt(ev.MsgIndex), importance,
				nullableString(ev.BodyHash),
			); err != nil {
				// Don't return — keep going so a partial schema (no 009
				// yet) doesn't break new turn ingestion.
				break
			}
		}
	}
	return id, nil
}

// CountAPITurns returns the total number of rows in api_turns. Useful for
// tests and the status command.
func (s *Store) CountAPITurns(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_turns`).Scan(&n)
	return n, err
}

// CountUniqueCompressions returns the number of distinct pre-compression
// tool_result bodies that hit the compressor for sessionID. (V7-9 dedup
// accounting, v1.7.12+.)
//
// Pre-v1.7.12 rows have NULL body_hash and are excluded — the partial
// index `idx_compression_events_turn_body_hash WHERE body_hash IS NOT
// NULL` keeps the query fast. Same body across N turns counts once;
// the same hash across two sessions counts once per session (the
// session_id scope is part of the dedup question, not a bug).
//
// For a gross event count, query `compression_events` directly without
// DISTINCT.
func (s *Store) CountUniqueCompressions(ctx context.Context, sessionID string) (int, error) {
	if strings.TrimSpace(sessionID) == "" {
		return 0, errors.New("store.CountUniqueCompressions: sessionID is required")
	}
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT ce.body_hash)
		FROM compression_events ce
		JOIN api_turns at ON ce.api_turn_id = at.id
		WHERE at.session_id = ?
		  AND ce.body_hash IS NOT NULL
	`, sessionID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store.CountUniqueCompressions: %w", err)
	}
	return n, nil
}

// --- helpers ---

func timestamp(t time.Time) string {
	if t.IsZero() {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// InsertObserverLog records a single line in the observer_log table. Level
// should be one of "debug", "info", "warn", "error". Details is optional —
// callers typically pass a compact JSON blob or the empty string.
func (s *Store) InsertObserverLog(ctx context.Context, level, component, message, details string) error {
	if strings.TrimSpace(level) == "" || strings.TrimSpace(component) == "" {
		return errors.New("store.InsertObserverLog: level and component required")
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO observer_log (timestamp, level, component, message, details)
		 VALUES (?, ?, ?, ?, ?)`,
		timestamp(time.Now().UTC()), level, component, message, nullableString(details),
	)
	if err != nil {
		return fmt.Errorf("store.InsertObserverLog: %w", err)
	}
	return nil
}

// UnrecoverableEntry is a row from the adapter_unrecoverable_files
// table (migration 025). Pins the file's identity (size + mtime) at
// the time of failure so the adapter can re-stat on lookup and
// invalidate when the file changes.
type UnrecoverableEntry struct {
	Adapter         string
	SourceFile      string
	FileSize        int64
	FileMtimeUnix   int64
	Reason          string
	LastAttemptedAt time.Time
}

// LookupUnrecoverable returns the persisted unrecoverable record for
// (adapter, sourceFile) when the supplied size + mtime still match
// the values captured at failure. Returns (nil, nil) on miss — either
// no entry exists, or the file has drifted (caller should retry the
// full recovery path and either re-mark or clear depending on
// outcome). Errors only on DB-layer failures.
//
// Used by the antigravity adapter (and any future adapter with
// expensive multi-path recovery) to short-circuit ParseSessionFile
// for files that already failed every available path. See
// docs/backfill-flag-audit-2026-05-19.md and the migration 025 header
// for the design rationale.
func (s *Store) LookupUnrecoverable(ctx context.Context, adapter, sourceFile string, fileSize, fileMtimeUnix int64) (*UnrecoverableEntry, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT adapter, source_file, file_size, file_mtime_unix, reason, last_attempted_at
		 FROM adapter_unrecoverable_files
		 WHERE adapter = ? AND source_file = ?`,
		adapter, sourceFile,
	)
	var e UnrecoverableEntry
	var attempted string
	if err := row.Scan(&e.Adapter, &e.SourceFile, &e.FileSize, &e.FileMtimeUnix, &e.Reason, &attempted); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store.LookupUnrecoverable: %w", err)
	}
	if e.FileSize != fileSize || e.FileMtimeUnix != fileMtimeUnix {
		// File has changed since the failure was recorded — the
		// caller should retry. Don't auto-delete here; the caller
		// decides whether the retry succeeds (clear) or fails again
		// (re-mark with the new size/mtime via MarkUnrecoverable).
		return nil, nil
	}
	t, terr := time.Parse(time.RFC3339Nano, attempted)
	if terr == nil {
		e.LastAttemptedAt = t
	}
	return &e, nil
}

// MarkUnrecoverable records (or refreshes) a failure entry. Upsert
// semantics: the same (adapter, source_file) key updates in place,
// replacing the size/mtime/reason/timestamp so a re-attempted-then-
// re-failed file pins to the latest content rather than the original
// failure's bytes.
func (s *Store) MarkUnrecoverable(ctx context.Context, adapter, sourceFile string, fileSize, fileMtimeUnix int64, reason string) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO adapter_unrecoverable_files
		   (adapter, source_file, file_size, file_mtime_unix, reason, last_attempted_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(adapter, source_file) DO UPDATE SET
		   file_size         = excluded.file_size,
		   file_mtime_unix   = excluded.file_mtime_unix,
		   reason            = excluded.reason,
		   last_attempted_at = excluded.last_attempted_at`,
		adapter, sourceFile, fileSize, fileMtimeUnix, reason,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("store.MarkUnrecoverable: %w", err)
	}
	return nil
}

// ClearUnrecoverable removes the failure record for (adapter,
// sourceFile). Called after a successful parse so a future change to
// the file doesn't get short-circuited by a stale entry. Idempotent
// — deleting a nonexistent row is a no-op.
func (s *Store) ClearUnrecoverable(ctx context.Context, adapter, sourceFile string) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM adapter_unrecoverable_files WHERE adapter = ? AND source_file = ?`,
		adapter, sourceFile,
	)
	if err != nil {
		return fmt.Errorf("store.ClearUnrecoverable: %w", err)
	}
	return nil
}

// UpsertClaudecodeEffort records an effort.level value extracted from a
// Claude Code hook payload (PreToolUse / PostToolUse / Stop /
// SubagentStop). Two writes happen in one transaction:
//
//  1. Sidecar upsert into claudecode_effort keyed by
//     (session_id, tool_use_id). Last-write-wins so a re-fired hook
//     just refreshes the value.
//  2. Best-effort stamp onto an already-inserted matching action row's
//     metadata.effort_level. Race-safe in both orderings: if the JSONL
//     parser hasn't inserted the action yet, the UPDATE no-ops and the
//     adapter-side lookup (LoadClaudecodeEffortMap) catches it on
//     ingest; if the row already exists, this UPDATE writes it
//     immediately so the dashboard reflects the effort without waiting
//     for a re-parse.
//
// toolUseID is the Anthropic `toolu_xxxxx` ID for tool-use events. For
// Stop / SubagentStop (no tool_use context) the hook passes a
// synthetic key (e.g. "__stop__:<uuid>") so it doesn't collide with
// per-tool rows.
func (s *Store) UpsertClaudecodeEffort(ctx context.Context, sessionID, toolUseID, effortLevel, eventName string) error {
	if sessionID == "" || toolUseID == "" || effortLevel == "" {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertClaudecodeEffort: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO claudecode_effort
		   (session_id, tool_use_id, effort_level, event_name, received_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(session_id, tool_use_id) DO UPDATE SET
		   effort_level = excluded.effort_level,
		   event_name   = excluded.event_name,
		   received_at  = excluded.received_at`,
		sessionID, toolUseID, effortLevel, eventName, now,
	); err != nil {
		return fmt.Errorf("store.UpsertClaudecodeEffort: insert sidecar: %w", err)
	}

	// Stamp any matching action row in place. source_event_id is the
	// Anthropic block ID for tool_use rows (set by
	// internal/adapter/claudecode/adapter.go::buildToolUseEvent).
	// json_set on a NULL column would yield NULL — coalesce first.
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE actions
		   SET metadata = json_set(COALESCE(metadata, '{}'), '$.effort_level', ?)
		 WHERE (session_id = ? OR session_id IN (SELECT id FROM sessions WHERE parent_thread_id = ?))
		   AND source_event_id = ?
		   AND tool            = 'claude-code'`,
		effortLevel, sessionID, sessionID, toolUseID,
	); err != nil {
		return fmt.Errorf("store.UpsertClaudecodeEffort: stamp action: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.UpsertClaudecodeEffort: commit: %w", err)
	}
	return nil
}

// LoadClaudecodeEffortMap returns toolUseID → effort_level for every
// claudecode_effort row in the given session. The claude-code JSONL
// adapter consults this map at parse time to stamp metadata.EffortLevel
// on tool-use events that fired BEFORE their hooks landed (or whose
// hooks haven't fired yet — the map is empty in that case, which is
// fine; the UpsertClaudecodeEffort UPDATE will catch up).
func (s *Store) LoadClaudecodeEffortMap(ctx context.Context, sessionID string) (map[string]string, error) {
	if sessionID == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT tool_use_id, effort_level FROM claudecode_effort WHERE session_id = ?`,
		sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf("store.LoadClaudecodeEffortMap: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var tid, eff string
		if err := rows.Scan(&tid, &eff); err != nil {
			return nil, fmt.Errorf("store.LoadClaudecodeEffortMap: scan: %w", err)
		}
		out[tid] = eff
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadClaudecodeEffortMap: rows: %w", err)
	}
	return out, nil
}

func nullableTimestamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableFloat64(v float64) any {
	if v == 0 {
		return nil
	}
	return v
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func sha256Hex(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sha256HexOrEmpty is sha256Hex's intentional alias used at INSERT call
// sites for path/file columns where a NULL/empty source yields an empty
// hash. The behavior is identical to sha256Hex; the second name documents
// intent at the call site (this column may legitimately be empty), so a
// reader doesn't need to re-derive the contract from the function body.
func sha256HexOrEmpty(s string) string { return sha256Hex(s) }
