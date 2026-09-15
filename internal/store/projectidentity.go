package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
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
