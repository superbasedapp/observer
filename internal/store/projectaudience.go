package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The node's index of the org-signed project mapping (agent migration 190,
// security plan section 7.11, lane sec-p). NODE-LOCAL: the privacy sentinel
// forbids orgpush.go from naming org_project_mapping_index.
//
// ONE WRITER (ReplaceOrgProjectMappingIndex, called by the org client after it
// accepted a v3 delivery; ClearOrgProjectMappingIndex on a re-enrolment) and
// one reader (LookupOrgProjects, the daemon's matcher). The signed mapping
// file stays the source of truth: the index is derived from it and replaced
// whole.

// OrgProjectMappingRow is one index row.
type OrgProjectMappingRow struct {
	Hash         string
	Kind         string // "remote" or "root"
	OrgProjectID string
}

// Index row kinds.
const (
	OrgProjectHashRemote = "remote"
	OrgProjectHashRoot   = "root"
)

// ReplaceOrgProjectMappingIndex replaces the whole index with rows, all under
// one epoch and mapping digest, in one transaction.
func (s *Store) ReplaceOrgProjectMappingIndex(ctx context.Context, epoch int64, digest string, rows []OrgProjectMappingRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.ReplaceOrgProjectMappingIndex: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_project_mapping_index`); err != nil {
		return fmt.Errorf("store.ReplaceOrgProjectMappingIndex: clear: %w", err)
	}
	for _, r := range rows {
		if r.Hash == "" || r.OrgProjectID == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO org_project_mapping_index (hash, kind, org_project_id, epoch, mapping_digest)
			VALUES (?, ?, ?, ?, ?)`, r.Hash, r.Kind, r.OrgProjectID, epoch, digest); err != nil {
			return fmt.Errorf("store.ReplaceOrgProjectMappingIndex: insert: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.ReplaceOrgProjectMappingIndex: commit: %w", err)
	}
	return nil
}

// ClearOrgProjectMappingIndex removes every row (a re-enrolment, or a node
// that no longer holds a v3 delivery).
func (s *Store) ClearOrgProjectMappingIndex(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM org_project_mapping_index`); err != nil {
		return fmt.Errorf("store.ClearOrgProjectMappingIndex: %w", err)
	}
	return nil
}

// ProjectAudienceFenceSuffix tags the guard_policy_state rows that record the
// last accepted project audience (Path = <org-server-url> + this suffix,
// Version = the epoch): the node's downgrade fence. Its writer is the org
// client (orgclient.ProjectAudienceStateSuffix is this constant).
const ProjectAudienceFenceSuffix = "#project-audience"

// ClearProjectAudienceFence removes the project audience's downgrade fence
// rows (a re-enrolment into a new identity starts a new fence, audit finding
// 9). They are the one guard_policy_state rows ever removed: the rest of that
// table stays an append-only load log.
func (s *Store) ClearProjectAudienceFence(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM guard_policy_state WHERE layer = 'org' AND substr(path, -length(?)) = ?`,
		ProjectAudienceFenceSuffix, ProjectAudienceFenceSuffix); err != nil {
		return fmt.Errorf("store.ClearProjectAudienceFence: %w", err)
	}
	return nil
}

// OrgProjectLookup is LookupOrgProjects' answer.
type OrgProjectLookup struct {
	// OrgProjectIDs are the matched projects, sorted.
	OrgProjectIDs []string
	// Epoch and MappingDigest are the index's (0 and "" for an empty index).
	Epoch         int64
	MappingDigest string
}

// LookupOrgProjects returns every project whose remote-kind hash is one of
// remoteHashes or whose root commit hash is rootHash, plus the epoch and
// digest the index holds. Empty hashes are ignored.
func (s *Store) LookupOrgProjects(ctx context.Context, remoteHashes []string, rootHash string) (OrgProjectLookup, error) {
	var out OrgProjectLookup
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(epoch), 0), COALESCE(MAX(mapping_digest), '') FROM org_project_mapping_index`).
		Scan(&out.Epoch, &out.MappingDigest); err != nil {
		return OrgProjectLookup{}, fmt.Errorf("store.LookupOrgProjects: header: %w", err)
	}
	var where []string
	var args []any
	for _, h := range remoteHashes {
		if h != "" {
			where = append(where, "(kind = ? AND hash = ?)")
			args = append(args, OrgProjectHashRemote, h)
		}
	}
	if rootHash != "" {
		where = append(where, "(kind = ? AND hash = ?)")
		args = append(args, OrgProjectHashRoot, rootHash)
	}
	if len(where) == 0 {
		return out, nil
	}
	//nolint:gosec // G202: the clauses are fixed text, the values bound.
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT org_project_id FROM org_project_mapping_index WHERE `+strings.Join(where, " OR "), args...)
	if err != nil {
		return OrgProjectLookup{}, fmt.Errorf("store.LookupOrgProjects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return OrgProjectLookup{}, fmt.Errorf("store.LookupOrgProjects: scan: %w", err)
		}
		out.OrgProjectIDs = append(out.OrgProjectIDs, id)
	}
	if err := rows.Err(); err != nil {
		return OrgProjectLookup{}, fmt.Errorf("store.LookupOrgProjects: rows: %w", err)
	}
	sort.Strings(out.OrgProjectIDs)
	return out, nil
}

// CachedRootCommit returns the root commit the lazy resolver stored for a
// project root ("" when none). The project audience's matcher reads it so a
// fork, mirror or remote-less copy still matches by root commit without an
// exec on its path.
func (s *Store) CachedRootCommit(ctx context.Context, rootPath string) (string, error) {
	var sha string
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(root_commit_sha, '') FROM projects WHERE root_path = ?`, normalizeProjectRoot(rootPath)).Scan(&sha)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("store.CachedRootCommit: %w", err)
	}
	return sha, nil
}

// ProjectAudienceRoots lists the project roots with a session started or
// ended since since, or created since then: the roots the daemon's project
// audience matcher keeps current. Core (the security module's
// SecActiveProjectRoots is compiled out with it). A root that is not a path
// (projectRootIsPath; FU-193's "Xcode (project unknown)") is left out: the
// matcher reads each root as a repository.
func (s *Store) ProjectAudienceRoots(ctx context.Context, since time.Time) ([]string, error) {
	ts := timestamp(since)
	rows, err := s.db.QueryContext(ctx, `SELECT root_path FROM projects
		WHERE root_path <> '' AND (created_at >= ? OR id IN (
			SELECT project_id FROM sessions WHERE started_at >= ? OR ended_at >= ?))
		ORDER BY root_path`, ts, ts, ts)
	if err != nil {
		return nil, fmt.Errorf("store.ProjectAudienceRoots: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, fmt.Errorf("store.ProjectAudienceRoots: %w", err)
		}
		if !projectRootIsPath(r) {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LaunchRootCommitDue reports whether the project audience's launch-time
// root-commit exec (lane sec-p2a, the fork and mirror hard case) should run
// for rootPath: true when the project has no row yet (a brand-new clone,
// which RootCommitNeedsCheck reports false for) or when RootCommitNeedsCheck
// says its 7-day retry fence is due. A cached root commit is never re-run.
func (s *Store) LaunchRootCommitDue(ctx context.Context, rootPath string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM projects WHERE root_path = ?`, normalizeProjectRoot(rootPath)).Scan(&n); err != nil {
		return false, fmt.Errorf("store.LaunchRootCommitDue: %w", err)
	}
	if n == 0 {
		return true, nil
	}
	return s.RootCommitNeedsCheck(ctx, rootPath)
}

// CacheLaunchRootCommit stores the result of the launch-time root-commit exec
// for rootPath. It creates the project row when the launch comes before the
// root's first session (the session's own ingest fills the rest,
// backfill-on-touch, and UpsertProject never clobbers with an empty value),
// and every attempt stamps the retry fence, so a repository whose exec fails
// or times out is retried at most every RootCommitRecheckInterval.
func (s *Store) CacheLaunchRootCommit(ctx context.Context, rootPath, sha string) error {
	if _, err := s.UpsertProjectWithIdentity(ctx, rootPath, "", ProjectIdentity{RootCommitSHA: sha}); err != nil {
		return fmt.Errorf("store.CacheLaunchRootCommit: %w", err)
	}
	return s.RecordRootCommitCheck(ctx, rootPath, sha)
}
