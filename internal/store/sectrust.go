package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The repository trust accept flow (security pillar plan sections 4.6 and
// 5.1 item 5; agent migration 178, component security.trust).
//
// ONE OWNER: sec_config_baseline and sec_config_files (the config
// baseline snapshot, agent migration 180) are written exclusively here. NODE-LOCAL:
// a developer's accepts are never pushed (privacy sentinel). No file
// content is stored, only paths, keys, reason codes and digests.

// SecTrustItem is one judged item of one project: a reason the repository
// trust check raised, named by its content digest.
type SecTrustItem struct {
	// ContentHash is the item's digest (sectrust.Digest, "sha256:<hex>").
	ContentHash string
	// Scope is the agentconfig scope of the file ("project_shared",
	// "project_local", or "user" for the config baseline's home directory
	// items, recorded under the user-scope key, never a project's).
	Scope string
	// PathClass is the agentconfig trust class the file was read as.
	PathClass string
	// RelPath is slash-separated and relative to the repository root.
	RelPath string
	// ItemKey is the key path, variable name or git key in the file.
	ItemKey string
	// ReasonCode is the trust check's reason code.
	ReasonCode string
}

// SecTrustRecord is one stored item with its seen and accept stamps.
type SecTrustRecord struct {
	SecTrustItem
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	// AcceptedBy and AcceptedAt are empty and zero until the developer
	// accepts the digest.
	AcceptedBy string
	AcceptedAt time.Time
}

// Accepted reports whether the developer accepted the record's digest.
func (r SecTrustRecord) Accepted() bool { return !r.AcceptedAt.IsZero() }

// errNoProjectHash refuses a write or read with no project.
var errNoProjectHash = errors.New("store: sec_config_baseline needs a project root hash")

// secTrustBound caps the free-text columns.
const secTrustBound = 512

// upsertSecTrust writes items for one project, stamping seen times, and
// the accept when by is set.
func (s *Store) upsertSecTrust(ctx context.Context, op, projectRootHash string, items []SecTrustItem, by string, now time.Time) (int, error) {
	if strings.TrimSpace(projectRootHash) == "" {
		return 0, fmt.Errorf("%s: %w", op, errNoProjectHash)
	}
	stamp := stampTime(now)
	acceptedAt := ""
	if by != "" {
		acceptedAt = stamp
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = tx.Rollback() }()
	n := 0
	for _, it := range items {
		if !strings.HasPrefix(it.ContentHash, "sha256:") {
			return 0, fmt.Errorf("%s: digest %q is not a sha256 digest", op, it.ContentHash)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sec_config_baseline (
			    project_root_hash, content_hash, scope, path_class, rel_path, item_key, reason_code,
			    first_seen_at, last_seen_at, accepted_by, accepted_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(project_root_hash, content_hash) DO UPDATE SET
			    last_seen_at = excluded.last_seen_at,
			    accepted_by = CASE WHEN excluded.accepted_at <> '' THEN excluded.accepted_by ELSE sec_config_baseline.accepted_by END,
			    accepted_at = CASE WHEN excluded.accepted_at <> '' THEN excluded.accepted_at ELSE sec_config_baseline.accepted_at END`,
			projectRootHash, it.ContentHash, orDefaultScope(it.Scope, "project_shared"), boundText(it.PathClass, 64),
			boundText(it.RelPath, secTrustBound), boundText(it.ItemKey, secTrustBound), boundText(it.ReasonCode, 64),
			stamp, stamp, boundText(by, 128), acceptedAt); err != nil {
			return 0, fmt.Errorf("%s: %w", op, err)
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// RecordSecTrustItems records the items a trust check raised for one
// project (first and last seen), leaving any accept as it is.
func (s *Store) RecordSecTrustItems(ctx context.Context, projectRootHash string, items []SecTrustItem, now time.Time) error {
	_, err := s.upsertSecTrust(ctx, "store.RecordSecTrustItems", projectRootHash, items, "", now)
	return err
}

// AcceptSecTrustItems records the developer's accept of each item's exact
// digest, with who accepted it and when. by must name who accepted.
func (s *Store) AcceptSecTrustItems(ctx context.Context, projectRootHash string, items []SecTrustItem, by string, now time.Time) (int, error) {
	if strings.TrimSpace(by) == "" {
		return 0, errors.New("store.AcceptSecTrustItems: an accept must say who accepted")
	}
	return s.upsertSecTrust(ctx, "store.AcceptSecTrustItems", projectRootHash, items, by, now)
}

// RevokeSecTrustAccept clears the accept of one digest; the record stays.
// It reports whether an accept was cleared.
func (s *Store) RevokeSecTrustAccept(ctx context.Context, projectRootHash, contentHash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sec_config_baseline SET accepted_by = '', accepted_at = ''
		WHERE project_root_hash = ? AND content_hash = ? AND accepted_at <> ''`,
		projectRootHash, contentHash)
	if err != nil {
		return false, fmt.Errorf("store.RevokeSecTrustAccept: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store.RevokeSecTrustAccept: %w", err)
	}
	return n > 0, nil
}

// AcceptedSecTrustDigests returns the accepted digests of one project.
func (s *Store) AcceptedSecTrustDigests(ctx context.Context, projectRootHash string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT content_hash FROM sec_config_baseline
		WHERE project_root_hash = ? AND accepted_at <> ''`, projectRootHash)
	if err != nil {
		return nil, fmt.Errorf("store.AcceptedSecTrustDigests: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("store.AcceptedSecTrustDigests: %w", err)
		}
		out[h] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.AcceptedSecTrustDigests: %w", err)
	}
	return out, nil
}

// ListSecTrustItems returns one project's records, accepted first, then by
// path and key.
func (s *Store) ListSecTrustItems(ctx context.Context, projectRootHash string) ([]SecTrustRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT content_hash, scope, path_class, rel_path, item_key, reason_code,
		       first_seen_at, last_seen_at, accepted_by, accepted_at
		FROM sec_config_baseline WHERE project_root_hash = ?
		ORDER BY accepted_at = '' , rel_path, item_key, content_hash`, projectRootHash)
	if err != nil {
		return nil, fmt.Errorf("store.ListSecTrustItems: %w", err)
	}
	defer rows.Close()
	var out []SecTrustRecord
	for rows.Next() {
		var r SecTrustRecord
		var first, last, at string
		if err := rows.Scan(&r.ContentHash, &r.Scope, &r.PathClass, &r.RelPath, &r.ItemKey, &r.ReasonCode,
			&first, &last, &r.AcceptedBy, &at); err != nil {
			return nil, fmt.Errorf("store.ListSecTrustItems: %w", err)
		}
		r.FirstSeenAt = parseStamp(first)
		r.LastSeenAt = parseStamp(last)
		r.AcceptedAt = parseStamp(at)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListSecTrustItems: %w", err)
	}
	return out, nil
}

// orDefaultScope is s, or def when s is blank.
func orDefaultScope(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// SecConfigFile is one file of a stored config baseline snapshot
// (sec_config_files, agent migration 180).
type SecConfigFile struct {
	RelPath   string
	PathClass string
	SHA256    string
	Size      int64
}

// LoadSecConfigFiles returns one project's stored snapshot, by path, and
// whether one exists.
func (s *Store) LoadSecConfigFiles(ctx context.Context, projectRootHash string) ([]SecConfigFile, bool, error) {
	if strings.TrimSpace(projectRootHash) == "" {
		return nil, false, fmt.Errorf("store.LoadSecConfigFiles: %w", errNoProjectHash)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT rel_path, path_class, content_sha256, size_bytes FROM sec_config_files
		WHERE project_root_hash = ? ORDER BY rel_path`, projectRootHash)
	if err != nil {
		return nil, false, fmt.Errorf("store.LoadSecConfigFiles: %w", err)
	}
	defer rows.Close()
	var out []SecConfigFile
	found := false
	for rows.Next() {
		var f SecConfigFile
		if err := rows.Scan(&f.RelPath, &f.PathClass, &f.SHA256, &f.Size); err != nil {
			return nil, false, fmt.Errorf("store.LoadSecConfigFiles: %w", err)
		}
		found = true
		if f.RelPath == "" {
			continue // the empty-snapshot marker
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("store.LoadSecConfigFiles: %w", err)
	}
	return out, found, nil
}

// ReplaceSecConfigFiles stores one project's snapshot, replacing the
// previous one in one transaction.
func (s *Store) ReplaceSecConfigFiles(ctx context.Context, projectRootHash string, files []SecConfigFile, now time.Time) error {
	if strings.TrimSpace(projectRootHash) == "" {
		return fmt.Errorf("store.ReplaceSecConfigFiles: %w", errNoProjectHash)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.ReplaceSecConfigFiles: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sec_config_files WHERE project_root_hash = ?`, projectRootHash); err != nil {
		return fmt.Errorf("store.ReplaceSecConfigFiles: %w", err)
	}
	stamp := stampTime(now)
	if len(files) == 0 {
		// A project with no config files still has a snapshot, so the
		// first file it gains reads as added: one marker row with an empty
		// path stands for "taken, nothing there".
		files = []SecConfigFile{{}}
	}
	for _, f := range files {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sec_config_files (project_root_hash, rel_path, path_class, content_sha256, size_bytes, seen_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			projectRootHash, boundText(f.RelPath, secTrustBound), boundText(f.PathClass, 64), boundText(f.SHA256, 64), f.Size, stamp); err != nil {
			return fmt.Errorf("store.ReplaceSecConfigFiles: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.ReplaceSecConfigFiles: %w", err)
	}
	return nil
}

// AgentWriteAction is the latest agent file write to one path: what the
// config baseline attributes a change to.
type AgentWriteAction struct {
	ActionID  int64
	SessionID string
	Tool      string
	At        time.Time
}

// LatestAgentWriteTo returns the most recent agent write or edit action
// whose target is one of targets (the absolute and project-relative
// spellings of one file) at or after since, and whether there is one.
func (s *Store) LatestAgentWriteTo(ctx context.Context, targets []string, since time.Time) (AgentWriteAction, bool, error) {
	if len(targets) == 0 {
		return AgentWriteAction{}, false, nil
	}
	args := make([]any, 0, len(targets))
	marks := make([]string, 0, len(targets))
	for _, t := range targets {
		args = append(args, t)
		marks = append(marks, "?")
	}
	var a AgentWriteAction
	var at string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, session_id, tool, timestamp FROM actions
		WHERE target IN (`+strings.Join(marks, ",")+`) AND action_type IN ('write_file', 'edit_file')
		ORDER BY id DESC LIMIT 1`, args...).Scan(&a.ActionID, &a.SessionID, &a.Tool, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentWriteAction{}, false, nil
	}
	if err != nil {
		return AgentWriteAction{}, false, fmt.Errorf("store.LatestAgentWriteTo: %w", err)
	}
	a.At = parseStamp(at)
	if a.At.IsZero() || a.At.Before(since) {
		return AgentWriteAction{}, false, nil
	}
	return a, true, nil
}

// AgentFileWrite is one agent write or edit action with the root of the
// project it ran in: what the config baseline's event rescan reads.
type AgentFileWrite struct {
	ActionID    int64
	ProjectRoot string
	Target      string
}

// AgentFileWritesAfter returns the agent write and edit actions whose id is
// above afterID, oldest first, at most limit, each with its project's root
// (actions read, never written). It is the config baseline's change feed:
// both capture paths (the hooks and the watcher) land their actions here.
func (s *Store) AgentFileWritesAfter(ctx context.Context, afterID int64, limit int) ([]AgentFileWrite, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, COALESCE(p.root_path, ''), COALESCE(a.target, '') FROM actions a
		LEFT JOIN projects p ON p.id = a.project_id
		WHERE a.id > ? AND a.action_type IN ('write_file', 'edit_file')
		ORDER BY a.id LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store.AgentFileWritesAfter: %w", err)
	}
	defer rows.Close()
	var out []AgentFileWrite
	for rows.Next() {
		var w AgentFileWrite
		if err := rows.Scan(&w.ActionID, &w.ProjectRoot, &w.Target); err != nil {
			return nil, fmt.Errorf("store.AgentFileWritesAfter: scan: %w", err)
		}
		out = append(out, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.AgentFileWritesAfter: rows: %w", err)
	}
	return out, nil
}

// LatestActionID returns the highest action id (0 with none): where the
// config baseline's change feed starts, so a restart never replays history.
func (s *Store) LatestActionID(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(id) FROM actions`).Scan(&id); err != nil {
		return 0, fmt.Errorf("store.LatestActionID: %w", err)
	}
	return id.Int64, nil
}

// SecLastConfigSnapshot returns when one project's stored snapshot was
// taken (zero when there is none).
func (s *Store) SecLastConfigSnapshot(ctx context.Context, projectRootHash string) (time.Time, error) {
	var at sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(seen_at) FROM sec_config_files WHERE project_root_hash = ?`, projectRootHash).Scan(&at); err != nil {
		return time.Time{}, fmt.Errorf("store.SecLastConfigSnapshot: %w", err)
	}
	return parseStamp(at.String), nil
}

// SessionToolVersion is one (project, tool, recorded version) a session
// ran with: what the agent version hygiene check compares with its CVE
// table (security pillar plan section 5.1 item 4).
type SessionToolVersion struct {
	ProjectRoot string
	Tool        string
	ToolVersion string
	// SessionID is the newest session with this triple.
	SessionID string
}

// RecentSessionToolVersions returns the distinct (project, tool, version)
// triples of sessions started at or after since that recorded a version,
// at most limit, newest first. It only reads sessions and projects.
func (s *Store) RecentSessionToolVersions(ctx context.Context, since time.Time, limit int) ([]SessionToolVersion, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.root_path, s.tool, s.tool_version, MAX(s.id), MAX(s.started_at) AS latest
		FROM sessions s JOIN projects p ON p.id = s.project_id
		WHERE s.tool_version IS NOT NULL AND s.tool_version <> '' AND p.root_path <> '' AND s.started_at >= ?
		GROUP BY p.root_path, s.tool, s.tool_version
		ORDER BY latest DESC LIMIT ?`, stampTime(since), limit)
	if err != nil {
		return nil, fmt.Errorf("store.RecentSessionToolVersions: %w", err)
	}
	defer rows.Close()
	var out []SessionToolVersion
	for rows.Next() {
		var v SessionToolVersion
		var latest string
		if err := rows.Scan(&v.ProjectRoot, &v.Tool, &v.ToolVersion, &v.SessionID, &latest); err != nil {
			return nil, fmt.Errorf("store.RecentSessionToolVersions: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.RecentSessionToolVersions: %w", err)
	}
	return out, nil
}
