package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Read-only git-commit-history capture, node-side (docs/plans/
// projects-page-roi-and-commit-alignment-plan-2026-09-21.md §2 R2/R3/R12,
// §3.2).
//
// THIS FILE IS THE ONE OWNER of project_commits / project_commit_files /
// project_commit_scan (agent migration 127) — CLAUDE.md module-boundary
// rule #4. Nothing else in the tree writes them. internal/commitscan calls
// through this seam via injected funcs; it never imports internal/store
// itself (imports_test.go pins that).
//
// NODE-LOCAL: none of the three tables is ever named in
// internal/store/orgpush.go — pinned in the forbidden-table sentinel
// (tests/invariant/privacy_test.go).

// commitSubjectMaxBytes bounds the scrubbed subject stored per commit —
// defence in depth against a pathological single-line commit message; a
// real subject is a handful of words.
const commitSubjectMaxBytes = 4000

// gitNotFoundMarker is the exact substring internal/commitscan writes into
// project_commit_scan.last_error when the injected Exec seam reports git is
// unavailable (see cmd/observer/commitscan_wire.go). CommitCaptureState
// looks for this substring rather than importing commitscan's error type,
// keeping this file's only import of commit-capture concepts to
// internal/commitlog (the pure row shapes) — store must not depend on the
// scanner package (CLAUDE.md module-boundary discipline: the scanner is
// injected by the host, never a dependency of the store it writes to).
const gitNotFoundMarker = "git not found"

// ProjectCommitRow is one project_commits row, as read back for the
// Projects-page detail surfaces (W3).
type ProjectCommitRow struct {
	ID          int64
	ProjectID   int64
	SHA         string
	AuthorHash  string
	Subject     string
	Parents     []string
	AuthoredAt  time.Time
	CommittedAt time.Time
	IsMerge     bool
	Reachable   bool
	FilesCount  int
	Added       int
	Deleted     int
}

// ProjectCommitFileRow is one project_commit_files row joined back to its
// owning commit's identity, for the attribution join (internal/projectroi).
type ProjectCommitFileRow struct {
	CommitID    int64
	SHA         string
	CommittedAt time.Time
	RelPath     string
	PathHash    string
	Status      string
	Added       int
	Deleted     int
	Binary      bool
}

// ScanState is the per-project watermark + health project_commit_scan
// holds. The zero value (returned alongside ok=false by CommitScanState)
// means "never scanned".
type ScanState struct {
	ProjectID           int64
	LastSHA             string
	LastCommittedAt     time.Time
	LastScanAt          time.Time
	LastError           string
	ConsecutiveFailures int
	// LocalAuthorHash is the hash of the repository's configured identity
	// (agent migration 146, review 2026-09-29 finding 8), same rule as
	// project_commits.author_hash. "" = unknown. A write with "" KEEPS the
	// stored value (a failed or identity-less scan never forgets the last
	// known identity).
	LocalAuthorHash string
}

// ProjectRoot is one active project's identity + filesystem root, the
// candidate set internal/commitscan polls.
type ProjectRoot struct {
	ID       int64
	RootPath string
}

// UpsertCommits writes a batch of parsed commits for one project. It is
// idempotent and safe to call with an overlapping window every scanner
// tick: existing (project_id, sha) rows are refreshed in place (a
// re-parse — e.g. a periodic scan's capped output followed by a fuller
// backfill pass — replaces the stored metadata and file list) rather than
// skipped, EXCEPT the `reachable` flag, which only
// MarkCommitsReachability ever changes (a commit revalidation pass must
// not be undone by the next ordinary log scan re-inserting it).
//
// Subject is scrubbed through the store's shared content scrubber
// (contentScrubber, messagecontent.go) before insert — commit messages are
// free text a developer wrote and can carry a pasted secret exactly like
// any other captured text. inserted counts only GENUINELY NEW commits
// (rows that did not exist before this call), which is what the scanner's
// per-tick log line and `observer backfill --commits`'s summary report.
func (s *Store) UpsertCommits(ctx context.Context, projectID int64, commits []commitlog.Commit, scannedAt time.Time) (int, error) {
	if len(commits) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.UpsertCommits: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	scannedAtStr := timestamp(scannedAt)
	inserted := 0

	for _, c := range commits {
		var existed bool
		var probe int
		if err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM project_commits WHERE project_id = ? AND sha = ?`, projectID, c.SHA,
		).Scan(&probe); err == nil {
			existed = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			return inserted, fmt.Errorf("store.UpsertCommits: check existing %s: %w", c.SHA, err)
		}

		parentsJSON, err := json.Marshal(c.Parents)
		if err != nil {
			return inserted, fmt.Errorf("store.UpsertCommits: marshal parents for %s: %w", c.SHA, err)
		}
		subject := scrub.TruncateN(contentScrubber().String(c.Subject), commitSubjectMaxBytes)
		isMerge := 0
		if c.IsMerge {
			isMerge = 1
		}
		var added, deleted int
		for _, f := range c.Files {
			added += f.Added
			deleted += f.Deleted
		}

		var commitID int64
		err = tx.QueryRowContext(ctx, `
			INSERT INTO project_commits
			  (project_id, sha, parents_json, author_hash, authored_at, committed_at,
			   subject, is_merge, files_count, added, deleted, scanned_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(project_id, sha) DO UPDATE SET
				parents_json  = excluded.parents_json,
				author_hash   = excluded.author_hash,
				authored_at   = excluded.authored_at,
				committed_at  = excluded.committed_at,
				subject       = excluded.subject,
				is_merge      = excluded.is_merge,
				files_count   = excluded.files_count,
				added         = excluded.added,
				deleted       = excluded.deleted,
				scanned_at    = excluded.scanned_at
			RETURNING id`,
			projectID, c.SHA, string(parentsJSON), c.AuthorHash, timestamp(c.AuthoredAt), timestamp(c.CommittedAt),
			subject, isMerge, len(c.Files), added, deleted, scannedAtStr,
		).Scan(&commitID)
		if err != nil {
			return inserted, fmt.Errorf("store.UpsertCommits: upsert %s: %w", c.SHA, err)
		}
		if !existed {
			inserted++
		}

		if _, err := tx.ExecContext(ctx,
			`DELETE FROM project_commit_files WHERE commit_id = ?`, commitID); err != nil {
			return inserted, fmt.Errorf("store.UpsertCommits: clear files for %s: %w", c.SHA, err)
		}
		for _, f := range c.Files {
			binary := 0
			if f.Binary {
				binary = 1
			}
			// f.Status is best-effort (commitlog.CommitFile's doc comment):
			// zero means "not derived" and must land as "", never the NUL
			// byte string(byte(0)) would otherwise produce.
			status := ""
			if f.Status != 0 {
				status = string(f.Status)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO project_commit_files (commit_id, rel_path, path_hash, status, added, deleted, binary)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				commitID, f.RelPath, f.PathHash, status, f.Added, f.Deleted, binary,
			); err != nil {
				return inserted, fmt.Errorf("store.UpsertCommits: insert file %s@%s: %w", f.RelPath, c.SHA, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("store.UpsertCommits: commit: %w", err)
	}
	return inserted, nil
}

// MarkCommitsReachability revalidates the reachable flag for every stored
// commit at or after `since`, against the given set of currently
// HEAD-reachable shas (plan R2/F3): a stored sha absent from the set is
// flagged reachable=0 (never deleted — it still explains a prompt chain's
// history); a sha present in the set is restored to reachable=1 if it had
// previously fallen out. `since` is the caller's revalidation-window
// start (LinkWindow + a lookback margin); nothing outside it is touched.
// A ZERO `since` means UNBOUNDED - every stored row for the project is
// revalidated (the sub-project self-heal path, SOL-F15). It is handled
// explicitly here because the shared timestamp() helper maps a zero time
// to "now", which would silently revalidate nothing.
func (s *Store) MarkCommitsReachability(ctx context.Context, projectID int64, reachableSHAs map[string]bool, since time.Time) error {
	query := `SELECT sha, reachable FROM project_commits WHERE project_id = ? AND committed_at >= ?`
	args := []any{projectID, timestamp(since)}
	if since.IsZero() {
		query = `SELECT sha, reachable FROM project_commits WHERE project_id = ?`
		args = []any{projectID}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("store.MarkCommitsReachability: select: %w", err)
	}
	type flip struct {
		sha  string
		want bool
	}
	var flips []flip
	for rows.Next() {
		var sha string
		var reachable int
		if err := rows.Scan(&sha, &reachable); err != nil {
			rows.Close()
			return fmt.Errorf("store.MarkCommitsReachability: scan: %w", err)
		}
		want := reachableSHAs[sha]
		if want != (reachable != 0) {
			flips = append(flips, flip{sha: sha, want: want})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("store.MarkCommitsReachability: rows: %w", err)
	}
	rows.Close()
	if len(flips) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.MarkCommitsReachability: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, f := range flips {
		want := 0
		if f.want {
			want = 1
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE project_commits SET reachable = ? WHERE project_id = ? AND sha = ?`,
			want, projectID, f.sha); err != nil {
			return fmt.Errorf("store.MarkCommitsReachability: update %s: %w", f.sha, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.MarkCommitsReachability: commit: %w", err)
	}
	return nil
}

// LoadProjectCommits returns one project's commits in [since, until],
// newest first, capped at limit (plan R11 — a detail read is never
// unbounded; limit <= 0 falls back to 500).
func (s *Store) LoadProjectCommits(ctx context.Context, projectID int64, since, until time.Time, limit int) ([]ProjectCommitRow, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, sha, parents_json, author_hash, authored_at, committed_at,
		       subject, is_merge, reachable, files_count, added, deleted
		  FROM project_commits
		 WHERE project_id = ? AND committed_at >= ? AND committed_at < ?
		 ORDER BY committed_at DESC
		 LIMIT ?`,
		projectID, timestamp(since), timestamp(until), limit)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectCommits: %w", err)
	}
	defer rows.Close()

	var out []ProjectCommitRow
	for rows.Next() {
		var (
			r                       ProjectCommitRow
			parentsJSON             string
			authoredAt, committedAt string
			isMerge, reachable      int
		)
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.SHA, &parentsJSON, &r.AuthorHash, &authoredAt, &committedAt,
			&r.Subject, &isMerge, &reachable, &r.FilesCount, &r.Added, &r.Deleted); err != nil {
			return nil, fmt.Errorf("store.LoadProjectCommits: scan: %w", err)
		}
		r.AuthoredAt = parseCommitTime(authoredAt)
		r.CommittedAt = parseCommitTime(committedAt)
		r.IsMerge = isMerge != 0
		r.Reachable = reachable != 0
		if parentsJSON != "" {
			_ = json.Unmarshal([]byte(parentsJSON), &r.Parents)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadProjectCommits: rows: %w", err)
	}
	return out, nil
}

// LoadCommitFiles returns changed-file rows for one project's commits in
// [since, until], newest-commit first, capped at limit rows (limit <= 0
// falls back to 2000 — several files per commit, so the row cap is higher
// than LoadProjectCommits's commit cap).
func (s *Store) LoadCommitFiles(ctx context.Context, projectID int64, since, until time.Time, limit int) ([]ProjectCommitFileRow, error) {
	if limit <= 0 {
		limit = 2000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT cf.commit_id, c.sha, c.committed_at, cf.rel_path, cf.path_hash, cf.status, cf.added, cf.deleted, cf.binary
		  FROM project_commit_files cf
		  JOIN project_commits c ON c.id = cf.commit_id
		 WHERE c.project_id = ? AND c.committed_at >= ? AND c.committed_at < ?
		 ORDER BY c.committed_at DESC, cf.commit_id DESC
		 LIMIT ?`,
		projectID, timestamp(since), timestamp(until), limit)
	if err != nil {
		return nil, fmt.Errorf("store.LoadCommitFiles: %w", err)
	}
	defer rows.Close()

	var out []ProjectCommitFileRow
	for rows.Next() {
		var (
			r           ProjectCommitFileRow
			committedAt string
			binary      int
		)
		if err := rows.Scan(&r.CommitID, &r.SHA, &committedAt, &r.RelPath, &r.PathHash, &r.Status, &r.Added, &r.Deleted, &binary); err != nil {
			return nil, fmt.Errorf("store.LoadCommitFiles: scan: %w", err)
		}
		r.CommittedAt = parseCommitTime(committedAt)
		r.Binary = binary != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadCommitFiles: rows: %w", err)
	}
	return out, nil
}

// CommitScanState reads one project's scanner watermark. ok=false means
// this project has never been scanned.
func (s *Store) CommitScanState(ctx context.Context, projectID int64) (ScanState, bool, error) {
	var (
		st                          ScanState
		lastCommittedAt, lastScanAt string
	)
	st.ProjectID = projectID
	err := s.db.QueryRowContext(ctx,
		`SELECT last_sha, last_committed_at, last_scan_at, last_error, consecutive_failures, local_author_hash
		   FROM project_commit_scan WHERE project_id = ?`, projectID,
	).Scan(&st.LastSHA, &lastCommittedAt, &lastScanAt, &st.LastError, &st.ConsecutiveFailures, &st.LocalAuthorHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanState{}, false, nil
	}
	if err != nil {
		return ScanState{}, false, fmt.Errorf("store.CommitScanState: %w", err)
	}
	st.LastCommittedAt = parseCommitTime(lastCommittedAt)
	st.LastScanAt = parseCommitTime(lastScanAt)
	return st, true, nil
}

// SetCommitScanState upserts one project's scanner watermark. Called after
// every scan attempt — success or failure — so the health surfaces (doctor,
// the page's capture banner) always reflect the last attempt.
func (s *Store) SetCommitScanState(ctx context.Context, st ScanState) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO project_commit_scan
		  (project_id, last_sha, last_committed_at, last_scan_at, last_error, consecutive_failures, local_author_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id) DO UPDATE SET
			last_sha              = excluded.last_sha,
			last_committed_at     = excluded.last_committed_at,
			last_scan_at          = excluded.last_scan_at,
			last_error            = excluded.last_error,
			consecutive_failures  = excluded.consecutive_failures,
			local_author_hash     = CASE WHEN excluded.local_author_hash <> ''
			                             THEN excluded.local_author_hash
			                             ELSE project_commit_scan.local_author_hash END`,
		st.ProjectID, st.LastSHA, timestamp(st.LastCommittedAt), timestamp(st.LastScanAt),
		st.LastError, st.ConsecutiveFailures, st.LocalAuthorHash)
	if err != nil {
		return fmt.Errorf("store.SetCommitScanState: %w", err)
	}
	return nil
}

// ActiveProjectRoots lists every project with at least one session started
// within the last sinceDays days (the commit scanner's candidate root
// set — plan R2: only ACTIVE projects are polled). sinceDays <= 0 means no
// bound (every known project).
func (s *Store) ActiveProjectRoots(ctx context.Context, sinceDays int) ([]ProjectRoot, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if sinceDays > 0 {
		cutoff := timestamp(time.Now().UTC().AddDate(0, 0, -sinceDays))
		rows, err = s.db.QueryContext(ctx, `
			SELECT p.id, p.root_path
			  FROM projects p
			 WHERE EXISTS (SELECT 1 FROM sessions s WHERE s.project_id = p.id AND s.started_at >= ?)
			 ORDER BY p.id`, cutoff)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT p.id, p.root_path FROM projects p ORDER BY p.id`)
	}
	if err != nil {
		return nil, fmt.Errorf("store.ActiveProjectRoots: %w", err)
	}
	defer rows.Close()

	var out []ProjectRoot
	for rows.Next() {
		var r ProjectRoot
		if err := rows.Scan(&r.ID, &r.RootPath); err != nil {
			return nil, fmt.Errorf("store.ActiveProjectRoots: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ActiveProjectRoots: rows: %w", err)
	}
	return out, nil
}

// CommitCaptureState reports this project's commit-capture health as one
// of four honest states (plan §3.4's `capture.commits` field):
// "never_scanned" (no project_commit_scan row yet), "no_git" (the last
// scan attempt's error names git as unavailable — see gitNotFoundMarker),
// "error" (the last scan attempt failed for any other reason — a timeout,
// a deleted or unreadable root — and no scan has succeeded since), or
// "ok" (the last scan completed).
func (s *Store) CommitCaptureState(ctx context.Context, projectID int64) (string, error) {
	st, ok, err := s.CommitScanState(ctx, projectID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "never_scanned", nil
	}
	return commitCaptureStateFor(st.LastError, st.ConsecutiveFailures), nil
}

// commitCaptureStateFor is the ONE derivation of a scanned project's
// capture state from its persisted scan row, shared by
// CommitCaptureState (detail) and LoadProjectListExtras (list). A
// failing scanner is reported as "error", never hidden behind "ok"
// (F4 of the 2026-09-22 arc review); the scanner clears last_error and
// the failure counter on the next successful scan.
func commitCaptureStateFor(lastError string, consecutiveFailures int) string {
	switch {
	case strings.Contains(lastError, gitNotFoundMarker):
		return "no_git"
	case lastError != "" && consecutiveFailures > 0:
		return "error"
	default:
		return "ok"
	}
}

// parseCommitTime parses a stored RFC3339Nano stamp; an empty or
// unparseable value yields the zero time (mirrors cloudParseTime).
func parseCommitTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	return time.Time{}
}

// ProjectsWithCommitsSince lists every project holding at least one stored
// commit committed at or after since, ascending by id - the candidate set the
// commit-ownership org composer (commitownersummary.go) folds, so that file
// never names project_commits itself.
func (s *Store) ProjectsWithCommitsSince(ctx context.Context, since time.Time) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT project_id FROM project_commits WHERE committed_at >= ? ORDER BY project_id`,
		timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.ProjectsWithCommitsSince: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store.ProjectsWithCommitsSince: scan: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ProjectsWithCommitsSince: rows: %w", err)
	}
	return out, nil
}

// probeProjectCommits is the org-push snapshot-gate fingerprint over the
// commit ledger (orgsnapgate.go): a new commit moves MAX(id), and a
// reachability flip (MarkCommitsReachability, which changes no id) moves the
// reachable count. A resolved or changed local identity
// (project_commit_scan.local_author_hash, the foreign_author ownership gate)
// moves the ownership answer without touching project_commits, so the
// per-project identity hashes are folded in too (one short row per project).
// Declared here, beside the tables' one writer, so the probe SQL stays with
// the tables' owner.
func (s *Store) probeProjectCommits(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx,
		`SELECT 'pc' || COALESCE(MAX(id), 0) || ':' || COUNT(*) || ':' || COALESCE(SUM(reachable), 0)
		     || ':' || COALESCE((SELECT group_concat(project_id || '=' || local_author_hash, ',')
		                           FROM (SELECT project_id, local_author_hash FROM project_commit_scan
		                                  WHERE local_author_hash <> '' ORDER BY project_id)), '')
		   FROM project_commits`)
}
