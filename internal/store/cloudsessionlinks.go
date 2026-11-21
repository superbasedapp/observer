package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

// cloudsessionlinks.go is the store seam of cloud-agent delivery credit
// (cloud-agents arc lane CA-C5; docs/projects-page.md "Cloud-agent
// credit"). It owns cloud_session_links (agent migration 246, NODE-LOCAL,
// privacy sentinel): the pull requests and branches a cloud-agent
// connector's vendor said a session produced. RecordCloudSessionLinks is the
// table's ONE writer (internal/cloudagentssvc calls it once per landed
// task); CreditCloudCommits loads the credit input for a project and runs
// the pure rule table internal/projectroi.CreditCloud over an Ownership
// answer. Subject parsing (delivery.SquashSubjectPR / MergeSubjectHead) and
// remote normalisation happen here, at the boundary, so the pure package
// reads plain facts.

// CloudSessionLink is one pointer a vendor returned for a cloud session.
type CloudSessionLink struct {
	SessionID string
	Connector string
	// Remote is the repository, "host/owner/repo"; it is normalised and
	// lowercased before it is stored.
	Remote string
	// PRNumber is the stated PR number (0 = none); Branch the stated branch
	// ("" = none). A link carries at least one.
	PRNumber int64
	Branch   string
}

// maxCloudBranch bounds a stored branch name (a git ref is at most 255
// bytes in practice).
const maxCloudBranch = 255

// cloudClaimCap bounds the claims one credit fold reads (newest first).
const cloudClaimCap = 2000

// cloudLinkKey is the one normalisation of a link's repository.
func cloudLinkKey(remote string) string {
	norm := git.NormalizeRemote(remote)
	if !hostedRemote(norm) {
		return ""
	}
	return strings.ToLower(norm)
}

// validCloudBranch refuses a branch name that cannot be a git ref.
func validCloudBranch(b string) bool {
	return b != "" && len(b) <= maxCloudBranch && !strings.ContainsAny(b, " \t\r\n\x00~^:?*[\\") && !strings.Contains(b, "..")
}

// RecordCloudSessionLinks upserts a session's links. A link with no
// hosted repository, or with neither a PR number nor a valid branch, is
// skipped (never guessed). It returns how many links it wrote.
func (s *Store) RecordCloudSessionLinks(ctx context.Context, links []CloudSessionLink, now time.Time) (int, error) {
	if len(links) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.RecordCloudSessionLinks: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	at := timestamp(now.UTC())
	n := 0
	for _, l := range links {
		remote := cloudLinkKey(l.Remote)
		branch := strings.TrimSpace(l.Branch)
		if branch != "" && !validCloudBranch(branch) {
			branch = ""
		}
		if l.SessionID == "" || remote == "" || l.PRNumber < 0 || (l.PRNumber == 0 && branch == "") {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO cloud_session_links (session_id, connector, remote, pr_number, branch, first_seen_at, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(session_id, remote, pr_number, branch) DO UPDATE SET
				connector    = excluded.connector,
				last_seen_at = excluded.last_seen_at`,
			l.SessionID, l.Connector, remote, l.PRNumber, branch, at, at); err != nil {
			return 0, fmt.Errorf("store.RecordCloudSessionLinks: %w", err)
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.RecordCloudSessionLinks: commit: %w", err)
	}
	return n, nil
}

// ListCloudSessionLinks returns one session's stored links, oldest first.
func (s *Store) ListCloudSessionLinks(ctx context.Context, sessionID string) ([]CloudSessionLink, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT session_id, connector, remote, pr_number, branch FROM cloud_session_links
		 WHERE session_id = ? ORDER BY id`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.ListCloudSessionLinks: %w", err)
	}
	defer rows.Close()
	var out []CloudSessionLink
	for rows.Next() {
		var l CloudSessionLink
		if err := rows.Scan(&l.SessionID, &l.Connector, &l.Remote, &l.PRNumber, &l.Branch); err != nil {
			return nil, fmt.Errorf("store.ListCloudSessionLinks: scan: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListCloudSessionLinks: rows: %w", err)
	}
	return out, nil
}

// projectRemoteKeys returns a project's repositories as cloud link keys:
// projects.git_remote plus every project_remotes row.
func (s *Store) projectRemoteKeys(ctx context.Context, projectID int64) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(r string) {
		if k := cloudLinkKey(r); k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	var remote sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT git_remote FROM projects WHERE id = ?`, projectID).Scan(&remote)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store.projectRemoteKeys: %w", err)
	}
	if remote.Valid {
		add(remote.String)
	}
	remotes, err := s.LoadProjectRemotes(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("store.projectRemoteKeys: %w", err)
	}
	for _, r := range remotes {
		if r.Host != "" && r.RepoSlug != "" {
			add(r.Host + "/" + r.RepoSlug)
		}
	}
	return out, nil
}

// LoadCloudCreditInput assembles the cloud-credit input for one project and
// the given commit rows. With no claim on any of the project's repositories
// it returns an input with no claims and reads nothing more.
func (s *Store) LoadCloudCreditInput(ctx context.Context, projectID int64, rows []ProjectCommitRow) (projectroi.CloudCreditInput, error) {
	var in projectroi.CloudCreditInput
	remotes, err := s.projectRemoteKeys(ctx, projectID)
	if err != nil || len(remotes) == 0 {
		return in, err
	}
	in.ProjectRemotes = remotes
	args := make([]any, 0, len(remotes)+1)
	for _, r := range remotes {
		args = append(args, r)
	}
	args = append(args, cloudClaimCap)
	//nolint:gosec // G202: only bound placeholders, built from a count, are concatenated.
	q, err := s.db.QueryContext(ctx, `
		SELECT l.session_id, l.connector, l.remote, l.pr_number, l.branch, COALESCE(s.started_at, '')
		  FROM cloud_session_links l
		  JOIN sessions s ON s.id = l.session_id
		 WHERE l.remote IN (`+placeholders(len(remotes))+`)
		 ORDER BY l.id DESC LIMIT ?`, args...)
	if err != nil {
		return in, fmt.Errorf("store.LoadCloudCreditInput: claims: %w", err)
	}
	numbers, branches := map[int64]bool{}, map[string]bool{}
	for q.Next() {
		var c projectroi.CloudClaim
		var started string
		if err := q.Scan(&c.SessionID, &c.Connector, &c.Remote, &c.PRNumber, &c.Branch, &started); err != nil {
			_ = q.Close()
			return in, fmt.Errorf("store.LoadCloudCreditInput: claims scan: %w", err)
		}
		c.SessionStart = parseCommitTime(started)
		in.Claims = append(in.Claims, c)
		if c.PRNumber > 0 {
			numbers[c.PRNumber] = true
		}
		if c.Branch != "" {
			branches[c.Branch] = true
		}
	}
	if err := q.Err(); err != nil {
		_ = q.Close()
		return in, fmt.Errorf("store.LoadCloudCreditInput: claims rows: %w", err)
	}
	_ = q.Close()
	if len(in.Claims) == 0 {
		return in, nil
	}
	for _, r := range rows {
		c := projectroi.CloudCommit{
			ID: r.ID, SHA: r.SHA, CommittedAt: r.CommittedAt, IsMerge: r.IsMerge, Reachable: r.Reachable, Files: r.FilesCount,
		}
		if n, ok := delivery.SquashSubjectPR(r.Subject); ok && !r.IsMerge {
			c.SquashPR = n
		}
		if n, head, ok := delivery.MergeSubjectHead(r.Subject); ok && r.IsMerge {
			c.MergePR, c.MergeHead = n, head
			numbers[n] = true
		}
		in.Commits = append(in.Commits, c)
	}
	prs, err := s.loadCloudCreditPRs(ctx, remotes, numbers, branches)
	if err != nil {
		return in, err
	}
	in.PRs = prs
	return in, nil
}

// loadCloudCreditPRs reads the stored provider PRs on the project's
// repositories whose number a claim (or a merge subject) names, or whose
// head ref is a claimed branch, with their commit lists.
func (s *Store) loadCloudCreditPRs(ctx context.Context, remotes []string, numbers map[int64]bool, branches map[string]bool) ([]projectroi.CloudPR, error) {
	if len(numbers) == 0 && len(branches) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(remotes)+len(numbers)+len(branches))
	for _, r := range remotes {
		args = append(args, r)
	}
	var match []string
	if len(numbers) > 0 {
		match = append(match, `p.number IN (`+placeholders(len(numbers))+`)`)
		for n := range numbers {
			args = append(args, n)
		}
	}
	if len(branches) > 0 {
		match = append(match, `p.head_ref IN (`+placeholders(len(branches))+`)`)
		for b := range branches {
			args = append(args, b)
		}
	}
	prs, err := s.queryPRs(ctx, `SELECT `+prColumns+` FROM pull_requests p
		 WHERE lower(p.host || '/' || p.repo_slug) IN (`+placeholders(len(remotes))+`)
		   AND (`+strings.Join(match, " OR ")+`)
		 ORDER BY p.id`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.loadCloudCreditPRs: %w", err)
	}
	out := make([]projectroi.CloudPR, 0, len(prs))
	for _, p := range prs {
		cp := projectroi.CloudPR{
			Remote: strings.ToLower(p.Host + "/" + p.RepoSlug), Number: p.Number, HeadRef: p.HeadRef,
			MergeCommitSHA: p.MergeCommitSHA, CreatedAt: p.CreatedAt,
		}
		commits, err := s.db.QueryContext(ctx, `SELECT sha FROM pull_request_commits WHERE pr_id = ? ORDER BY position`, p.ID)
		if err != nil {
			return nil, fmt.Errorf("store.loadCloudCreditPRs: commits: %w", err)
		}
		for commits.Next() {
			var sha string
			if err := commits.Scan(&sha); err != nil {
				_ = commits.Close()
				return nil, fmt.Errorf("store.loadCloudCreditPRs: commits scan: %w", err)
			}
			cp.CommitSHAs = append(cp.CommitSHAs, sha)
		}
		if err := commits.Err(); err != nil {
			_ = commits.Close()
			return nil, fmt.Errorf("store.loadCloudCreditPRs: commits rows: %w", err)
		}
		_ = commits.Close()
		out = append(out, cp)
	}
	return out, nil
}

// CreditCloudCommits overlays cloud-agent credit on an Ownership answer for
// one project's commit rows (projectroi.CreditCloud). With no cloud link on
// the project's repositories the input map is returned unchanged.
func (s *Store) CreditCloudCommits(ctx context.Context, projectID int64, own map[int64]projectroi.CommitOwnership, rows []ProjectCommitRow) (map[int64]projectroi.CommitOwnership, error) {
	in, err := s.LoadCloudCreditInput(ctx, projectID, rows)
	if err != nil {
		return own, fmt.Errorf("store.CreditCloudCommits: %w", err)
	}
	return projectroi.CreditCloud(own, in), nil
}

// ListCloudPRClaims returns the distinct PR numbers and branches cloud
// sessions claimed on one repository ("host/owner/repo") whose session
// started at or after since, newest first, capped at limit.
func (s *Store) ListCloudPRClaims(ctx context.Context, remote string, since time.Time, limit int) ([]delivery.CloudPRClaim, error) {
	key := cloudLinkKey(remote)
	if key == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 25
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT l.pr_number, l.branch, MAX(l.last_seen_at) AS seen
		  FROM cloud_session_links l
		  JOIN sessions s ON s.id = l.session_id
		 WHERE l.remote = ? AND s.started_at >= ?
		 GROUP BY l.pr_number, l.branch
		 ORDER BY seen DESC LIMIT ?`, key, timestamp(since), limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListCloudPRClaims: %w", err)
	}
	defer rows.Close()
	var out []delivery.CloudPRClaim
	for rows.Next() {
		var c delivery.CloudPRClaim
		var seen string
		if err := rows.Scan(&c.PRNumber, &c.Branch, &seen); err != nil {
			return nil, fmt.Errorf("store.ListCloudPRClaims: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListCloudPRClaims: rows: %w", err)
	}
	return out, nil
}

// FindPullRequestByNumber returns the stored PR number on one repository
// (host + "owner/repo"), from any provider link; ok=false when none is
// stored. When several links stored it, the most recently fetched wins.
func (s *Store) FindPullRequestByNumber(ctx context.Context, host, slug string, number int64) (delivery.PullRequest, bool, error) {
	prs, err := s.queryPRs(ctx, `SELECT `+prColumns+` FROM pull_requests p
		 WHERE lower(p.host) = lower(?) AND lower(p.repo_slug) = lower(?) AND p.number = ?
		 ORDER BY p.fetched_at DESC, p.id DESC LIMIT 1`, host, slug, number)
	if err != nil {
		return delivery.PullRequest{}, false, fmt.Errorf("store.FindPullRequestByNumber: %w", err)
	}
	if len(prs) == 0 {
		return delivery.PullRequest{}, false, nil
	}
	return prs[0], true, nil
}
