package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// delivery.go is the ONE store seam of the commit to PR to merge arc
// (docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md 6.1 and 12.3,
// operator decision D-689). It is the sole writer of every delivery table
// (CLAUDE.md module-boundary rule 4):
//
//	project_remotes, commit_landings, provider_links, pull_requests,
//	pull_request_commits, delivery_mirrors, delivery_project_settings,
//	delivery_branch_tips                  (agent migrations 166 to 172)
//
// The two project_commits columns of migration 165 stay with their owner,
// commits.go (SetCommitPatchFingerprint). This file reads project_commits
// (sha, subject, fingerprint) but never writes it.
//
// NODE-LOCAL: no table here is ever named in internal/store/orgpush.go
// (tests/invariant/privacy_test.go forbids them by name). The org wire is
// composed in deliverysummary.go, which orgpush.go CALLS.
//
// SECRETS: provider_links holds a keychain entry NAME, never a token; every
// remote URL is re-parsed through delivery.ParseRemoteURL before it is
// stored, so a credential embedded in a remote URL cannot reach a table even
// if a caller passes the raw value.

// deliveryRepoWindow is how far back an AI-touched commit keeps its project
// on the provider poll list (ListDeliveryRepos).
const deliveryRepoWindow = 90 * 24 * time.Hour

// prTitleMaxBytes caps a stored PR title (plan 6.1).
const prTitleMaxBytes = 512

// prCommitsCap is GitHub's own PR commit list cap (plan 6.1).
const prCommitsCap = 250

// deliveryErrMaxBytes caps a stored provider or mirror error message.
const deliveryErrMaxBytes = 500

// branchTipsLoadCap bounds LoadBranchTips.
const branchTipsLoadCap = 200

// SessionLanding is one commit a session contributed to, with its delivery
// outcome and the PR that holds it (LoadSessionLandings).
type SessionLanding struct {
	CommitID    int64
	SHA         string
	Subject     string
	CommittedAt time.Time
	Reachable   bool
	// Owner is true when this session is the commit's owner (its ranked
	// first contributor).
	Owner bool
	// Evaluated is false while the commit has no landing row yet (its
	// fingerprint is still pending); Landing is then the zero value.
	Evaluated bool
	Landing   delivery.Landing
	// PR is the stored PR the landing names, nil when none.
	PR *delivery.PullRequest
}

// ---------------------------------------------------------------- remotes

// UpsertProjectRemote records one project remote as the landing scan read it.
// The URL is re-parsed so userinfo can never be stored; a URL that does not
// parse is stored empty (host, provider and slug as given).
func (s *Store) UpsertProjectRemote(ctx context.Context, r delivery.Remote) error {
	if r.ProjectID <= 0 || strings.TrimSpace(r.Name) == "" {
		return errors.New("store.UpsertProjectRemote: project id and remote name required")
	}
	url := ""
	if u, host, provider, slug, ok := delivery.ParseRemoteURL(r.URL); ok {
		url = u
		if r.Host == "" {
			r.Host = host
		}
		if r.Provider == "" {
			r.Provider = provider
		}
		if r.RepoSlug == "" {
			r.RepoSlug = slug
		}
	}
	if r.Provider == "" {
		r.Provider = delivery.ProviderUnknown
	}
	if r.ObservedAt.IsZero() {
		r.ObservedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO project_remotes
		  (project_id, remote_name, url, host, provider, repo_slug, default_branch,
		   default_ref_sha, fetch_head_at, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, remote_name) DO UPDATE SET
			url             = excluded.url,
			host            = excluded.host,
			provider        = excluded.provider,
			repo_slug       = excluded.repo_slug,
			default_branch  = excluded.default_branch,
			default_ref_sha = excluded.default_ref_sha,
			fetch_head_at   = excluded.fetch_head_at,
			observed_at     = excluded.observed_at`,
		r.ProjectID, r.Name, url, strings.ToLower(r.Host), string(r.Provider), r.RepoSlug, r.DefaultBranch,
		r.DefaultRefSHA, optionalTimestamp(r.FetchHeadAt), timestamp(r.ObservedAt))
	if err != nil {
		return fmt.Errorf("store.UpsertProjectRemote: %w", err)
	}
	return nil
}

const remoteColumns = `project_id, remote_name, url, host, provider, repo_slug, default_branch,
	default_ref_sha, fetch_head_at, observed_at`

func scanRemotes(rows *sql.Rows) ([]delivery.Remote, error) {
	defer rows.Close()
	var out []delivery.Remote
	for rows.Next() {
		var (
			r                  delivery.Remote
			provider           string
			fetchHead, observe string
		)
		if err := rows.Scan(&r.ProjectID, &r.Name, &r.URL, &r.Host, &provider, &r.RepoSlug, &r.DefaultBranch,
			&r.DefaultRefSHA, &fetchHead, &observe); err != nil {
			return nil, err
		}
		r.Provider = delivery.Provider(provider)
		r.FetchHeadAt = parseCommitTime(fetchHead)
		r.ObservedAt = parseCommitTime(observe)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LoadProjectRemotes returns one project's remotes, by name.
func (s *Store) LoadProjectRemotes(ctx context.Context, projectID int64) ([]delivery.Remote, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+remoteColumns+` FROM project_remotes WHERE project_id = ? ORDER BY remote_name`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectRemotes: %w", err)
	}
	out, err := scanRemotes(rows)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectRemotes: %w", err)
	}
	return out, nil
}

// ListDeliveryRepos returns one row per project remote, for every project
// with an AI-touched commit (a commit_landings row) committed in the last 90
// days: the repositories the provider service polls.
func (s *Store) ListDeliveryRepos(ctx context.Context) ([]delivery.Remote, error) {
	since := timestamp(time.Now().UTC().Add(-deliveryRepoWindow))
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+remoteColumns+` FROM project_remotes r
		 WHERE EXISTS (SELECT 1 FROM commit_landings cl
		                 JOIN project_commits c ON c.id = cl.commit_id
		                WHERE cl.project_id = r.project_id AND c.committed_at >= ?)
		 ORDER BY r.project_id, r.remote_name`, since)
	if err != nil {
		return nil, fmt.Errorf("store.ListDeliveryRepos: %w", err)
	}
	out, err := scanRemotes(rows)
	if err != nil {
		return nil, fmt.Errorf("store.ListDeliveryRepos: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------- commits

// LoadDeliveryCommits returns one project's AI-touched commits committed at
// or after since, as the matching rule needs them. A commit is AI-touched
// when the Ownership fold (LoadCommitOwnership, the same fold the session
// "Commits" card and the org wire use) gives it an owner, OR when it already
// has a landing row: Ownership drops every unreachable commit (rule O2), and
// a squash-merged branch that was deleted must keep its landing. The
// Ownership gates (merge, foreign author, no AI edit) therefore decide which
// commits enter; IsMerge and ForeignAuthor are still set from the row so
// rule G1 stays meaningful.
func (s *Store) LoadDeliveryCommits(ctx context.Context, projectID int64, since time.Time) ([]delivery.Commit, error) {
	now := time.Now().UTC()
	res, err := s.LoadCommitOwnership(ctx, projectID, since.Add(-projectroi.DefaultLinkWindow), now.Add(time.Minute),
		projectroi.DefaultLinkWindow, orgOwnershipCaps)
	if err != nil {
		return nil, fmt.Errorf("store.LoadDeliveryCommits: %w", err)
	}
	type ownInfo struct {
		sessions []string
		foreign  bool
	}
	owned := map[int64]ownInfo{}
	for id, o := range res.Ownership {
		info := ownInfo{foreign: o.Reason == projectroi.OwnerNoneForeignAuthor}
		if o.OwnerSessionID != "" {
			for _, c := range o.Contributors {
				info.sessions = append(info.sessions, c.SessionID)
			}
		}
		owned[id] = info
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT c.id, c.sha, c.subject, c.committed_at, c.reachable, c.is_merge,
		       COALESCE(c.patch_fp, ''), c.patch_fp_state,
		       cl.commit_id IS NOT NULL, COALESCE(cl.contributors_json, '[]')
		  FROM project_commits c
		  LEFT JOIN commit_landings cl ON cl.commit_id = c.id
		 WHERE c.project_id = ? AND c.committed_at >= ?
		 ORDER BY c.committed_at, c.id`, projectID, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.LoadDeliveryCommits: %w", err)
	}
	defer rows.Close()
	var out []delivery.Commit
	for rows.Next() {
		var (
			c                  delivery.Commit
			committed          string
			reachable, isMerge int
			hasLanding         bool
			contributors       string
		)
		if err := rows.Scan(&c.ID, &c.SHA, &c.Subject, &committed, &reachable, &isMerge,
			&c.PatchFP, &c.PatchFPState, &hasLanding, &contributors); err != nil {
			return nil, fmt.Errorf("store.LoadDeliveryCommits: scan: %w", err)
		}
		info := owned[c.ID]
		if len(info.sessions) == 0 && !hasLanding {
			continue // not AI-touched: the Ownership gates said no
		}
		c.ProjectID = projectID
		c.CommittedAt = parseCommitTime(committed)
		c.Reachable = reachable != 0
		c.IsMerge = isMerge != 0
		c.ForeignAuthor = info.foreign
		c.AIContributor = true
		c.SessionIDs = info.sessions
		if len(c.SessionIDs) == 0 {
			_ = json.Unmarshal([]byte(contributors), &c.SessionIDs)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadDeliveryCommits: rows: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------- landings

// UpsertCommitLandings writes evaluated landings (one row per commit). A
// landing with no SessionIDs keeps the stored contributor list.
func (s *Store) UpsertCommitLandings(ctx context.Context, landings []delivery.Landing) error {
	if len(landings) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertCommitLandings: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, l := range landings {
		contributors := ""
		if len(l.SessionIDs) > 0 {
			b, err := json.Marshal(l.SessionIDs)
			if err != nil {
				return fmt.Errorf("store.UpsertCommitLandings: contributors: %w", err)
			}
			contributors = string(b)
		}
		var prID any
		if l.PRID > 0 {
			prID = l.PRID
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO commit_landings
			  (commit_id, project_id, status, kind, confidence, rule_id, rule_version, landing_sha,
			   pr_id, pr_number, abandon_reason, source, first_pushed_at, landed_at, landed_at_source,
			   evaluated_at, contributors_json)
			SELECT ?, c.project_id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? = '' THEN '[]' ELSE ? END
			  FROM project_commits c WHERE c.id = ?
			ON CONFLICT(commit_id) DO UPDATE SET
				status           = excluded.status,
				kind             = excluded.kind,
				confidence       = excluded.confidence,
				rule_id          = excluded.rule_id,
				rule_version     = excluded.rule_version,
				landing_sha      = excluded.landing_sha,
				pr_id            = excluded.pr_id,
				pr_number        = excluded.pr_number,
				abandon_reason   = excluded.abandon_reason,
				source           = excluded.source,
				first_pushed_at  = excluded.first_pushed_at,
				landed_at        = excluded.landed_at,
				landed_at_source = excluded.landed_at_source,
				evaluated_at     = excluded.evaluated_at,
				contributors_json = CASE WHEN ? = '' THEN commit_landings.contributors_json
				                         ELSE excluded.contributors_json END`,
			l.CommitID, string(l.Status), string(l.Kind), string(l.Confidence), l.RuleID, l.RuleVersion, l.LandingSHA,
			prID, l.PRNumber, string(l.AbandonReason), string(l.Source), optionalTimestamp(l.FirstPushedAt),
			optionalTimestamp(l.LandedAt), l.LandedAtSource, timestamp(l.EvaluatedAt), contributors, contributors,
			l.CommitID, contributors)
		if err != nil {
			return fmt.Errorf("store.UpsertCommitLandings: commit %d: %w", l.CommitID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.UpsertCommitLandings: commit: %w", err)
	}
	return nil
}

const landingColumns = `cl.commit_id, cl.status, cl.kind, cl.confidence, cl.rule_id, cl.rule_version,
	cl.landing_sha, COALESCE(cl.pr_id, 0), cl.pr_number, cl.abandon_reason, cl.source, cl.first_pushed_at,
	cl.landed_at, cl.landed_at_source, cl.evaluated_at, cl.contributors_json`

// scanLanding scans landingColumns plus extra destinations after them.
func scanLanding(sc interface{ Scan(...any) error }, extra ...any) (delivery.Landing, error) {
	var (
		l                                       delivery.Landing
		status, kind, conf, reason, source      string
		firstPushed, landedAt, evaluated, contr string
	)
	dest := append([]any{
		&l.CommitID, &status, &kind, &conf, &l.RuleID, &l.RuleVersion,
		&l.LandingSHA, &l.PRID, &l.PRNumber, &reason, &source, &firstPushed,
		&landedAt, &l.LandedAtSource, &evaluated, &contr,
	}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return l, err
	}
	l.Status = delivery.LandingStatus(status)
	l.Kind = delivery.LandingKind(kind)
	l.Confidence = delivery.Confidence(conf)
	l.AbandonReason = delivery.AbandonReason(reason)
	l.Source = delivery.EvidenceSource(source)
	l.FirstPushedAt = parseCommitTime(firstPushed)
	l.LandedAt = parseCommitTime(landedAt)
	l.EvaluatedAt = parseCommitTime(evaluated)
	_ = json.Unmarshal([]byte(contr), &l.SessionIDs)
	return l, nil
}

// LoadProjectLandings returns the landings of one project's commits
// committed in [since, until), oldest commit first.
func (s *Store) LoadProjectLandings(ctx context.Context, projectID int64, since, until time.Time) ([]delivery.Landing, error) {
	wl, err := s.loadLandingsWithCommitTime(ctx, projectID, since, until)
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectLandings: %w", err)
	}
	out := make([]delivery.Landing, len(wl))
	for i, w := range wl {
		out[i] = w.Landing
	}
	return out, nil
}

// landingWithCommit is one landing with its commit's identity, for the wire
// composer (deliverysummary.go), which must not name these tables itself.
type landingWithCommit struct {
	ProjectID   int64
	SHA         string
	CommittedAt time.Time
	Landing     delivery.Landing
}

// loadLandingsWithCommitTime loads landings for commits committed in
// [since, until); projectID <= 0 means every project.
func (s *Store) loadLandingsWithCommitTime(ctx context.Context, projectID int64, since, until time.Time) ([]landingWithCommit, error) {
	q := `SELECT ` + landingColumns + `, cl.project_id, c.sha, c.committed_at
		  FROM commit_landings cl JOIN project_commits c ON c.id = cl.commit_id
		 WHERE c.committed_at >= ? AND c.committed_at < ?`
	args := []any{timestamp(since), timestamp(until)}
	if projectID > 0 {
		q += ` AND cl.project_id = ?`
		args = append(args, projectID)
	}
	q += ` ORDER BY c.committed_at, c.id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.loadLandingsWithCommitTime: %w", err)
	}
	defer rows.Close()
	var out []landingWithCommit
	for rows.Next() {
		var (
			w         landingWithCommit
			committed string
		)
		l, err := scanLanding(rows, &w.ProjectID, &w.SHA, &committed)
		if err != nil {
			return nil, fmt.Errorf("store.loadLandingsWithCommitTime: scan: %w", err)
		}
		w.Landing = l
		w.CommittedAt = parseCommitTime(committed)
		out = append(out, w)
	}
	return out, rows.Err()
}

// LoadSessionLandings returns every commit one session contributed to, with
// its landing and PR. Contribution is the union of the Ownership fold over
// the session's span (commits still on HEAD, including ones not evaluated
// yet) and the landing rows whose stored contributor list names the session
// (commits that have since fallen out of HEAD). Oldest commit first.
func (s *Store) LoadSessionLandings(ctx context.Context, sessionID string) ([]SessionLanding, error) {
	now := time.Now().UTC()
	byCommit := map[int64]*SessionLanding{}
	w, ok, err := s.LoadSessionWindow(ctx, sessionID, now)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSessionLandings: %w", err)
	}
	if ok {
		since, until := SessionOwnershipSpan(w, projectroi.DefaultLinkWindow, now)
		res, err := s.LoadCommitOwnership(ctx, w.ProjectID, since, until, projectroi.DefaultLinkWindow, orgOwnershipCaps)
		if err != nil {
			return nil, fmt.Errorf("store.LoadSessionLandings: %w", err)
		}
		rowByID := map[int64]ProjectCommitRow{}
		for _, c := range res.Commits {
			rowByID[c.ID] = c
		}
		for id, own := range res.Ownership {
			for _, con := range own.Contributors {
				if con.SessionID != sessionID {
					continue
				}
				c := rowByID[id]
				byCommit[id] = &SessionLanding{
					CommitID: id, SHA: c.SHA, Subject: c.Subject, CommittedAt: c.CommittedAt,
					Reachable: c.Reachable, Owner: own.OwnerSessionID == sessionID,
				}
			}
		}
	}

	//nolint:gosec // G202: landingColumns is a package literal; inPlaceholders is only bound placeholders.
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+landingColumns+`, c.sha, c.subject, c.committed_at, c.reachable
		  FROM commit_landings cl JOIN project_commits c ON c.id = cl.commit_id
		 WHERE EXISTS (SELECT 1 FROM json_each(cl.contributors_json) j WHERE j.value = ?)
		    OR cl.commit_id IN (`+inPlaceholders(len(byCommit))+`)`,
		append([]any{sessionID}, commitIDArgs(byCommit)...)...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSessionLandings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			sha, subject, committed string
			reachable               int
		)
		l, err := scanLanding(rows, &sha, &subject, &committed, &reachable)
		if err != nil {
			return nil, fmt.Errorf("store.LoadSessionLandings: scan: %w", err)
		}
		sl := byCommit[l.CommitID]
		if sl == nil {
			sl = &SessionLanding{
				CommitID: l.CommitID, SHA: sha, Subject: subject, CommittedAt: parseCommitTime(committed),
				Reachable: reachable != 0, Owner: len(l.SessionIDs) > 0 && l.SessionIDs[0] == sessionID,
			}
			byCommit[l.CommitID] = sl
		}
		sl.Evaluated, sl.Landing = true, l
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadSessionLandings: rows: %w", err)
	}
	rows.Close()

	out := make([]SessionLanding, 0, len(byCommit))
	for _, sl := range byCommit {
		if sl.Evaluated && sl.Landing.PRID > 0 {
			pr, found, err := s.loadPullRequest(ctx, sl.Landing.PRID)
			if err != nil {
				return nil, fmt.Errorf("store.LoadSessionLandings: %w", err)
			}
			if found {
				sl.PR = &pr
			}
		}
		out = append(out, *sl)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CommittedAt.Equal(out[j].CommittedAt) {
			return out[i].CommittedAt.Before(out[j].CommittedAt)
		}
		return out[i].CommitID < out[j].CommitID
	})
	return out, nil
}

// inPlaceholders returns n comma-separated "?" (at least one, so an empty IN
// list stays valid SQL and matches nothing for a NULL argument).
func inPlaceholders(n int) string {
	if n <= 0 {
		return "NULL"
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func commitIDArgs(m map[int64]*SessionLanding) []any {
	out := make([]any, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out
}

// ---------------------------------------------------------------- provider links

// CreateProviderLink records a code-host connection and returns its id. One
// connection exists per (provider, host): connecting again replaces the
// auth mode, key name and account and returns the SAME id, so the keychain
// entry name derived from it stays stable.
func (s *Store) CreateProviderLink(ctx context.Context, l delivery.ProviderLink) (int64, error) {
	if l.Provider == "" || strings.TrimSpace(l.Host) == "" || l.AuthMode == "" {
		return 0, errors.New("store.CreateProviderLink: provider, host and auth mode required")
	}
	if l.Status == "" {
		l.Status = "never_checked"
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO provider_links
		  (provider, host, auth_mode, key_name, account_login, scopes_seen, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider, host) DO UPDATE SET
			auth_mode     = excluded.auth_mode,
			key_name      = excluded.key_name,
			account_login = excluded.account_login,
			scopes_seen   = excluded.scopes_seen,
			status        = excluded.status
		RETURNING id`,
		string(l.Provider), strings.ToLower(l.Host), l.AuthMode, l.KeyName, l.AccountLogin, l.ScopesSeen,
		l.Status, timestamp(l.CreatedAt)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store.CreateProviderLink: %w", err)
	}
	return id, nil
}

// ListProviderLinks returns every code-host connection, by id.
func (s *Store) ListProviderLinks(ctx context.Context) ([]delivery.ProviderLink, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, provider, host, auth_mode, key_name, account_login, scopes_seen, status,
		       last_ok_at, last_error_kind, last_error, next_run_at, consecutive_failures, created_at
		  FROM provider_links ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store.ListProviderLinks: %w", err)
	}
	defer rows.Close()
	var out []delivery.ProviderLink
	for rows.Next() {
		var (
			l                             delivery.ProviderLink
			provider, okAt, next, created string
		)
		if err := rows.Scan(&l.ID, &provider, &l.Host, &l.AuthMode, &l.KeyName, &l.AccountLogin, &l.ScopesSeen,
			&l.Status, &okAt, &l.LastErrorKind, &l.LastError, &next, &l.ConsecutiveFailures, &created); err != nil {
			return nil, fmt.Errorf("store.ListProviderLinks: scan: %w", err)
		}
		l.Provider = delivery.Provider(provider)
		l.LastOKAt, l.NextRunAt, l.CreatedAt = parseCommitTime(okAt), parseCommitTime(next), parseCommitTime(created)
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListProviderLinks: rows: %w", err)
	}
	return out, nil
}

// UpdateProviderLinkStatus records the outcome of one provider poll. A zero
// okAt keeps the stored last-success time; errMsg is scrubbed and capped.
func (s *Store) UpdateProviderLinkStatus(ctx context.Context, id int64, status, errKind, errMsg string, okAt, nextRun time.Time, failures int) error {
	msg := scrub.TruncateN(contentScrubber().String(errMsg), deliveryErrMaxBytes)
	res, err := s.db.ExecContext(ctx, `
		UPDATE provider_links SET
			status               = ?,
			last_error_kind      = ?,
			last_error           = ?,
			last_ok_at           = CASE WHEN ? = '' THEN last_ok_at ELSE ? END,
			next_run_at          = ?,
			consecutive_failures = ?
		 WHERE id = ?`,
		status, errKind, msg, optionalTimestamp(okAt), optionalTimestamp(okAt), optionalTimestamp(nextRun), failures, id)
	if err != nil {
		return fmt.Errorf("store.UpdateProviderLinkStatus: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.UpdateProviderLinkStatus: no provider link %d", id)
	}
	return nil
}

// DeleteProviderLink removes a connection and every PR fetched through it.
// Landings that named one of those PRs keep their status but lose the PR
// link (the next evaluation recomputes them).
func (s *Store) DeleteProviderLink(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.DeleteProviderLink: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmts := []string{
		`UPDATE commit_landings SET pr_id = NULL WHERE pr_id IN (SELECT id FROM pull_requests WHERE provider_link_id = ?)`,
		`DELETE FROM pull_request_commits WHERE pr_id IN (SELECT id FROM pull_requests WHERE provider_link_id = ?)`,
		`DELETE FROM pull_requests WHERE provider_link_id = ?`,
		`DELETE FROM provider_links WHERE id = ?`,
	}
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return fmt.Errorf("store.DeleteProviderLink: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.DeleteProviderLink: commit: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- pull requests

// UpsertPullRequest stores one PR keyed by (link, repo slug, number) and
// returns its id. The title is scrubbed and capped at 512 bytes. commits nil
// keeps the stored commit list (a list-endpoint refresh); a non-nil slice
// replaces it, capped at 250, keeping a fingerprint already computed for a
// sha the new list still holds.
func (s *Store) UpsertPullRequest(ctx context.Context, pr delivery.PullRequest, commits []delivery.PRCommit) (int64, error) {
	if pr.RepoSlug == "" || pr.Number <= 0 {
		return 0, errors.New("store.UpsertPullRequest: repo slug and number required")
	}
	facets, err := json.Marshal(pr.Facets)
	if err != nil {
		return 0, fmt.Errorf("store.UpsertPullRequest: facets: %w", err)
	}
	if pr.FetchedAt.IsZero() {
		pr.FetchedAt = time.Now().UTC()
	}
	title := scrub.TruncateN(contentScrubber().String(pr.Title), prTitleMaxBytes)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.UpsertPullRequest: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO pull_requests
		  (provider_link_id, provider, host, repo_slug, number, title, url, author_login, pr_state,
		   merge_readiness, facets_json, provider_raw_state, head_sha, base_ref, merge_commit_sha,
		   merge_method, created_at, merged_at, closed_at, updated_at, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider_link_id, repo_slug, number) DO UPDATE SET
			provider           = excluded.provider,
			host               = excluded.host,
			title              = excluded.title,
			url                = excluded.url,
			author_login       = excluded.author_login,
			pr_state           = excluded.pr_state,
			merge_readiness    = excluded.merge_readiness,
			facets_json        = excluded.facets_json,
			provider_raw_state = excluded.provider_raw_state,
			head_sha           = excluded.head_sha,
			base_ref           = excluded.base_ref,
			merge_commit_sha   = excluded.merge_commit_sha,
			merge_method       = excluded.merge_method,
			created_at         = excluded.created_at,
			merged_at          = excluded.merged_at,
			closed_at          = excluded.closed_at,
			updated_at         = excluded.updated_at,
			fetched_at         = excluded.fetched_at
		RETURNING id`,
		pr.LinkID, string(pr.Provider), strings.ToLower(pr.Host), pr.RepoSlug, pr.Number, title, pr.URL,
		pr.AuthorLogin, string(pr.State), string(pr.Readiness), string(facets), pr.RawState, pr.HeadSHA,
		pr.BaseRef, pr.MergeCommitSHA, string(pr.MergeMethod), optionalTimestamp(pr.CreatedAt),
		optionalTimestamp(pr.MergedAt), optionalTimestamp(pr.ClosedAt), optionalTimestamp(pr.UpdatedAt),
		timestamp(pr.FetchedAt)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store.UpsertPullRequest: %w", err)
	}
	if commits != nil {
		if err := replacePRCommits(ctx, tx, id, commits); err != nil {
			return 0, fmt.Errorf("store.UpsertPullRequest: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.UpsertPullRequest: commit: %w", err)
	}
	return id, nil
}

// replacePRCommits swaps a PR's commit list inside tx, keeping a stored
// fingerprint for a sha the new list still holds.
func replacePRCommits(ctx context.Context, tx *sql.Tx, prID int64, commits []delivery.PRCommit) error {
	known := map[string]string{}
	rows, err := tx.QueryContext(ctx, `SELECT sha, patch_fp FROM pull_request_commits WHERE pr_id = ?`, prID)
	if err != nil {
		return fmt.Errorf("replacePRCommits: load: %w", err)
	}
	for rows.Next() {
		var sha, fp string
		if err := rows.Scan(&sha, &fp); err != nil {
			rows.Close()
			return fmt.Errorf("replacePRCommits: scan: %w", err)
		}
		known[sha] = fp
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `DELETE FROM pull_request_commits WHERE pr_id = ?`, prID); err != nil {
		return fmt.Errorf("replacePRCommits: clear: %w", err)
	}
	if len(commits) > prCommitsCap {
		commits = commits[:prCommitsCap]
	}
	for _, c := range commits {
		fp := c.PatchFP
		if fp == "" {
			fp = known[c.SHA]
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO pull_request_commits (pr_id, sha, position, patch_fp) VALUES (?, ?, ?, ?)
			ON CONFLICT(pr_id, sha) DO NOTHING`, prID, c.SHA, c.Position, fp); err != nil {
			return fmt.Errorf("replacePRCommits: insert %s: %w", c.SHA, err)
		}
	}
	return nil
}

// SetPRCommitPatchFingerprint records the locally computed fingerprint of
// one PR commit (rules P2 and P3 match on it).
func (s *Store) SetPRCommitPatchFingerprint(ctx context.Context, prID int64, sha, fp string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE pull_request_commits SET patch_fp = ? WHERE pr_id = ? AND sha = ?`, fp, prID, sha); err != nil {
		return fmt.Errorf("store.SetPRCommitPatchFingerprint: %w", err)
	}
	return nil
}

const prColumns = `p.id, p.provider_link_id, p.provider, p.host, p.repo_slug, p.number, p.title, p.url,
	p.author_login, p.pr_state, p.merge_readiness, p.facets_json, p.provider_raw_state, p.head_sha,
	p.base_ref, p.merge_commit_sha, p.merge_method, p.created_at, p.merged_at, p.closed_at,
	p.updated_at, p.fetched_at`

func scanPR(sc interface{ Scan(...any) error }) (delivery.PullRequest, error) {
	var (
		p                                          delivery.PullRequest
		provider, state, readiness, facets, method string
		created, merged, closed, updated, fetched  string
	)
	if err := sc.Scan(&p.ID, &p.LinkID, &provider, &p.Host, &p.RepoSlug, &p.Number, &p.Title, &p.URL,
		&p.AuthorLogin, &state, &readiness, &facets, &p.RawState, &p.HeadSHA, &p.BaseRef, &p.MergeCommitSHA,
		&method, &created, &merged, &closed, &updated, &fetched); err != nil {
		return p, err
	}
	p.Provider = delivery.Provider(provider)
	p.State = delivery.PRState(state)
	p.Readiness = delivery.Readiness(readiness)
	p.MergeMethod = delivery.MergeMethod(method)
	_ = json.Unmarshal([]byte(facets), &p.Facets)
	p.CreatedAt, p.MergedAt, p.ClosedAt = parseCommitTime(created), parseCommitTime(merged), parseCommitTime(closed)
	p.UpdatedAt, p.FetchedAt = parseCommitTime(updated), parseCommitTime(fetched)
	return p, nil
}

func (s *Store) queryPRs(ctx context.Context, q string, args ...any) ([]delivery.PullRequest, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []delivery.PullRequest
	for rows.Next() {
		p, err := scanPR(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) loadPullRequest(ctx context.Context, id int64) (delivery.PullRequest, bool, error) {
	p, err := scanPR(s.db.QueryRowContext(ctx, `SELECT `+prColumns+` FROM pull_requests p WHERE p.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, false, nil
	}
	if err != nil {
		return p, false, fmt.Errorf("store.loadPullRequest: %w", err)
	}
	return p, true, nil
}

// LoadProjectPullRequests returns the stored PRs linked to one project's
// commits committed at or after since: a PR whose commit list holds one of
// the project's commits, or a PR a landing names. Ordered by PR number.
func (s *Store) LoadProjectPullRequests(ctx context.Context, projectID int64, since time.Time) ([]delivery.PullRequest, error) {
	out, err := s.queryPRs(ctx, `
		SELECT `+prColumns+` FROM pull_requests p
		 WHERE p.id IN (
		       SELECT prc.pr_id FROM pull_request_commits prc
		         JOIN project_commits c ON c.sha = prc.sha
		        WHERE c.project_id = ? AND c.committed_at >= ?
		       UNION
		       SELECT cl.pr_id FROM commit_landings cl
		         JOIN project_commits c ON c.id = cl.commit_id
		        WHERE cl.project_id = ? AND cl.pr_id IS NOT NULL AND c.committed_at >= ?)
		 ORDER BY p.number, p.id`,
		projectID, timestamp(since), projectID, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectPullRequests: %w", err)
	}
	return out, nil
}

// LoadPullRequestCommits returns one PR's commit list in list order.
func (s *Store) LoadPullRequestCommits(ctx context.Context, prID int64) ([]delivery.PRCommit, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT sha, position, patch_fp FROM pull_request_commits WHERE pr_id = ? ORDER BY position, sha`, prID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadPullRequestCommits: %w", err)
	}
	defer rows.Close()
	var out []delivery.PRCommit
	for rows.Next() {
		var c delivery.PRCommit
		if err := rows.Scan(&c.SHA, &c.Position, &c.PatchFP); err != nil {
			return nil, fmt.Errorf("store.LoadPullRequestCommits: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadPullRequestCommits: rows: %w", err)
	}
	return out, nil
}

// FindPullRequestsForSHA returns the stored PRs whose commit list, head or
// merge commit is sha, by PR number.
func (s *Store) FindPullRequestsForSHA(ctx context.Context, sha string) ([]delivery.PullRequest, error) {
	out, err := s.queryPRs(ctx, `
		SELECT `+prColumns+` FROM pull_requests p
		 WHERE p.id IN (SELECT pr_id FROM pull_request_commits WHERE sha = ?)
		    OR p.head_sha = ? OR p.merge_commit_sha = ?
		 ORDER BY p.number, p.id`, sha, sha, sha)
	if err != nil {
		return nil, fmt.Errorf("store.FindPullRequestsForSHA: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------- mirrors

// UpsertDeliveryMirror records an Observer mirror keyed by its URL hash and
// returns its id. The URL is re-parsed so it never carries userinfo; an
// empty URLHash is derived from it (delivery.MirrorKey).
func (s *Store) UpsertDeliveryMirror(ctx context.Context, m delivery.Mirror) (int64, error) {
	u, _, _, _, ok := delivery.ParseRemoteURL(m.URL)
	if !ok {
		return 0, errors.New("store.UpsertDeliveryMirror: mirror URL is not a remote code host")
	}
	m.URL = u
	if m.URLHash == "" {
		m.URLHash = delivery.MirrorKey(u)
	}
	if m.Status == "" {
		m.Status = "never"
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO delivery_mirrors
		  (url_hash, url, path, default_branch, tip_sha, size_bytes, status, last_error,
		   last_refresh_at, last_check_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(url_hash) DO UPDATE SET
			url             = excluded.url,
			path            = excluded.path,
			default_branch  = excluded.default_branch,
			tip_sha         = excluded.tip_sha,
			size_bytes      = excluded.size_bytes,
			status          = excluded.status,
			last_error      = excluded.last_error,
			last_refresh_at = excluded.last_refresh_at,
			last_check_at   = excluded.last_check_at
		RETURNING id`,
		m.URLHash, m.URL, m.Path, m.DefaultBranch, m.TipSHA, m.SizeBytes, m.Status,
		scrub.TruncateN(contentScrubber().String(m.LastError), deliveryErrMaxBytes),
		optionalTimestamp(m.LastRefreshAt), optionalTimestamp(m.LastCheckAt), timestamp(m.CreatedAt)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store.UpsertDeliveryMirror: %w", err)
	}
	return id, nil
}

// ListDeliveryMirrors returns every Observer mirror, by id.
func (s *Store) ListDeliveryMirrors(ctx context.Context) ([]delivery.Mirror, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, url_hash, url, path, default_branch, tip_sha, size_bytes, status, last_error,
		       last_refresh_at, last_check_at, created_at
		  FROM delivery_mirrors ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store.ListDeliveryMirrors: %w", err)
	}
	defer rows.Close()
	var out []delivery.Mirror
	for rows.Next() {
		var (
			m                       delivery.Mirror
			refresh, check, created string
		)
		if err := rows.Scan(&m.ID, &m.URLHash, &m.URL, &m.Path, &m.DefaultBranch, &m.TipSHA, &m.SizeBytes,
			&m.Status, &m.LastError, &refresh, &check, &created); err != nil {
			return nil, fmt.Errorf("store.ListDeliveryMirrors: scan: %w", err)
		}
		m.LastRefreshAt, m.LastCheckAt, m.CreatedAt = parseCommitTime(refresh), parseCommitTime(check), parseCommitTime(created)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListDeliveryMirrors: rows: %w", err)
	}
	return out, nil
}

// DeleteDeliveryMirror removes a mirror's row (the caller removes its
// directory).
func (s *Store) DeleteDeliveryMirror(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM delivery_mirrors WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store.DeleteDeliveryMirror: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- project settings

// GetDeliveryProjectSettings returns one project's delivery switches; a
// project with no row gets the zero value (no mirror, no schedule).
func (s *Store) GetDeliveryProjectSettings(ctx context.Context, projectID int64) (delivery.ProjectSettings, error) {
	ps := delivery.ProjectSettings{ProjectID: projectID}
	var (
		enabled int
		updated string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT mirror_enabled, schedule_minutes, updated_at FROM delivery_project_settings WHERE project_id = ?`,
		projectID).Scan(&enabled, &ps.ScheduleMinutes, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return ps, nil
	}
	if err != nil {
		return ps, fmt.Errorf("store.GetDeliveryProjectSettings: %w", err)
	}
	ps.MirrorEnabled = enabled != 0
	ps.UpdatedAt = parseCommitTime(updated)
	return ps, nil
}

// SetDeliveryProjectSettings upserts one project's delivery switches.
func (s *Store) SetDeliveryProjectSettings(ctx context.Context, ps delivery.ProjectSettings) error {
	if ps.ProjectID <= 0 {
		return errors.New("store.SetDeliveryProjectSettings: project id required")
	}
	enabled := 0
	if ps.MirrorEnabled {
		enabled = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO delivery_project_settings (project_id, mirror_enabled, schedule_minutes, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(project_id) DO UPDATE SET
			mirror_enabled   = excluded.mirror_enabled,
			schedule_minutes = excluded.schedule_minutes,
			updated_at       = excluded.updated_at`,
		ps.ProjectID, enabled, ps.ScheduleMinutes, timestamp(ps.UpdatedAt))
	if err != nil {
		return fmt.Errorf("store.SetDeliveryProjectSettings: %w", err)
	}
	return nil
}

// ListDeliveryProjectSettings returns every project's stored switches, by
// project id.
func (s *Store) ListDeliveryProjectSettings(ctx context.Context) ([]delivery.ProjectSettings, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT project_id, mirror_enabled, schedule_minutes, updated_at FROM delivery_project_settings ORDER BY project_id`)
	if err != nil {
		return nil, fmt.Errorf("store.ListDeliveryProjectSettings: %w", err)
	}
	defer rows.Close()
	var out []delivery.ProjectSettings
	for rows.Next() {
		var (
			ps      delivery.ProjectSettings
			enabled int
			updated string
		)
		if err := rows.Scan(&ps.ProjectID, &enabled, &ps.ScheduleMinutes, &updated); err != nil {
			return nil, fmt.Errorf("store.ListDeliveryProjectSettings: scan: %w", err)
		}
		ps.MirrorEnabled = enabled != 0
		ps.UpdatedAt = parseCommitTime(updated)
		out = append(out, ps)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListDeliveryProjectSettings: rows: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------- branch tips

// UpsertBranchTips records branch tips keyed by (project, ref name hash).
// RefNameHash is derived from RefName when empty.
func (s *Store) UpsertBranchTips(ctx context.Context, tips []delivery.BranchTip) error {
	if len(tips) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertBranchTips: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range tips {
		if t.RefNameHash == "" {
			t.RefNameHash = sha256Hex(t.RefName)
		}
		if t.RangeFPState == "" {
			t.RangeFPState = delivery.FPPending
		}
		members, err := json.Marshal(nonNilStrings(t.MemberSHAs))
		if err != nil {
			return fmt.Errorf("store.UpsertBranchTips: members: %w", err)
		}
		files, err := json.Marshal(nonNilStrings(t.Files))
		if err != nil {
			return fmt.Errorf("store.UpsertBranchTips: files: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO delivery_branch_tips
			  (project_id, ref_name_hash, ref_name, tip_sha, merge_base_sha, range_fp, range_fp_state,
			   member_shas_json, files_json, observed_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(project_id, ref_name_hash) DO UPDATE SET
				ref_name         = excluded.ref_name,
				tip_sha          = excluded.tip_sha,
				merge_base_sha   = excluded.merge_base_sha,
				range_fp         = excluded.range_fp,
				range_fp_state   = excluded.range_fp_state,
				member_shas_json = excluded.member_shas_json,
				files_json       = excluded.files_json,
				observed_at      = excluded.observed_at`,
			t.ProjectID, t.RefNameHash, t.RefName, t.TipSHA, t.MergeBaseSHA, t.RangeFP, t.RangeFPState,
			string(members), string(files), timestamp(t.ObservedAt)); err != nil {
			return fmt.Errorf("store.UpsertBranchTips: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.UpsertBranchTips: commit: %w", err)
	}
	return nil
}

// LoadBranchTips returns one project's recorded branch tips, newest first,
// capped at 200.
func (s *Store) LoadBranchTips(ctx context.Context, projectID int64) ([]delivery.BranchTip, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT project_id, ref_name_hash, ref_name, tip_sha, merge_base_sha, range_fp, range_fp_state,
		       member_shas_json, files_json, observed_at
		  FROM delivery_branch_tips WHERE project_id = ?
		 ORDER BY observed_at DESC LIMIT ?`, projectID, branchTipsLoadCap)
	if err != nil {
		return nil, fmt.Errorf("store.LoadBranchTips: %w", err)
	}
	defer rows.Close()
	var out []delivery.BranchTip
	for rows.Next() {
		var (
			t                        delivery.BranchTip
			members, files, observed string
		)
		if err := rows.Scan(&t.ProjectID, &t.RefNameHash, &t.RefName, &t.TipSHA, &t.MergeBaseSHA, &t.RangeFP,
			&t.RangeFPState, &members, &files, &observed); err != nil {
			return nil, fmt.Errorf("store.LoadBranchTips: scan: %w", err)
		}
		_ = json.Unmarshal([]byte(members), &t.MemberSHAs)
		_ = json.Unmarshal([]byte(files), &t.Files)
		t.ObservedAt = parseCommitTime(observed)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadBranchTips: rows: %w", err)
	}
	return out, nil
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// ---------------------------------------------------------------- wire support

// wirePR is one PR with the project it was linked through and that
// project's AI-touched commit shas in it, for deliverysummary.go.
type wirePR struct {
	ProjectID int64
	PR        delivery.PullRequest
	SHAs      []string
}

// loadWirePullRequests returns every stored PR that holds at least one
// evaluated (AI-touched) commit committed at or after since, once per
// (project, PR), with that project's AI commit shas in it.
func (s *Store) loadWirePullRequests(ctx context.Context, since time.Time) ([]wirePR, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT cl.project_id, prc.pr_id, c.sha
		  FROM commit_landings cl
		  JOIN project_commits c ON c.id = cl.commit_id
		  JOIN pull_request_commits prc ON prc.sha = c.sha
		 WHERE c.committed_at >= ?
		UNION
		SELECT DISTINCT cl.project_id, cl.pr_id, c.sha
		  FROM commit_landings cl
		  JOIN project_commits c ON c.id = cl.commit_id
		 WHERE cl.pr_id IS NOT NULL AND c.committed_at >= ?
		 ORDER BY 1, 2, 3`, timestamp(since), timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.loadWirePullRequests: %w", err)
	}
	type key struct{ project, pr int64 }
	order := []key{}
	shas := map[key][]string{}
	for rows.Next() {
		var (
			k   key
			sha string
		)
		if err := rows.Scan(&k.project, &k.pr, &sha); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store.loadWirePullRequests: scan: %w", err)
		}
		if _, seen := shas[k]; !seen {
			order = append(order, k)
		}
		shas[k] = append(shas[k], sha)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store.loadWirePullRequests: rows: %w", err)
	}
	rows.Close()
	out := make([]wirePR, 0, len(order))
	for _, k := range order {
		pr, ok, err := s.loadPullRequest(ctx, k.pr)
		if err != nil {
			return nil, fmt.Errorf("store.loadWirePullRequests: %w", err)
		}
		if ok {
			out = append(out, wirePR{ProjectID: k.project, PR: pr, SHAs: shas[k]})
		}
	}
	return out, nil
}

// probeDelivery is the org-push snapshot-gate fingerprint of the delivery
// wire (orgsnapgate.go): a landing whose status, kind or PR changes, a PR
// whose state changes, a fresher fetch of the user's remote and a provider
// sync all move it. The landing term is a weighted sum rather than
// MAX(evaluated_at), because every scan pass re-stamps evaluated_at.
// Declared here, beside the tables' one writer.
func (s *Store) probeDelivery(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'dl' || (SELECT COUNT(*) || ':' || COALESCE(SUM(commit_id * (unicode(status) * 131 + length(status) * 31
		                     + length(kind) * 7 + COALESCE(pr_id, 0) + pr_number)), 0) || ':' || COALESCE(MAX(landed_at), '')
		                  FROM commit_landings)
		     || '|' || (SELECT COUNT(*) || ':' || COALESCE(MAX(updated_at), '') || ':'
		                     || COALESCE(SUM(id * (length(pr_state) * 13 + length(merge_readiness))), 0)
		                  FROM pull_requests)
		     || '|' || (SELECT COALESCE(MAX(fetch_head_at), '') FROM project_remotes)
		     || '|' || (SELECT COALESCE(MAX(last_ok_at), '') FROM provider_links)
		     || '|' || (SELECT COALESCE(MAX(last_refresh_at), '') FROM delivery_mirrors)`)
}
