package orgcontract

// Delivery (commit to PR to merge) wire rows, docs/plans/
// commit-pr-merge-tracking-plan-2026-10-15.md sections 6.2 and 12 (operator
// decision D-689): every node sends daily COUNTS; PR identity (number,
// title, URL, repository) and hashed commit links ship only under
// ShareOptions.shipsRawContent() (an individual node with full_content or
// admin_managed, or a managed enrolment with the enterprise grant).
//
// Node side: composed by internal/store/deliverysummary.go, which
// internal/store/orgpush.go calls as a function, so the node-local delivery
// table names never appear in the push seam. Server side: ingested into
// delivery_daily and org_pull_requests (server migration 236, pg 0103).
//
// Compat: both keys are omitempty additions to PushEnvelope. An older server
// ignores them; an older node never sends them (the org page then says "no
// delivery data from this node yet").

// DeliveryDayRow is one (project, day) bucket of this node's AI-touched
// commits and the PRs that hold them, counts only. Day is the commit's
// committer date (UTC, YYYY-MM-DD) for commit counts and the PR's own event
// date (opened, merged, closed) for PR counts.
//
// Natural key on the server: (org_id, pushed_by_user_id, project_root_hash,
// day). A later push for the same key replaces the row (the counts are
// recomputed over a sliding window on the node, never incremented).
type DeliveryDayRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// ProjectRootHash is projects.root_path_hash, the same hash
	// SessionRow and CommitOwnershipRow carry.
	ProjectRootHash string `json:"project_root_hash"`
	Day             string `json:"day"`
	// RuleVersion is internal/delivery.RuleVersion at evaluation time.
	RuleVersion int `json:"rule_version"`
	// Source is "provider" when a code host connection answered for this
	// project in the window, else "local" (closed set).
	Source string `json:"source"`
	// FetchAgeBucket is how old the evidence is: for "local", the age of the
	// user's own last fetch (FETCH_HEAD) or of the Observer mirror; for
	// "provider", the last successful sync. One of "<1h", "<24h", "<7d",
	// "stale", "unknown".
	FetchAgeBucket string `json:"fetch_age_bucket"`

	AICommits             int64 `json:"ai_commits"`
	AICommitsPushed       int64 `json:"ai_commits_pushed"`
	AICommitsInPR         int64 `json:"ai_commits_in_pr"`
	AICommitsLanded       int64 `json:"ai_commits_landed"`
	LandedExact           int64 `json:"landed_exact"`
	LandedPatch           int64 `json:"landed_patch"`
	LandedSquash          int64 `json:"landed_squash"`
	AICommitsAbandoned    int64 `json:"ai_commits_abandoned"`
	AICommitsLikelyLanded int64 `json:"ai_commits_likely_landed"`

	// PR counts are "PRs that contain at least one of this node's
	// AI-touched commits", never "PRs this developer authored".
	PRsOpened         int64 `json:"prs_opened"`
	PRsMerged         int64 `json:"prs_merged"`
	PRsClosedUnmerged int64 `json:"prs_closed_unmerged"`
	PRsOpenReady      int64 `json:"prs_open_ready"`
	PRsOpenBlocked    int64 `json:"prs_open_blocked"`
	PRsDraft          int64 `json:"prs_draft"`

	// Time to merge over PRs merged on Day (provider created_at to
	// merged_at), seconds. MergeSamples is the sample size; 0 means the
	// percentiles are absent, never zero.
	MergeSecondsP50 int64 `json:"merge_seconds_p50"`
	MergeSecondsP75 int64 `json:"merge_seconds_p75"`
	MergeSamples    int64 `json:"merge_samples"`
}

// PullRequestRow is one PR that holds at least one of this node's
// AI-touched commits. RAW-CONTENT GATED as a whole: a node not under
// shipsRawContent() sends none. Repo slug and title name clients and
// codenames, the same posture as sessions.git_remote.
//
// Natural key on the server: (org_id, pushed_by_user_id, provider,
// repo_slug_hash, number). The server dedupes org-level PR counts by
// (repo_slug_hash, number); per-developer views do not.
type PullRequestRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Provider is the closed provider id ("github" in this release).
	Provider string `json:"provider"`
	// RepoSlug is "owner/repo"; RepoSlugHash is sha256 hex of the lowercase
	// "host/owner/repo" and is the server key (always set).
	RepoSlug     string `json:"repo_slug,omitempty"`
	RepoSlugHash string `json:"repo_slug_hash"`
	Number       int64  `json:"number"`
	Title        string `json:"title,omitempty"`
	URL          string `json:"url,omitempty"`
	// PRState: draft | open | merged | closed_unmerged.
	PRState string `json:"pr_state"`
	// MergeReadiness: ready | conflicts | checks_failing | checks_pending |
	// changes_requested | review_required | behind | blocked_other |
	// unknown ("" when not open).
	MergeReadiness string `json:"merge_readiness,omitempty"`
	// MergeMethod: merge | squash | rebase | "" (unknown or not merged).
	MergeMethod string `json:"merge_method,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	MergedAt    string `json:"merged_at,omitempty"`
	ClosedAt    string `json:"closed_at,omitempty"`
	// ProjectRootHash ties the PR to the node project it was found for.
	ProjectRootHash string `json:"project_root_hash"`
	// CommitSHAHashes are sha256 hex of each of this node's AI-touched
	// commits in the PR (the CommitOwnershipRow.CommitSHAHash rule), so the
	// server joins a PR to commit ownership and so to sessions.
	CommitSHAHashes []string `json:"commit_sha_hashes,omitempty"`
}
