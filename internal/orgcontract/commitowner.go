package orgcontract

// commitowner.go is the commit-ownership org wire (lane F-PROJ, operator ask
// 2026-09-28: "which session owned a git commit" must reach the ORG dashboard
// too). One row per (project root, commit) a node's AI edits reached, composed
// node-side by internal/store/commitownersummary.go over the ONE ownership
// fold (internal/projectroi.Ownership via store.LoadCommitOwnership) the node
// dashboard reads, so the org answer and the node answer cannot come from two
// different rules.
//
// WHAT NEVER CROSSES (docs/security.md COMMIT-1/COMMIT-2/COMMIT-3). No author
// identity of any kind: the node's project_commits.author_hash is an UNSALTED
// 16-hex prefix of the git author name, which is not adequate pseudonymisation
// for an org projection (COMMIT-2), so there is no author field on this row at
// all - not even a re-hashed one. No path, no rel_path and no path hash: the
// per-file grain of a commit is a file-level activity map of the repository,
// a strictly deeper disclosure than "this session owned this commit". Only
// commit-level numstat TOTALS and the AI-side counts ship.
//
// WHICH COMMITS SHIP. Only a commit that at least one of this node's AI
// sessions contributed to (an owned commit), plus an UNREACHABLE commit in the
// window so a previously shipped owner row can be flipped to "no longer on
// the checked-out branch". A commit no AI edit reached (a human commit, or a
// teammate's commit in a shared repository) never leaves the node, and a
// merge never carries attribution (R4.4), so neither ships. An unreachable row
// carries only its identity, time and flags: no numstat, no subject, no
// contributors.
//
// DEFAULT POSTURE. The row is ids and counts (a commit-sha HASH, session ids,
// line and file counts, a closed reason vocabulary) - the same disclosure
// class as the Lines-of-Code aggregates (loc.go), so it rides the DEFAULT
// metadata-only posture. TWO fields are gated on ShareOptions.shipsRawContent()
// (full_content / admin_managed / enterprise-granted):
//
//   - Subject: a commit message is free text a developer wrote, already
//     scrubbed through the node's content scrubber at capture. Empty means
//     "not shared", never "no subject".
//   - CommitSHA, the RAW commit id (review 2026-09-29 finding 3, docs/security.md
//     COMMIT-3): a raw sha is a lookup key into any repository the reader can
//     open, where it reveals the subject, the paths and the author the wire
//     otherwise withholds. The default posture ships only CommitSHAHash
//     (sha256 hex of the full sha, the root_commit_hash rule of
//     internal/store/projectidentity.go), which is the server's natural key.
//     HONEST LIMIT: an unsalted hash of a sha is a JOIN key, not
//     pseudonymisation against someone who can already read the repository -
//     they can hash its shas and match. It keeps the raw id off the default
//     wire and out of copy-paste reach; it does not hide a commit from a
//     repository reader.
//
// COMPAT. A node built before CommitSHAHash existed sends only CommitSHA; the
// server computes the hash from it (the ingest hashOrComputed precedent). A
// node built after it sends no CommitSHA on the default posture, which a
// server built before it cannot key and skips - nothing leaks, nothing is
// mis-keyed.
//
// NEVER DELETED. A commit that falls out of HEAD is flagged reachable=false by
// the node (it keeps the row, R2); the server then flips its stored row's
// reachable flag and KEEPS the last known owner and contributors, so the
// history of who owned a rewritten commit survives the rewrite.

// CommitContributorRow is one session's contribution to one commit.
type CommitContributorRow struct {
	// SessionID is the contributing session (a sub-agent's work is folded
	// into its PARENT session node-side, so a child session never appears).
	SessionID string `json:"session_id"`
	// Share is this session's share of the commit on the row's ShareBasis;
	// a commit's contributors sum to 1.
	Share float64 `json:"share"`
	// CodeLines / CommentLines are the AI code lines (added + modified) and
	// added comment lines this session's carried edits contributed, code
	// files only.
	CodeLines    int64 `json:"code_lines"`
	CommentLines int64 `json:"comment_lines"`
	// Files is the distinct files this session's carried edits cover.
	Files int64 `json:"files"`
	// Prompts is how many distinct prompts of this session reached the
	// commit.
	Prompts int64 `json:"prompts"`
}

// CommitOwnershipRow is one commit's ownership outcome as the node's rule
// computed it.
//
// Natural key on the server is (org_id, pushed_by_user_id, project_root_hash,
// commit_sha_hash) since server migration 189 (it was the raw commit_sha
// before): the OWNER is in the key (the ORG-SCOPE-2 lesson), so two
// developers whose nodes both observed the same commit of a shared repository
// each keep their own row. The upsert only replaces a stored row with one
// produced by a rule version at least as new (see
// internal/orgserver/ingest/commitowner.go).
type CommitOwnershipRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (the server
	// re-stamps both from the authenticated pusher, like every wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// ProjectRootHash is projects.root_path_hash - the SAME hash
	// SessionRow.ProjectRootHash and SessionLOCRow.ProjectRootHash carry, so
	// the org side joins a commit to its project group without any new
	// identifier.
	ProjectRootHash string `json:"project_root_hash"`
	// CommitSHA is the full RAW commit id - GATED: it ships only under
	// ShareOptions.shipsRawContent() (review 2026-09-29 finding 3). Empty =
	// not shared.
	CommitSHA string `json:"commit_sha,omitempty"`
	// CommitSHAHash is sha256 hex of the full commit id, always sent by a
	// node built after finding 3; the server's natural key. Empty only from a
	// node that predates it (the server then computes it from CommitSHA).
	CommitSHAHash string `json:"commit_sha_hash,omitempty"`
	// CommittedAt is the committer date, RFC3339 UTC.
	CommittedAt string `json:"committed_at"`
	// Reachable is false once the commit fell out of `git rev-list HEAD`
	// (a rebase, a reset, a branch switch). IsMerge marks a merge commit.
	Reachable bool `json:"reachable"`
	IsMerge   bool `json:"is_merge"`

	// FilesCount / Added / Deleted are the commit's numstat totals (every
	// file in the commit, AI-touched or not). Zero on an unreachable row.
	FilesCount int64 `json:"files_count"`
	Added      int64 `json:"added"`
	Deleted    int64 `json:"deleted"`

	// AIFiles is the distinct files any contributing session's AI edits
	// carried into this commit; AICodeLines / AICommentLines are the sum of
	// the contributors' CodeLines / CommentLines.
	AIFiles        int64 `json:"ai_files"`
	AICodeLines    int64 `json:"ai_code_lines"`
	AICommentLines int64 `json:"ai_comment_lines"`

	// OwnerSessionID is the owning session, "" when the commit has no owner
	// (then OwnerReason is one of the projectroi OwnerNone* values).
	OwnerSessionID string `json:"owner_session_id,omitempty"`
	// OwnerReason is the projectroi reason constant verbatim: which ranking
	// row decided the owner, or why there is none.
	OwnerReason string `json:"owner_reason"`
	// ShareBasis is "code_lines" or "files"; empty when there are no
	// contributors.
	ShareBasis string `json:"share_basis,omitempty"`
	// Contributors are ranked by the ownership rule; Contributors[0] is the
	// owner whenever OwnerSessionID is set.
	Contributors []CommitContributorRow `json:"contributors,omitempty"`

	// Subject is the scrubbed commit subject. THE ONE GATED FIELD: it ships
	// only under ShareOptions.shipsRawContent(). Empty = not shared.
	Subject string `json:"subject,omitempty"`

	// RuleVersion is internal/projectroi.OwnershipRuleVersion - the version
	// of the ownership rule that produced the row.
	RuleVersion int `json:"rule_version"`
}
