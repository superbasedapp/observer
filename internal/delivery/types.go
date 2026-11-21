package delivery

import "time"

// types.go is the SHARED CONTRACT of the delivery arc (docs/plans/
// commit-pr-merge-tracking-plan-2026-10-15.md section 12.3): the closed
// vocabularies and the plain row shapes every other delivery package passes
// around. internal/store/delivery.go persists these shapes,
// internal/landingscan and internal/deliverysvc produce them,
// internal/deliverynet returns provider payloads already normalised into
// them, and the dashboard composes them. This package is PURE (no sql, net,
// http, os/exec, fsnotify; pinned by imports_test.go).

// RuleVersion is bumped whenever a rule in the matching table or the GitHub
// mapping table changes meaning, so stored landings evaluated under an older
// version are re-evaluated (the loc.Version precedent).
const RuleVersion = 1

// Provider is the closed code-host id.
type Provider string

// The closed Provider vocabulary. Only GitHub has a provider connection in
// this release (D-689); the others are classified so the page can say which
// host a remote is on and offer the mirror path.
const (
	ProviderGitHub      Provider = "github"
	ProviderGitLab      Provider = "gitlab"
	ProviderBitbucket   Provider = "bitbucket"
	ProviderAzureDevOps Provider = "azure_devops"
	ProviderUnknown     Provider = "unknown"
)

// PRState is a PR's lifecycle state (plan 5.1).
type PRState string

// The closed PRState vocabulary.
const (
	PRDraft          PRState = "draft"
	PROpen           PRState = "open"
	PRMerged         PRState = "merged"
	PRClosedUnmerged PRState = "closed_unmerged"
)

// Readiness is an open PR's merge readiness (plan 5.1). "" for a PR that is
// not open.
type Readiness string

// The closed Readiness vocabulary. A PR is MERGEABLE when its state is
// PROpen and its readiness is ReadyToMerge.
const (
	ReadyToMerge      Readiness = "ready"
	ReadyConflicts    Readiness = "conflicts"
	ReadyChecksFail   Readiness = "checks_failing"
	ReadyChecksPend   Readiness = "checks_pending"
	ReadyChangesReq   Readiness = "changes_requested"
	ReadyReviewReq    Readiness = "review_required"
	ReadyBehind       Readiness = "behind"
	ReadyBlockedOther Readiness = "blocked_other"
	ReadyUnknown      Readiness = "unknown"
)

// MergeMethod is how a merged PR landed. "" when unknown.
type MergeMethod string

// The closed MergeMethod vocabulary.
const (
	MergeCommit MergeMethod = "merge"
	MergeSquash MergeMethod = "squash"
	MergeRebase MergeMethod = "rebase"
)

// LandingStatus is one AI-touched commit's delivery outcome (plan 4).
type LandingStatus string

// The closed LandingStatus vocabulary.
const (
	StatusInFlight     LandingStatus = "in_flight"
	StatusLocalOnly    LandingStatus = "local_only"
	StatusPushed       LandingStatus = "pushed"
	StatusInPR         LandingStatus = "in_pr"
	StatusLanded       LandingStatus = "landed"
	StatusLikelyLanded LandingStatus = "likely_landed"
	StatusAbandoned    LandingStatus = "abandoned"
	StatusLandingLost  LandingStatus = "landing_lost"
)

// LandingKind is how a landed commit landed.
type LandingKind string

// The closed LandingKind vocabulary.
const (
	KindExactSHA    LandingKind = "exact_sha"
	KindMerge       LandingKind = "merge"
	KindSquash      LandingKind = "squash"
	KindRebase      LandingKind = "rebase"
	KindPatchID     LandingKind = "patch_id"
	KindSquashFiles LandingKind = "squash_files"
	KindContent     LandingKind = "content"
)

// Confidence is a landing's confidence (closed).
type Confidence string

// The closed Confidence vocabulary.
const (
	ConfExact  Confidence = "exact"
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// AbandonReason says why a commit reads as abandoned.
type AbandonReason string

// The closed AbandonReason vocabulary.
const (
	AbandonPRClosed AbandonReason = "pr_closed"
	AbandonDropped  AbandonReason = "dropped"
)

// EvidenceSource says where a remote's landing evidence came from.
type EvidenceSource string

// The closed EvidenceSource vocabulary.
const (
	// SourceUserRefs: the user's own remote-tracking refs, read-only, as
	// fresh as the user's last fetch (FETCH_HEAD age).
	SourceUserRefs EvidenceSource = "user_refs"
	// SourceMirror: the Observer-owned bare blobless mirror under
	// ~/.observer/delivery/mirrors (plan 12.2).
	SourceMirror EvidenceSource = "mirror"
	// SourceProvider: the code host's API (GitHub in this release).
	SourceProvider EvidenceSource = "provider"
)

// Remote is one project remote as the local scan observed it. URL never
// carries userinfo (ParseRemoteURL strips it before anything stores it).
type Remote struct {
	ProjectID     int64
	Name          string // "origin"
	URL           string // normalised, userinfo stripped
	Host          string // "github.com"
	Provider      Provider
	RepoSlug      string // "owner/repo"
	DefaultBranch string // "main"; "" when unknown
	// DefaultRefSHA is the user's refs/remotes/<name>/<default> tip as read
	// (never fetched by Observer). "" when that ref does not exist locally.
	DefaultRefSHA string
	// FetchHeadAt is the mtime of the user's .git/FETCH_HEAD (zero when
	// absent): "as of your last fetch".
	FetchHeadAt time.Time
	ObservedAt  time.Time
}

// PullRequest is one provider PR, normalised (deliverynet maps raw GitHub
// JSON into this through MapGitHubPR).
type PullRequest struct {
	ID        int64 // store row id; 0 before insert
	LinkID    int64 // provider_links.id
	Provider  Provider
	Host      string
	RepoSlug  string
	Number    int64
	Title     string
	URL       string
	State     PRState
	Readiness Readiness // "" unless State == PROpen
	Facets    Facets
	RawState  string // provider's own strings, for a tooltip ("open/unstable")
	HeadSHA   string
	// HeadRef is the PR's head branch name ("" when the provider did not
	// say). NODE-LOCAL: it stays in pull_requests (agent migration 246) and
	// never rides the org wire (branch names encode ticket ids, the M2
	// precedent). Cloud delivery credit resolves a branch-only cloud claim
	// (a Cursor run's git.branches) to its PR through it.
	HeadRef        string
	BaseRef        string
	MergeCommitSHA string // only meaningful when State == PRMerged
	MergeMethod    MergeMethod
	AuthorLogin    string
	CreatedAt      time.Time
	MergedAt       time.Time
	ClosedAt       time.Time
	UpdatedAt      time.Time
	FetchedAt      time.Time
}

// Facets are the individual readiness signals behind Readiness, so the UI
// can show the first blocking reason on the chip and every reason in the
// expanded row. Each is a closed value or "".
type Facets struct {
	Checks    string `json:"checks,omitempty"`    // passing | failing | pending | none | nonrequired_failing
	Review    string `json:"review,omitempty"`    // approved | changes_requested | review_required_inferred | none
	Conflicts string `json:"conflicts,omitempty"` // none | conflicts | unknown
	Behind    bool   `json:"behind,omitempty"`
}

// PRCommit is one commit listed in a PR.
type PRCommit struct {
	SHA      string
	Position int
	// PatchFP is the commit's patch fingerprint when it could be computed
	// locally (the object exists in the user's repository), "" otherwise.
	// Rules P2 and P3 match on it (force-push and rebase cases).
	PatchFP string
}

// Patch fingerprint states (project_commits.patch_fp_state and
// delivery_branch_tips.range_fp_state). A closed set; only FPOK carries a
// fingerprint.
const (
	FPPending    = "pending"     // not computed yet (rule G2 defers)
	FPOK         = "ok"          // fingerprint computed
	FPTooLarge   = "too_large"   // diff over the 2 MiB cap: lands only by L1, P1 or P2
	FPBinaryOnly = "binary_only" // every changed file is binary
	FPEmpty      = "empty"       // the diff is empty (an empty commit)
	FPError      = "error"       // git could not produce the diff (missing object, timeout)
)

// BranchTip is one local branch tip the landing scan saw holding an
// AI-touched commit that has not landed (delivery_branch_tips). It lets rule
// L3 (squash) and L4 (squash, files match) keep working after the branch is
// deleted. RefName is the branch's display name and stays on this node; the
// stored key is RefNameHash (branch names encode ticket ids, the M2
// precedent).
type BranchTip struct {
	ProjectID    int64
	RefNameHash  string
	RefName      string
	TipSHA       string
	MergeBaseSHA string
	// RangeFP is the fingerprint of the cumulative diff merge-base..tip;
	// RangeFPState is one of the FP* states.
	RangeFP      string
	RangeFPState string
	// MemberSHAs are the commits in merge-base..tip (capped); Files the
	// repository-relative paths the cumulative diff touches.
	MemberSHAs []string
	Files      []string
	ObservedAt time.Time
}

// Commit is one AI-touched commit as the evaluation needs it (loaded by the
// store from project_commits plus the Ownership gates).
type Commit struct {
	ID          int64
	ProjectID   int64
	SHA         string
	Subject     string
	CommittedAt time.Time
	Reachable   bool
	IsMerge     bool
	// PatchFP is the stored patch fingerprint; PatchFPState is
	// pending | ok | too_large | binary_only | error.
	PatchFP      string
	PatchFPState string
	// AIContributor is true when at least one AI session contributed under
	// the Ownership rule; ForeignAuthor marks a teammate's pulled commit.
	AIContributor bool
	ForeignAuthor bool
	// SessionIDs are the AI sessions that contributed to the commit, as the
	// Ownership fold last saw them. Kept on the landing row so a commit that
	// later falls out of HEAD (a squash-merged branch that was deleted) still
	// answers "which sessions' work landed".
	SessionIDs []string
}

// Landing is one AI-touched commit's evaluated outcome (commit_landings).
type Landing struct {
	CommitID       int64
	Status         LandingStatus
	Kind           LandingKind // "" unless landed / likely_landed
	Confidence     Confidence
	RuleID         string // "P1", "L2", ...
	RuleVersion    int
	LandingSHA     string // the commit on the default branch that carries it
	PRID           int64  // pull_requests.id, 0 when none
	PRNumber       int64  // from the provider or a subject template, 0 when none
	AbandonReason  AbandonReason
	Source         EvidenceSource
	FirstPushedAt  time.Time
	LandedAt       time.Time
	LandedAtSource string // provider | first_seen | merge_commit
	EvaluatedAt    time.Time
	// SessionIDs carries Commit.SessionIDs through to the stored row (an
	// empty slice keeps the stored value).
	SessionIDs []string
}

// LandedAt sources (Landing.LandedAtSource), a closed set.
const (
	LandedAtProvider    = "provider"
	LandedAtFirstSeen   = "first_seen"
	LandedAtMergeCommit = "merge_commit"
)

// ProviderLink is one code-host connection (provider_links). The secret
// lives in the OS keychain (service "sbo-delivery-v1", name KeyName); the
// database only ever holds the name.
type ProviderLink struct {
	ID       int64
	Provider Provider
	Host     string // "github.com"
	// AuthMode is "token" (fine-grained, keychain) or "gh_cli" (borrows the
	// user's gh login; Observer stores nothing).
	AuthMode            string
	KeyName             string
	AccountLogin        string
	ScopesSeen          string
	Status              string // ok | auth_failed | rate_limited | unreachable | repo_moved | wrong_shape | disabled | never_checked
	LastOKAt            time.Time
	LastErrorKind       string
	LastError           string
	NextRunAt           time.Time
	ConsecutiveFailures int
	CreatedAt           time.Time
}

// Mirror is one Observer-owned bare blobless mirror (delivery_mirrors).
type Mirror struct {
	ID            int64
	URLHash       string // sha256(normalised URL)[:16], also the dir name
	URL           string // normalised, userinfo stripped
	Path          string // ~/.observer/delivery/mirrors/<URLHash>.git
	DefaultBranch string
	TipSHA        string
	SizeBytes     int64
	// Status: ok | cloning | failed | over_cap | never |
	// needs_noninteractive_credentials (a clone, ls-remote or fetch
	// stopped at a password, passphrase or host key prompt that mirror
	// git never shows; the UI says "Needs non-interactive credentials").
	Status        string
	LastError     string
	LastRefreshAt time.Time
	LastCheckAt   time.Time // last ls-remote no-change check
	CreatedAt     time.Time
}

// ProjectSettings are one project's delivery switches
// (delivery_project_settings). Zero value: no mirror, no schedule.
type ProjectSettings struct {
	ProjectID int64
	// MirrorEnabled opts this project's non-GitHub (or unconnected) remote
	// into an Observer-owned mirror; ScheduleMinutes > 0 refreshes it on a
	// schedule (minimum 30), 0 means "Check now" only.
	MirrorEnabled   bool
	ScheduleMinutes int
	UpdatedAt       time.Time
}

// CloudPRClaim is one pull request or branch a cloud coding agent's vendor
// said a cloud session produced on a repository (cloud_session_links, agent
// migration 246; lane CA-C5). The provider service fetches the PR it names
// (by number, or by head branch) so cloud delivery credit has provider
// evidence. PRNumber 0 means only Branch was stated.
type CloudPRClaim struct {
	PRNumber int64
	Branch   string
}
