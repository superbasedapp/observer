package skillhistory

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
)

// Scope values. They mirror internal/guidance's Scope vocabulary.
const (
	ScopeProject = string(guidance.ScopeProject)
	ScopeUser    = string(guidance.ScopeUser)
)

// Snapshot events (session_skill_snapshots.event).
const (
	EventSessionStart = "session_start"
	EventSkillInvoke  = "skill_invoke"
)

// Snapshot member states (skill_snapshot_members.state).
const (
	MemberPresent    = "present"
	MemberUnreadable = "unreadable"
)

// Tree memo states (project_skill_trees.state).
const (
	TreeOK      = "ok"
	TreeMissing = "missing"
)

// Session relations.
const (
	RelationSubagent = "subagent"
	RelationFork     = "fork"
)

// Observed-column states (see observedRules).
const (
	ObsNotApplicable  = "n/a"
	ObsNotMeasurable  = "not_measurable"
	ObsNotCaptured    = "not_captured"
	ObsObserved       = "observed"
	ObsChanged        = "changed_during_session"
	ObsAbsent         = "absent"
	ObsUnknown        = "unknown"
	ObsHomeUnresolved = "home_unresolved"
	// ObsAfterStart: the session's FIRST snapshot came from a resume or
	// compact re-fire well after the start, so it says what was on disk
	// then, not what was available at the start.
	ObsAfterStart = "observed_after_start"
)

// Observed-column reasons (ObservedCell.Reason).
const (
	// ObsReasonSubagent: a sub-agent session never fires SessionStart;
	// its skills are the parent session's.
	ObsReasonSubagent = "subagent"
)

// HEAD-column reasons (HeadCell.Reason).
const (
	HeadReasonNotScanned = "not_scanned"
	// HeadReasonSameSecond: HEAD moved to more than one commit within the
	// chosen reflog second (a rebase, a pull); 1-second reflog resolution
	// cannot say which one a later session started on with certainty.
	HeadReasonSameSecond = "same_second"
	// HeadReasonSkew: a move lies within the skew margin of the start.
	HeadReasonSkew = "skew"
)

// Snapshot sources that mark a real session start (SessionStart source).
var startSources = map[string]bool{"startup": true, "clear": true}

// HEAD-column states (see headRules).
const (
	HeadNotApplicable     = "n/a"
	HeadNotInProjectGit   = "not_in_project_git"
	HeadGitUnavailable    = "git_unavailable"
	HeadReflogUnavailable = "reflog_unavailable"
	HeadMovedNearStart    = "head_moved_near_start"
	HeadPending           = "pending"
	HeadCommitUnavailable = "commit_unavailable"
	HeadCommitted         = "committed"
	HeadAbsentInCommit    = "absent_in_commit"
)

// Invoked-entry states.
const (
	InvNotMeasurable      = "not_measurable"
	InvVersion            = "version"
	InvVersionNotCaptured = "version_not_captured"
	InvUnknown            = "unknown"
)

// Current in-git states.
const (
	GitCommitted       = "committed"
	GitRemoved         = "removed"
	GitNotCommitted    = "not_committed"
	GitNotInProjectGit = "not_in_project_git"
	GitUnknown         = "unknown"
)

// InventoryFile is one CURRENT guidance row of kind skill (from
// project_guidance_files, the project root and the home sentinel root).
// RelPath is project-relative, or "~/"-prefixed for user scope, forward
// slashes.
type InventoryFile struct {
	Scope   string
	RelPath string
	Name    string
	Present bool
}

// TimelineCommit is one commit (from project_commits/project_commit_files)
// that touched at least one file under a skill directory. Files lists the
// touched paths under skill directories only.
type TimelineCommit struct {
	SHA         string
	CommittedAt time.Time
	Subject     string
	Reachable   bool
	IsMerge     bool
	Files       []string
	// Parents are the commit's parent shas (project_commits.parents_json).
	// With [Input.Ancestry] they order commits that share one committer
	// second; the sha never does.
	Parents []string
}

// Tree is one tree-memo entry: the skill files present in a commit's tree.
// State is TreeOK or TreeMissing. Files maps rel path to its entry.
type Tree struct {
	SHA   string
	State string
	Files map[string]TreeFile
}

// TreeFile is one path in a Tree.
type TreeFile struct {
	Mode    string
	BlobOID string
}

// HeadMove is one captured reflog entry: HEAD moved to SHA at MovedAt.
type HeadMove struct {
	MovedAt time.Time
	SHA     string
	Kind    string
	// Seq orders moves that share one reflog second (the reflog has
	// 1-second resolution): larger is newer. Captured from the reflog's
	// own output order.
	Seq int64
}

// WorktreeEntry is one non-clean skill path from the status porcelain
// (repo-root prefix already stripped to project-relative).
type WorktreeEntry struct {
	RelPath string
	State   string
}

// GitState is the git step's per-project state. Scanned=false means the
// step has never completed for this project.
type GitState struct {
	Scanned      bool
	LastScanAt   time.Time
	HeadSHA      string
	ReflogSince  time.Time
	IgnoreCase   bool
	Shallow      bool
	ObjectFormat string
	LastError    string
	// ProbeUnknown names repository probes whose answer is unknown (the
	// probe failed and there is no earlier answer): "ignorecase",
	// "shallow", "object_format".
	ProbeUnknown []string
}

// Session is one session of the project inside the window.
type Session struct {
	ID        string
	Tool      string
	StartedAt time.Time
	Relation  string
	ParentID  string
}

// Snapshot is one hook snapshot with its members.
type Snapshot struct {
	SessionID    string
	Tool         string
	Event        string
	Source       string
	ToolUseID    string
	InvokedName  string
	ObservedAt   time.Time
	Complete     bool
	HomeResolved bool
	Members      []Member
}

// Member is one SKILL.md a snapshot saw.
type Member struct {
	Scope     string
	RelPath   string
	Name      string
	State     string
	BlobOID   string
	BlobOIDLF string
}

// Invocation is one captured skill_invoke action.
type Invocation struct {
	SessionID string
	Tool      string
	Name      string
	ToolUseID string
	At        time.Time
}

// Input is everything [Build] needs. The store seam fills every slice;
// Rules is internal/guidance's discovery table; SnapshotEmitters and
// InvocationMeasurable are capability tables keyed by tool id.
type Input struct {
	Inventory   []InventoryFile
	Timeline    []TimelineCommit
	Trees       []Tree
	HeadMoves   []HeadMove
	Worktree    []WorktreeEntry
	Git         GitState
	Sessions    []Session
	Snapshots   []Snapshot
	Invocations []Invocation
	Rules       []guidance.Rule
	// Ancestry maps sha -> parent shas for every recorded commit that
	// shares a committer second with another timeline commit (it may
	// include commits that touched no skill, so a chain through them
	// still orders the group).
	Ancestry map[string][]string
	// TimelineTruncated reports the loader dropped the OLDEST timeline
	// rows at its cap.
	TimelineTruncated    bool
	SnapshotEmitters     map[string]bool
	InvocationMeasurable map[string]bool
	// SkewMargin is how close a reflog move may be to a session start
	// before the HEAD column refuses to pick a side. Zero means
	// DefaultSkewMargin.
	SkewMargin time.Duration
	// MaxSessions caps the sessions resolved (newest kept). Zero means
	// DefaultMaxSessions.
	MaxSessions int
	// MaxCells caps the sparse cells emitted. Zero means DefaultMaxCells.
	MaxCells int
}

// Defaults for the Input caps.
const (
	DefaultSkewMargin  = 120 * time.Second
	DefaultMaxSessions = 500
	DefaultMaxCells    = 5000
)

// Result is the derivation's output.
type Result struct {
	Skills               []Skill
	Sessions             []SessionRow
	Spans                []Span
	Cells                []Cell
	Unmatched            []NamedCount
	Ambiguous            []AmbiguousInvocation
	Truncated            bool
	ObservedSince        time.Time
	SnapshotCapabilities map[string]bool
}

// Skill is one skill directory with its history.
type Skill struct {
	Key         string
	Scope       string
	Dir         string
	Name        string
	Names       []string
	Present     bool
	Tools       []string
	Ambiguous   bool
	Current     Current
	MovedFrom   *Move
	Versions    []Version
	Commits     []SkillCommit
	Invocations InvocationSummary
}

// Current is the skill's current state.
type Current struct {
	InGit       string
	Worktree    string
	HeadVersion string
	CannotMatch string
}

// Move records an exact-content move of a skill directory.
type Move struct {
	FromDir string
	SHA     string
}

// Version is one distinct SKILL.md content, identified by its blob id.
type Version struct {
	ID                string
	BlobOID           string
	Ordinal           int
	FirstSeen         time.Time
	IntroducedBy      *CommitRef
	ReintroducedIn    []string
	InCommits         bool
	ObservedFirst     time.Time
	ObservedLast      time.Time
	SessionsAvailable int
	Invocations       int
}

// CommitRef names a commit.
type CommitRef struct {
	SHA         string
	CommittedAt time.Time
	Subject     string
	Reachable   bool
}

// SkillCommit is one commit that touched the skill directory.
type SkillCommit struct {
	SHA            string
	CommittedAt    time.Time
	Subject        string
	Reachable      bool
	IsMerge        bool
	Status         string // A | M | D | "" (SKILL.md untouched) | "?" (tree not resolved, chain state unknown, or order-unknown same-second commit)
	SkillMDChanged bool
	Files          int
	Version        string
}

// InvocationSummary counts a skill's captured invocations in the window.
type InvocationSummary struct {
	Measurable bool
	Count      int
	Last       time.Time
}

// SessionRow is one resolved session.
type SessionRow struct {
	ID             string
	Tool           string
	StartedAt      time.Time
	Relation       string
	ParentID       string
	ParentInWindow bool
}

// ObservedCell is the Observed column.
type ObservedCell struct {
	State       string
	Version     string
	Changed     []string
	LineEndings bool
	// Source is the first snapshot's SessionStart source when State is
	// ObsAfterStart (resume | compact | ...).
	Source string
	// Reason qualifies a state (ObsReasonSubagent on not_captured).
	Reason string
}

// HeadCell is the HEAD-at-session-start column.
type HeadCell struct {
	State      string
	Version    string
	SHA        string
	Candidates []string
	Reason     string
}

// InvokedEntry is one invocation in a cell.
type InvokedEntry struct {
	At      time.Time
	State   string
	Version string
}

// Span is a run of consecutive sessions (oldest to newest) that share the
// same Observed and HEAD resolution for one skill.
type Span struct {
	SkillKey    string
	FromSession string
	ToSession   string
	From        time.Time
	To          time.Time
	Sessions    int
	Observed    ObservedCell
	Head        HeadCell
}

// Cell is one sparse (session, skill) cell: emitted only where something
// is worth pointing at (an invocation, a change during the session, an
// observed version differing from HEAD's).
type Cell struct {
	SkillKey  string
	SessionID string
	Observed  ObservedCell
	Head      HeadCell
	Invoked   []InvokedEntry
}

// NamedCount is an invocation name that matched no skill.
type NamedCount struct {
	Tool  string
	Name  string
	Count int
}

// AmbiguousInvocation is an invocation name that matched more than one
// skill (a project and a home skill with the same name).
type AmbiguousInvocation struct {
	Tool       string
	Name       string
	Count      int
	Candidates []string
}
