package projectroi

import "time"

// Prompt is one `user_prompt` action: the point in a session where a
// developer asked the AI for something. ActionID is the owning
// actions.id; SessionID scopes it to one conversation.
type Prompt struct {
	ActionID  int64
	SessionID string
	At        time.Time
	Preview   string
	Tool      string
}

// Edit is one AI-authored code change to a single file, aggregated by
// the loader from a file_changes row.
//
// Contract: the loader guarantees every Edit passed to this package has
// actor == "ai" and ActionID > 0 (docs/plans/.../2026-09-21.md §2 R4.1
// — human/system/editor rows and action-less rows are excluded
// structurally before this package ever sees them; Link does not
// re-check either condition).
type Edit struct {
	ActionID     int64
	SessionID    string
	At           time.Time
	PathHash     string
	AddedCode    int
	ModifiedCode int
	DeletedCode  int
	// AddedComment is the edit's added comment lines (file_changes.
	// added_comment). There is no modified-comment bucket: a rewritten
	// comment books as one deleted plus one added comment line.
	AddedComment int
	// Category is the file's internal/loc category ("code", "docs",
	// "config", ...). Only a code file's lines are CODE lines: a docs or
	// config file still participates in file-level reach (it is a file the
	// AI touched), but contributes zero to CodeLines/CommentLines. Empty is
	// treated as "code" so a caller that predates the field (and every
	// hand-built test Edit) keeps its prior meaning.
	Category string
	// Sidechain marks an edit made by a sub-agent run. Sidechain edits
	// participate in linking exactly like any other edit; the loader is
	// responsible for stamping their SessionID with the PARENT session
	// so ordinary same-session prompt matching (R4.1/F20) applies
	// unchanged.
	Sidechain bool
	// Overwrite is carried through untouched for display; it plays no
	// role in the R4 attribution rule.
	Overwrite bool
}

// countsAsCode reports whether this edit's line buckets are CODE lines.
func (e Edit) countsAsCode() bool { return e.Category == "" || e.Category == "code" }

// CodeLines is the edit's authored code lines (added + modified), or 0 for
// a non-code file. This is the ONE definition every Projects-page "AI code
// lines" figure (commit ledger, by-session spend, the reached-line proxy,
// commit ownership) folds through, so a docs-heavy edit can never inflate
// a number labelled "code" (the pre-2026-09-28 surfaces summed docs and
// config lines into it).
func (e Edit) CodeLines() int {
	if !e.countsAsCode() {
		return 0
	}
	return e.AddedCode + e.ModifiedCode
}

// CommentLines is the edit's added comment lines, or 0 for a non-code
// file. Paired with CodeLines through internal/loc.SplitAuthored for the
// code-vs-comment share.
func (e Edit) CommentLines() int {
	if !e.countsAsCode() {
		return 0
	}
	return e.AddedComment
}

// CommitFile is one file touched by a Commit, keyed by the same
// PathHash convention file_changes uses (internal/loc.PathHash).
type CommitFile struct {
	PathHash string
	Added    int
	Deleted  int
}

// Commit is one captured git commit on the project's checked-out
// branch (R2: HEAD-only, --no-renames).
type Commit struct {
	ID          int64
	SHA         string
	CommittedAt time.Time
	// IsMerge marks a merge commit. Per R4.4, a merge never carries
	// anything: Link ignores IsMerge commits' Files entirely.
	IsMerge bool
	// Reachable is false for a commit that fell out of `git rev-list
	// HEAD` history since it was captured (R2 reachability
	// revalidation). An unreachable commit carries nothing, same as a
	// merge; the row is kept for display, never deleted.
	Reachable bool
	// ForeignAuthor marks a commit whose author is NOT the local developer
	// of this repository: its stored author hash differs from the hash of the
	// repo's configured git identity (user.name - the %an field the commit
	// scanner hashes; internal/commitlog.HashAuthorName), as resolved by the
	// scanner (review 2026-09-29 finding 8). A teammate's commit pulled into
	// the checkout carries nothing, same as a merge or an unreachable commit,
	// so it can never be "owned" by, or mark as committed, a local AI
	// session. false when the local identity is UNKNOWN (user.name unset or
	// not yet resolved) or the commit has no author hash: the rule then keeps
	// its pre-author-check behaviour.
	ForeignAuthor bool
	Files         []CommitFile
}

// Turn is one proxied/observed API turn: a unit of spend inside a
// session.
type Turn struct {
	SessionID string
	At        time.Time
	// CostUSD is the turn's dollar cost as the CALLER resolved it — the
	// store loads the recorded column, and the dashboard composition
	// prices any turn whose recorded cost is zero through the process
	// cost engine before handing the slice to this package (the same
	// read-time rule every other cost surface applies; this corpus
	// stores 0 and prices on read). This package never prices.
	CostUSD   float64
	Input     int64
	Output    int64
	CacheRead int64
	// CacheCreation, CacheCreation1h, Reasoning and WebSearchRequests
	// are carried only so the caller can price the turn; no rule here
	// reads them.
	CacheCreation     int64
	CacheCreation1h   int64
	Reasoning         int64
	WebSearchRequests int64
	Model             string
	Tool              string
	// Source names the capture path ("proxy" = api_turns, "jsonl" =
	// token_usage) and TurnID the upstream message/request id when the
	// capture recorded one. Both exist only so the caller can de-duplicate
	// a turn captured by BOTH paths before pricing (the cost engine's
	// per-turn rule); no rule here reads them.
	Source string
	TurnID string
	// Priced is false when the turn is not FULLY priced
	// (cost.TurnRow.FullyPriced): it carries no recorded cost and no
	// pricing entry exists for its model (CostUSD is 0 by absence, not by
	// price), or its cached tokens billed against a cache-read rate the
	// vendor never quoted (CostUSD is a known under-count). Buckets count
	// these as unpriced_turns so a total is never mistaken for an exact
	// figure.
	Priced bool
}

// Task is one task_items row rolled up with its attributed cost.
type Task struct {
	SessionID string
	Key       string
	Status    string
	CostUSD   float64
}

// Session is one coding session in the project's window.
type Session struct {
	ID        string
	Tool      string
	StartedAt time.Time
	EndedAt   time.Time
	CostUSD   float64
}

// Options configures Link.
type Options struct {
	// LinkWindow bounds how long after a prompt a commit may still be
	// counted as carrying that prompt's files (R4.4). Zero or negative
	// means DefaultLinkWindow.
	LinkWindow time.Duration
}

// DefaultLinkWindow is the [projects].commit_link_window_days default
// from R4.4 — 14 days.
const DefaultLinkWindow = 14 * 24 * time.Hour

// window returns o.LinkWindow, or DefaultLinkWindow when it is not set.
func (o Options) window() time.Duration {
	if o.LinkWindow <= 0 {
		return DefaultLinkWindow
	}
	return o.LinkWindow
}
