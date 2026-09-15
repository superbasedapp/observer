package taskflow

import "time"

// Normalized status vocabulary. Five vendor dialects collapse onto this
// one set at the decoder boundary (§R2.2); the raw vendor string is kept
// alongside it (RawStatus) so a per-tool dialect never has to be
// re-derived from the normalized value.
const (
	StatusPending    = "pending"
	StatusInProgress = "in_progress"
	StatusCompleted  = "completed"
	StatusCancelled  = "cancelled"
	StatusBlocked    = "blocked"
	StatusDeleted    = "deleted"
	// StatusVanished is a SYNTHETIC status — no vendor ever emits it.
	// The store seam (internal/store/taskflow.go) writes it when a
	// Snapshot-kind rewrite no longer lists an item that was
	// last-known in_progress (§R2.3.4's "vanish" case, 14 live
	// instances on the grounding corpus): the item's open window is
	// closed AT THE LAST SIGHTING (the snapshot event's own ts) rather
	// than left open forever. Consumers (Summarize's TerminalStatus,
	// the dashboard caveats) must render this distinctly from a real
	// completion — "task disappeared from the list, never marked
	// done" — never fold it into a completed count.
	StatusVanished = "vanished"
)

// MatchMode values ([tasks].match_mode, FIX-4 / docs/task-tracking.md
// §Configuration). Exported so internal/config's validator and the
// store seam share one vocabulary instead of two hand-copied string
// literals.
const (
	MatchModeExact      = "exact"
	MatchModeNormalized = "normalized"
)

// terminalStatuses are statuses that close an in_progress window.
// StatusDeleted is a removal, not a completion, but it still closes any
// open window (a deleted task cannot still be "in progress").
// StatusVanished is likewise a closure, not a completion — see its doc
// comment above.
var terminalStatuses = map[string]bool{
	StatusCompleted: true,
	StatusCancelled: true,
	StatusDeleted:   true,
	StatusVanished:  true,
}

// IsTerminal reports whether status closes an open in_progress window.
func IsTerminal(status string) bool { return terminalStatuses[status] }

// TaskEventKind discriminates how Items must be interpreted — the
// capability switch CLAUDE.md #3 asks for, never a tool-identity branch.
type TaskEventKind int

const (
	// SnapshotKind: Items is the COMPLETE current list this call sent.
	// Anything previously tracked for this session that is absent from
	// Items either vanished (content-hash keys: the wording changed or
	// the item was dropped) or was genuinely removed (keyed snapshots).
	SnapshotKind TaskEventKind = iota
	// DeltaKind: Items is the SET OF CHANGES this one call made. Every
	// other tracked item for the session is untouched by this event.
	DeltaKind
)

func (k TaskEventKind) String() string {
	if k == DeltaKind {
		return "delta"
	}
	return "snapshot"
}

// KeyKind records how Key was derived, so a consumer can suppress the
// text-matching caveat on genuinely keyed tools without re-inspecting
// the tool name.
const (
	KeyNative  = "native_id"    // vendor-assigned id (claude-code taskId, copilot id, freebuff id, kiro-cli index)
	KeyContent = "content_hash" // no vendor id — identity is the item's own text
)

// TaskItem is one item mentioned by a single TaskEvent — one entry in a
// Snapshot's array, or the one (rarely few) item(s) a Delta call touched.
type TaskItem struct {
	// Key is always populated by the decoder: the vendor id for
	// KeyNative, or a deterministic hash of the trimmed content for
	// KeyContent (see ContentKey). Two items across two different calls
	// with the identical trimmed content always produce the same Key —
	// that IS the v1 "exact string match" identity rule (§R2.3.4).
	Key     string
	KeyKind string
	// Content / ActiveForm / Owner are the best-available free text.
	// Empty means "this call did not carry that field" — the fold
	// (Apply) only overwrites a stored value when the new one is
	// non-empty, so a status-only Delta call never blanks a task's text.
	Content    string
	ActiveForm string
	Owner      string
	// RawStatus is the exact vendor string ("not-started", "done", …).
	// Status is RawStatus normalized onto the vocabulary above, or ""
	// when the vendor dialect has no equivalent (defensive: never
	// invented). StatusKnown is false for a Delta call that did not
	// touch status at all (claude-code's content-only TaskUpdate rows,
	// §R2.2 finding 1) — Apply must not synthesize a transition then.
	RawStatus   string
	Status      string
	StatusKnown bool
	// Order is the item's position in a Snapshot's array (0-based). Zero
	// for Delta items, which carry no ordering concept.
	Order int
}

// TaskEvent is one decoded todo/plan tool call (or one envelope inside a
// post_tool_batch array). SourceEventID is the dedup key — the tool's
// tool_use_id where known, else the action's own source_event_id — so a
// claude-code Task call captured BOTH by its own actions row and by a
// post_tool_batch envelope is applied exactly once (the store seam
// enforces this with a UNIQUE constraint, not this package).
type TaskEvent struct {
	Tool          string
	RawToolName   string
	SessionID     string
	ActionID      int64
	SourceEventID string
	Ts            time.Time
	Kind          TaskEventKind
	Items         []TaskItem
	// Failed marks a Delta call whose own tool output reports the
	// update was rejected (claude-code "Task not found" /
	// "<tool_use_error>"). A failed call must not mutate state or emit
	// a transition (§R2.6 item 5) — Apply skips every item on a Failed
	// event.
	Failed bool
}

// Transition is one status change to persist (task_transitions).
// FromStatus is "" for an item's first-observed state (no prior row).
type Transition struct {
	Key        string
	FromStatus string
	ToStatus   string
	Ts         time.Time
	ActionID   int64
	// SourceEventID is carried through so the store's UNIQUE(session_id,
	// key, source_event_id) constraint can de-duplicate the
	// post_tool_batch / direct-action double-capture case as a no-op
	// upsert rather than a second transition row.
	SourceEventID string
}

// ItemState is the persisted state of one task_items row, as far as
// Apply needs to know it. The store seam loads this from the DB before
// calling Apply and writes back whatever Apply returns.
type ItemState struct {
	Content     string
	ActiveForm  string
	Owner       string
	RawStatus   string
	Status      string
	FirstSeenAt time.Time
	// LastSnapshotActionID is the ID of the most recent Snapshot-kind
	// action that listed this key. Only meaningful for content_hash /
	// keyed-snapshot items; the store seam uses it to detect vanished
	// items between two consecutive snapshots for the same session.
	LastSnapshotActionID int64
	Order                int
}
