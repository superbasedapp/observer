package adapter

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Adapter turns one AI coding tool's session data into normalized ToolEvents
// and TokenEvents. Implementations live in internal/adapter/<name>.
//
// Implementations MUST:
//   - Scrub raw tool inputs before returning — no secrets escape the adapter.
//   - Emit deterministic SourceEventID values so re-parsing is idempotent.
//   - Advance the returned offset past the last fully-parsed event, so that
//     the caller can persist it to parse_cursors and skip on next call.
type Adapter interface {
	// Name is a stable identifier stored in the `tool` column. It must be
	// one of the models.Tool* constants.
	Name() string

	// WatchPaths returns absolute directories the watcher should monitor
	// for new or changed session files. Paths that do not exist are skipped
	// at registry time — adapters should return their canonical path
	// regardless of installed state.
	WatchPaths() []string

	// IsSessionFile filters fsnotify events. Returns true if path is a
	// session file this adapter should parse.
	IsSessionFile(path string) bool

	// ParseSessionFile parses path from fromOffset to EOF, returning the
	// produced events and the new byte offset to persist. Malformed lines
	// are skipped, not fatal — adapters advance past them so repeated calls
	// make progress.
	ParseSessionFile(ctx context.Context, path string, fromOffset int64) (ParseResult, error)
}

// CursorKind classifies what an adapter's persisted parse cursor
// (parse_cursors.byte_offset) actually MEANS for a given file, and
// whether that file is expected to produce action rows at all.
//
// The zero value is CursorByteOffset, so an adapter that does not
// implement CursorSemantics keeps the historical assumption — every
// tracked file is an append-only text log tailed by byte offset —
// unchanged.
//
// Consumers branch on the derived capability predicates
// (LagMeaningful / ActionsExpected), never on the kind constant or on
// a tool name (CLAUDE.md module rule #3).
type CursorKind uint8

const (
	// CursorByteOffset is an append-only text file tailed by byte
	// offset. `file_size - byte_offset` is a real ingest lag, and a
	// cursor that reached EOF on a non-trivial file without emitting
	// any action is the adapter-misroute fingerprint.
	CursorByteOffset CursorKind = iota

	// CursorWatermark is an opaque high-water mark — a SQLite row id,
	// a Unix-millis `updated_at`, a `MAX(time_updated)` — that the
	// adapter compares against store rows, not against bytes on disk.
	// Comparing it to the file size is a category error in BOTH
	// directions: a small row-id watermark makes a multi-megabyte
	// store read "permanently behind", and a Unix-millis watermark
	// dwarfs the file size and makes it read "permanently at EOF".
	// Neither lag nor the zero-action fingerprint means anything here.
	CursorWatermark

	// CursorEncrypted is a file a current adapter recognises and
	// tracks but cannot decode on this host by design (the Antigravity
	// desktop OSCrypt `.pb` conversation store). Emitting zero actions
	// is the EXPECTED outcome, not evidence of a misroute. Byte lag
	// still means something: these adapters advance the cursor to the
	// file size once a file is judged unrecoverable and hold it when a
	// retry is still pending.
	CursorEncrypted

	// CursorNoActions is a file an adapter reads but which never
	// produces action rows of its own — either because it carries only
	// token / usage / correlation records, or because the events it
	// contributes are attributed to a sibling file. Grok's global
	// `logs/unified.jsonl` (per-request token splits keyed by `sid`),
	// Qoder's `segments/*.jsonl` run logs, Copilot CLI's
	// `logs/process-*.log`, OpenClaw's `<id>.trajectory.jsonl` and
	// kiro-cli's flat `.json` state sidecar (whose events land under
	// the canonical `.jsonl`) are all this shape — each verified
	// against a live DB as having produced zero `actions` rows ever.
	// Byte lag is real; the zero-action fingerprint is not.
	//
	// Declare this ONLY with that evidence in hand. Cursor's per-chat
	// `store.db` LOOKS like a member (it stores the system prompt and
	// prompt budget, not activity) but demonstrably emits action rows
	// — 104 of them across 20 files on the measurement host — so
	// declaring it here would have suppressed a real signal.
	CursorNoActions
)

// String returns the stable machine-readable tag surfaced on the
// watcher-health wire.
func (k CursorKind) String() string {
	switch k {
	case CursorWatermark:
		return "watermark"
	case CursorEncrypted:
		return "encrypted"
	case CursorNoActions:
		return "no_actions"
	default:
		return "byte_offset"
	}
}

// LagMeaningful reports whether `file_size - byte_offset` is a real
// ingest lag for this kind of cursor. False for watermark cursors,
// whose value is not a byte count at all.
//
// An unrecognised kind degrades to the byte-offset answer: the safe
// direction is to keep reporting a signal, never to invent a
// suppression.
func (k CursorKind) LagMeaningful() bool {
	return k != CursorWatermark
}

// SizeGateMeaningful reports whether the watcher's oversize-file DoS
// guard (Options.MaxFileBytes) applies to this kind of file. The guard
// exists to stop a WHOLE-FILE READ of a hostile multi-GB session log
// from ballooning the daemon's heap — a rationale that only holds for
// files the adapter actually slurps. A watermark store is a SQLite
// database the adapter opens through the sql driver and queries
// INCREMENTALLY against its persisted high-water mark; its on-disk
// size is unrelated to per-parse allocation, and every healthy store
// GROWS past any fixed cap eventually — at which point the gate turns
// into permanent, silent capture loss for that tool (observed
// 2026-08-27: a 53 MB Windows opencode.db crossed the 50 MB cap and
// every session inside stopped ingesting, exit-0, WARN-only).
//
// Encrypted and no-actions files stay gated: the Antigravity `.pb`
// path decrypts a whole-file read, and no-actions files are tailed
// text. An unrecognised kind degrades to "gated" — the conservative
// direction for a DoS guard.
func (k CursorKind) SizeGateMeaningful() bool {
	return k != CursorWatermark
}

// ActionsExpected reports whether a non-trivial file of this kind
// SHOULD have produced at least one action row. False for undecodable
// stores and for files that carry tokens or state only. Also false for
// watermark cursors — not because such a store never holds actions
// (cline-cli's sessions.db does), but because the fingerprint's
// precondition, "the cursor reached EOF", cannot be established from a
// value that is not a byte count.
//
// An unrecognised kind degrades to the byte-offset answer for the same
// reason as LagMeaningful.
func (k CursorKind) ActionsExpected() bool {
	switch k {
	case CursorWatermark, CursorEncrypted, CursorNoActions:
		return false
	default:
		return true
	}
}

// FileCursorSemantics is one adapter's declaration about one file.
type FileCursorSemantics struct {
	// Kind classifies the cursor. Zero value = CursorByteOffset.
	Kind CursorKind
	// Detail is a short operator-facing explanation of WHY, surfaced
	// verbatim in the dashboard's watcher-health payload. Empty is
	// allowed; consumers fall back to a generic phrasing.
	Detail string
	// StreamsFromCursor declares that a parse of this file SEEKS to the
	// persisted byte offset and STREAMS forward through a fixed-size
	// reader — so one parse allocates on the order of the unread tail,
	// not of the file.
	//
	// It is a SEPARATE capability from Kind, and deliberately so: a
	// byte-offset cursor does NOT imply streaming. At least seven
	// adapters persist `NewOffset = fi.Size()` while doing a whole-file
	// os.ReadFile on every tick (kirocrew, cline, copilot's modern
	// store, deepseek, cursor's scan, gemini, antigravity) — for those a
	// 4 GB file with a 2 KB append has a 2 KB unread delta and a 4 GB
	// allocation, so gating on the delta would turn the DoS guard into a
	// no-op for exactly the files it was written for.
	//
	// The zero value is false = "assume whole-file read", which keeps
	// the total-size gate every adapter had before this field existed.
	// Set it true only with the seek verified at a file:line.
	StreamsFromCursor bool
}

// DeltaGateMeaningful reports whether the watcher's oversize DoS guard
// should compare the UNREAD DELTA (file size minus the persisted
// cursor) instead of the file's total size.
//
// True only when the adapter declared StreamsFromCursor AND the cursor
// is an actual byte offset — a watermark/encrypted/no-actions cursor is
// not a byte count, so subtracting it from a size is a category error
// (and watermark files are exempt from the guard entirely via
// SizeGateMeaningful).
func (s FileCursorSemantics) DeltaGateMeaningful() bool {
	return s.StreamsFromCursor && s.Kind == CursorByteOffset
}

// CursorSemantics is an OPTIONAL interface an adapter implements when
// the cursor it persists for at least one of its files is NOT a byte
// offset into an append-only text file, or when a file it tracks is
// not expected to yield actions.
//
// It is deliberately NOT part of Adapter: adding a method there would
// force all ~29 adapters to change (CLAUDE.md module rule #6,
// "additive, not invasive"). Adapters that do not implement it keep
// byte-offset semantics for every file they claim.
//
// The method is per-PATH, not per-adapter, because several adapters
// mix shapes — cline-cli tails `hooks.jsonl` by byte offset while
// scanning `sessions.db` by a Unix-millis watermark, and kiro-cli
// mixes flat file-size bundles with a SQLite watermark store.
//
// Implementations must be pure and cheap: no I/O, no locking. They
// are called once per parse_cursors row on a dashboard request.
type CursorSemantics interface {
	// CursorSemanticsFor returns the semantics of path's cursor. It is
	// only consulted for paths the same adapter's IsSessionFile
	// accepts; a path the adapter does not recognise may return the
	// zero value.
	CursorSemanticsFor(path string) FileCursorSemantics
}

// ResolveCursorSemantics resolves the cursor semantics of path across
// a set of adapters, using the SAME first-match rule as the
// composed IsSessionFile predicate: the first adapter that claims the
// path decides. When that adapter does not implement CursorSemantics,
// the byte-offset default applies — which is exactly the behaviour
// every adapter had before this interface existed.
//
// A path no adapter claims also resolves to the byte-offset default;
// such rows are already tagged orphan_unmatched upstream.
func ResolveCursorSemantics(adapters []Adapter, path string) FileCursorSemantics {
	for _, a := range adapters {
		if !a.IsSessionFile(path) {
			continue
		}
		if cs, ok := a.(CursorSemantics); ok {
			return cs.CursorSemanticsFor(path)
		}
		return FileCursorSemantics{}
	}
	return FileCursorSemantics{}
}

// ParseResult is the value returned by Adapter.ParseSessionFile.
type ParseResult struct {
	ToolEvents  []models.ToolEvent
	TokenEvents []models.TokenEvent
	// CacheObservations carries per-assistant-turn cache-relevant
	// views (Tier-2, transcript-derived) emitted by adapters that
	// can see content blocks + usage envelopes. Populated by the
	// claudecode adapter in C7 of the cachetrack arc (docs/plans/
	// cache-tracking-implementation-spec-2026-06-08.md §9). Tier-1
	// rollout adds codex / opencode / kilo-cli / cline-cli per
	// §14.3. Additive — adapters that don't populate it leave it
	// nil; the watcher / store pass-through silently no-ops on an
	// empty slice.
	CacheObservations []models.CacheTurnObservation
	// SessionProcessSeeds carries candidate (OS pid → session)
	// attribution links an adapter discovered in its own session data
	// (cline-cli's sessions.pid column, qwen-code's runtime.json
	// sidecar). The watcher plumbs them into store.IngestOptions; the
	// store validates liveness + identity and writes the
	// session_pid_bridge rows so direct process attribution works for
	// watcher/SQLite adapters, not just the hook-driven ones. Additive
	// — adapters that don't populate it leave it nil and every stop on
	// the path silently no-ops.
	SessionProcessSeeds []models.SessionProcessSeed
	// SessionLineages carries codex fork/subagent lineage markers an
	// adapter captured from the owning session_meta. The watcher plumbs
	// them into store.IngestOptions; the store persists them node-local
	// via Store.SetSessionLineage (migration 069) — never on the
	// org-push wire. Additive: adapters that don't populate it leave it
	// nil and every stop on the path silently no-ops.
	SessionLineages []models.SessionLineage
	// SessionSurfaces carries the capture-surface attribution an
	// adapter resolved from a grounded on-disk discriminator (Claude
	// Code `entrypoint`, Codex `originator`/`source`, Cline `source`,
	// a store's path shape, ...) into the normalized models.Surface*
	// vocabulary. The watcher plumbs them into store.IngestOptions; the
	// store persists them node-local via Store.SetSessionSurface
	// (migration 094) — never on the org-push wire. Additive: adapters
	// with no discriminator leave it nil and every stop on the path
	// silently no-ops. One entry per session per parse is plenty; the
	// store write is first-wins-unless-empty so re-stamps are idempotent.
	SessionSurfaces []models.SessionSurface
	// OutcomeUpdates carries outcomes for actions persisted by an
	// EARLIER parse window. A tool_use and its tool_result are two
	// separate records; a poll tick that ends between them persists
	// the call optimistically successful, and the next window resumes
	// past the tool_use with an empty correlation map — the result
	// would otherwise be dropped, because the store's action upsert
	// cannot flip success / error_message on conflict. An adapter that
	// can reconstruct the row's (SourceFile, SourceEventID) key from
	// the RESULT record alone emits the outcome here instead; the
	// watcher plumbs it into store.IngestOptions, which applies it via
	// Store.UpdateActionOutcome after the batch insert. Additive — nil
	// is a clean no-op at every stop on the path, and an entry that
	// matches no row is silently tolerated (unknown id, pruned row).
	OutcomeUpdates []models.ActionOutcomeUpdate
	// NewOffset is the byte offset to persist in parse_cursors. Subsequent
	// calls with this value as fromOffset will resume from the next
	// unparsed byte.
	NewOffset int64
	// Warnings carries non-fatal messages (malformed lines, unknown tool
	// names, etc.) for logging. They do not prevent progress.
	Warnings []string
	// RetrySuggested asks the watcher to keep the file on the poll
	// loop even when NewOffset == fromOffset (no advance). Adapters
	// set this when a transient miss may resolve on a later attempt —
	// e.g. a fresh Antigravity-CLI .pb file whose decrypt secret
	// hasn't been bootstrapped or whose embedded gRPC server is still
	// booting. Adapters are responsible for the freshness gate: set
	// only when retry has a plausible chance of succeeding. The
	// watcher writes the cursor (with MAX semantics) so the row stays
	// visible to pollCursors, which then refires processFile on the
	// next tick.
	RetrySuggested bool
}
