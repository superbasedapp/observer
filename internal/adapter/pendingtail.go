package adapter

import (
	"os"
	"time"
)

// DEFERRED TOOL RESULTS.
//
// In a JSONL transcript a tool call and its result are SEPARATE records,
// written however many seconds (or minutes) apart the tool took to run. A
// poll tick that ends between them used to persist the call optimistically
// successful and then DISCARD the outcome entirely: the call -> ToolEvent
// correlation is parse-local, so the next parse resumed past the call with
// an empty map and dropped the result on the floor. The premature
// Success=true was permanent: the store's action
// `ON CONFLICT(source_file, source_event_id)` clause updates duration_ms /
// metadata / raw_tool_input / raw_tool_output / content_bytes / an unknown
// action_type, and NOTHING else. Neither `success` nor `error_message` can
// be flipped by re-emitting the same SourceEventID, so the pair MUST be
// resolved inside one parse window.
//
// DeferUnpairedTail keeps the pair in one window: at EOF, a call still
// waiting for its result rewinds the byte cursor to the start of its own
// record and drops every event from that record onward, structurally the
// same deferral the line loop already applies to a partially written
// trailing line. The next poll re-reads the record whole and, once the
// result has landed, emits ONE row carrying the real success / error /
// output.
//
// Two bounds stop the deferral from ever stalling ingestion, because a call
// whose result never arrives (interrupted session, crashed host) is not
// distinguishable from one still running:
//
//   - MaxDeferTailBytes: the deferral point must be within this many bytes
//     of the parsed end. A transcript that has written well past an
//     unanswered call is plainly not waiting on it, so the call is flushed
//     with the optimistic outcome and the parse moves on.
//   - PendingResultGrace: the transcript must have been modified within
//     this window. An abandoned transcript stops growing, so its tail is
//     flushed once the grace expires. The window is deliberately wider than
//     the 30-minute ceiling claude-code documents for its longest running
//     tool: a long shell command writes nothing to the transcript until it
//     finishes, so mtime staleness during a live call is expected.
//
// The adapters that use it (commandcode, droid, muse, primeagent, kimchi)
// each keep their own map of pending calls; this file owns the rewind.
const (
	// MaxDeferTailBytes bounds how far behind the parsed end a pending
	// call's record may start and still be deferred.
	MaxDeferTailBytes = 1 << 20
	// PendingResultGrace bounds how long ago the transcript may have last
	// been modified and still have its pending tail deferred.
	PendingResultGrace = 90 * time.Minute
)

// PendingMark locates a tool call still waiting for its result: the rewind
// coordinates of the record that produced its ToolEvent (the byte offset of
// the record's line, and the event-slice lengths from before the record was
// handled, so truncation removes the WHOLE record's output, sibling text
// blocks and usage-derived TokenEvents included).
type PendingMark struct {
	// ToolIdx is the index of the call's ToolEvent in res.ToolEvents, which
	// the adapter uses to stamp the outcome when the result arrives.
	// DeferUnpairedTail does not read it.
	ToolIdx int
	// LineStart is the byte offset of the record's line.
	LineStart int64
	// ToolLen and TokenLen are len(res.ToolEvents) and len(res.TokenEvents)
	// before the record was handled.
	ToolLen  int
	TokenLen int
	// CacheLen is len(res.CacheObservations) before the record was handled.
	// It is applied only when DeferUnpairedTail is asked to rewind cache
	// observations.
	CacheLen int
}

// DeferUnpairedTail rewinds res to just before the record of the earliest
// call in pending (the one whose record starts first in the file at path),
// so the next parse sees the call and its result together. ToolEvents and
// TokenEvents are cut back to the mark; CacheObservations too when
// rewindCache is set. It is a no-op when nothing is pending or when either
// bound above says the result is not coming.
func DeferUnpairedTail(res *ParseResult, path string, pending map[string]PendingMark, rewindCache bool) {
	mark, ok := earliestPending(pending)
	if !ok {
		return
	}
	if res.NewOffset-mark.LineStart > MaxDeferTailBytes {
		return
	}
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > PendingResultGrace {
		return
	}
	if mark.ToolLen <= len(res.ToolEvents) {
		res.ToolEvents = res.ToolEvents[:mark.ToolLen]
	}
	if mark.TokenLen <= len(res.TokenEvents) {
		res.TokenEvents = res.TokenEvents[:mark.TokenLen]
	}
	if rewindCache && mark.CacheLen <= len(res.CacheObservations) {
		res.CacheObservations = res.CacheObservations[:mark.CacheLen]
	}
	res.NewOffset = mark.LineStart
	// The cursor did not advance, so ask the watcher to keep polling:
	// without this a brand-new transcript whose FIRST parse defers would
	// get no parse_cursors row at all and would only be rediscovered by the
	// periodic full scan.
	res.RetrySuggested = true
}

// earliestPending returns the pending call whose record starts earliest in
// the file. Calls from the same record share its rewind coordinates, so
// which of them wins a tie does not matter.
func earliestPending(pending map[string]PendingMark) (PendingMark, bool) {
	var (
		best  PendingMark
		found bool
	)
	for _, m := range pending {
		if !found || m.LineStart < best.LineStart {
			best, found = m, true
		}
	}
	return best, found
}
