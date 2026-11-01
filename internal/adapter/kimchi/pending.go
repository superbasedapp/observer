package kimchi

import (
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// A toolCall and its `toolResult` are two SEPARATE session entries,
// written however long the tool took apart. A poll tick that lands
// between them would persist the call optimistically successful and then
// lose the outcome: the call → ToolEvent correlation is parse-local, and
// the store's action ON CONFLICT clause cannot flip `success` /
// `error_message` on a re-emit. So the pair must resolve inside ONE parse
// window (the prime-agent precedent, same pi-mono envelope).
//
// At EOF, a call still awaiting its result rewinds the byte cursor to the
// start of its own entry and drops every event from that entry onward; the
// next poll re-reads it whole. Two bounds stop a result that never comes
// (an interrupted session) from stalling ingestion:
//
//   - maxDeferTailBytes — the deferral point must sit within this many
//     bytes of the parsed end.
//   - pendingResultGrace — the file must have been modified within this
//     window; an abandoned transcript stops growing, so its tail is
//     flushed once the grace expires. Kimchi's bash tool can run a
//     background command for up to an hour (`--bash-process-limit`,
//     default 3600s), so the grace is wider than that.
const (
	maxDeferTailBytes  = 1 << 20
	pendingResultGrace = 90 * time.Minute
)

// pendingMark locates a still-unanswered toolCall: the index of its
// ToolEvent plus the rewind coordinates of the entry that produced it
// (the entry's byte offset and the event-slice lengths from before the
// entry was handled, so truncation removes the WHOLE entry's output).
type pendingMark struct {
	idx       int
	lineStart int64
	toolLen   int
	tokenLen  int
	cacheLen  int
}

// deferUnpairedTail rewinds res to just before the earliest toolCall still
// awaiting its result. A no-op when nothing is pending or when either
// bound says the result is not coming.
func (st *parseState) deferUnpairedTail(res *adapter.ParseResult) {
	mark, ok := st.earliestPending()
	if !ok {
		return
	}
	if res.NewOffset-mark.lineStart > maxDeferTailBytes {
		return
	}
	info, err := os.Stat(st.path)
	if err != nil || time.Since(info.ModTime()) > pendingResultGrace {
		return
	}
	if mark.toolLen <= len(res.ToolEvents) {
		res.ToolEvents = res.ToolEvents[:mark.toolLen]
	}
	if mark.tokenLen <= len(res.TokenEvents) {
		res.TokenEvents = res.TokenEvents[:mark.tokenLen]
	}
	if mark.cacheLen <= len(res.CacheObservations) {
		res.CacheObservations = res.CacheObservations[:mark.cacheLen]
	}
	res.NewOffset = mark.lineStart
	// The cursor did not advance, so keep the file on the poll loop.
	res.RetrySuggested = true
}

// earliestPending returns the pending call whose entry starts earliest.
func (st *parseState) earliestPending() (pendingMark, bool) {
	var (
		best  pendingMark
		found bool
	)
	for _, m := range st.pendingCall {
		if !found || m.lineStart < best.lineStart {
			best, found = m, true
		}
	}
	return best, found
}
