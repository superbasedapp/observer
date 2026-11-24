package conversation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// EstimateTokens returns a rough token estimate for msgs using the
// canonical "chars / 4" heuristic. Not byte-perfect but good enough to
// gate the rolling-summarisation threshold; correctness of compression
// never rides on this number.
func EstimateTokens(msgs []Message) int {
	total := 0
	for _, m := range msgs {
		total += len(m.Text) + len(m.Role)
	}
	return total / 4
}

// summaryCache is a process-wide in-memory cache of (input-hash →
// summary) so repeated summarisation of the same messages doesn't
// re-call the upstream summariser. Bounded by a soft cap; eviction is
// "drop everything when we hit the cap" — simpler than LRU and
// sufficient because rolling-summ on a single long session never has
// more than a few dozen distinct prefix hashes.
type summaryCache struct {
	mu    sync.Mutex
	cache map[string]string
	cap   int
}

func newSummaryCache(cap int) *summaryCache {
	if cap <= 0 {
		cap = 64
	}
	return &summaryCache{cache: map[string]string{}, cap: cap}
}

// messagesHash is the canonical message-list hasher. Used by the
// summary cache (input dedup) and the rolling sticky-boundary state
// (cross-turn invariance check). Field separators 0x1f / 0x1e keep
// distinct messages from collapsing under content equivalences.
func messagesHash(msgs []Message) string {
	h := sha256.New()
	for _, m := range msgs {
		h.Write([]byte(m.Role))
		h.Write([]byte{0x1f})
		h.Write([]byte(m.Text))
		h.Write([]byte{0x1e})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *summaryCache) hash(msgs []Message) string { return messagesHash(msgs) }

func (c *summaryCache) Get(msgs []Message) (string, bool) {
	key := c.hash(msgs)
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.cache[key]
	return s, ok
}

func (c *summaryCache) Put(msgs []Message, summary string) {
	key := c.hash(msgs)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= c.cap {
		c.cache = map[string]string{}
	}
	c.cache[key] = summary
}

// rollingState tracks the per-session sticky summary boundary that
// preserves cross-turn invariance: turn N+1 reuses turn N's summary +
// boundary (so the prefix bytes of the request body are byte-
// identical, hitting Anthropic's prompt cache) until the unsummarised
// tail grows past 2 × PreserveLastN messages, at which point a fresh
// summary is issued at the new boundary.
//
// Without this stickiness a naïve re-summarisation each turn would
// produce a slightly-different summary text → different marker bytes →
// different prefix → cache miss → cache_creation_tokens charged on
// every turn — the v1.4.38 regression class re-introduced via the
// rolling layer.
type rollingState struct {
	mu        sync.Mutex
	bySession map[string]*sessionRolling
}

// sessionRolling is one session's sticky summary state.
type sessionRolling struct {
	summary   string
	boundary  int    // count of older messages summarised; tail = msgs[boundary:]
	inputHash string // hash of msgs[:boundary] at the time the summary was produced
}

func newRollingState() *rollingState {
	return &rollingState{bySession: map[string]*sessionRolling{}}
}

func (r *rollingState) get(sessionID string) (*sessionRolling, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bySession == nil {
		return nil, false
	}
	s, ok := r.bySession[sessionID]
	return s, ok
}

func (r *rollingState) set(sessionID string, s *sessionRolling) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bySession == nil {
		r.bySession = map[string]*sessionRolling{}
	}
	r.bySession[sessionID] = s
}

// summarizableBoundary returns the largest K ≤ initialK such that
// every tool_use_id referenced by `tool_result` blocks in `msgs[K:]`
// has its producing `tool_use` block also in `msgs[K:]`.
//
// Anthropic's Messages API rejects requests where a `tool_result`
// block has no matching `tool_use` in the immediately preceding
// message. If naive rolling-summarisation drops msgs[:initialK]
// wholesale and that range contained a `tool_use` whose `tool_use_id`
// is still referenced by a `tool_result` in the preserved tail, the
// outgoing body is invalid and Anthropic returns 400.
//
// The fix walks backward from initialK and includes any message that
// produces a referenced id (decrementing K to that index). Chained
// preservation: when a newly-included message itself consumes
// tool_use_ids, those are added to the referenced set so further
// expansion can pick up earlier producers.
//
// Reads tool_use ids from [Message.ToolUseIDs] / [Message.ReferencedIDs]
// which the extractor populates at message-build time, so the hot
// path doesn't re-parse Raw bytes per call. Falls back to nil when
// these fields are empty (synthesised marker messages, or messages
// without tool blocks).
//
// Returns 0 when the entire conversation forms one tool-pair chain;
// the caller no-ops summarisation in that case (degraded gracefully —
// the request just goes upstream uncompressed).
//
// Provider-verified pairs ([Message.KeepWithNext], an OpenAI Responses
// reasoning item and its output item) are never split either: the
// boundary moves back until the message before it does not glue to the
// one after it, and the tool-pair expansion re-runs on the wider tail
// until neither rule moves it.
func summarizableBoundary(msgs []Message, initialK int) int {
	if initialK <= 0 || initialK > len(msgs) {
		return initialK
	}
	k := initialK
	for {
		next := toolPairBoundary(msgs, k)
		for next > 0 && msgs[next-1].KeepWithNext {
			next--
		}
		if next == k {
			return k
		}
		k = next
	}
}

// toolPairBoundary is the tool_use / tool_result half of
// [summarizableBoundary]: the largest K ≤ initialK whose tail holds the
// producer of every id its tool results reference.
func toolPairBoundary(msgs []Message, initialK int) int {
	if initialK <= 0 || initialK > len(msgs) {
		return initialK
	}

	// Phase 1: collect every tool_use_id referenced by tool_result
	// blocks in the tail. These are the IDs whose producers we must
	// keep in the tail (or expand the tail to include).
	referenced := map[string]bool{}
	for i := initialK; i < len(msgs); i++ {
		for _, id := range msgs[i].ReferencedIDs {
			referenced[id] = true
		}
	}
	if len(referenced) == 0 {
		return initialK
	}

	// Phase 2: walk backward, expanding K to include any message
	// that produces a referenced id. New consumed ids get added to
	// `referenced` so chained pairs propagate.
	K := initialK
	for i := initialK - 1; i >= 0; i-- {
		keep := false
		for _, id := range msgs[i].ToolUseIDs {
			if referenced[id] {
				keep = true
				break
			}
		}
		if keep {
			K = i
			for _, id := range msgs[i].ReferencedIDs {
				referenced[id] = true
			}
		}
	}
	return K
}

// summarizeIfThreshold runs rolling summarisation when the message
// list exceeds the token threshold. Returns the (possibly rewritten)
// messages and a single event describing the savings (mechanism =
// "rolling_summary"). No-ops gracefully on every error path so the
// pipeline never fails because of summarisation:
//
//   - factory is nil
//   - session has no summariser available
//   - token count under threshold
//   - PreserveLastN exceeds msg count (nothing to summarise)
//   - Summarize call returns an error
//
// In each no-op case the original msgs slice is returned unchanged and
// the event slice is empty.
//
// Cross-turn invariance: when the same session has already crossed
// threshold on an earlier turn, this function reuses the prior
// summary + boundary so the prefix bytes stay byte-identical across
// turns. The boundary is only re-built when the unsummarised tail
// grows past 2 × PreserveLastN messages (i.e. enough new content has
// accumulated that re-summarising is worth a fresh upstream call and
// the resulting cache miss). See [rollingState] for the full sticky-
// boundary contract.
func (p *Pipeline) summarizeIfThreshold(ctx context.Context, msgs []Message, sessionID, provider string) ([]Message, []Event) {
	factory := p.summarizerFor(provider)
	if factory == nil || p.rollingThresholdTokens <= 0 || sessionID == "" {
		return msgs, nil
	}
	preserve := p.cfg.PreserveLastN
	if preserve <= 0 {
		preserve = 6
	}
	if len(msgs) <= preserve {
		return msgs, nil
	}
	if EstimateTokens(msgs) < p.rollingThresholdTokens {
		return msgs, nil
	}
	if p.rollingState == nil {
		p.rollingState = newRollingState()
	}
	if p.summaryCache == nil {
		p.summaryCache = newSummaryCache(64)
	}

	// Decide whether to reuse the existing sticky boundary or rebuild.
	var summary string
	var boundary int
	rebuilt := false

	existing, _ := p.rollingState.get(sessionID)
	if existing != nil && existing.boundary > 0 && existing.boundary <= len(msgs) {
		// Verify msgs[:boundary] still matches what we summarised. If
		// the proxy re-extracted a different shape (rare — e.g.
		// downstream rewrites by a non-rolling pass) the hash check
		// catches it and we rebuild.
		if messagesHash(msgs[:existing.boundary]) == existing.inputHash {
			tailLen := len(msgs) - existing.boundary
			if tailLen <= 2*preserve {
				summary = existing.summary
				boundary = existing.boundary
			}
		}
	}

	if boundary == 0 {
		summarizer := factory.For(sessionID)
		if summarizer == nil {
			return msgs, nil
		}
		initialK := len(msgs) - preserve
		if initialK <= 0 {
			return msgs, nil
		}
		// Tool-pair safety: a naive boundary at len-preserve can split
		// a tool_use/tool_result pair, leaving an orphaned tool_result
		// in the tail with no producer. Anthropic rejects such bodies
		// with HTTP 400 ("unexpected tool_use_id ... no corresponding
		// tool_use block in the previous message"). Expand the
		// boundary backward to keep every referenced producer.
		boundary = summarizableBoundary(msgs, initialK)
		if boundary <= 0 {
			// Whole conversation is one tool-pair chain — can't
			// safely summarise without breaking pairs. Degrade
			// gracefully (no compression this turn).
			return msgs, nil
		}
		older := msgs[:boundary]
		if cached, ok := p.summaryCache.Get(older); ok {
			summary = cached
		} else {
			s, err := summarizer.Summarize(ctx, older)
			if err != nil {
				return msgs, nil
			}
			summary = s
			p.summaryCache.Put(older, summary)
		}
		p.rollingState.set(sessionID, &sessionRolling{
			summary:   summary,
			boundary:  boundary,
			inputHash: messagesHash(older),
		})
		rebuilt = true
	}
	_ = rebuilt

	if boundary <= 0 || boundary >= len(msgs) {
		return msgs, nil
	}
	older := msgs[:boundary]
	tail := msgs[boundary:]

	originalBytes := 0
	for _, m := range older {
		originalBytes += m.ByteLen
	}
	marker := Message{
		Role:    RoleSystem,
		Text:    formatRollingSummaryMarker(boundary, summary),
		ByteLen: 0,
	}
	marker.ByteLen = len(marker.Text)
	if marker.ByteLen >= originalBytes {
		return msgs, nil
	}

	out := make([]Message, 0, 1+len(tail))
	out = append(out, marker)
	out = append(out, tail...)

	event := Event{
		Mechanism:       "rolling_summary",
		OriginalBytes:   originalBytes,
		CompressedBytes: marker.ByteLen,
		MsgIndex:        0,
	}
	return out, []Event{event}
}

// formatRollingSummaryMarker is the canonical D20 marker form.
// Deterministic per (count, summary) — same inputs → same bytes →
// cross-turn invariance preserved.
func formatRollingSummaryMarker(count int, summary string) string {
	summary = strings.TrimSpace(summary)
	return fmt.Sprintf("[%d earlier messages summarized: %s]", count, summary)
}
