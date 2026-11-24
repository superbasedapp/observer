package conversation

import (
	"encoding/json"
	"strings"
	"unicode"
)

// Role constants used by [Message.Role]. Callers map provider-specific
// roles onto this set ("assistant" covers both providers; OpenAI's "tool"
// and Anthropic's user-role tool_result both map to [RoleTool] when the
// message is a tool-result carrier).
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// Message is the provider-agnostic per-message unit the scorer and budget
// enforcer operate on. Raw preserves the original JSON bytes so the proxy
// can round-trip a message unchanged when the compressor chooses not to
// touch it.
type Message struct {
	// Role is one of [RoleSystem], [RoleUser], [RoleAssistant], [RoleTool].
	Role string
	// Text is a flattened, scrub-safe string rendering of the message
	// payload. For tool_use blocks it's the tool name + JSON input; for
	// tool_result blocks it's the result body. Used for scoring, budget
	// math, and any per-type compression pass.
	Text string
	// ByteLen is the serialized byte length of the message, used by the
	// budget enforcer to decide how many messages to drop.
	ByteLen int
	// RawIndex is the message's 0-based position in the original array.
	RawIndex int
	// Raw is the original JSON bytes, preserved for round-tripping.
	Raw json.RawMessage
	// ToolUseIDs lists every tool_use_id this message produces (Claude
	// Code's parallel tool calls put multiple tool_use blocks in one
	// assistant message, so this is a slice — `nil` for messages
	// without tool_use blocks). Tool results reference these IDs via
	// [ReferencedIDs].
	ToolUseIDs []string
	// ReferencedIDs lists tool_use_ids this message cites. For tool_result
	// blocks this is the single ID the result satisfies; for assistant
	// reasoning it may be empty.
	ReferencedIDs []string
	// Pinned marks protocol-significant messages that must survive the
	// drop pass even when they are not part of a completed live pair.
	// OpenAI tool-call producer messages use this so the compressor
	// never drops an unfinished assistant/function_call turn.
	Pinned bool
	// KeepWithNext marks a message the provider verifies together with
	// the message right after it, so the two must never be separated: a
	// rolling-summary boundary never falls between them (the pair is
	// summarized whole or kept whole). OpenAI Responses reasoning items
	// set it — the provider rejects a reasoning item that lost its
	// following output item. The drop pass needs no separate rule
	// because both sides are Pinned.
	KeepWithNext bool
	// NoCompress prevents per-type compression from rewriting this
	// message's body. Set on tool_result messages from MCP tools
	// (`mcp__*`) where the values ARE the answer (action_ids, file
	// hashes, costs, stashed bytes); JSON / code / logs compression
	// would replace those scalars with type sentinels and corrupt
	// the response. Surfaced 2026-05-08 dogfood: search_past_outputs
	// returned 10 hits but the model saw "placeholders only".
	NoCompress bool
}

// ScoreOptions tunes the importance scorer.
type ScoreOptions struct {
	// PreserveLastN messages always score 1.0 regardless of the formula.
	// Matches the [compression.conversation.preserve_last_n] config knob.
	PreserveLastN int
	// Weights overrides the default coefficient set. Zero-valued weights
	// use defaults: Recency=0.4, Reference=0.3, Density=0.2, Role=0.1.
	Weights ScoreWeights
}

// ScoreWeights are the coefficients applied to each signal. The four
// fields are expected to sum to 1.0 so a score stays in [0, 1]; the
// scorer does not enforce this, letting callers bias one signal over
// another.
type ScoreWeights struct {
	Recency   float64
	Reference float64
	Density   float64
	Role      float64
}

// defaultWeights is the starting coefficient set — recency dominates so
// the newest messages are never candidates for compression, reference
// counts catch live tool-use threads, density strips out whitespace-heavy
// outputs, and role weight gives user/system messages an edge.
var defaultWeights = ScoreWeights{Recency: 0.4, Reference: 0.3, Density: 0.2, Role: 0.1}

// ScoredMessage pairs a Message with its importance score and the raw
// component signals for diagnostics.
type ScoredMessage struct {
	Message
	Score      float64
	Components ScoreComponents
	Preserved  bool // set when PreserveLastN pinned this message.
}

// ScoreComponents records the normalized per-signal contributions. Useful
// for observer_log and dashboard breakdowns.
type ScoreComponents struct {
	Recency   float64
	Reference float64
	Density   float64
	Role      float64
}

// Score computes a per-message importance score in [0, 1]. Messages in the
// last [ScoreOptions.PreserveLastN] window are pinned to 1.0 and flagged
// so the budget enforcer will never drop them.
//
// The four signals combine as:
//
//	score = w.Recency*recency + w.Reference*ref + w.Density*density + w.Role*role
//
// where:
//   - recency is (i+1)/n so the last message gets 1.0 and the oldest gets 1/n
//   - reference is 1.0 when the message's ToolUseID is cited by a later
//     message (the tool result is still live), 0.0 otherwise
//   - density is the fraction of non-whitespace bytes, discouraging the
//     enforcer from keeping whitespace-padded outputs
//   - role is a constant per role: system=1.0, user=0.9, assistant=0.7,
//     tool=0.5 — tool outputs are the most-compressible by policy
func Score(msgs []Message, opts ScoreOptions) []ScoredMessage {
	if len(msgs) == 0 {
		return nil
	}
	w := opts.Weights
	if w == (ScoreWeights{}) {
		w = defaultWeights
	}
	referencedLater := referencedLaterSet(msgs)

	out := make([]ScoredMessage, len(msgs))
	n := float64(len(msgs))
	preserveFrom := len(msgs) - opts.PreserveLastN
	if preserveFrom < 0 {
		preserveFrom = 0
	}

	for i, m := range msgs {
		comp := ScoreComponents{
			Recency: float64(i+1) / n,
			Density: densityScore(m.Text),
			Role:    roleWeight(m.Role),
		}
		// Reference component: any of this message's tool_use IDs being
		// cited by a later tool_result earns the full reference weight.
		// Multi-block parallel tool calls (Claude Code's "Read + LS +
		// LS" pattern) all count.
		for _, id := range m.ToolUseIDs {
			if referencedLater[id] {
				comp.Reference = 1.0
				break
			}
		}
		score := w.Recency*comp.Recency +
			w.Reference*comp.Reference +
			w.Density*comp.Density +
			w.Role*comp.Role

		// Tool-pair integrity: BOTH sides of every live tool_use ↔
		// tool_result pairing MUST survive the drop pass. Anthropic
		// rejects the request otherwise:
		//   - dropping the tool_use leaves the surviving tool_result
		//     orphan ("tool_result must have a corresponding tool_use
		//     block in the previous message")
		//   - dropping the tool_result leaves the surviving tool_use
		//     unanswered ("tool_use blocks must be followed by
		//     tool_result blocks", which Claude Code surfaces as "tool
		//     use concurrency issues")
		// Score components alone don't guarantee survival — the drop
		// pass only honours Preserved. So mark BOTH the producer side
		// (any of m.ToolUseIDs is referencedLater) AND the consumer
		// side (any of m.ReferencedIDs intersects the live set) as
		// preserved. Messages may also arrive pre-pinned by an adapter
		// when the provider's protocol requires they survive even before
		// a result lands (for example OpenAI assistant/function_call
		// producers). Asymmetric only when neither side is live and the
		// message was not pre-pinned — those stay droppable, no orphan
		// possible.
		toolPairLive := false
		for _, id := range m.ToolUseIDs {
			if referencedLater[id] {
				toolPairLive = true
				break
			}
		}
		if !toolPairLive {
			for _, id := range m.ReferencedIDs {
				if referencedLater[id] {
					toolPairLive = true
					break
				}
			}
		}
		// User/system instructions are the conversational backbone.
		// They are usually small relative to tool output, and dropping
		// them can leave the model with only compressed markers and no
		// recoverable task. Compression markers themselves stay droppable
		// so they don't accumulate forever across turns.
		rolePinned := m.Role == RoleSystem || (m.Role == RoleUser && !isCompressionMarkerText(m.Text))
		preserved := (opts.PreserveLastN > 0 && i >= preserveFrom) || toolPairLive || m.Pinned || rolePinned
		if preserved {
			score = 1.0
		}
		out[i] = ScoredMessage{
			Message:    m,
			Score:      score,
			Components: comp,
			Preserved:  preserved,
		}
	}
	return out
}

func isCompressionMarkerText(text string) bool {
	if text == "" {
		return false
	}
	return strings.Contains(text, "messages compressed") &&
		strings.Contains(text, "search_past_outputs")
}

// referencedLaterSet returns the set of tool_use IDs that appear as a
// [Message.ReferencedIDs] entry on a later message (i.e. the thread is
// still live — a result satisfies this call). Set membership is keyed by
// the string ID so lookup is O(1). Walks BOTH sides of the producer/
// consumer pairing: a producer ID lands in `later` iff it appears in
// `seenReferences` from any later message (including the same message
// when both blocks are emitted in one turn).
func referencedLaterSet(msgs []Message) map[string]bool {
	later := make(map[string]bool)
	// Walk from the end back: every ReferencedID we see goes into the
	// set. When we hit the producer message (ToolUseID == ID), we know
	// it was referenced later because we iterated later→earlier.
	seenReferences := make(map[string]bool)
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		for _, id := range m.ReferencedIDs {
			seenReferences[id] = true
		}
		for _, id := range m.ToolUseIDs {
			if seenReferences[id] {
				later[id] = true
			}
		}
	}
	return later
}

// densityScore returns the fraction of non-whitespace runes in s, clamped
// to [0, 1]. A fully-empty or whitespace-only string scores 0; a message
// with no whitespace scores 1.
func densityScore(s string) float64 {
	if s == "" {
		return 0
	}
	total := 0
	nonWS := 0
	for _, r := range s {
		total++
		if !unicode.IsSpace(r) {
			nonWS++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(nonWS) / float64(total)
}

// roleWeight gives each role a fixed importance coefficient. System and
// user messages are near-untouchable by design; tool outputs are the most
// compressible. Unknown roles fall back to the assistant weight so custom
// roles don't get pinned at 0.
func roleWeight(role string) float64 {
	switch strings.ToLower(role) {
	case RoleSystem:
		return 1.0
	case RoleUser:
		return 0.9
	case RoleAssistant:
		return 0.7
	case RoleTool:
		return 0.5
	default:
		return 0.7
	}
}
