package deepagents

import (
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
)

// MaxBlocksPerSession caps the per-thread Tier-2 accumulator's running block
// count: the shared cacheobs default (same memory budget and OOM guard as
// every other Tier-2 producer).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// The canonical block forms live in cacheobs (message.go), so this adapter's
// chain bytes cannot drift from the other Tier-2 producers'. The wrappers
// below keep the builder's call sites unchanged.

// accumulateTextCache feeds one already-scrubbed text block into acc, tagged
// by the message role.
func accumulateTextCache(acc *cacheobs.Accumulator, text, role string) {
	acc.ObserveText(text, role)
}

// accumulateToolResultCache feeds one already-scrubbed, flattened tool result
// into acc.
func accumulateToolResultCache(acc *cacheobs.Accumulator, scrubbedText string) {
	acc.ObserveToolResult(scrubbedText)
}

// accumulateToolCallCache feeds one assistant tool call (name plus the
// already-scrubbed argument JSON) into acc.
func accumulateToolCallCache(acc *cacheobs.Accumulator, name, scrubbedInput string) {
	acc.ObserveToolUse(name, scrubbedInput)
}
