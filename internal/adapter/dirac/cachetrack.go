package dirac

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-session Tier-2 accumulator's running
// block count: the shared cacheobs default (same memory budget, same OOM
// guard as every other Tier-2 producer).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// The canonical block forms live in cacheobs (message.go), so this
// adapter's chain bytes cannot drift from the other Tier-2 producers'. The
// wrappers below keep the parse loop's call sites unchanged.

// accumulateTextCache feeds one text block's (already scrubbed) content
// into acc, tagged by the message's role.
func accumulateTextCache(acc *cacheobs.Accumulator, text, role string) {
	acc.ObserveText(text, role)
}

// accumulateToolCallCache feeds one tool_use block's name + (already
// scrubbed) input JSON into acc.
func accumulateToolCallCache(acc *cacheobs.Accumulator, name, scrubbedInput string) {
	acc.ObserveToolUse(name, scrubbedInput)
}

// accumulateToolResultCache feeds one tool_result block's (already
// scrubbed, already flattened) text into acc.
func accumulateToolResultCache(acc *cacheobs.Accumulator, scrubbedText string) {
	acc.ObserveToolResult(scrubbedText)
}

// emitCacheObservation drains acc into one CacheTurnObservation for a
// token-bearing assistant message. Returns nil for an all-zero bundle.
// The provider id is mapped onto the cachetrack vocabulary first so an
// OpenAI-family turn takes the implicit-cache path (§15.3 overlay).
func emitCacheObservation(acc *cacheobs.Accumulator, path, sessionID, messageID, model, provider string, ts time.Time, tp tokenSplit) *models.CacheTurnObservation {
	usage := models.CacheUsage{
		NetInputTokens:      tp.input,
		OutputTokens:        tp.output,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrite,
	}
	return acc.EmitTurn(path, sessionID, messageID, model, cacheProvider(provider), ts, usage)
}
