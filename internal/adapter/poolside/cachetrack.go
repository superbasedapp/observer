package poolside

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

// accumulateTextCache feeds an already-scrubbed plain-text block (a user
// prompt or an assistant message) into acc under the given role.
func accumulateTextCache(acc *cacheobs.Accumulator, text, role string) {
	acc.ObserveText(text, role)
}

// accumulateToolCallCache feeds one tool_call.parsed's name + (already
// scrubbed) serialized input into acc.
func accumulateToolCallCache(acc *cacheobs.Accumulator, name, scrubbedInput string) {
	acc.ObserveToolUse(name, scrubbedInput)
}

// accumulateToolResultCache feeds one tool_call.result's (already
// scrubbed) observation text into acc.
func accumulateToolResultCache(acc *cacheobs.Accumulator, scrubbedText string) {
	acc.ObserveToolResult(scrubbedText)
}

// emitCacheObservation drains acc's pending content-block delta into one
// CacheTurnObservation for a tool_call.inference.end record's usage, when
// tp carries anything worth persisting.
func emitCacheObservation(acc *cacheobs.Accumulator, path, sessionID, messageID, model string, ts time.Time, tp tokenParts) *models.CacheTurnObservation {
	usage := models.CacheUsage{
		NetInputTokens:      tp.inputNet,
		OutputTokens:        tp.outputNet,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrit,
	}
	// Poolside's tool_call.inference.end never states which upstream
	// provider served the model, so provider is always "" — a no-op
	// today, kept for consistency with every other Tier-2 producer's
	// identical overlay call.
	return acc.EmitTurn(path, sessionID, messageID, model, "", ts, usage)
}
