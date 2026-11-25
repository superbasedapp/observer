package codebuddy

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

// emitCacheObservation drains acc's pending content-block delta into one
// CacheTurnObservation for a record's outer usage envelope, when that
// envelope carries anything worth persisting. Returns nil when the
// derived CacheUsage is all-zero — emitTokens already gates on
// tokenParts.isZero() before calling this, so tp here is never the zero
// value in practice, but the check is kept for defense in depth (mirrors
// every other Tier-2 producer's identical gate).
func emitCacheObservation(acc *cacheobs.Accumulator, path, sessionID, messageID, model string, ts time.Time, tp tokenParts) *models.CacheTurnObservation {
	usage := models.CacheUsage{
		NetInputTokens:      tp.inputNet,
		OutputTokens:        tp.output,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrit,
	}
	// §15.3 boundary: a CodeBuddy usage record never states which
	// upstream provider served the model (CodeBuddy fronts every model
	// through its own gateway; the model id is not a provider id),
	// so provider is always "" here — a no-op today, kept for
	// consistency with every other Tier-2 producer's identical overlay
	// call.
	return acc.EmitTurn(path, sessionID, messageID, model, "", ts, usage)
}
