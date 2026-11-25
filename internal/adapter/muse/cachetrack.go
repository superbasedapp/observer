package muse

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
// adapter's chain bytes cannot drift from the other Tier-2 producers'.
// Muse's tool calls were recorded with the "args" key, hence
// ObserveToolUseArgs. The wrappers below keep the parse loop's call sites
// unchanged.

// accumulatePromptCache feeds a run-level `started` event's (already
// scrubbed) prompt text into acc, as a single "user" text block. A
// `started` event is one-shot per run (see emitRunStart's isSubagent /
// task-id carve-out), so no once-only guard is needed.
func accumulatePromptCache(acc *cacheobs.Accumulator, text string) {
	acc.ObserveText(text, "user")
}

// accumulateAssistantMessageCache feeds an assistant_message_committed
// event's (already scrubbed) visible reply into acc.
func accumulateAssistantMessageCache(acc *cacheobs.Accumulator, text string) {
	acc.ObserveText(text, "assistant")
}

// accumulateToolCallCache feeds one assistant_tool_calls_committed entry's
// name + (already scrubbed) serialized args into acc.
func accumulateToolCallCache(acc *cacheobs.Accumulator, name, scrubbedArgs string) {
	acc.ObserveToolUseArgs(name, scrubbedArgs)
}

// accumulateToolResultCache feeds one tool_result_batch_committed entry's
// (already scrubbed) result text into acc.
func accumulateToolResultCache(acc *cacheobs.Accumulator, scrubbedText string) {
	acc.ObserveToolResult(scrubbedText)
}

// emitCacheObservation drains acc's pending content-block delta into one
// CacheTurnObservation for a model_completed record's usage, when tp
// carries anything worth persisting. Returns nil when the derived
// CacheUsage is all-zero — emitTokens already gates on e.Usage.isZero()
// before calling this, so tp here is never the zero value in practice,
// but the check is kept for defense in depth (mirrors every other Tier-2
// producer's identical gate).
func emitCacheObservation(acc *cacheobs.Accumulator, path, sessionID, messageID, model string, ts time.Time, tp tokenParts) *models.CacheTurnObservation {
	usage := models.CacheUsage{
		NetInputTokens:      tp.inputNet,
		OutputTokens:        tp.outputNet,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrit,
	}
	// §15.3 boundary: Muse's model_completed record never states which
	// upstream provider served the model (provider_id lives only on the
	// unrelated run.model.configured record we don't thread through
	// here), so provider is always "" — a no-op today, kept for
	// consistency with every other Tier-2 producer's identical overlay
	// call.
	return acc.EmitTurn(path, sessionID, messageID, model, "", ts, usage)
}
