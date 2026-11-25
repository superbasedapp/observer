package openclaw

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-session Tier-2 accumulator's running
// block count: the shared cacheobs default (same memory budget, same OOM
// guard as every other Tier-2 producer).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// This file wires the MESSAGE-LOG half of OpenClaw's dual-log capture
// (see adapter.go's parseSessionJSONL/parseMessageLine) into cacheobs.
// The message log carries real content for every call it covers (user
// prompts, assistant text, tool calls, tool results) plus that call's
// own usage row, which is exactly what a Tier-2 cache observation needs.
//
// The TRAJECTORY log (parseTrajectoryJSONL) is deliberately left
// unwired here: model.completed events carry no message content at all
// (see trajLine's doc comment) — only data.promptCache.lastCallUsage —
// so there is nothing to build a BlockHashes chain from, and the task's
// rule against fabricating observations rules out synthesizing one. The
// trajectory's sole remaining job (covering gateway-injected turns the
// message log zeroes out, per hasUsage) stays a TokenEvent-only gap;
// wiring it would also require sharing one accumulator's running state
// across two independently-parsed files, which risks incoherent chain
// semantics if the two files are re-parsed out of order. See
// docs/plans/adapter-parity-audit-2026-08-25.md §2.6 for the fuller
// writeup.

// The canonical block forms live in cacheobs (message.go), so this
// adapter's chain bytes cannot drift from the other Tier-2 producers'.
// OpenClaw's tool calls were recorded with the "args" key, hence
// ObserveToolUseArgs. The wrappers below keep the parse loop's call sites
// unchanged.

// accumulateUserTextCache feeds a user message's (already scrubbed)
// visible text into acc.
func accumulateUserTextCache(acc *cacheobs.Accumulator, text string) {
	acc.ObserveText(text, "user")
}

// accumulateAssistantTextCache feeds an assistant message's (already
// scrubbed) visible text part into acc.
func accumulateAssistantTextCache(acc *cacheobs.Accumulator, text string) {
	acc.ObserveText(text, "assistant")
}

// accumulateToolCallCache feeds one toolCall content part's name + raw
// (already scrubbed) arguments JSON into acc.
func accumulateToolCallCache(acc *cacheobs.Accumulator, name, scrubbedArgs string) {
	acc.ObserveToolUseArgs(name, scrubbedArgs)
}

// accumulateToolResultCache feeds one toolResult message's (already
// scrubbed) flattened output text into acc.
func accumulateToolResultCache(acc *cacheobs.Accumulator, scrubbedText string) {
	acc.ObserveToolResult(scrubbedText)
}

// emitCacheObservation drains acc's pending content-block delta into one
// CacheTurnObservation for a message-log usage row, when u carries
// anything worth persisting. Returns nil for the all-zero case (the
// caller already gates on hasUsage before calling this, so this is
// defense in depth, matching every other Tier-2 producer's identical
// gate).
func emitCacheObservation(acc *cacheobs.Accumulator, path, sessionID, messageID, model string, ts time.Time, u tokenUsage) *models.CacheTurnObservation {
	usage := models.CacheUsage{
		NetInputTokens:      u.Input,
		OutputTokens:        u.Output,
		CacheReadTokens:     u.CacheRead,
		CacheCreationTokens: u.CacheWrite,
	}
	// §15.3 boundary: the message log's per-call provider/modelId live on
	// the outer jsonlLine, not the usage row itself, and this helper only
	// sees the usage — provider is always "" here, a no-op today, kept
	// for consistency with every other Tier-2 producer's identical
	// overlay call.
	return acc.EmitTurn(path, sessionID, messageID, model, "", ts, usage)
}
