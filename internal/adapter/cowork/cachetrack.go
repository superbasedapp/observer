package cowork

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-session Tier-2 accumulator's
// running block count: the shared cacheobs default (same memory
// budget, same OOM guard as every other Tier-2 producer).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// emitCacheObservationsTier2 builds one CacheTurnObservation per
// model in a `result` record's modelUsage map, draining cacheAcc's
// running per-session content-block delta.
//
// cowork's authoritative per-turn token accounting lives ONLY on the
// `result` record's modelUsage map (see handleResult's doc comment —
// assistant.message.usage is a streaming snapshot that drops
// output_tokens on most chunks and never sees internally-dispatched
// haiku calls). Content blocks, however, stream in on the "user" and
// "assistant" records that precede each result; handleUser and
// handleAssistant feed cacheAcc as they're parsed so the chain stays
// in transcript order regardless of which record carries usage.
//
// modelUsage is usually a single-entry map, but cowork can dispatch
// an internal model (e.g. a haiku sub-call for a background task)
// alongside the primary model within one result — the fixture-
// validated case carries both claude-opus-4-6 and
// claude-haiku-4-5-20251001 in the same result. sortedModels fixes
// iteration order (handleResult already sorts it for the TokenEvent
// loop; reused here for the same determinism reason). Because
// Accumulator.Emit drains and resets the pending delta, only the
// FIRST model in sorted order receives the turn's new BlockHashes;
// subsequent models in the same result emit with an empty delta
// (a valid, cheap no-op turn — never a fabricated one). This avoids
// crediting one turn's content blocks into two independent chains,
// and mirrors the ordering the TokenEvent path already commits to.
func emitCacheObservationsTier2(
	acc *cacheobs.Accumulator,
	path, sessionID string,
	rec rawRecord,
	ts time.Time,
	modelUsage map[string]rawResultModelUsage,
	tier1hFrac float64,
	sortedModels []string,
) []models.CacheTurnObservation {
	if len(sortedModels) == 0 {
		return nil
	}
	var out []models.CacheTurnObservation
	for _, model := range sortedModels {
		mu, ok := modelUsage[model]
		if !ok {
			continue
		}
		cw := mu.CacheCreationInputTokens
		cw1h := int64(float64(cw) * tier1hFrac)
		if cw1h > cw {
			cw1h = cw
		}
		usage := models.CacheUsage{
			NetInputTokens:        mu.InputTokens,
			OutputTokens:          mu.OutputTokens,
			CacheReadTokens:       mu.CacheReadInputTokens,
			CacheCreationTokens:   cw,
			CacheCreation1hTokens: cw1h,
		}
		messageID := "result:" + rec.UUID + ":" + model
		// §15.3 boundary: cowork is Anthropic-first-party (the
		// audit.jsonl usage shape is the Anthropic Messages API
		// response verbatim, including the 5m/1h cache-creation
		// tier split no gateway-fronted provider exposes) — the
		// overlay is applied uniformly for consistency with every
		// other Tier-2 producer, but it defaults to false
		// (Anthropic-shape) for cowork's model strings, so it is a
		// no-op in practice. EmitTurn skips an all-zero usage (nil).
		if obs := acc.EmitTurn(path, sessionID, messageID, model, "", ts, usage); obs != nil {
			out = append(out, *obs)
		}
	}
	return out
}

// accumulateCacheBlocksTier2 converts cowork's Anthropic-shape
// content blocks into deterministic CacheBlockMeta entries, in array
// order (cacheobs.ContentBlocks). cowork's rawContentBlock schema is
// the same text/thinking/tool_use/tool_result/image shape cline and
// cline-cli marshal, through the same cacheobs canonical forms; the
// "image" case carries no payload (image bytes are never stored) —
// only the block's presence/ordering feeds the chain.
func accumulateCacheBlocksTier2(blocks []rawContentBlock, role string) []models.CacheBlockMeta {
	return cacheobs.ContentBlocks(blocks, role, marshalCanonicalBlockTier2)
}

// marshalCanonicalBlockTier2 maps one cowork content block onto its
// cacheobs canonical form. Returns (canonical bytes, engine kind
// label, ok=false on unknown block type).
func marshalCanonicalBlockTier2(b rawContentBlock) (canon []byte, kind string, ok bool) {
	switch b.Type {
	case "text":
		return cacheobs.ContentText("text", b.Text)
	case "thinking":
		return cacheobs.ContentText("thinking", b.Thinking)
	case "tool_use":
		return cacheobs.ContentToolUse(b.ID, b.Name, b.Input)
	case "tool_result":
		return cacheobs.ContentToolResult(b.ToolUseID, b.IsError, b.Content)
	case "image":
		return cacheobs.ContentImage()
	default:
		return nil, "", false
	}
}
