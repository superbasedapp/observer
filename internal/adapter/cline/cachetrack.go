package cline

import (
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-session Tier-2 accumulator's
// running block count: the shared cacheobs default (same memory
// budget, same OOM guard as every other Tier-2 producer).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// buildCacheObservations walks the whole-file message array (the
// same slice ParseSessionFile decodes) and emits one
// CacheTurnObservation per message carrying token accounting
// (msg.Usage != nil or msg.Metrics != nil, mirroring
// tokenEventFor's own gate). cline/roo-code content blocks are the
// same Anthropic-shape schema as cline-cli's — text / thinking /
// tool_use / tool_result / image — so the canonical forms come
// from cacheobs (content.go), shared with cline-cli and cowork,
// with an "image" case since cline surfaces pasted images
// cline-cli's fixture set never exercised.
//
// The file is re-read whole on every poll (not JSONL-appended), so
// this is called once per ParseSessionFile invocation over the
// full decoded msgs slice; store-level (source_file,
// source_event_id) idempotency dedupes across re-parses exactly
// like the TokenEvent path above.
func buildCacheObservations(msgs []rawMessage, path, sessionID string) []models.CacheTurnObservation {
	if len(msgs) == 0 {
		return nil
	}
	acc := cacheobs.New(MaxBlocksPerSession)
	var out []models.CacheTurnObservation
	for i := range msgs {
		msg := &msgs[i]
		blocks := decodeContent(msg.Content)
		acc.ObserveBlocks(accumulateCacheBlocksTier2(blocks, msg.Role))

		ev, ok := tokenEventFor(msg, path, sessionID, "", "", "", "", msg.resolvedModel(), parseMilliTimestamp(msg.Ts), i)
		if !ok {
			continue
		}
		usage := models.CacheUsage{
			NetInputTokens:      ev.InputTokens,
			OutputTokens:        ev.OutputTokens,
			CacheReadTokens:     ev.CacheReadTokens,
			CacheCreationTokens: ev.CacheCreationTokens,
		}
		messageID := sessionID + ":" + strconv.Itoa(i)
		// §15.3 boundary: cline's non-Anthropic providers (metrics-
		// shape messages, providerId="cline") route through
		// implicit-cache-shape gateways depending on the resolved
		// model. Anthropic-shape (msg.Usage != nil) messages always
		// stay Anthropic-routed in practice, but the overlay is
		// applied uniformly — cachetrack.IsImplicitCacheProvider
		// defaults to false (Anthropic-shape) for an unmatched/empty
		// provider string, so this is a no-op for the common case.
		// EmitTurn skips an all-zero usage (nil).
		if obs := acc.EmitTurn(path, sessionID, messageID, msg.resolvedModel(), "", parseMilliTimestamp(msg.Ts), usage); obs != nil {
			out = append(out, *obs)
		}
	}
	return out
}

// accumulateCacheBlocksTier2 converts cline/roo-code's Anthropic-
// shape content blocks into deterministic CacheBlockMeta entries,
// in array order (cacheobs.ContentBlocks).
func accumulateCacheBlocksTier2(blocks []rawContentBlock, role string) []models.CacheBlockMeta {
	return cacheobs.ContentBlocks(blocks, role, marshalCanonicalBlockTier2)
}

// marshalCanonicalBlockTier2 maps one cline/roo-code content block
// onto its cacheobs canonical form. Returns (canonical bytes, engine
// kind label, ok=false on unknown block type).
func marshalCanonicalBlockTier2(b rawContentBlock) (canon []byte, kind string, ok bool) {
	switch b.Type {
	case "text":
		return cacheobs.ContentText("text", b.Text)
	case "thinking", "redacted_thinking":
		txt := b.Thinking
		if txt == "" && b.Type == "redacted_thinking" {
			txt = "[redacted thinking]"
		}
		return cacheobs.ContentText("thinking", txt)
	case "tool_use":
		return cacheobs.ContentToolUse(b.ID, b.Name, b.Input)
	case "tool_result":
		return cacheobs.ContentToolResult(b.ToolUseID, b.IsError, b.Content)
	case "image":
		// No text/binary payload folded into the chain — image
		// bytes are never stored. The block's presence (and
		// ordering) is what the chain needs to stay position-
		// accurate against the source transcript.
		return cacheobs.ContentImage()
	default:
		return nil, "", false
	}
}
